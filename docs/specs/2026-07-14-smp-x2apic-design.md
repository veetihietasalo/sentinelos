# SMP Bring-up via x2APIC — Design

Status: **phase 1 implemented; AP bring-up, per-CPU scheduler + IPIs, the per-core LAPIC timer (see the 2026-09-18 note at the end) and IOAPIC routing (3b-ii, see the 2026-10-04 note) implemented** · Track A (Intel/AMD CPU +
security), step 3 · Author: scheduler / hal track
Depends on: `hal::pic` (8259 remap + EOI), `hal::pit` (100 Hz IRQ0),
`hal::cpu` MSR primitives (`read_msr`/`write_msr`, shipped), `hal::cpuid`
(feature detection, shipped).
Escalation: touches the **TCB** (new privileged MSR call sites for the LAPIC) and
the interrupt-delivery path → requires kernel-reviewer + verification-engineer
sign-off before each phase merges (charter invariant #6).

## Goal

Take SentinelOS from strictly single-core to genuine **symmetric multiprocessing**
(SMP): every logical CPU the firmware reports running kernel code, so the eventual
scheduler, the AI/ML compute path (many-core matmul), and a desktop workload have
more than one core to use. This is the load-bearing prerequisite for everything
compute-heavy on the roadmap — a single core caps us far below the hardware.

SMP is not one change; it is a sequence where each step is independently bootable
and testable. Doing it as a single "enable all cores" leap is how kernels
triple-fault. This doc defines the phases and locks down phase 1.

## Background: why the PIC alone cannot do SMP

The legacy 8259 PIC pair delivers every hardware IRQ to **one** CPU (the BSP). It
has no concept of "core 3" and no way to send a CPU-to-CPU signal. Multi-core
needs three pieces of APIC hardware the PIC cannot provide:

| Piece | Role | Phase |
|---|---|---|
| **Local APIC (LAPIC)** | Per-core interrupt controller; the target of IPIs and the local timer. Each core has its own. | 1 (this PR: BSP only) |
| **IOAPIC** | Routes external device IRQs (timer, keyboard, NIC…) to a chosen LAPIC/vector, replacing the PIC's fixed wiring. | 2 |
| **IPIs (INIT / SIPI)** | Inter-processor interrupts the BSP sends to wake and launch the Application Processors (APs). | 3 |

We use **x2APIC** (MSR-based LAPIC access, `IA32_APIC_BASE.EXTD`) rather than
legacy xAPIC (MMIO at `0xFEE0_0000`): MSR access needs no BAR mapping, has no
32-bit APIC-ID limit (matters for large core counts and the AI/ML target), and is
what every CPU worth targeting for this project supports. Detection is `cpuid`
leaf 1 ECX bit 21.

## Phase 1 — enable the BSP's LAPIC in x2APIC, virtual-wire (**implemented**)

The smallest non-disruptive step: switch the BSP's own LAPIC into x2APIC mode and
software-enable it, **without** touching how device IRQs are delivered yet. That
"without" is the whole trick, and it is why this phase is safe to ship alone.

### Virtual wire — keeping the PIC alive under an enabled LAPIC

Once the LAPIC is enabled it becomes the CPU's interrupt gateway; a naïvely
enabled LAPIC would swallow the PIC's INTR line and the PIT would stop ticking
(clock dead, `hlt` idle loop never wakes). The architectural fix is **virtual
wire mode**:

- Program **LVT LINT0 = ExtINT**. The 8259's INTR passes straight through the
  LAPIC: on an interrupt the CPU runs its normal INTA cycle and fetches the vector
  **from the PIC**, exactly as before. The existing PIT / keyboard / mouse / NIC
  handlers — which EOI the *PIC* (`hal::pic`, P5) — stay correct verbatim, because
  ExtINT delivery never sets the LAPIC's ISR, so no LAPIC EOI is owed.
- Program **LVT LINT1 = NMI** (the conventional NMI routing).
- Program **SVR = software-enable | spurious vector `0xFF`**.

Net effect: the LAPIC is on and addressable (so `id()` works and later phases can
send IPIs), but the single-core IRQ path is byte-for-byte unchanged. Nothing to
migrate, nothing to re-verify in the drivers.

### TCB surface (registered in `hal-tcb.md` §2i, AP1/AP2)

`hal::apic` adds **no new raw instruction** — it reuses the existing
`cpu::read_msr` / `cpu::write_msr` primitives (C9/C10). Two new call sites:

- `enable_bsp() -> Option<u32>` — `cpuid`-gated on x2APIC; OR-s `EN|EXTD` into
  `IA32_APIC_BASE`, writes `SVR`/`LINT0`/`LINT1`, returns the BSP's x2APIC ID.
  `None` (and stay on xAPIC/PIC) if x2APIC is not advertised.
- `id()` — read MSR `0x802`; valid only after the mode switch.
- `logical_cpu_count()` / `has_x2apic()` — pure `cpuid` reads, no privileged op.

### Liveness proof (why the boot test can trust it)

`kmain` calls `enable_bsp()` right after `interrupts::init_timer()`, then briefly
`sti`s and spins until the PIT tick count advances by 3, then `cli`s again and
logs the result. If the virtual wire were misprogrammed the clock would be dead
and this spin would hang until the 60 s boot-test cap — a **loud** failure — rather
than the timer silently stopping later. The serial line

```
[smp] x2APIC enabled; BSP apic id=0; 4 logical CPU(s); timer live (N ticks)
```

is the phase-1 acceptance evidence **where x2APIC is present** (KVM / real
hardware). Under CI's TCG emulation x2APIC is unavailable, so the probe branch is
skipped and the fallback line is shown instead — see the Testing section for why,
and why the test still meaningfully guards against regression.

## Phase 2 — IOAPIC: route device IRQs through the APIC (implemented 2026-10-04, SMP 3b-ii)

Fully mask the 8259 PIC and take LINT0 out of ExtINT; program the IOAPIC
redirection-table entries to deliver the timer / keyboard / mouse / NIC IRQs to the
BSP's LAPIC at their current vectors, and switch each driver's EOI from
`pic::end_of_interrupt` to a **LAPIC EOI** (a single MSR write to `0x80B`). Parse
the ACPI MADT to locate the IOAPIC base and the GSI mapping. Only after this does a
LAPIC EOI become owed — so `hal::apic` gains an `eoi()` and the drivers' handlers
switch over together. This is the phase that actually changes the driver IRQ path,
so it gets its own boot-test pass (every existing input/net/timer test must still
green).

## Phase 3 — AP bring-up (INIT–SIPI–SIPI) (proposed)

For each AP the MADT lists: send **INIT** then two **SIPI** IPIs (via the x2APIC
ICR, MSR `0x830`) pointing at a real-mode trampoline page ≤ 1 MiB. The trampoline
brings the AP from 16-bit real mode → 32-bit protected → 64-bit long mode, loads
the shared GDT/IDT, points it at its own stack, runs `cpu_security::enable()` on
that core (the existing "re-run on each AP" hook), enables its LAPIC, and parks it
in a `hlt` loop waiting for scheduler work. The trampoline + the mode-transition
asm are **new TCB** (hal-specialist) and the sharpest unsafe in the project so far.

## Phase 4 — per-CPU state (proposed)

Give each core its own current-thread pointer, run-queue slot, and scratch via
`GS`-based per-CPU data (`IA32_KERNEL_GS_BASE` / `swapgs`). Everything the kernel
currently keeps in a single `static` that assumes one core (the console guard, the
allocator lock hold-time, the tick counter's readers) gets audited for SMP safety.

## Phase 5 — SMP-safe kernel (proposed)

Audit every `static`/lock in the safe crates for real (not single-core-fiction)
concurrency: the `mm` `SpinMutex` (§5e) and the NIC/driver locks already exist "for
future SMP" and now actually spin; the console `cli` guard is **not** an SMP lock
and needs one; the lock-free input/mouse rings need re-checking as genuine SPSC
across cores. Only here does the framekernel's `#![forbid(unsafe_code)]` safe-Rust
concurrency story get its real test.

## Testing

- **Phase 1 (now):** `cargo xtask test` boots with `-cpu Haswell,+smep,+smap,+umip -smp 4`
  and asserts `boot-bringup-ok` is still reached (no regression to the single-core
  IRQ path). **Environment caveat (important):** QEMU 8.2's software emulation
  (TCG — used in CI and the dev sandbox, no KVM) **cannot advertise x2APIC under
  any CPU model** — even an explicit `+x2apic` is rejected
  (`TCG doesn't support requested feature: CPUID.01H:ECX.x2apic`) and `-cpu max`
  simply omits it. So the test flags deliberately **do not** request `+x2apic`
  (it would only add misleading warnings): under TCG `enable_bsp()` is
  `has_x2apic()`-gated to a safe no-op and the serial shows
  `[smp] x2APIC not advertised; staying on legacy xAPIC/PIC` — graceful
  degradation, the same pattern as `cpu_security` on a CPU lacking SMEP. To
  exercise the **enable** path (`[smp] x2APIC enabled …; timer live (N ticks)`),
  boot under **KVM** (`-enable-kvm -cpu host`) or on real hardware, where x2APIC
  is present natively; there the `kmain` timer-liveness probe proves the PIT still
  ticks through LINT0=ExtINT across the switch.
- **C1 evidence (the enable-path proof) is now automated.** `cargo xtask test-kvm`
  (`make test-kvm`) boots under `-enable-kvm -cpu host` and **asserts** the
  `[smp] x2APIC enabled … timer live` line, failing if the enable path did not run.
  The `.github/workflows/kvm-smp.yml` CI job runs exactly this on a KVM-capable
  runner and uploads the serial log as the artifact `smp-x2apic-kvm-serial-log` —
  that log is the C1 record for issue #10. If a runner lacks `/dev/kvm` the job
  skips with a warning (no false green claim), and the proof falls back to running
  `make test-kvm` on real hardware.
- **Phase 2:** all existing input / net / timer boot assertions must still pass
  with IRQs coming via the IOAPIC + LAPIC EOI.
- **Phase 3+:** each AP prints a `[smp] AP n online (apic id=…)` line; the boot
  test counts `-smp N` online lines. A per-CPU counter incremented by all cores
  proves they run independently.
- **Verification.** The LAPIC MSR writes and the AP trampoline asm are inline
  asm / raw asm Miri cannot execute; document residual risk and have
  verification-engineer review the SAFETY arguments per invariant #2 (no unsafe
  merges unverified). The pure helpers (`logical_cpu_count` bitfield extraction,
  MADT parsing in the safe kernel) are Kani/unit-test candidates.

## Open questions

- **MADT vs. `cpuid` for the CPU list.** Phase 1 reports `cpuid` leaf 1's
  logical-CPU count (max addressable), which is enough for a bring-up line. Phase 3
  needs the *actual* enabled-AP list + their APIC IDs, which is the ACPI MADT's
  job. Proposal: pull in a minimal ACPI table walker (safe kernel crate over a
  `hal` "give me the RSDP from Limine" primitive) at phase 3, not before.
- **x2APIC-only, or an xAPIC fallback?** Every realistic target has x2APIC and
  phase 1 already degrades gracefully when it is absent. Proposal: require x2APIC
  for actual SMP (phase 3+); keep the single-core PIC path as the no-x2APIC
  fallback rather than implementing MMIO xAPIC too.
- **Trampoline page allocation.** The SIPI vector must be a page-aligned physical
  address < 1 MiB. Proposal: reserve a low frame from the Limine memory map at
  boot specifically for the AP trampoline (phase 3).

## References

- Intel SDM Vol. 3A ch. 8 (APIC), ch. 10 (MP init: INIT–SIPI–SIPI); the x2APIC MSR
  layout (`IA32_APIC_BASE` `0x1B`, registers `0x800`–`0x8FF`).
- SentinelOS strategy & roadmap (`docs/research/2026-07-14-sentinelos-strategy-and-roadmap.md`),
  Track A. The literature improvement-map's SMP / many-core scheduling entries
  (arXiv:2601.20435) inform phases 4–5 (per-CPU state + SMP-safe concurrency), not
  the bring-up mechanics here.

## Status note — 2026-09-18

What landed, against the phase table above (the numbering there is the original
plan; the work shipped in a different order):

- **Phase 1** (BSP LAPIC, virtual wire): shipped; since PR-2 the register access is
  dual-path — x2APIC MSRs where advertised, one uncached xAPIC MMIO page under
  QEMU TCG — so the "x2APIC-only?" open question resolved as **both**.
- **Phase 3 (AP bring-up)**: shipped via the **Limine MP protocol**, not a
  hand-rolled trampoline; the MADT question resolved as "the bootloader's CPU
  list". See `docs/specs/2026-07-16-smp-ap-bringup-design.md`.
- **Phase 4 (per-CPU state)**: shipped as a dense-index array in the safe kernel,
  not `GS`-base (rationale in the AP bring-up doc).
- **IPIs**: shipped as the per-CPU scheduler's reschedule wake-up (vector `0xF0`).
- **Per-core LAPIC timer** (not in the original table): shipped — calibrated against
  the PIT on the BSP, periodic at 100 Hz on every core (vector `0xF1`), carrying
  `sched::on_tick`; the PIT is wall clock only. Proof: `[sched] ap-preemptive: …`.
- **Core-independent monotonic clock (3b-i, 2026-09-18)**: shipped as
  `kernel::clock` — the max over per-core aligned LAPIC-tick counts, advanced by
  any core, never backwards, at most one per tick (Kani). Cross-core waits and
  the preemption-proof tasks time on it, so a BSP with `IF = 0` no longer stalls
  them (hal-tcb invariant 4.15 retired as a hazard). Proof: `[clock] mono: …
  pit-frozen=yes bsp-stalled-advance=yes rate-ok=yes ok`. The PIT stays the
  wall clock for uptime and the LAPIC calibration reference.
- **Phase 2 (IOAPIC, 3b-ii)**: shipped 2026-10-04 — see the note below.
- **Phase 5 (SMP-safe kernel)**: partially shipped alongside — cross-core console
  lock, the no-allocation-under-IRQ-lock rule, per-core preempt state; the
  input/mouse rings and driver locks are still unaudited for real concurrency.

## Status note — 2026-10-04 (SMP 3b-ii: IOAPIC routing)

Shipped ahead of component PR-3 (the 2026-09-18 sequencing put it after; it
blocks nothing and touches none of PR-2b/PR-3's files).

- **ACPI walk (`kernel::acpi`, safe).** `&[u8] -> Result` decoders for the RSDP
  (v1 → RSDT, v2 → XSDT when its extended checksum holds), SDT headers and
  checksums, root-table entries, and the MADT — types 0/9 (CPUs), **1 (IOAPIC)**,
  **2 (Interrupt Source Override)**, 3 (NMI source), 4/0xA (LAPIC NMI) — into a
  fixed-size `MadtInfo` (no heap growth on firmware input). Malformed or
  truncated tables are `Err`; loops are bounded by the table length. One fetch
  walker (`discover_madt`) sequences reads through `hal::acpi::read_phys`, which
  copies into two fixed buffers (4 KiB root, 8 KiB MADT). QEMU's q35 firmware
  (SeaBIOS) hands out a revision-0 RSDP, so the RSDT path is the one exercised at
  boot; the salvaged 2026-07-17 draft supported only the XSDT and would have
  failed here. Kani, compositional (each harness < 60 s): the structure walk
  `for_each_entry` is total and exactly tiles the table
  (`madt_walk_is_total_and_tiles`), each structure decodes totally and exactly
  (`one_entry_decode_is_total_and_exact`), `push` respects capacity
  (`push_respects_capacity`), plus a composed 46-byte smoke
  (`madt_body_smoke_46`), `rsdp_decode_is_total` and `root_entry_is_total`; host tests use QEMU's real MADT and RSDT bytes,
  captured from this kernel's boot, plus a 200 000-mutant deterministic fuzz test.
- **`hal`.** `hal::acpi` (RSDP + bounded copy-out reader, AC1–AC2),
  `hal::ioapic` (validated mapping, indirect register access under one lock
  per sequence, redirection entries with Kani-proved packing — unmasked entries
  are fixed delivery of a vector ≥ 0x20 only, IO1–IO4),
  `apic::eoi_if_in_service` / `apic::mask_lint0` (AP8–AP9), `pic::mask_all`
  (P6). Every mapped physical span is checked against `MAXPHYADDR` and for
  overflow first (`mm::phys_span`, Kani) — page-table leaves are `phys | flags`
  unmasked, so high bits would otherwise alias a kernel frame. The EOI decision is made
  per interrupt from the LAPIC's in-service register: a LAPIC message (IOAPIC)
  EOIs the LAPIC, a virtual-wire ExtINT EOIs the 8259 — no flag to fall out of
  step.
- **Policy (`kernel::ioapic`).** PIT (ISA 0 → GSI 2 under QEMU), keyboard (1),
  mouse (12) and the e1000's legacy line (11, level/active-high per the
  override — a PCI line is routed only when an ISA override declares it level
  and its GSI is free, else the NIC stays polled) are routed fixed/physical to
  the **BSP**, vectors unchanged; no GSI carries two routes. BSP
  because the PIT is the wall clock and the input rings/NIC frames are consumed
  by the BSP idle loop; balancing is a product decision. 8259 fully masked,
  LINT0 masked, both read back. If the PIT is not seen ticking through the
  IOAPIC within a bounded spin the switch is rolled back to the virtual wire.
- **Boot proof** (exact match, TCG and KVM):
  `[ioapic] madt: ioapics=1 overrides=5 gsi-base=0 pins=24 pic=masked lint0=masked routed=pit,kbd,mouse,nic irq0-gsi=2 dest=apic0 pit-live=yes ok`.
  On the first of its two boots the boot test then unlocks the lock screen and
  types `about` over QMP and asserts `[ioapic] kbd: irq1 -> gsi1 vector=33 irqs>=1 pic=masked lint0=masked via=ioapic ok`
  and `[shell] ran: about`. The LAPIC-timer calibration now counts
  IOAPIC-routed PIT ticks; every pre-existing line still passes.
- **Found on the way (by inspection):** `hal::e1000`'s driver lock is taken in
  the NIC handler and, with interrupts enabled, by the idle loop when the Net app
  reads `net::status` — a latent same-core deadlock. The lock now masks
  interrupts for its critical section (hal-tcb N7). No boot hit it.
- **Not done:** `_PRT`/AML (the NIC line relies on QEMU's PIRQ steering also
  driving the IOAPIC pin), MSI, interrupt remapping (destinations > 255), load
  balancing, a coverage-guided fuzz lane.
