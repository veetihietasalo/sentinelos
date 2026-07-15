# SMP Application-Processor Bring-up — Design

Status: **proposed** · Track A (SMP), phase 2 · Author: kernel-architect
Depends on: phase 1 (x2APIC BSP enable, shipped: `hal::apic::{enable_bsp,id,logical_cpu_count}`),
`hal::mm` (frame allocator + `map_page`), `hal::simd::enable` (per-core vector state), `hal::gdt`/
`hal::idt` (BSP tables), the scheduler design (`docs/specs/2026-07-15-scheduler-design.md`, its
SMP-forward section is the starting point).
Escalation: **new TCB** — the ICR MSR write sequence and a 16-bit real-mode trampoline (the largest
asm since the ISR stubs). Requires **kernel-reviewer + verification-engineer** sign-off (charter
invariant #6). Miri/Kani cannot execute the asm; they gate the MADT parser and per-CPU bookkeeping.

## Summary

Bring every firmware-reported logical CPU into 64-bit Rust kernel code. The BSP enumerates APs
from the ACPI MADT, starts each with **INIT–SIPI–SIPI** over the x2APIC ICR (MSR `0x830`) pointing
at a low-memory real-mode trampoline that walks the AP 16→32→64-bit into a single sealed HAL entry.
Per-CPU state is a **fixed array indexed by a dense cpu-index** (safe kernel, zero new TCB). The
global `VECTOR_SAVE_ARMED` and its SMP hazard are **deleted**: `isr_common` now gates its per-IRQ
`xsave` on a **live `CR4.OSXSAVE` read**, and the AP ordering "OSXSAVE before `sti`" is enforced by
a single branch-free entry sequence. Scheduler goes per-CPU run queues, **no work stealing** this
phase. Lands in two PRs.

## Framekernel classification

| Module | Class | Owner |
|--------|-------|-------|
| `hal::smp` (trampoline blob, INIT-SIPI-SIPI, AP bootstrap page tables, `run_ap`) | **TCB (unsafe)** | hal-specialist |
| `hal::apic` +`send_init_sipi_sipi`, `enable_ap` | **TCB** | hal-specialist |
| `hal::idt` `isr_common` live-CR4 gate (removes `VECTOR_SAVE_ARMED`) | **TCB** | hal-specialist |
| `hal::simd::enable` (drop global arm; idempotent per-core) | **TCB** | hal-specialist |
| `hal::acpi` (Limine RSDP ptr + bounded HHDM byte view) | **TCB (1 slice)** | hal-specialist |
| `hal::cpu` +`read_cr3`, `udelay` | **TCB (trivial)** | hal-specialist |
| `hal::mm::frame` reserve low `<1 MiB` | **TCB (1 guard)** | hal-specialist |
| `kernel::acpi` (MADT byte parser → AP list) | safe `forbid(unsafe)` | kernel-engineer |
| `kernel::smp` (`PerCpu` array, accessors, `ap_main`, bring-up driver) | safe | kernel-engineer |
| `kernel::sched` per-CPU split (PR-2) | safe | kernel-engineer |

Rationale: **per-CPU state stays out of the TCB.** We index a `static [PerCpu; MAX_CPUS]` by a dense
cpu-index derived from the safe `apic::id()` MSR read — pure safe Rust. **GS-base is rejected:**
`%gs`-relative access needs `swapgs`/`wrgsbase` inline asm at *every* per-CPU load, dragging the
accessor into the TCB, and needs nightly `#[thread_local]` to be ergonomic. Phase 2 has no hot
per-CPU path, so the array lookup's cost is irrelevant; revisit GS-base only if syscall entry later
needs a single-instruction `current`.

## (1) Trampoline memory contract

- **Low frame.** `hal::mm::frame` seeding is changed to **exclude all frames `< 0x10_0000`** (it
  already skips frame 0). Low conventional RAM (<256 frames) is reserved wholesale for SMP/BIOS use —
  negligible cost, zero double-allocation risk. `hal::smp::init_trampoline()` runs in `kmain`
  **before `mm::init()`**, scans `bootinfo::usable_regions()` for the lowest page with
  `0x1000 ≤ phys < 0x10_0000`, and records it as `TRAMPOLINE_PHYS`. SIPI vector = `TRAMPOLINE_PHYS >> 12`.
- **Blob.** The trampoline is a position-independent 16-bit `global_asm!` blob (its own real-mode
  GDT with 32-bit + 64-bit descriptors, the mode-transition code, and a parameter block).
  `init_trampoline` copies it byte-wise to `TRAMPOLINE_PHYS + hhdm` (HHDM view) and patches the block.
- **16→32→64 hop.** AP resets executing at `CS=(vec<<8), IP=0` in real mode, interrupts masked:
  1. `cli`; `lgdt` the in-page GDT; set `CR0.PE`; far-jmp → 32-bit code (flush).
  2. set `CR4.PAE`; `mov cr3, boot_cr3`; set `IA32_EFER.LME`; set `CR0.PG` → long mode.
  3. far-jmp → 64-bit code still in the identity-mapped low page; `mov rsp, stack_top`;
     `mov rdi, percpu`; `jmp entry64` (higher-half `run_ap`, reachable via the shared PML4 slots).
- **AP bootstrap page tables** (`hal::smp::build_ap_page_tables`, once): a PML4 that (a) identity-maps
  `[0, 2 MiB)` with one 2 MiB huge page (covers the trampoline), and (b) copies the kernel PML4's
  higher-half entries (slots 256..512) so the higher-half kernel + HHDM are reachable. Its phys addr
  is `boot_cr3`. `run_ap` switches to the canonical kernel `CR3` once in the higher half (drops the
  identity map). We build our own tables rather than depend on an undocumented Limine low identity map.
- **Per-AP handoff** (parameter block, fixed offset in the low page):

  | field | bytes | filled by | consumed by |
  |-------|-------|-----------|-------------|
  | `boot_cr3` | u64 | BSP once | trampoline step 2 |
  | `entry64`  | u64 | BSP once | trampoline step 3 (`run_ap` addr) |
  | `stack_top`| u64 | BSP per-AP | trampoline step 3 (`rsp`) |
  | `percpu`   | u64 | BSP per-AP | trampoline step 3 (`rdi`) |
  | `apic_id`  | u32 | BSP per-AP | `run_ap` |

  Bring-up is **serial** (one AP at a time), so the shared `stack_top`/`percpu` slot is written by
  the BSP and read by exactly one AP — no race. The BSP advances to AP k+1 only after AP k publishes
  `PerCpu.online` (which happens after the AP is on its own stack, so the slot is free to reuse).

## (2) INIT–SIPI–SIPI (x2APIC ICR, MSR `0x830`)

x2APIC ICR is a single 64-bit `wrmsr` (destination in bits 63:32; **no** xAPIC delivery-status poll —
bit 12 is reserved-0). `dest` = target x2APIC ID; `vec` = `TRAMPOLINE_PHYS >> 12`.

| step | ICR value | meaning | wait |
|------|-----------|---------|------|
| 1 INIT   | `(dest<<32) \| 0x0000_4500`        | INIT, assert, edge, physical | 10 ms |
| 2 SIPI   | `(dest<<32) \| 0x0000_4600 \| vec` | Startup, vector = page | 200 µs |
| 3 SIPI   | `(dest<<32) \| 0x0000_4600 \| vec` | Startup (SDM-mandated retry) | poll `online`, ≤100 ms |

Delays: 10 ms via the PIT (1 tick at 100 Hz); the sub-tick 200 µs via `cpu::udelay` (a calibrated
`pause` spin). The **two SIPIs are the retry** (the second is harmless if the AP already left
wait-for-SIPI). No further INIT-SIPI-SIPI retry loop this phase. **Fail-safe:** if `PerCpu.online`
is not set within 100 ms, log `[smp] cpuN FAILED to start` and continue — the BSP and already-online
APs keep running (never hang the machine on a dead AP).

## (3) PerCpu layout + accessor (`kernel::smp`, safe)

```rust
pub const MAX_CPUS: usize = 64;
pub struct PerCpu {
    cpu_index: u32,            // dense 0..N (BSP = 0)
    apic_id:   u32,            // x2APIC ID
    online:    AtomicBool,     // AP sets true at the end of run_ap
    // PR-2: run queue slot, current, preempt_count, need_resched move here
}
static CPUS: [PerCpu; MAX_CPUS];          // fixed, no heap; PerCpu is Sync (atomics only)
static CPU_COUNT: AtomicUsize;            // set by enumeration
pub fn cpus() -> &'static [PerCpu];       // 0..CPU_COUNT
pub fn by_index(i: u32) -> &'static PerCpu;
pub fn this_cpu() -> &'static PerCpu;     // lookup by apic::id() → dense index
```

APIC IDs may be sparse; enumeration compacts them to a dense `apic_id → index` map. `run_ap` receives
its `&PerCpu` directly from the handoff (no lookup at entry); `this_cpu()` is for later general use.
All accessors are safe — the only privileged read is the existing `apic::id()`.

## (4) Per-core vector-state fix (deletes `VECTOR_SAVE_ARMED`)

**Mechanism (b), chosen:** `isr_common` gates its per-IRQ `xsave`/`xrstor` on a **live `CR4.OSXSAVE`
read** (`mov rax, cr4; test`) instead of the global `VECTOR_SAVE_ARMED` flag. This is *structurally*
correct: the exact architectural precondition for `xsave` is read from the hardware, per-core,
per-interrupt, so it cannot desync. An AP that has not yet run `simd::enable` reads OSXSAVE=0 and
takes the existing "nothing saved" path (`r15=0` → skips restore too) — no `#UD`, ever. The global
flag, `arm_vector_save()`, and the documented SMP hazard in `idt.rs` are **removed**. Sound because
cores are homogeneous, so the BSP's one-time `xsave_area_size ≤ 4096` assert holds for every core.

The `simd::*_ready` flags stay **global** (they encode a machine-homogeneous "this tier is verified
usable" fact). Their SMP hazard is closed not by making them per-core but by **enforcing that every
AP runs its own `simd::enable()` before any code that reads them** — see (5), guaranteed by the
ordered `run_ap` sequence.

## (5) AP startup ordering — invariants

1. BSP finishes single-core bring-up (GDT/IDT/PIC/PIT/`simd::enable`/`apic::enable_bsp`) unchanged.
2. BSP `init_trampoline()` + `build_ap_page_tables()` run **before `mm::init()`** seeds frames (low
   memory already excluded), so the trampoline page and bootstrap PML4 are permanently owned.
3. BSP enumerates APs (MADT) → dense cpu-index map + `CPUS`/`CPU_COUNT`.
4. Per AP k (serial): fill handoff (`stack_top`,`percpu`,`apic_id`) → INIT → 10 ms → SIPI → 200 µs →
   SIPI → wait `PerCpu[k].online` (≤100 ms).
5. The AP runs the trampoline (real→prot→long) with **IF masked throughout** (`cli` at reset; IF
   stays 0 until `run_ap`'s final `sti`).
6. `run_ap` executes a **fixed, branch-free** privileged sequence:
   `lgdt(shared)` → `lidt(shared)` → `cr3 = kernel` → `simd::enable()` (sets `CR4.OSXSAVE`+`XCR0`,
   self-tests) → `apic::enable_ap()` (x2APIC EN + SVR; **no** LINT0=ExtINT — APs do not front the PIC)
   → publish `online=true` → `sti` → `ap_main(percpu)`.
7. **Invariant:** `sti` on an AP is unreachable before `simd::enable()` — there is exactly one AP Rust
   entry (`run_ap`) and its sequence has no earlier `sti`. So OSXSAVE is always set before the first
   interrupt (structural, not documented).
8. **Invariant:** `isr_common` independently gates on live `CR4.OSXSAVE`, so even a future mis-ordered
   edit cannot `#UD`.
9. **Invariant:** the handoff slot is written by the BSP and read by one AP at a time (serial) — no race.
10. **Invariant:** an AP reads `simd::*_ready` only after its own `simd::enable()` (order in #6); cores
    are homogeneous, so the global flags are correct for it.
11. **Fail-safe:** a non-checking-in AP is logged and skipped; the machine stays up.

## (6) Boot proof

- `run_ap` prints `[smp] cpuN online (apic id=…)` for each AP; the BSP prints the expected count.
  xtask asserts one `online` line per enumerated AP under **KVM** (deterministic count from `-smp 4`).
- Each AP then runs a fixed int8 GEMM (its `simd::enable` already self-tested the tier) and prints
  `[smp] cpuN gemm ok` — proving that AP's own vector state is live and bit-exact.
- **KVM is the gate** (TCG has no x2APIC, like phase 1): the `test-kvm` job asserts the online count +
  the per-AP gemm lines. **TCG boot must still pass** via the phase-1 no-op fallback (`enable_bsp`
  returns `None` → SMP bring-up is skipped, single-core path unchanged).

## (7) TCB delta (rows for `kernel/docs/hal-tcb.md`, new §10 `hal::smp`)

| # | Location | Unsafe op | Soundness | Verification |
|---|----------|-----------|-----------|--------------|
| SMP1 | `smp.rs` trampoline `global_asm!` | 16→32→64 mode transition (PE/PAE/LME/PG, far jmps) | PI blob in an owned identity-mapped low page; loads only BSP-patched `boot_cr3`/`entry64`/`stack_top`; IF masked throughout | Reasoned + KVM boot proof (opaque to Miri) |
| SMP2 | `smp::init_trampoline` | copy blob + patch block via `TRAMPOLINE_PHYS+hhdm` | Writes only within the one reserved `<1 MiB` page; runs once on BSP before APs exist | Reasoned + KVM |
| SMP3 | `smp::build_ap_page_tables` | raw PML4/PDPT/PD writes (2 MiB identity + copied higher-half slots) | Reuses audited frame alloc; identity range is fixed `[0,2 MiB)`; higher-half slots copied from live kernel PML4 | Reasoned + KVM |
| SMP4 | `apic::send_init_sipi_sipi` | `write_msr(0x830, …)` INIT + 2×SIPI | New call site on audited `write_msr`; fixed architectural values; ICR cannot alias Rust memory | Reasoned + KVM |
| SMP5 | `apic::enable_ap` | `write_msr` EN + SVR on the AP | Same class as `enable_bsp` minus virtual-wire; per-core LAPIC enable | Reasoned + KVM |
| SMP6 | `smp::run_ap` | AP-side `lgdt`/`lidt`/`mov cr3`/`sti` + far entry | Branch-free ordered sequence; loads the shared, already-audited GDT/IDT and kernel CR3 | Reasoned + KVM |
| ACPI1 | `acpi::rsdp` | read Limine RSDP response pointer | Pointer copy from a `#[used]` request Limine filled (same pattern as `bootinfo`) | Reasoned |
| ACPI2 | `acpi::phys_bytes(phys,len)` | build `&[u8]` over HHDM-mapped ACPI region | Bounded by `len`; ACPI tables are HHDM-reachable RAM; read-only view | Reasoned + host tests on parser |

**Edits:** `idt.rs` — delete `VECTOR_SAVE_ARMED`/`arm_vector_save`; `isr_common` reads live `CR4`
(**removes** the §ISR SMP-hazard row). `simd.rs` — drop the `arm_vector_save` call; `enable` stays
idempotent per-core. `cpu.rs` — add `read_cr3` (side-effect-free) + `udelay`. `mm/frame.rs` — extend
the frame-0 skip to `< 0x10_0000`.

## (8) PR staging

Two PRs. The trampoline TCB and the scheduler refactor are independently reviewable and each
independently bootable (PR-1 boots with APs parked in an idle loop; PR-2 makes them schedulable) —
matching the x2APIC doc's "each step independently bootable" ethos.

- **PR-1 — AP bring-up + enumeration + per-CPU state + vector fix + boot proofs.** The TCB-heavy PR;
  the trampoline is useless without enumeration and enumeration is untestable without bring-up, so
  they ship as a unit. Gate: kernel-reviewer + verification-engineer.
- **PR-2 — per-CPU scheduler integration.** Moves `SCHED`/`ready`/`current`/`PREEMPT_COUNT`/
  `NEED_RESCHED` into `PerCpu`; per-CPU run queues, **no work stealing**; BSP spawns, APs run their own
  idle + explicitly-assigned tasks. Safe-kernel only. Gate: kernel-reviewer. Depends on scheduler
  PR-A/PR-B being landed.

### PR-1 checklist

1. `hal::mm::frame`: exclude frames `< 0x10_0000` from seeding (extend the frame-0 guard).
2. `hal::cpu`: add `read_cr3()` and `udelay(us)` (calibrated `pause` spin).
3. `hal::acpi`: Limine `RsdpRequest` + `rsdp()` + bounded `phys_bytes(phys,len)` HHDM view.
4. `kernel::acpi` (`forbid(unsafe)`): walk RSDP→XSDT→MADT; yield enabled Local-APIC (type 0) +
   x2APIC (type 9) entries → `Vec<CpuEntry{apic_id,enabled}>`. Host tests + Kani on the length decode.
5. `kernel::smp`: `PerCpu`, `CPUS`/`CPU_COUNT`, dense `apic_id→index` map, `cpus`/`by_index`/`this_cpu`.
6. `hal::smp`: the 16-bit trampoline `global_asm!` blob + parameter-block layout.
7. `hal::smp::init_trampoline` (copy+patch to the reserved low page) and `build_ap_page_tables`.
8. `hal::apic`: `send_init_sipi_sipi(dest, vec)` (ICR sequence) + `enable_ap()`.
9. `hal::smp::run_ap`: the fixed branch-free AP entry sequence; prints `[smp] cpuN online`.
10. `hal::idt`: delete `VECTOR_SAVE_ARMED`/`arm_vector_save`; `isr_common` gates on live `CR4.OSXSAVE`.
11. `hal::simd`: drop the `arm_vector_save` call site.
12. `kernel::smp::bring_up_aps`: enumerate → per-AP serial INIT-SIPI-SIPI → wait `online` → count report.
13. `kmain`: call `init_trampoline`/`build_ap_page_tables` before `mm::init`; call `bring_up_aps` after
    `apic::enable_bsp` returns `Some`; `ap_main` = per-AP GEMM (`[smp] cpuN gemm ok`) then `hlt` idle.
14. `xtask` KVM job: assert one `online` line per enumerated AP + each `cpuN gemm ok`; TCG asserts the
    no-op fallback still boots.
15. Update `hal-tcb.md` §10 (SMP1–6, ACPI1–2) and remove the `VECTOR_SAVE_ARMED` hazard row.

### PR-2 checklist

1. Move `current`/`ready`/`zombie` out of the single `SCHED` into a per-`PerCpu` `SpinMutex<CpuSched>`.
2. Make `PREEMPT_COUNT`/`NEED_RESCHED` per-CPU fields (read via `this_cpu()`).
3. `sched::init` adopts each core's `run_ap` idle context as its `Task(cpu_index)` idle task.
4. `spawn` gains a target cpu-index (BSP-driven placement; default = BSP) — **no** cross-CPU stealing.
5. Timer preemption (`on_tick`) operates on `this_cpu()`'s queue only.
6. `schedule()` selects from the local queue; empty ⇒ stay on local idle (unchanged discipline: lock
   never held across `switch`).
7. Assert scheduler invariants #1–#5 hold **per-CPU** (no id shared across cores' queues).
8. Host + Miri tests: per-CPU queue rotation with a mock `switch`; Kani: local queue never loses/dupes ids.
9. Boot proof: BSP spawns a task pinned to an AP; serial shows it running on `cpuN` (distinct from BSP).
10. `xtask` KVM: assert the pinned-task-on-AP line.
11. Update the scheduler design doc's SMP-forward note to "implemented (per-CPU, no stealing)".

## Limits (out of scope)

No CPU hotplug; no work stealing / load balancing (BSP places, APs run their own idle + assigned
tasks); no TLB shootdown (no cross-CPU unmapping yet); no per-CPU heaps (shared global allocator, its
`SpinMutex` now genuinely contends — audited under phase-5); x2APIC-only (no-x2APIC hosts stay
single-core via the phase-1 fallback).

## Open questions

1. **Limine low identity map.** If a Limine guarantee that the low `<4 GiB` is identity-mapped is
   confirmed, `build_ap_page_tables` (SMP3) can be dropped and the trampoline can load the kernel CR3
   directly — removing a TCB row. Proposed: build our own tables now (robust), revisit if confirmed.
2. **`MAX_CPUS`.** Fixed at 64 (static array, no heap). Enough for every near-term target; a
   heap-`Box<[PerCpu]>` sized at enumeration is the fallback if we ever exceed it.
3. **`udelay` calibration.** A `pause`-spin is coarse; the 200 µs SIPI gap is a minimum, so an
   over-estimate is safe. Acceptable, or calibrate against the PIT once at boot?
4. **AP idle in phase 2.** Before PR-2, APs `hlt`-loop after their GEMM proof — confirm that parked
   state vs. immediately entering an empty per-CPU scheduler.
