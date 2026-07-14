# CPU Security-Feature Enablement — Design

Status: **proposed** · Track A (Intel/AMD CPU + security), step 2 · Author: security track
Depends on: `hal::cpuid` vendor + security-feature **detection** (shipped).
Escalation: touches the **TCB** (new privileged CR4/MSR writers) and the security
posture → requires kernel-reviewer + verification-engineer sign-off before merge
(charter invariant #6).

## Goal

Turn the CPU security features we now *detect* into ones we *enforce*: give the
kernel hardware-backed **W^X** and **user/kernel isolation** on both Intel and
AMD. These are cheap to enable, standards-based (so they ride the "every
motherboard" goal), and directly serve the privacy-first mission.

In scope for the first implementation phase:

| Feature | Bit | Effect once enabled |
|---|---|---|
| **NX** (No-eXecute) | `IA32_EFER.NXE` (MSR `0xC000_0080`, bit 11) | Honors PTE bit 63 → data/stack pages can be marked non-executable (W^X) |
| **SMEP** | `CR4` bit 20 | Ring-0 **cannot execute** a page mapped user-accessible (`U=1`) |
| **SMAP** | `CR4` bit 21 | Ring-0 **cannot read/write** a `U=1` page unless `RFLAGS.AC=1` (`stac`/`clac`) |
| **UMIP** | `CR4` bit 11 | Ring-3 cannot run `sgdt/sidt/sldt/smsw/str` (kernel-address leaks) |

Out of scope here (later phases): CET shadow-stack/IBT, AMD SME/Intel TME memory
encryption, per-CPU enable on APs (SMP), and the userland-copy machinery.

## Why this needs a design, not a one-line `cr4 |= …`

Each bit changes what faults. Enabling one against wrong assumptions bricks boot.

- **NX** — enabling `EFER.NXE` alone is safe (no PTE sets bit 63 yet). The *value*
  comes when paging marks data/stack NX and code executable. **Action:** audit
  `hal/src/mm/paging.rs` for any existing use of PTE bit 63, and confirm the page
  flags API can express NX. Enabling NXE now + applying NX bits incrementally is
  safe and reversible.
- **SMEP** — safe to enable **iff no kernel-executed page is mapped `U=1`**. There
  is no userland yet and higher-half kernel mappings are supervisor, so this holds
  today. **Action:** audit the boot/identity/higher-half mappings for stray `U=1`
  on kernel code before enabling.
- **SMAP** — the sharp one. Once on, *any* ring-0 access to a `U=1` page faults
  unless `AC` is set. With no user pages today, enabling is safe **now** — and
  enabling it *before* userland exists is deliberate: it forces every future
  kernel↔user copy through a `stac`/`clac`-guarded `copy_to_user`/`copy_from_user`
  from day one, instead of retrofitting it. That is a security win, not a cost.
- **UMIP** — only affects ring-3 (none yet); safe to enable now.

Net: all four are **safe to enable at boot today**; the discipline they impose is
what the follow-up userland work must respect.

## New TCB primitives (unsafe HAL)

Add to `hal` (each a safe wrapper over one `unsafe` block, `// SAFETY:` documented,
and registered in `kernel/docs/hal-tcb.md`):

- `cpu::read_cr4() -> u64` / `cpu::write_cr4(u64)` — `mov rax, cr4` / `mov cr4, rax`.
  `write_cr4` is genuinely dangerous (can disable paging features); it is only
  ever called by `cpu_security::enable` with a read-modify-write that **sets**
  bits and clears none.
- `cpu::read_msr(u32) -> u64` / `cpu::write_msr(u32, u64)` — `rdmsr`/`wrmsr`
  (edx:eax split). Used for `IA32_EFER`.

## Safe enablement API

```rust
// hal::cpu_security
pub struct Enabled { pub nx: bool, pub smep: bool, pub smap: bool, pub umip: bool }

/// Enable every requested feature the CPU actually advertises. Each bit is gated
/// on its CPUID flag — never set an unsupported bit (that #GPs). Idempotent;
/// call on the BSP at boot and on each AP once SMP lands.
pub fn enable() -> Enabled;
```

Sequence (BSP, after paging is up, before interrupts/userland):
1. Read `hal::cpuid::info()` (already have it) for `nx`/`smep`/`smap`/`umip`.
2. If `nx`: `write_msr(EFER, read_msr(EFER) | NXE)`.
3. Read CR4; OR in only the supported+intended `SMEP|SMAP|UMIP` bits; `write_cr4`.
4. Return `Enabled { … }` and log `"[cpu-sec] enabled: nx smep smap umip"` on serial.

Gating on detection means a CPU/hypervisor lacking a feature simply skips it —
the same graceful-degradation the detection layer already uses.

## Testing

- **QEMU exposure.** The default `qemu64` model does **not** expose SMEP/SMAP/UMIP,
  so detection returns absent and `enable()` is a safe no-op — which proves
  graceful degradation but exercises nothing. To actually enable + boot with them
  on, the boot test's QEMU CPU must advertise them: switch `xtask` to
  `-cpu Haswell,+smep,+smap,+umip` (or `-cpu max`). Then the boot test proves the
  kernel still reaches `boot-bringup-ok` **with the bits set** (no regression).
- **Assertion.** Have the boot test optionally assert the `[cpu-sec] enabled:`
  serial line lists the features the chosen `-cpu` advertises.
- **Negative (deferred to userland).** A ring-0 jump into a `U=1` page must `#PF`
  under SMEP, and a guardless user read must `#PF` under SMAP — both require user
  pages, so they land with the userland-copy work, not here.
- **Verification.** The `cr4`/`wrmsr` wrappers are inline asm (Miri can't execute
  them); document residual risk and have verification-engineer review the SAFETY
  arguments, per invariant #2 (no unsafe merges unverified).

## Phasing

1. **This PR's follow-up** — CR4/MSR HAL primitives + `cpu_security::enable()`,
   enable NX+SMEP+SMAP+UMIP on the BSP at boot, log it, switch the QEMU test CPU.
2. **With userland** — W^X page flags (NX on data/stack); `stac`/`clac` +
   `copy_{to,from}_user`; SMEP/SMAP negative tests.
3. **With SMP** — re-run `enable()` on each AP.

## Open questions

- Prefer `-cpu Haswell,+…` (deterministic feature set) or `-cpu max` (broadest) for
  the boot test? Leaning `Haswell,+smep,+smap,+umip` for reproducibility.
- Should `enable()` live in `hal` (TCB) or a thin `hal` primitive + policy in the
  `kernel`/security crate? Proposal: primitives in `hal`, the enable *policy* is
  trivial enough to keep beside them; revisit if it grows.
