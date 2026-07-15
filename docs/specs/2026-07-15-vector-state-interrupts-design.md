# Vector State Across Interrupts — Design

Status: **proposed → implementing** · Track A (kernel core) · Author: kernel / HAL
Depends on: `hal::simd` vector-state enablement (`CR4.OSXSAVE` + `XCR0`, shipped),
`hal::idt` ISR stubs (shipped).
Escalation: touches the ISR entry path (hottest asm in the TCB) and adds new
`XSAVE`/`XRSTOR` privileged ops → kernel-reviewer + verification-engineer sign-off
(charter invariants #2/#6), same gate as the SMP MSR path.

## Problem

The int8 GEMM tiers (`hal::simd`, tiers Scalar→AVX2→AVX-512F→VNNI) keep live
accumulators in `YMM`/`ZMM` registers. The ISR entry stubs (`hal::idt::isr_common`)
save only the 15 general-purpose registers, **not** the vector registers. So the
GEMM wrappers today carry a hard precondition: **run with interrupts disabled**,
else an IRQ landing mid-GEMM whose handler clobbers a vector register would corrupt
the in-flight accumulators → silently wrong output. That confines all vector
compute — including the quantized-MLP inference workload — to the interrupts-off
boot window, so it cannot run in a live, scheduled system.

## Key finding — the soft-float target emits no vector instructions

The kernel builds for `x86_64-unknown-none`, a **soft-float** target with SSE/AVX
disabled in its baseline (only `fxsr` is on). Disassembly of the whole kernel
confirms: **the only vector-register instructions in the entire image are the three
hand-written GEMM `asm!` kernels** (`avx2_madd8`, `avx512_madd16`, `vnni_dp16`).
Every other function — all interrupt handlers, `memcpy`, struct copies — compiles to
pure GP-register code with zero `XMM`/`YMM`/`ZMM` use. The compiler *cannot* emit
SSE/AVX because those features are disabled.

So the premise behind the interrupts-off constraint ("a handler's `memcpy` could
clobber `XMM`") is **false for this target**: a compiled interrupt handler cannot
clobber vector state, because it contains no vector instructions. The only ways
vector state can be disturbed across an interrupt are (a) a handler that itself
invokes vector code (only the GEMM does, and no handler calls it), or (b) a
*preemptive context switch* that resumes a different task's vector code — which
requires per-task save/restore in the switch path (no preemptive scheduler exists
yet).

## Design (defense-in-depth: proportionate guard **and** per-IRQ save)

Two independent mechanisms, either of which alone makes vector GEMM safe under
interrupts; together they are belt-and-suspenders.

### 1. Machine-checked "handlers are vector-free" invariant (proportionate)

A build/CI guard (`cargo xtask check-no-vector`) disassembles the kernel ELF and
asserts that **every** `XMM`/`YMM`/`ZMM` instruction lives inside one of the three
audited GEMM `asm!` symbols. If a future handler (or any non-GEMM code) ever emits a
vector instruction, the build fails. This turns "an IRQ can't clobber vectors" from
an assumption into a property checked on every build — the framekernel-appropriate
guarantee for this target, at zero runtime cost.

### 2. Per-IRQ `XSAVE`/`XRSTOR` in `isr_common` (maximal defense)

`isr_common` additionally saves the full enabled vector state on interrupt entry and
restores it on exit, so even a (guard-forbidden, hence impossible) vector-using
handler could not corrupt an interrupted GEMM. Details:

- **Gated on an armed flag.** A `static VECTOR_SAVE_ARMED: AtomicU8`, set to 1 by
  `hal::simd::enable` **after** it turns on `CR4.OSXSAVE` + `XCR0`. `isr_common`
  reads it; if 0 (before enable, or on a CPU without `xsave`) it skips the save
  entirely — so `xsave` is executed only when it is architecturally legal, and the
  interrupt path is unchanged on non-vector CPUs. `enable` runs in the interrupts-off
  boot window, so the 0→1 transition is never observed mid-interrupt.
- **On-stack save area.** The stub reserves a fixed, compile-time
  `VECTOR_SAVE_AREA_MAX` bytes on the interrupt stack, 64-byte aligned, zeroes the
  64-byte `XSAVE` header (so `XCOMP_BV = 0` → standard, non-compacted format), and
  `xsave`s with save-mask `edx:eax = -1` (all components, intersected with `XCR0`).
  On-stack (not per-CPU) so it is correct even if an exception nests inside a handler.
- **Sizing.** `VECTOR_SAVE_AREA_MAX` is a compile-time constant sized for
  x87+SSE+AVX+AVX-512 (~2.7 KiB, rounded to 4096). At boot, `enable` reads the
  actual required size from `cpuid` leaf `0xD` (`hal::cpu::xsave_area_size`) and
  asserts it fits the reserved constant — a runtime backstop against the constant
  being too small on some future CPU.

### 3. Relaxed GEMM precondition

`hal::simd::gemm_i8_*` may run with interrupts enabled. The **load-bearing**
guarantee is #1 (compiled handlers are vector-free, so an IRQ *cannot* clobber vector
state); #2's per-IRQ save is defense-in-depth that hardens against a hypothetical
vector-using handler. So even when #2 is *disarmed* (a CPU whose `XSAVE` area does not
fit the reserved buffer, or a failed round-trip self-test), interrupts-on GEMM is
still safe by #1 — disarming does **not** re-impose an interrupts-off contract on
callers. A **boot proof** (`kernel::ml::prove_interrupts_on`) runs GEMMs with
interrupts **enabled** and the PIT ticking, bit-exact — a stress test that shows
interrupts fired and the per-IRQ save didn't corrupt results (it does not
deterministically hit the mid-`madd` clobber window; #1 is what rules that out).

### 4. Staged `XSAVE`/`XRSTOR` primitives for the future context-switch path

`hal::cpu::xsave`/`xrstor` (`pub(crate) unsafe`) + `xsave_area_size` are added and
validated by a boot-time round-trip self-test (set a known vector value → `xsave` →
zero the register → `xrstor` → confirm restored). These are the primitives a
preemptive scheduler's context switch will use to save/restore per-task vector state
(the only remaining scenario the per-IRQ save does not itself cover, since a switch
resumes a *different* task). No preemptive scheduler exists yet, so this PR only
lands and validates the primitives; the switch integration is future work.

## TCB delta

- `hal::cpu`: `xsave`/`xrstor` (`XSAVE`/`XRSTOR`), `xsave_area_size` (cpuid `0xD`).
- `hal::idt::isr_common`: the gated per-IRQ `xsave`/`xrstor` asm.
- New `static VECTOR_SAVE_ARMED`.
- `hal::simd::xsave_roundtrip_ok`: three VEX `asm!` blocks (`vmovdqu`/`vpxor`).
All catalogued in `hal-tcb.md` (cpu C13/C14; idt I1; the self-test VEX asm noted under
C13). `kernel` stays `#![forbid(unsafe_code)]`.

## Testing

- **Invariant guard**: `cargo xtask check-no-vector` disassembles the shipped debug
  ELF and asserts every vector instruction lives in the `hal::simd` module. Wired into
  CI (`kernel.yml`). Its detection core (`find_vector_violations`) has **automated**
  unit tests that plant a vector instruction (operand form, operand-less `vzeroupper`,
  and opmask `%k`) in a synthetic handler symbol and assert it is flagged — and one
  inside `hal::simd` and assert it is **not** — so the guard's efficacy is regression-
  tested, not just manually probed once.
- **`xsave`/`xrstor` round-trip self-test** at boot (state survives save→zero→restore),
  gating the arming.
- **Interrupts-on GEMM stress proof** (`prove_interrupts_on`): GEMMs with `sti` set and
  the PIT firing, asserted bit-exact (see §3 for what it does/doesn't prove).
- Existing boot proofs (`prove`, `infer_prove`) unchanged; the always-on Kernel CI +
  KVM jobs continue to assert them, now with the per-IRQ save active in `isr_common`.

## Residual risk & follow-ups

- **SMP (must fix before AP interrupt bring-up).** `VECTOR_SAVE_ARMED` is a single
  **global** flag but `CR4.OSXSAVE` is **per-core**. Once APs start, an AP that takes
  any interrupt before running its own `simd::enable` would `xsave` with `OSXSAVE`
  unset → `#UD`. Before SMP: make the flag per-core (or the `xsave` gate a per-core
  check), and enforce "each AP sets `OSXSAVE` before enabling interrupts" (stronger
  than "before any GEMM"). Not triggerable today (single-core; no AP handler path).
- **AVX-512/VNNI save path is KVM-only.** Under TCG only x87+SSE+YMM state is saved;
  the wider `ZMM`/opmask/`Hi16_ZMM` components and the `4096 ≥ cpuid-0xD` sizing assert
  are dynamically exercised only on an AVX-512 KVM runner (`kvm-smp`, non-deterministic
  runner assignment) — reasoned + boot-observed there, not every-run.
- **Nested-exception save is reasoned, not exercised.** The on-stack (vs per-CPU) area
  is what makes a fault-in-handler correct, but the boot proof fires only maskable
  timer IRQs through interrupt gates (IF cleared ⇒ no nesting), so nesting is never hit.
- **Per-interrupt stack cost.** Each armed interrupt reserves ≥ `VECTOR_SAVE_AREA_MAX`
  (4096) bytes on the current kernel stack; bounded because interrupt gates block
  maskable-IRQ nesting, so depth = exception/NMI nesting. The double-fault IST is the
  stack-overflow backstop.
- **Preemptive context switch (future).** A switch resuming a different task's vector
  code needs per-task save via C13/C14 — no preemptive scheduler exists yet.
