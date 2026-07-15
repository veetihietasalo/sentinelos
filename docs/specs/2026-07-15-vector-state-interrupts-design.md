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

With both mechanisms in place, `hal::simd::gemm_i8_*` may run with interrupts
enabled. The doc precondition changes from "interrupts must be disabled" to a note
that vector state is preserved across interrupts (by #1's guarantee that handlers are
vector-free, backed by #2's per-IRQ save). A **boot proof** runs a GEMM with
interrupts **enabled** and the PIT ticking, verifying the result is still bit-exact —
empirically validating the relaxed precondition under real interrupt pressure.

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
All catalogued in `hal-tcb.md`. `kernel` stays `#![forbid(unsafe_code)]`.

## Testing

- **Invariant guard**: `cargo xtask check-no-vector` passes on the current tree and
  fails if a non-GEMM function gains a vector instruction (verified by a deliberate
  probe during development). Wired into CI.
- **`xsave`/`xrstor` round-trip self-test** at boot (state survives save→zero→restore).
- **Interrupts-on GEMM boot proof**: a GEMM computed with `sti` set and the PIT
  firing, asserted bit-exact against the scalar reference.
- Existing boot proofs (`prove`, `infer_prove`) unchanged; the always-on Kernel CI +
  KVM jobs continue to assert them, now with the per-IRQ save active in `isr_common`.
