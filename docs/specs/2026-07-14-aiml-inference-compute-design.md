# AI/ML Inference Compute Path — Design

Status: **phase 1 (scalar tier) implemented, SIMD/AMX tiers proposed** · Track C
(AI/ML compute), step 1 · Author: kernel / compute track
Depends on: `hal::cpuid` AMX + AVX-512 **detection** (C1, shipped — `Feature`
flags `amx_tile`/`amx_int8`/`amx_bf16`/`avx512_vnni`/`avx512_bf16`).
Escalation: the scalar tier is pure **safe** Rust (no TCB change). The AVX-512 and
AMX tiers add `core::arch` SIMD intrinsics + XSAVE/XCR0/XFD/tile-config
enablement (new TCB) → those phases require kernel-reviewer + verification-engineer
sign-off (charter invariants #2/#6), same gate as the SMP MSR path.

## Goal

Turn the AMX / AVX-512 features we now *detect* (C1) into a working **quantized
inference primitive** — the AI/ML wedge that is SentinelOS's end goal. The
load-bearing operation for quantized transformer/CNN inference is an **int8 × int8
→ int32** matrix multiply (GEMM): AMX's `TDPBSSD`, AVX-512's `VPDPBUSD` (VNNI),
and a scalar loop all compute exactly this, differing only in throughput. So a
single `gemm_i8` entry point with a **tiered** implementation, dispatched by
`cpuid`, is the right substrate: correctness lives in one scalar reference, and
each hardware tier is validated against it.

**Testability (important, measured — not assumed).** The **scalar** tier needs no
special CPU features, so it runs and is verified under QEMU TCG unconditionally —
the boot proof executes a real int8 GEMM every boot. The AVX-512 and AMX tiers are
a different story: a direct probe shows QEMU 8.2's TCG in this sandbox does **not**
emulate them — requesting `avx512*`/`amx-*` yields `TCG doesn't support requested
feature` and the bits are dropped (so the guest reads `detected=scalar`), exactly
as it drops x2APIC. So those tiers execute only under **KVM** (`-cpu host` on
capable silicon) or real hardware — the same environment constraint as SMP
phase 2. Their correctness check is cheap *wherever* they run, though: the int8→i32
GEMM is **exact**, so a SIMD tier must produce output **bit-identical** to the
scalar reference (a differential test, not a tolerance).

## Why quantized int8 first (not f32)

- It is the dominant format for *inference* (as opposed to training): 4× the
  memory bandwidth and throughput of f32, with accuracy loss that post-training
  quantization keeps negligible for most models.
- It maps 1:1 onto the hardware we detect: AMX int8 tiles and AVX-512 VNNI are
  *built* for int8·int8→int32. bf16 (AMX_BF16 / AVX512_BF16) is the natural second
  format and reuses the same tiered structure.
- The accumulation is exact in i32 (no float non-determinism), so the scalar
  reference and every SIMD tier must produce **bit-identical** results — a strong,
  cheap correctness oracle.

## Tiers (dispatched by `cpuid`, best implemented wins)

| Tier | Instruction | Detection (C1 `Feature`) | Status |
|---|---|---|---|
| **Scalar** | plain `i32 += i8*i8` loop | always | **implemented** — the reference |
| **AVX2** | `VPMULLD`/`VPADDD` (256-bit, broadcast-A × 8 cols/step) | `avx2` | **implemented** (`hal::simd`) |
| **AVX-512 VNNI** | `VPDPBUSD` (512-bit, 64×int8/step) | `avx512_vnni` (+`avx512f`/`bw`/`vl`) | proposed |
| **AMX int8** | `TDPBSSD` on tile registers | `amx_int8` + `amx_tile` | proposed |

`detected_capability()` reports the best tier the CPU *advertises*; `active_tier()`
reports the best tier actually *implemented and verified* — AVX2 when present and
its self-test passes (see Phase 2), else Scalar. `gemm_i8` dispatches to it, so the
result is always correct and never claims a tier it does not run. The boot proof
prints both so the gap is visible, not hidden.

## Phase 1 — scalar reference + dispatch (**implemented**)

`kernel::ml` (safe Rust, in the `#![forbid(unsafe_code)]` kernel crate):

- **Quantization** — symmetric int8: `quant_scale(&[f32]) -> f32` (max-abs / 127,
  floored to a tiny epsilon so an all-zero tensor cannot divide by zero),
  `quantize(&[f32], scale, &mut [i8])`, `dequantize(i32, scale_a, scale_b) -> f32`.
- **GEMM** — `gemm_i8_scalar(a, b, c, m, k, n)`: row-major `C[m×n] = A[m×k]·B[k×n]`
  with i32 accumulation; `gemm_i8(...)` is the tier-dispatching public entry.
- **Dispatch** — `capability_from_flags(...)` (pure, unit + candidate-Kani
  tested) maps detected flags → `Tier`; `detected_capability(&CpuInfo)` reads them
  via the `Feature` list.
- **Boot proof** — `ml::prove()` runs a real int8 GEMM (a 4×4 `identity · B = B`
  with a 4×**12** `B` so, on the AVX2 tier, the 256-bit vector path executes, not
  just the scalar tail), checks the i32 checksum against a compile-time constant,
  and logs `[ml] inference: detected=…, active=…; 4x4*4x12 int8 GEMM ok;
  checksum=1128` before `boot-bringup-ok`. Under the boot test's `-cpu Haswell`,
  `detected=avx2` (Haswell has AVX2) but `active=scalar` — the AVX2 self-test fails
  under TCG (see Phase 2), so it correctly falls back. On real hardware / KVM,
  `active=avx2`.

No TCB change: it only *reads* the existing safe `cpuid::info()` and computes.

## Phase 2 — AVX2 tier (**implemented**)

The first SIMD tier, and the first vector code in the TCB — chosen first because
AVX2 is universal (every x86-64 CPU since 2013, and QEMU TCG advertises it), so it
is the one SIMD tier reachable by the existing CI, and it establishes all the
infrastructure the AVX-512/AMX tiers reuse.

**Kernel** (`hal::simd::gemm_i8_avx2`, `#[target_feature(enable = "avx2")]`): for
each output row, broadcast each `A[i][p]` and multiply-accumulate a whole row of
`B` into a row of `C` — eight int32 columns per 256-bit step (`VPMOVSXBD` sign-
extend → `VPMULLD` → `VPADDD`), scalar tail for the remaining `< 8`. The K-sum runs
in the same ascending order as the scalar loop, so the result is **bit-identical**.

**Vector-state enablement** (new TCB, `hal::simd::enable`): AVX (`YMM`) needs
`CR4.OSXSAVE` + `XCR0[2:1:0]` (x87|SSE|AVX) set via `XSETBV`, else AVX instructions
`#UD`. New `hal::cpu` primitives `xgetbv`/`xsetbv` back this (registered in
hal-tcb.md), cpuid-gated exactly like `cpu_security`.

**SIMD self-test (robustness).** `enable` runs the AVX2 kernel on a fixed input and
compares it to a scalar computation; the AVX2 tier is marked usable
(`avx2_ready`) **only** on a bit-exact match. This makes the kernel resilient to a
broken vector unit: **QEMU 8.2 TCG mis-emulates `VPMULLD`** (it drops the odd
32-bit lanes, like `VPMULDQ`), so under TCG the self-test fails and the ML path
transparently uses the scalar reference — never computing garbage — while on real
hardware / KVM it passes and the AVX2 kernel runs. This is why the AVX2 tier is
executed & proven in the **KVM CI job** (`kvm-smp.yml`, which asserts
`[ml] … active=avx2`), not the TCG job (where `active=scalar`).

**Verification:** a host differential harness asserts AVX2 == scalar bit-for-bit
over many shapes (incl. non-multiples-of-8, negatives, extremes) — it runs on the
CI host (real AVX2), independent of the kernel's own enablement. The full kernel
path (enable → self-test → dispatch → AVX2) is proven on real silicon by the KVM
boot assertion.

## Phase 3 — AVX-512 VNNI tier (proposed)

Add a `VPDPBUSD`-based kernel behind the same `gemm_i8` entry, selected when
`avx512_vnni` is present. Mechanics: AVX-512 needs `XCR0[7:5]` (opmask + ZMM
hi256 + ZMM16-31) enabled via `XSETBV` after `CR4.OSXSAVE` — extending the
`hal::simd::enable` state setup, cpuid-gated. The intrinsics
(`core::arch::x86_64::_mm512_dpbusd_epi32`) are `unsafe` + `#[target_feature]` in
`hal::simd`, validated by the same bit-identical-vs-scalar differential harness and
a self-test. Neither TCG (drops AVX-512) nor the current KVM runner (no AVX-512
VNNI observed under `-cpu host`) can execute it, so it needs AVX-512 hardware to
prove — the self-test keeps it dormant everywhere else.

## Phase 4 — AMX int8 tier (proposed)

The big one. AMX adds 8 tile registers + `TILECFG`, gated behind **XFD** (extended
feature disable) on modern CPUs: the OS must clear `IA32_XFD.TILEDATA` and enable
`XCR0[18:17]` (XTILECFG/XTILEDATA) before any tile instruction, or they `#UD` /
`#NM`. Sequence (new TCB, hal-specialist): `CR4.OSXSAVE` → `XSETBV` set
`XCR0[18:17]` → clear `IA32_XFD` → `LDTILECFG` a palette describing the tile
shapes → `TILELOADD` A/B tiles → `TDPBSSD` → `TILESTORED` C → `TILERELEASE`. AMX
also needs XSAVE area management if we ever context-switch mid-tile (deferred:
phase-1 inference runs to completion in one kernel call, no preemption). Validated
against the scalar reference bit-for-bit, exactly like phase 2.

## Testing

- **Phase 1 (now):** host unit tests for `gemm_i8_scalar` (identity, a hand-checked
  non-square case, and an i32-accumulation case whose partial sums exceed i8/i16 to
  prove no truncation), `quantize`/`dequantize` round-trip, `quant_scale`
  zero-input safety, and the pure `capability_from_flags` mapping. Boot test
  asserts the `[ml]` line + checksum via `cargo xtask test` (the scalar tier runs
  in TCG unconditionally).
- **Phase 2 (AVX2, now):** the decisive test is **bit-identical output vs. the
  scalar reference** over many `(m,k,n)` shapes and value ranges (non-multiples-of-8
  to hit the scalar tail, negatives, extremes) — because the int8→i32 GEMM is
  exact, any divergence is a real bug. This host differential harness runs on the
  CI host (real AVX2), independent of the kernel's own state enablement. The full
  kernel path (`enable` → self-test → dispatch → AVX2) is exercised on real silicon
  by the **KVM CI job** (`kvm-smp.yml`), which asserts `[ml] … active=avx2`. Under
  TCG the AVX2 self-test fails (broken `VPMULLD`) and the ML path uses scalar, so
  the TCG boot proof still passes (`active=scalar`, correct checksum) — the kernel
  never computes garbage on a broken vector unit.
- **Phases 3–4 (AVX-512 VNNI, AMX):** same differential-vs-scalar oracle + a
  self-test, but they can only *execute* where the hardware exists: QEMU 8.2 TCG
  does not emulate AVX-512/AMX (drops the CPUID bits, like x2APIC) and the current
  KVM runner shows no AVX-512 VNNI / AMX under `-cpu host`, so they need AVX-512 /
  Sapphire-Rapids hardware to prove. The self-test keeps them dormant (scalar
  fallback) everywhere they can't run, so nothing computes garbage. The
  XCR0/XFD/tile-config `XSETBV`/MSR writes are inline-asm (Miri/Kani-opaque, like
  the SMP MSRs) → verified by reasoning + the differential test + hardware boot
  evidence.

## Open questions

- **Where do the SIMD tiers live?** The intrinsics are `unsafe`, so either in
  `hal` (TCB) or a new `compute-simd` crate that is the *only other* crate allowed
  `unsafe`. Proposal: a dedicated `hal::simd` submodule so the TCB registry
  (`hal-tcb.md`) stays the single catalog of unsafe; revisit if it grows large.
- **Runtime dispatch vs. `#[target_feature]` monomorphization.** Stable Rust
  requires `#[target_feature(enable="avx512f")]` on the intrinsic-using fn (itself
  `unsafe`) and a runtime `cpuid` gate before calling it. That is the standard
  pattern and needs no nightly. Confirmed compatible with the stable-only rule.
- **bf16 path.** `AMX_BF16` / `AVX512_BF16` reuse this exact structure with a bf16
  input/f32-accumulate GEMM. Deferred until the int8 tiers land, but the `Tier`
  enum + dispatch are designed to extend to it.

## References

- Intel SDM Vol. 1 ch. 20 (AMX), Vol. 2 (`TDPBSSD`, `VPDPBUSD`, `LDTILECFG`); the
  `XCR0`/`IA32_XFD` state-enable requirements for AMX.
- SentinelOS strategy & roadmap (`docs/research/2026-07-14-sentinelos-strategy-and-roadmap.md`),
  Track C (AI/ML). C1 detection: `kernel/crates/hal/src/cpuid.rs`.
