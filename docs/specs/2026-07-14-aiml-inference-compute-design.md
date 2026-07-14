# AI/ML Inference Compute Path — Design

Status: **scalar + AVX2 + AVX-512F + AVX-512 VNNI tiers implemented; AMX tier
proposed** · Track C (AI/ML compute), step 1 · Author: kernel / compute track
Depends on: `hal::cpuid` AMX + AVX-512 **detection** (C1, shipped — `Feature`
flags `amx_tile`/`amx_int8`/`amx_bf16`/`avx512f`/`avx512_vnni`/`avx512_bf16`).
Escalation: the scalar tier is pure **safe** Rust (no TCB change). The AVX2,
AVX-512F, and VNNI tiers add inline-`asm!` vector kernels + `CR4.OSXSAVE`/`XCR0`
enablement (new TCB, shipped — hal-tcb.md §2j, SM1/SM2/SM3 + C11/C12; VNNI reuses
the `avx512f` `ZMM` state, no new privileged op); the AMX tier adds `XFD`/tile-config
on top. Each TCB-touching phase requires kernel-reviewer + verification-engineer
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
| **AVX-512F** | `VPMULLD`/`VPADDD` (512-bit, broadcast-A × 16 cols/step) | `avx512f` | **implemented** (`hal::simd`) |
| **AVX-512 VNNI** | `VPDPBUSD` (512-bit, fused unsigned×signed 4×int8 dot-product/lane) | `avx512_vnni` (+`avx512f`) | **implemented** (`hal::simd`) |
| **AMX int8** | `TDPBSSD` on tile registers | `amx_int8` + `amx_tile` | proposed |

Note the AVX-512F tier is the **same broadcast scheme** as AVX2, just 512-bit (16
columns/step) — it uses the foundation `VPMULLD`/`VPADDD` ops, distinct from the VNNI
tier's fused `VPDPBUSD` dot-product (which needs a packed B-panel layout + an
unsigned/signed bias correction). Both ship now: AVX-512F because it reuses the
proven broadcast structure verbatim, and VNNI as the genuine throughput jump (64
int8 MACs/step vs. 16).

`detected_capability()` reports the best tier the CPU *advertises*; `active_tier()`
reports the best tier actually *implemented and verified* — VNNI, else AVX-512F,
else AVX2 (each when present *and* its self-test passes; see Phases 2–4), else
Scalar. `gemm_i8` dispatches best-first (VNNI → AVX-512F → AVX2 → scalar), so the
result is always correct and never claims a tier it does not run. The boot proof
prints both `detected` and `active` so the gap is visible, not hidden.

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

**Kernel** (`hal::simd::gemm_i8_avx2`): for each output row, broadcast each
`A[i][p]` and multiply-accumulate a whole row of `B` into a row of `C` — eight
int32 columns per 256-bit step (`VPMOVSXBD` sign-extend → `VPMULLD` → `VPADDD`),
scalar tail for the remaining `< 8`. `wrapping_add` accumulation is associative, so
the SIMD-over-columns result is **bit-identical** to the scalar loop.

**Why inline `asm!`, not `core::arch` intrinsics.** The bare-metal target
`x86_64-unknown-none` (soft-float baseline) does **not** codegen the SIMD
intrinsics to VEX — in a debug build they emit as calls that never lower to
`vpmulld`, and `__m256i` passed across that call on the soft-float ABI is corrupted,
so the kernel computes wrong results on *real* hardware (the self-test caught this
during bring-up). The 256-bit inner step is therefore hand-written `asm!`
(`avx2_madd8`): it emits the exact instructions regardless of target, and the
vectors never cross a call boundary. (A `build-std`/custom-target with `+avx2` is
the alternative; `asm!` is simpler and matches the kernel's style.)

**Vector-state enablement** (new TCB, `hal::simd::enable`): AVX (`YMM`) needs
`CR4.OSXSAVE` + `XCR0[2:1:0]` (x87|SSE|AVX) set via `XSETBV`, else AVX instructions
`#UD`. New `hal::cpu` primitives `xgetbv`/`xsetbv` back this (registered in
hal-tcb.md), cpuid-gated exactly like `cpu_security`.

**SIMD self-test (robustness).** `enable` runs the AVX2 kernel on fixed inputs
(single block, multi-block + tail, ±127 extremes) and compares to a scalar
computation; the AVX2 tier is marked usable (`avx2_ready`) **only** on a bit-exact
match. So a vector unit that computes incorrectly can never make the kernel ship
garbage — it caught the soft-float codegen bug above (fall back to scalar), and
backstops any future CPU/emulator/toolchain regression. With the `asm!` kernel the
self-test passes under **both** TCG (`-cpu Haswell`) and KVM (`-cpu host`), so
`active=avx2` is asserted in both the always-on Kernel CI boot test and the KVM job.

**Verification:** a host differential harness asserts AVX2 == scalar bit-for-bit
over many shapes (non-multiples-of-8, negatives, ±127 extremes, an i32-accumulator
wrap, and a 300-shape pseudo-random sweep) — it runs on the CI host (real AVX2),
independent of the kernel's own enablement. The full kernel path (enable →
self-test → dispatch → AVX2) is proven under emulation **and** on real silicon by
the `active=avx2` boot assertions (TCG + KVM). Inline `asm!` is Miri/Kani-opaque
(like the rest of the HAL), so those tools do not cover SM1; the host differential
harness + boot self-test are its dynamic coverage.

## Phase 3 — AVX-512F tier (**implemented**)

A 512-bit widening of the proven AVX2 kernel, selected when `avx512f` is present.
Chosen as the next tier because it reuses the Phase-2 broadcast scheme **verbatim**
(only the vector width changes) yet doubles the columns/step, and the AVX-512
vector-state enablement it requires is the same `XCR0` extension the future VNNI
tier needs — so it lands the AVX-512 substrate at low risk.

**Kernel** (`hal::simd::gemm_i8_avx512`): identical structure to `gemm_i8_avx2`,
sixteen int32 columns per 512-bit `ZMM` step (`VPMOVSXBD` sign-extend m128 →
`VPMULLD` → `VPADDD`), scalar tail for the remaining `< 16`. Same associative
`wrapping_add`, so **bit-identical** to the scalar loop and to the AVX2 kernel. The
inner step is inline `asm!` (`avx512_madd16`, EVEX) for the same soft-float-codegen
reason as AVX2; `asm!` accepts the explicit `zmm` operands on this target with no
`#[target_feature]`.

**Vector-state enablement** (extends `hal::simd::enable`, already-registered TCB):
when `cpuid` advertises `avx512f`, `enable` additionally ORs `XCR0[7:5]` (opmask +
`ZMM_Hi256` + `Hi16_ZMM`) into the `XSETBV` write — all supported together iff
`avx512f`, so no `#GP`. On a non-AVX-512 host those bits are never set and the tier
stays dormant. No new `hal::cpu` primitive is needed (the `xgetbv`/`xsetbv` from
Phase 2 already back it); the only new raw op is the kernel's `ZMM` load/store
(hal-tcb.md **SM2**).

**Self-test + verification.** `enable` runs the AVX-512F kernel through the same
multi-shape self-test as AVX2 (now including an `n=33` multi-block case) and marks
`avx512_ready` **only** on a bit-exact scalar match. The host differential harness
runs *both* kernels against scalar over the same shape sweep (i32-wrap case + a
300-shape pseudo-random sweep), gated on `is_x86_feature_detected!` so each runs
only where the host supports it — verified locally on an `avx512f`/`vnni` host. TCG
cannot execute it (it drops the AVX-512 CPUID bits, so `avx512_ready` stays false
and the tier is skipped — `active` falls to `avx2`), but GitHub's KVM runner fleet
is heterogeneous and **some runners advertise AVX-512 under `-cpu host`** (observed:
a `detected=avx512-vnni` boot). The KVM boot job accepts `active=avx2` **or**
`active=avx512f` (plus `int8 GEMM ok`), so it proves whichever tier the assigned
runner's silicon supports without a flaky dependency on landing AVX-512 hardware.

## Phase 4 — AVX-512 VNNI tier (**implemented**)

The throughput jump over Phase 3 on the same 512-bit substrate: a `VPDPBUSD`-based
kernel (a fused 4×int8 dot-product-accumulate per lane — 64 int8 MACs/step vs. 16),
selected when `avx512_vnni` is present. No new privileged setup: VNNI reuses the
`avx512f` `ZMM` state Phase 3 already enables, so the only additions are a `cpuid`
gate + a self-test + the kernel.

**The two hard parts** (why it is a distinct phase, not a fold-in of the widening):

1. **Unsigned×signed asymmetry.** `VPDPBUSD` multiplies **unsigned** bytes (operand
   1) by **signed** bytes (operand 2); our operands are both signed int8. So the
   kernel biases `A` into unsigned range (`au = a + 128`, i.e. `a ^ 0x80` on the
   byte), accumulates `Σ_k au·b` with `VPDPBUSD`, then subtracts the correction
   `128·Σ_k B[k][j]` per output column `j`. Per term `au·b − 128·b = a·b` exactly in
   ℤ, and since every op is `wrapping` (mod 2³²) and `VPDPBUSD` wraps (it is *not*
   the saturating `VPDPBUSDS`), the whole thing is a ring identity mod 2³² →
   **bit-identical** to the ascending-`k` scalar `wrapping_add`.
2. **Packed B panel.** Each `VPDPBUSD` lane needs 4 contiguous K values for its
   column, so B is packed into a `[⌈k/4⌉][16][4]` panel per 16-column block (the
   last K-group zero-padded when `k % 4 ≠ 0`; zero padding contributes 0 to both the
   dot-product and the column-sum correction). The kernel packs one 64-byte panel per
   (block, K-group) on the **stack** and reuses it across all `m` rows via the
   in-memory C accumulators — so it stays **alloc-free**. An `n`-tail (`< 16`
   columns) is handled by the plain signed scalar loop.

The `VPDPBUSD` inner step is inline `asm!` (`vnni_dp16`, EVEX) for the same
soft-float-codegen reason as the other tiers (hal-tcb.md SM3); the packing and bias
correction are **safe** Rust. Validated by the same bit-identical-vs-scalar
differential harness + boot self-test (with a `k` not-÷-4 case added), and the bias
math was cross-checked standalone against the `VPDPBUSD` intrinsic over 212 shapes on
an `avx512vnni` host before the asm kernel was written. TCG cannot execute it (drops
the AVX-512 CPUID bits), so it's dormant there (`active` falls to `avx512f`/`avx2`);
the KVM boot job accepts `active=avx512-vnni` on runners that expose VNNI.

## Phase 5 — AMX int8 tier (proposed)

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
  for the scalar tail, negatives, ±127 extremes, an i32-accumulator wrap, and a
  300-shape pseudo-random sweep) — because the int8→i32 GEMM is exact, any
  divergence is a real bug. This host differential harness runs on the CI host
  (real AVX2), independent of the kernel's own state enablement. The full kernel
  path (`enable` → self-test → dispatch → AVX2) is exercised by the boot proof,
  which asserts `[ml] … active=avx2` under **both** the always-on Kernel CI (TCG,
  `-cpu Haswell`) and the KVM job (`-cpu host`) — the `asm!` kernel runs correctly
  in both. The boot self-test guarantees that if a vector unit ever computes wrong,
  the kernel falls back to scalar (`active=scalar`, correct checksum) rather than
  shipping garbage. `asm!` is Miri/Kani-opaque, so SM1's dynamic coverage is the
  host harness + boot self-test, not Miri.
- **Phase 3 (AVX-512F, now):** the same differential-vs-scalar oracle, extended to
  run **both** vector kernels — the host harness picks up `avx512f` via
  `is_x86_feature_detected!` and diffs the `ZMM` kernel against scalar over the full
  shape sweep (multi-16-block shapes, ±127 extremes, the i32-wrap case at `n=16`,
  and the 300-shape pseudo-random sweep); verified locally on an `avx512f` host. TCG
  cannot execute it, so the always-on Kernel CI still shows `active=avx2`; the KVM
  boot job accepts `active=avx2` **or** `active=avx512f` (plus `int8 GEMM ok`),
  proving whichever the runner supports. The self-test keeps the tier dormant
  (falls to AVX2/scalar) wherever `avx512f` is absent, so nothing computes garbage.
  `asm!` is Miri/Kani-opaque, so SM2's dynamic coverage is the host harness + boot
  self-test.
- **Phase 4 (AVX-512 VNNI, now):** the same differential-vs-scalar oracle, extended
  to the VNNI kernel — the host harness picks up `avx512vnni` via
  `is_x86_feature_detected!` and diffs `VPDPBUSD`+bias-correction against scalar over
  the full shape sweep (`k` not ÷ 4 to exercise K-group padding, `n` not ÷ 16, ±127,
  the i32-wrap case, and the 300-shape sweep); verified locally on an `avx512vnni`
  host. Because that hardware differential test **skips** on stock CI runners, the
  novel part — the unsigned/signed **bias-correction ring identity** — also gets an
  *always-on, hardware-independent* guard: a pure model (`vnni_cell_bias`, no `asm!`)
  proven equal to the scalar dot product by a Kani harness (symbolic bytes) and by
  host tests that run on **every** runner and under Miri (a 2000-shape sweep + a
  wrap case). TCG cannot execute the kernel, so the always-on Kernel CI shows
  `active=avx2`; the KVM boot job asserts `active=avx512-vnni` + `int8 GEMM ok` on
  runners that expose VNNI — **observed** on the tier's first CI run (serial log
  archived), which also confirms the AVX-512 `XCR0` enablement + the AVX-512F self-
  test at CPL-0. The boot self-test keeps the tier dormant wherever `avx512_vnni` is
  absent. The `asm!` step is Miri/Kani-opaque, so SM3's dynamic coverage is the host
  harness + boot self-test + the always-on bias guard.
- **Phase 5 (AMX, proposed):** same differential-vs-scalar oracle + a self-test, but
  it can only *execute* where the hardware exists: QEMU 8.2 TCG does not emulate AMX
  (drops the CPUID bits, like x2APIC); AMX (Sapphire-Rapids+) has not been seen on
  the KVM runner fleet and needs dedicated hardware. The self-test keeps it dormant
  (scalar fallback) everywhere it can't run, so nothing computes garbage. The
  XCR0/XFD/tile-config `XSETBV`/MSR writes are inline-asm (Miri/Kani-opaque, like the
  SMP MSRs) → verified by reasoning + the differential test + hardware boot evidence.

## Open questions

- **Where do the SIMD tiers live?** Resolved: `hal::simd` (TCB), so the TCB
  registry (`hal-tcb.md`) stays the single catalog of unsafe; revisit if it grows
  large.
- **Intrinsics vs. `asm!` on the bare-metal target.** Resolved by the AVX2 work:
  the soft-float `x86_64-unknown-none` target does **not** codegen `core::arch`
  SIMD intrinsics to VEX (they emit as calls and the `__m256i` ABI is broken), so
  the SIMD inner steps are hand-written inline `asm!` — which needs no nightly and
  no `#[target_feature]`, and emits the exact instructions. (Alternatives:
  `build-std` recompiling `core` with `+avx2`, or a custom target JSON; `asm!` is
  simpler and matches the kernel's existing style.) The boot self-test is the
  backstop if any tier's `asm!` is wrong on a given unit.
- **Perf: `VPMADDWD` fusion (future).** The AVX2 tier uses `VPMULLD`+`VPADDD`; a
  `VPMADDWD` (int16 multiply-add over `VPMOVSXBW`-extended int8) would fuse the pair
  and do 16 int8/step. Still bit-exact (associative `wrapping_add`). A throughput
  optimization for later — the correctness path is settled.
- **bf16 path.** `AMX_BF16` / `AVX512_BF16` reuse this exact structure with a bf16
  input/f32-accumulate GEMM. Deferred until the int8 tiers land, but the `Tier`
  enum + dispatch are designed to extend to it.

## References

- Intel SDM Vol. 1 ch. 20 (AMX), Vol. 2 (`TDPBSSD`, `VPDPBUSD`, `LDTILECFG`); the
  `XCR0`/`IA32_XFD` state-enable requirements for AMX.
- SentinelOS strategy & roadmap (`docs/research/2026-07-14-sentinelos-strategy-and-roadmap.md`),
  Track C (AI/ML). C1 detection: `kernel/crates/hal/src/cpuid.rs`.
