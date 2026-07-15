//! `kernel::ml` — the AI/ML compute path: quantized-inference primitives.
//!
//! SentinelOS's end goal is extreme AI/ML capability. The load-bearing operation
//! for quantized inference is an **int8 × int8 → int32** matrix multiply (GEMM):
//! AMX's `TDPBSSD`, AVX-512 VNNI's `VPDPBUSD`, and a plain scalar loop all compute
//! exactly this, differing only in throughput. So this module exposes one
//! [`gemm_i8`] entry with a **tiered** implementation selected by `cpuid`
//! ([`Tier`]), turning the C1 feature *detection* into an actual *inference path*.
//!
//! This is entirely **safe** Rust (the crate is `#![forbid(unsafe_code)]`): the
//! scalar reference and the dispatch only read the existing safe
//! [`hal::cpuid::info`] and compute; the vector kernels live behind safe wrappers
//! in the `hal` TCB. The **AVX2**, **AVX-512 Foundation**, and **AVX-512 VNNI**
//! (`VPDPBUSD`) tiers are implemented ([`hal::simd`], `XCR0`-gated inline `asm!`);
//! the **AMX** (`XFD`/tile-config) throughput tier is detected but not yet
//! implemented — a designed later phase. Every vector tier is validated
//! **bit-for-bit** against the scalar reference here, since the int8→i32 GEMM is
//! exact. See `docs/specs/2026-07-14-aiml-inference-compute-design.md`.

use hal::cpuid::{self, CpuInfo};

// ── compute tiers ───────────────────────────────────────────────────────────

/// A quantized-GEMM compute tier, best-to-worst throughput.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tier {
    /// Plain `i32 += i8*i8` loop — always available; the correctness reference.
    Scalar,
    /// AVX2 (256-bit) int8 GEMM — implemented (`hal::simd`). Detected via `avx2`.
    Avx2,
    /// AVX-512 **Foundation** (512-bit `ZMM`) int8 GEMM — implemented (`hal::simd`):
    /// the 16-wide `VPMULLD` broadcast sibling of the AVX2 kernel. Detected via
    /// `avx512f`. Distinct from [`Tier::Avx512Vnni`]: this uses the foundation
    /// `VPMULLD`/`VPADDD` ops, not the fused `VPDPBUSD` dot-product.
    Avx512F,
    /// AVX-512 VNNI (`VPDPBUSD`, fused unsigned×signed 4×int8 dot-product, 64×int8
    /// per step) — implemented (`hal::simd`). Detected via `avx512_vnni`.
    Avx512Vnni,
    /// AMX int8 tiles (`TDPBSSD`). Detected via `amx_int8` + `amx_tile`.
    Amx,
}

impl Tier {
    /// A short, stable label for boot/serial reporting.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Tier::Scalar => "scalar",
            Tier::Avx2 => "avx2",
            Tier::Avx512F => "avx512f",
            Tier::Avx512Vnni => "avx512-vnni",
            Tier::Amx => "amx-int8",
        }
    }
}

/// Map detected cpuid feature flags to the best hardware [`Tier`] they offer.
///
/// Pure (no cpuid read), so it is host-unit- and Kani-testable; the `cpuid` read
/// is done by [`detected_capability`].
#[must_use]
const fn capability_from_flags(
    amx_int8: bool,
    amx_tile: bool,
    avx512_vnni: bool,
    avx512f: bool,
    avx2: bool,
) -> Tier {
    // Best-to-worst: AMX int8 (needs BOTH the tile substrate and the int8
    // dot-product op) → AVX-512 VNNI → AVX-512 Foundation → AVX2 → scalar.
    if amx_int8 && amx_tile {
        Tier::Amx
    } else if avx512_vnni {
        Tier::Avx512Vnni
    } else if avx512f {
        Tier::Avx512F
    } else if avx2 {
        Tier::Avx2
    } else {
        Tier::Scalar
    }
}

/// Whether `info` advertises a named cpuid feature (present).
fn has(info: &CpuInfo, name: &str) -> bool {
    info.features().iter().any(|f| f.name == name && f.present)
}

/// The best hardware tier this CPU *advertises* (detected, per C1).
///
/// This is what the hardware *could* do; it is not necessarily what is
/// implemented yet — see [`active_tier`].
#[must_use]
pub fn detected_capability(info: &CpuInfo) -> Tier {
    capability_from_flags(
        has(info, "amx_int8"),
        has(info, "amx_tile"),
        has(info, "avx512_vnni"),
        has(info, "avx512f"),
        has(info, "avx2"),
    )
}

/// The best tier actually *implemented and runnable* right now.
///
/// **AVX-512 VNNI**, **AVX-512F**, and **AVX2** are implemented ([`hal::simd`]);
/// each is selected when the CPU advertises it *and* its vector state is enabled and
/// the boot self-test passed ([`hal::simd::avx512vnni_ready`] /
/// [`hal::simd::avx512_ready`] / [`hal::simd::avx2_ready`]), best first, else scalar.
/// AMX is detected but not yet implemented, so it never becomes active (it falls
/// back through [`gemm_i8`] to the VNNI/AVX-512F/AVX2/scalar kernels). [`gemm_i8`]
/// dispatches to this, so the result is always correct and never claims a tier it
/// does not run.
#[must_use]
pub fn active_tier() -> Tier {
    if hal::simd::avx512vnni_ready() {
        Tier::Avx512Vnni
    } else if hal::simd::avx512_ready() {
        Tier::Avx512F
    } else if hal::simd::avx2_ready() {
        Tier::Avx2
    } else {
        Tier::Scalar
    }
}

// ── quantization (symmetric int8) ─────────────────────────────────────────────

/// Symmetric int8 quantization scale for a tensor: `max|x| / 127`.
///
/// Floored so an all-zero (or vanishingly small) tensor never yields scale `0`
/// (which would divide by zero in [`quantize`]); such a tensor quantizes to all
/// zeros, which is correct.
#[must_use]
pub fn quant_scale(values: &[f32]) -> f32 {
    let mut max_abs = 0.0f32;
    for &v in values {
        // `f32::abs` is a `std`-only method (no libm in `core`); compute it by hand.
        let a = if v < 0.0 { -v } else { v };
        if a > max_abs {
            max_abs = a;
        }
    }
    let scale = max_abs / 127.0;
    if scale > 0.0 {
        scale
    } else {
        1.0
    }
}

/// Round a finite `f32` to the nearest `i32`, half away from zero.
///
/// `as i32` on a float truncates toward zero and saturates (Rust ≥ 1.45), so
/// adding ±0.5 first gives round-half-away without any `std`/libm dependency.
#[must_use]
fn round_to_i32(x: f32) -> i32 {
    if x >= 0.0 {
        (x + 0.5) as i32
    } else {
        (x - 0.5) as i32
    }
}

/// Clamp to the **symmetric** int8 range `[-127, 127]` (never `-128`, so negation
/// is exact for symmetric quantization).
#[must_use]
fn clamp_i8(q: i32) -> i8 {
    if q > 127 {
        127
    } else if q < -127 {
        -127
    } else {
        q as i8
    }
}

/// Quantize `values` into `out` (same length) at the given `scale`.
///
/// # Panics
/// If `values.len() != out.len()` (a caller contract, checked).
pub fn quantize(values: &[f32], scale: f32, out: &mut [i8]) {
    assert_eq!(values.len(), out.len(), "quantize: length mismatch");
    for (dst, &v) in out.iter_mut().zip(values) {
        *dst = clamp_i8(round_to_i32(v / scale));
    }
}

/// Dequantize an int32 accumulator back to `f32` given both operands' scales.
///
/// For `C = A·B` with per-tensor scales, `C_real = C_int32 * scale_a * scale_b`.
#[must_use]
pub fn dequantize(acc: i32, scale_a: f32, scale_b: f32) -> f32 {
    acc as f32 * scale_a * scale_b
}

// ── int8 GEMM ─────────────────────────────────────────────────────────────────

/// Scalar reference GEMM: `C[m×n] = A[m×k] · B[k×n]`, int8·int8 with **i32
/// accumulation** (row-major). The correctness oracle for every SIMD tier.
///
/// Accumulation uses `wrapping_add` to match the hardware (VNNI/AMX) int32
/// wrap-on-overflow semantics exactly — the SIMD tiers must reproduce this
/// bit-for-bit. Each product `i8*i8` fits i32 (≤ 127²), so only the running sum
/// can wrap; callers keep `k` bounded so it does not in practice.
///
/// # Panics
/// If any slice length disagrees with `m`/`k`/`n` (a caller contract, checked).
pub fn gemm_i8_scalar(a: &[i8], b: &[i8], c: &mut [i32], m: usize, k: usize, n: usize) {
    assert_eq!(a.len(), m * k, "gemm: A must be m*k");
    assert_eq!(b.len(), k * n, "gemm: B must be k*n");
    assert_eq!(c.len(), m * n, "gemm: C must be m*n");
    for i in 0..m {
        for j in 0..n {
            let mut acc: i32 = 0;
            for p in 0..k {
                let prod = a[i * k + p] as i32 * b[p * n + j] as i32;
                acc = acc.wrapping_add(prod);
            }
            c[i * n + j] = acc;
        }
    }
}

/// Public int8 GEMM entry — dispatches to the best *implemented* kernel.
///
/// Tries the AVX-512 VNNI kernel ([`hal::simd::gemm_i8_avx512vnni`]) first, then
/// AVX-512F ([`hal::simd::gemm_i8_avx512`]), then AVX2
/// ([`hal::simd::gemm_i8_avx2`]); each self-checks its feature + enabled vector
/// state and returns `false` when unavailable (or on bad dims), so we fall through
/// to the next tier and finally the scalar reference. All four produce bit-identical
/// results. The AMX kernel slots in here (tried first) once implemented (design doc
/// phase 5).
pub fn gemm_i8(a: &[i8], b: &[i8], c: &mut [i32], m: usize, k: usize, n: usize) {
    if hal::simd::gemm_i8_avx512vnni(a, b, c, m, k, n) {
        return;
    }
    if hal::simd::gemm_i8_avx512(a, b, c, m, k, n) {
        return;
    }
    if hal::simd::gemm_i8_avx2(a, b, c, m, k, n) {
        return;
    }
    gemm_i8_scalar(a, b, c, m, k, n);
}

// ── boot proof ────────────────────────────────────────────────────────────────

/// Checksum of the identity-GEMM boot proof: `identity · B = B`, so `Σ C = Σ B =
/// Σ(0..80) = 3160`. Self-evident — no hand-computed constant to get wrong.
const PROOF_CHECKSUM: i64 = 3160;

/// Run a real int8 GEMM through the live dispatch and log the result, proving the
/// inference path works end-to-end in the booted kernel.
///
/// Uses a 4×4 identity `A` and a 4×**20** `B` with `B[idx] = idx` (values 0..79,
/// all `< 127` so they fit int8 exactly). `identity·B = B`, so the output must equal
/// `B` and its checksum must be [`PROOF_CHECKSUM`] — a self-validating smoke test.
/// `n = 20` deliberately exceeds **16** so that whichever vector tier is active runs
/// its real vector body end-to-end (a full 16-wide `ZMM` block for AVX-512F, two
/// 8-wide `YMM` blocks for AVX2) plus a scalar tail — not just the tail. So the boot
/// proof exercises the live vector kernel: AVX2 under TCG (Haswell advertises
/// `avx2`), and AVX-512F on KVM runners that expose it. Rigorous index/accumulation
/// correctness lives in the host unit tests. Prints via the fmt-free serial helpers
/// because `println!("{}", n)` faults on this target for integer args (see
/// `memory.rs`).
pub fn prove() {
    let info = cpuid::info();
    let detected = detected_capability(&info);
    let active = active_tier();

    const M: usize = 4;
    const K: usize = 4;
    const N: usize = 20;
    let mut a = [0i8; M * K];
    for d in 0..M {
        a[d * K + d] = 1; // 4×4 identity
    }
    let mut b = [0i8; K * N];
    for (idx, slot) in b.iter_mut().enumerate() {
        *slot = idx as i8; // 0..79
    }
    let mut c = [0i32; M * N];
    gemm_i8(&a, &b, &mut c, M, K, N);

    let correct = c.iter().zip(&b).all(|(&ci, &bi)| ci == bi as i32);
    let checksum: i64 = c.iter().map(|&x| x as i64).sum();

    hal::serial::write_str("[ml] inference: detected=");
    hal::serial::write_str(detected.label());
    hal::serial::write_str(", active=");
    hal::serial::write_str(active.label());
    hal::serial::write_str("; 4x4*4x20 int8 GEMM ");
    hal::serial::write_str(if correct && checksum == PROOF_CHECKSUM {
        "ok"
    } else {
        "FAIL"
    });
    hal::serial::write_str("; checksum=");
    hal::serial::write_dec(checksum as u64);
    hal::serial::write_str("\n");
}

/// Prove vector GEMM is correct with **interrupts enabled** — validating that the
/// old "interrupts must be disabled" precondition is now lifted.
///
/// Two mechanisms make this safe (see the vector-state-across-interrupts design):
/// the **load-bearing** one is that on this soft-float target compiled interrupt
/// handlers contain **no** vector instructions (CI-enforced by `xtask
/// check-no-vector`), so they cannot clobber an interrupted GEMM's `YMM`/`ZMM` state;
/// and `hal::idt::isr_common` additionally `XSAVE`s/`XRSTOR`s the full vector state
/// per IRQ as defense-in-depth.
///
/// This is a **stress test**, not a deterministic proof of the precondition lift: it
/// runs the identity·B GEMM (the [`prove`] shape, so the active vector tier engages)
/// in a tight loop with `sti` set and the PIT firing, so timer IRQs land *during* the
/// loop, and asserts every result stays bit-exact. It reliably shows "interrupts
/// fired and the per-IRQ `xsave`/`xrstor` did not corrupt any result", and reports
/// `ok` only if the results held **and** the timer demonstrably advanced. It does
/// **not** deterministically hit the few-instruction window where a live `YMM`/`ZMM`
/// accumulator exists inside a single `madd` call (accumulators spill to `c` in
/// memory between calls) — that a handler can never clobber vectors at all is what
/// the CI guard guarantees. Restores the interrupts-off boot state. Prints fmt-free.
pub fn prove_interrupts_on() {
    const M: usize = 4;
    const K: usize = 4;
    const N: usize = 20;
    let mut a = [0i8; M * K];
    for d in 0..M {
        a[d * K + d] = 1;
    }
    let mut b = [0i8; K * N];
    for (idx, slot) in b.iter_mut().enumerate() {
        *slot = idx as i8;
    }
    let mut c = [0i32; M * N];

    let start = hal::pit::ticks();
    hal::cpu::enable_interrupts();
    let mut all_ok = true;
    let mut iters: u64 = 0;
    // Keep computing until the timer has advanced a few ticks (so IRQs certainly
    // landed mid-loop), with a hard iteration cap so a dead timer can't spin forever.
    while hal::pit::ticks().wrapping_sub(start) < 3 && iters < 50_000_000 {
        gemm_i8(&a, &b, &mut c, M, K, N);
        let checksum: i64 = c.iter().map(|&x| x as i64).sum();
        if checksum != PROOF_CHECKSUM {
            all_ok = false;
            break;
        }
        iters += 1;
    }
    hal::cpu::disable_interrupts();
    let elapsed = hal::pit::ticks().wrapping_sub(start);
    // `ok` requires BOTH: no corrupted result, and the timer actually advanced (else
    // we proved nothing about interrupts landing).
    let ok = all_ok && elapsed >= 1;

    hal::serial::write_str("[ml] gemm-under-irq: ");
    hal::serial::write_dec(iters);
    hal::serial::write_str(" gemms across ");
    hal::serial::write_dec(elapsed);
    hal::serial::write_str(" timer ticks -> ");
    hal::serial::write_str(if ok { "ok\n" } else { "FAIL\n" });
}

// ── quantized MLP inference — the first end-to-end workload ─────────────────────
//
// Everything above is a *primitive* (a GEMM, quantization, tier dispatch). This
// section composes them into an actual (tiny) neural-network forward pass, so the
// AI/ML path is exercised as *inference*, not just a bare matrix multiply — and the
// quantization API stops being test-only. It is entirely **safe** Rust built on the
// safe primitives; no new TCB.

/// ReLU activation, in place: `y := max(0, y)`. (`core` has no `f32::max`, and there
/// is no libm in the kernel, so compute it directly.)
fn relu_inplace(y: &mut [f32]) {
    for v in y.iter_mut() {
        if *v < 0.0 {
            *v = 0.0;
        }
    }
}

/// Quantize a whole f32 tensor into `out` (symmetric int8), returning the scale it
/// used — the standard "quantize this tensor" step ([`quant_scale`] + [`quantize`]).
///
/// # Panics
/// If `values.len() != out.len()` (via [`quantize`]).
pub fn quantize_tensor(values: &[f32], out: &mut [i8]) -> f32 {
    let scale = quant_scale(values);
    quantize(values, scale, out);
    scale
}

/// One dense (fully-connected) layer over a **batch**, pre-activation:
///
/// `Y[n_out × batch] = dequant( Wq[n_out × k_in] · Xq[k_in × batch] ) + bias`
///
/// The int8·int8→i32 GEMM runs through the tiered [`gemm_i8`] (so it uses the best
/// implemented vector tier), the i32 result is dequantized to f32 with the two
/// per-tensor scales, and `bias[i]` is added to every column of output row `i`.
/// Processing `batch` columns at once is what makes the GEMM's `n` dimension large
/// enough to engage the vector kernels — a plain matrix-vector product (`batch = 1`)
/// would stay on the scalar tail. Every buffer is caller-owned, so this allocates
/// nothing; `acc` is `n_out × batch` i32 scratch (also left holding the raw GEMM
/// output, which callers use as a deterministic checksum anchor).
///
/// # Panics
/// If `batch == 0`, or on any slice-length/dimension inconsistency (caller contract).
#[allow(clippy::too_many_arguments)]
pub fn dense_pre_activation(
    wq: &[i8],
    sw: f32,
    xq: &[i8],
    sx: f32,
    bias: &[f32],
    n_out: usize,
    k_in: usize,
    batch: usize,
    acc: &mut [i32],
    y: &mut [f32],
) {
    // A zero batch is a meaningless call and would otherwise panic downstream in
    // `chunks(0)` with an unrelated message; reject it explicitly (contract).
    assert!(batch > 0, "dense: batch must be nonzero");
    assert_eq!(wq.len(), n_out * k_in, "dense: W must be n_out*k_in");
    assert_eq!(xq.len(), k_in * batch, "dense: X must be k_in*batch");
    assert_eq!(bias.len(), n_out, "dense: bias must be n_out");
    assert_eq!(acc.len(), n_out * batch, "dense: acc must be n_out*batch");
    assert_eq!(y.len(), n_out * batch, "dense: y must be n_out*batch");
    gemm_i8(wq, xq, acc, n_out, k_in, batch);
    // Dequantize each i32 accumulator to f32 and add the per-row bias (broadcast
    // across the batch). `acc`/`y` are `n_out` rows of `batch` columns, row-major.
    for ((&bi, acc_row), y_row) in bias.iter().zip(acc.chunks(batch)).zip(y.chunks_mut(batch)) {
        for (yv, &av) in y_row.iter_mut().zip(acc_row) {
            *yv = dequantize(av, sw, sx) + bi;
        }
    }
}

// ── inference boot proof ────────────────────────────────────────────────────────

/// Checksum of the MLP boot proof's final int32 accumulator — a stable,
/// tier-independent regression anchor: the int8 GEMMs are bit-exact across every
/// tier and the f32 requant between layers is deterministic, so this integer is
/// fixed. Guarded against drift by the host test `mlp_boot_proof_checksum_is_stable`.
const INFER_CHECKSUM: i64 = 240475;

/// Deterministic f32 in `[-1, 1)` for the fixed-weight inference boot proof (no rng).
fn infer_fill(t: usize) -> f32 {
    let v = (t.wrapping_mul(2_654_435_761) >> 8) % 256;
    v as f32 / 128.0 - 1.0
}

/// The fixed batched 2-layer MLP forward pass shared by [`infer_prove`] and its host
/// test: returns the checksum of the final int32 accumulator. Architecture 4→8→3
/// with ReLU, `batch = 16`. Composes the full quantized-inference pipeline —
/// quantize inputs+weights → int8 GEMM (layer 1) → dequant+bias → ReLU → requantize
/// → int8 GEMM (layer 2) — through the live tiered [`gemm_i8`]. Alloc-free (fixed
/// stack buffers); `batch = 16` so each layer's GEMM engages the active vector tier.
fn infer_forward_checksum() -> i64 {
    const IN: usize = 4;
    const HID: usize = 8;
    const OUT: usize = 3;
    const B: usize = 16;

    let mut x = [0f32; IN * B];
    for (t, v) in x.iter_mut().enumerate() {
        *v = infer_fill(t);
    }
    let mut w1 = [0f32; HID * IN];
    for (t, v) in w1.iter_mut().enumerate() {
        *v = infer_fill(t * 3 + 1);
    }
    let mut w2 = [0f32; OUT * HID];
    for (t, v) in w2.iter_mut().enumerate() {
        *v = infer_fill(t * 7 + 5);
    }
    // Zero biases keep the anchor simple; the mixed-sign weighted sums still drive
    // ReLU to clamp a good fraction of the hidden activations (~38% here, and every
    // hidden row is mixed-sign), so the nonlinearity is genuinely exercised.
    let b1 = [0f32; HID];
    let b2 = [0f32; OUT];

    let mut xq = [0i8; IN * B];
    let sx = quantize_tensor(&x, &mut xq);
    let mut w1q = [0i8; HID * IN];
    let sw1 = quantize_tensor(&w1, &mut w1q);

    // Layer 1: H = ReLU(dequant(W1·X)).
    let mut acc1 = [0i32; HID * B];
    let mut h = [0f32; HID * B];
    dense_pre_activation(&w1q, sw1, &xq, sx, &b1, HID, IN, B, &mut acc1, &mut h);
    relu_inplace(&mut h);

    // Requantize the hidden activations; quantize layer-2 weights.
    let mut hq = [0i8; HID * B];
    let sh = quantize_tensor(&h, &mut hq);
    let mut w2q = [0i8; OUT * HID];
    let sw2 = quantize_tensor(&w2, &mut w2q);

    // Layer 2: Y = dequant(W2·H).
    let mut acc2 = [0i32; OUT * B];
    let mut y = [0f32; OUT * B];
    dense_pre_activation(&w2q, sw2, &hq, sh, &b2, OUT, HID, B, &mut acc2, &mut y);

    acc2.iter().map(|&v| v as i64).sum()
}

/// Run a real **batched quantized 2-layer MLP** forward pass through the live
/// inference path and log the result — proving end-to-end inference works in the
/// booted kernel, not just a bare GEMM. Self-validates by checksumming the final
/// int32 accumulator (exact + tier-independent) against [`INFER_CHECKSUM`]; a
/// mismatch means a tier computed the pipeline wrong. Prints via the fmt-free serial
/// helpers (integer `println!` faults on this target — see `memory.rs`).
pub fn infer_prove() {
    let checksum = infer_forward_checksum();
    let active = active_tier();

    hal::serial::write_str("[ml] mlp: 4-8-3 batch16 int8 forward via ");
    hal::serial::write_str(active.label());
    hal::serial::write_str(if checksum == INFER_CHECKSUM {
        " ok"
    } else {
        " FAIL"
    });
    hal::serial::write_str("; acc2 checksum=");
    // The accumulator sum can be negative; `write_dec` takes u64, so emit the sign.
    if checksum < 0 {
        hal::serial::write_str("-");
        hal::serial::write_dec((-checksum) as u64);
    } else {
        hal::serial::write_dec(checksum as u64);
    }
    hal::serial::write_str("\n");
}

// ── unit tests (host) ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gemm_identity_returns_b() {
        // 3×3 identity · B = B.
        let a = [1i8, 0, 0, 0, 1, 0, 0, 0, 1];
        let b = [1i8, 2, 3, 4, 5, 6, 7, 8, 9];
        let mut c = [0i32; 9];
        gemm_i8_scalar(&a, &b, &mut c, 3, 3, 3);
        assert_eq!(c, [1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }

    #[test]
    fn gemm_non_square_hand_checked() {
        // A is 2×3, B is 3×2 → C is 2×2.
        // A = [[1,2,3],[4,5,6]], B = [[7,8],[9,10],[11,12]]
        // C[0][0]=1*7+2*9+3*11=58, C[0][1]=1*8+2*10+3*12=64
        // C[1][0]=4*7+5*9+6*11=139, C[1][1]=4*8+5*10+6*12=154
        let a = [1i8, 2, 3, 4, 5, 6];
        let b = [7i8, 8, 9, 10, 11, 12];
        let mut c = [0i32; 4];
        gemm_i8_scalar(&a, &b, &mut c, 2, 3, 2);
        assert_eq!(c, [58, 64, 139, 154]);
    }

    #[test]
    fn gemm_accumulates_in_i32_beyond_i8_and_i16() {
        // 1×8 · 8×1 of all 127s → 8 * 127*127 = 129032, which overflows i8 and i16
        // but fits i32 — proves the accumulator is genuinely 32-bit, not truncated.
        let a = [127i8; 8];
        let b = [127i8; 8];
        let mut c = [0i32; 1];
        gemm_i8_scalar(&a, &b, &mut c, 1, 8, 1);
        assert_eq!(c[0], 8 * 127 * 127);
        assert!(c[0] > i16::MAX as i32);
    }

    #[test]
    fn gemm_handles_negative_values() {
        // 1×2 · 2×1: [-5, 3] · [4, -2] = -20 - 6 = -26.
        let a = [-5i8, 3];
        let b = [4i8, -2];
        let mut c = [0i32; 1];
        gemm_i8_scalar(&a, &b, &mut c, 1, 2, 1);
        assert_eq!(c[0], -26);
    }

    #[test]
    fn boot_proof_input_checksums_to_the_constant() {
        // Mirrors prove()'s 4×4 identity · 4×20 B computation (via the scalar
        // reference — gemm_i8's dispatch touches privileged CR4/XCR0 state that is
        // CPL-0-only, so it is exercised at boot, not in host tests). Guards
        // PROOF_CHECKSUM against drift.
        let mut a = [0i8; 16];
        for d in 0..4 {
            a[d * 4 + d] = 1;
        }
        let mut b = [0i8; 80];
        for (idx, slot) in b.iter_mut().enumerate() {
            *slot = idx as i8;
        }
        let mut c = [0i32; 80];
        gemm_i8_scalar(&a, &b, &mut c, 4, 4, 20);
        assert!(c.iter().zip(&b).all(|(&ci, &bi)| ci == bi as i32));
        let checksum: i64 = c.iter().map(|&x| x as i64).sum();
        assert_eq!(checksum, PROOF_CHECKSUM);
    }

    #[test]
    fn quantize_dequantize_roundtrip() {
        let values = [0.0f32, 0.5, -0.5, 1.0, -1.0, 0.25];
        let scale = quant_scale(&values);
        // max|x| = 1.0 → scale = 1/127.
        assert!((scale - 1.0 / 127.0).abs() < 1e-9);
        let mut q = [0i8; 6];
        quantize(&values, scale, &mut q);
        assert_eq!(q[3], 127); // 1.0 maps to +127
        assert_eq!(q[4], -127); // -1.0 maps to -127
        assert_eq!(q[0], 0);
        // Dequantized value stays within one quantization step of the original.
        for (&v, &qi) in values.iter().zip(&q) {
            let back = qi as f32 * scale;
            assert!((back - v).abs() <= scale);
        }
    }

    #[test]
    fn quant_scale_zero_input_is_safe() {
        // All-zero tensor must not divide by zero; scale falls back to 1.0.
        let values = [0.0f32; 8];
        let scale = quant_scale(&values);
        assert_eq!(scale, 1.0);
        let mut q = [1i8; 8];
        quantize(&values, scale, &mut q);
        assert_eq!(q, [0i8; 8]);
    }

    #[test]
    fn clamp_saturates_symmetrically() {
        assert_eq!(clamp_i8(200), 127);
        assert_eq!(clamp_i8(-200), -127);
        assert_eq!(clamp_i8(-128), -127); // never emits -128
        assert_eq!(clamp_i8(50), 50);
    }

    #[test]
    fn capability_mapping_is_best_to_worst() {
        // Args: (amx_int8, amx_tile, avx512_vnni, avx512f, avx2).
        // AMX needs both tile + int8, and wins over everything below it.
        assert_eq!(
            capability_from_flags(true, true, false, false, false),
            Tier::Amx
        );
        assert_eq!(
            capability_from_flags(true, true, true, true, true),
            Tier::Amx
        );
        // amx_int8 without the tile substrate is not usable → next tier wins.
        assert_eq!(
            capability_from_flags(true, false, true, true, true),
            Tier::Avx512Vnni
        );
        assert_eq!(
            capability_from_flags(false, false, true, true, false),
            Tier::Avx512Vnni
        );
        // No AMX/VNNI, but avx512f present → the AVX-512 Foundation tier (a
        // VNNI-capable CPU always has avx512f; VNNI still wins above).
        assert_eq!(
            capability_from_flags(false, false, false, true, true),
            Tier::Avx512F
        );
        assert_eq!(
            capability_from_flags(false, false, false, true, false),
            Tier::Avx512F
        );
        // No AMX/VNNI/avx512f → AVX2 if present.
        assert_eq!(
            capability_from_flags(false, false, false, false, true),
            Tier::Avx2
        );
        assert_eq!(
            capability_from_flags(true, false, false, false, true),
            Tier::Avx2
        );
        // Nothing usable → scalar (a lone amx_tile or amx_int8 is not usable).
        assert_eq!(
            capability_from_flags(false, false, false, false, false),
            Tier::Scalar
        );
        assert_eq!(
            capability_from_flags(false, true, false, false, false),
            Tier::Scalar
        );
    }

    // ── inference (MLP) ──────────────────────────────────────────────────────

    #[test]
    fn dense_pre_activation_hand_checked() {
        // W [2×2] = [[1,2],[3,4]], X [2×batch=2] = cols (5,7),(6,8); pre-quantized
        // int8 with scales sw=0.5, sx=0.25 (both exact powers of two → exact f32).
        // acc = W·X = [[1*5+2*7, 1*6+2*8],[3*5+4*7, 3*6+4*8]] = [[19,22],[43,50]].
        // y = acc*sw*sx + bias = acc*0.125 + [10, 20].
        let wq = [1i8, 2, 3, 4];
        let xq = [5i8, 6, 7, 8];
        let bias = [10.0f32, 20.0];
        let mut acc = [0i32; 4];
        let mut y = [0f32; 4];
        dense_pre_activation(&wq, 0.5, &xq, 0.25, &bias, 2, 2, 2, &mut acc, &mut y);
        assert_eq!(acc, [19, 22, 43, 50]);
        assert_eq!(y, [12.375, 12.75, 25.375, 26.25]);
    }

    #[test]
    #[should_panic(expected = "batch must be nonzero")]
    fn dense_rejects_zero_batch() {
        // A zero batch is internally consistent (all products are 0) but meaningless;
        // it must fail the explicit contract, not panic later in `chunks(0)`.
        let bias = [0.0f32; 2];
        let mut acc = [0i32; 0];
        let mut y = [0f32; 0];
        dense_pre_activation(&[], 1.0, &[], 1.0, &bias, 2, 0, 0, &mut acc, &mut y);
    }

    #[test]
    fn mlp_boot_proof_checksum_is_stable() {
        // Guards INFER_CHECKSUM against drift. The pipeline is deterministic and
        // tier-independent (int8 GEMMs are bit-exact across tiers; the f32 requant
        // is deterministic), so this holds on whatever tier the host runs.
        assert_eq!(infer_forward_checksum(), INFER_CHECKSUM);
    }

    #[test]
    fn mlp_approximates_f32_reference() {
        // The quantized 2-layer MLP must compute the *right function*: its output
        // stays close to a pure-f32 forward pass (int8 quant of ~[-1,1] values only
        // introduces small per-tensor rounding error). A transposed-weights or
        // wrong-scale bug would diverge far past this tolerance.
        const IN: usize = 4;
        const HID: usize = 6;
        const OUT: usize = 2;
        const B: usize = 8;
        let mut x = [0f32; IN * B];
        for (t, v) in x.iter_mut().enumerate() {
            *v = infer_fill(t + 11);
        }
        let mut w1 = [0f32; HID * IN];
        for (t, v) in w1.iter_mut().enumerate() {
            *v = infer_fill(t * 5 + 2);
        }
        let mut w2 = [0f32; OUT * HID];
        for (t, v) in w2.iter_mut().enumerate() {
            *v = infer_fill(t * 9 + 4);
        }

        // Pure-f32 reference forward: relu(W1·X) then W2·(·), zero biases.
        let mut h_ref = [0f32; HID * B];
        for i in 0..HID {
            for j in 0..B {
                let mut acc = 0.0f32;
                for p in 0..IN {
                    acc += w1[i * IN + p] * x[p * B + j];
                }
                h_ref[i * B + j] = if acc < 0.0 { 0.0 } else { acc };
            }
        }
        let mut y_ref = [0f32; OUT * B];
        for i in 0..OUT {
            for j in 0..B {
                let mut acc = 0.0f32;
                for p in 0..HID {
                    acc += w2[i * HID + p] * h_ref[p * B + j];
                }
                y_ref[i * B + j] = acc;
            }
        }

        // Quantized forward through the real primitives.
        let mut xq = [0i8; IN * B];
        let sx = quantize_tensor(&x, &mut xq);
        let mut w1q = [0i8; HID * IN];
        let sw1 = quantize_tensor(&w1, &mut w1q);
        let mut acc1 = [0i32; HID * B];
        let mut h = [0f32; HID * B];
        let zb1 = [0f32; HID];
        dense_pre_activation(&w1q, sw1, &xq, sx, &zb1, HID, IN, B, &mut acc1, &mut h);
        relu_inplace(&mut h);
        let mut hq = [0i8; HID * B];
        let sh = quantize_tensor(&h, &mut hq);
        let mut w2q = [0i8; OUT * HID];
        let sw2 = quantize_tensor(&w2, &mut w2q);
        let mut acc2 = [0i32; OUT * B];
        let mut y = [0f32; OUT * B];
        let zb2 = [0f32; OUT];
        dense_pre_activation(&w2q, sw2, &hq, sh, &zb2, OUT, HID, B, &mut acc2, &mut y);

        // Compare against the reference; tolerate quantization error, catch wiring bugs.
        let mut range = 0.0f32;
        for &r in &y_ref {
            let a = if r < 0.0 { -r } else { r };
            if a > range {
                range = a;
            }
        }
        let mut max_err = 0.0f32;
        for (&yq, &yr) in y.iter().zip(&y_ref) {
            let e = yq - yr;
            let e = if e < 0.0 { -e } else { e };
            if e > max_err {
                max_err = e;
            }
        }
        assert!(
            range > 0.1,
            "reference output is degenerate (range={range})"
        );
        assert!(
            max_err < 0.1 * range,
            "quantized MLP diverged from f32 reference: max_err={max_err}, range={range}"
        );
    }
}

/// Kani proof — the pure tier-selection logic is total (never panics) over all
/// flag combinations. Compiled only under `cargo kani`; excluded from the stable
/// build and `cargo test`. Run with `cargo kani -p kernel`.
#[cfg(kani)]
mod proofs {
    use super::{capability_from_flags, Tier};

    #[kani::proof]
    fn capability_from_flags_is_total() {
        let amx_int8: bool = kani::any();
        let amx_tile: bool = kani::any();
        let vnni: bool = kani::any();
        let avx512f: bool = kani::any();
        let avx2: bool = kani::any();
        let tier = capability_from_flags(amx_int8, amx_tile, vnni, avx512f, avx2);
        // AMX iff both amx bits; never claims AMX without the tile substrate.
        if amx_int8 && amx_tile {
            assert!(tier == Tier::Amx);
        } else {
            assert!(tier != Tier::Amx);
        }
        // Never claims a vector tier the CPU does not advertise.
        if tier == Tier::Avx512Vnni {
            assert!(vnni);
        }
        if tier == Tier::Avx512F {
            assert!(avx512f);
        }
        if tier == Tier::Avx2 {
            assert!(avx2);
        }
    }
}
