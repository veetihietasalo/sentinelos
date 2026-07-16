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

/// Quantize one `f32` value at the given `scale` — the shared per-element step
/// [`quantize`] and the transposing packer `quantize_transpose` both use.
#[must_use]
fn quantize_one(v: f32, scale: f32) -> i8 {
    clamp_i8(round_to_i32(v / scale))
}

/// Quantize `values` into `out` (same length) at the given `scale`.
///
/// # Panics
/// If `values.len() != out.len()` (a caller contract, checked).
pub fn quantize(values: &[f32], scale: f32, out: &mut [i8]) {
    assert_eq!(values.len(), out.len(), "quantize: length mismatch");
    for (dst, &v) in out.iter_mut().zip(values) {
        *dst = quantize_one(v, scale);
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

// ── quantized transformer block — inference workload 2 ──────────────────────────
//
// The MLP above is a single dense layer chained twice. This composes the same
// primitives (quantize/dequantize, the tiered `gemm_i8`) into the canonical
// modern-inference unit: one pre-norm quantized transformer block (multi-head
// self-attention + the existing FFN), adding the two primitives every
// transformer needs — softmax and layernorm — as libm-free, deterministic
// `f32` scalar code (no vector instructions, so `xtask check-no-vector` is
// unaffected). See `docs/specs/2026-07-16-inference-workload2-design.md`.

/// Why a new (`Result`-returning) `kernel::ml` entry refused its input.
///
/// Every variant is a caller-input problem — a bad dimension, a mismatched
/// buffer length, or an overflowing shape product — never an internal
/// computation failure: once these checks pass, the math underneath never
/// panics.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MlError {
    /// A tensor buffer's length did not match the length its dims imply.
    LengthMismatch,
    /// A required dimension (e.g. `seq`/`d_model`/`n_heads`/`d_ff`, or
    /// `softmax_rows`'/`layernorm_rows`' `rows`/`width`/`tokens`/`dim`) was zero.
    ZeroDimension,
    /// `d_model` is not evenly divisible by `n_heads` (ragged attention heads).
    HeadsIndivisible,
    /// A dimension product overflowed `usize` (the `checked_mul` last-line guard).
    ShapeOverflow,
}

/// `checked_mul` every factor together, failing with [`MlError::ShapeOverflow`]
/// on the first overflow — the shape-validation guard every new `Result`-based
/// entry runs before touching a buffer.
fn checked_shape(factors: &[usize]) -> Result<usize, MlError> {
    let mut product: usize = 1;
    for &f in factors {
        product = product.checked_mul(f).ok_or(MlError::ShapeOverflow)?;
    }
    Ok(product)
}

// ── libm-free transcendentals (private) ──────────────────────────────────────

/// Minimum input [`exp_f32`] accepts: below this, `2^k`'s integer range
/// reduction would need an exponent field outside the valid `[1, 254]` range.
/// `softmax_rows` always calls this with `x = xᵢ − maxⱼxⱼ ≤ 0`, so only the
/// lower bound needs guarding (see [`exp_f32`]'s docs for the bound derivation).
const EXP_MIN_ARG: f32 = -87.3;

/// `log2(e)` — `exp_f32`'s base-2/e range-reduction factor: `exp(x) =
/// 2^(x·log2(e))`.
const LOG2E: f32 = core::f32::consts::LOG2_E;

/// Maclaurin-series coefficients of `2^f = e^(f·ln 2)` around `f = 0`, degree 4
/// (`f ∈ [−0.5, 0.5]`): `2^f ≈ 1 + f·(C1 + f·(C2 + f·(C3 + f·C4)))`, i.e. the
/// degree-4 truncation of `Σₙ (f·ln2)ⁿ/n!`. Verified offline against `2^f`
/// computed in `f64`: max relative error over the interval is ~5.6e-5 —
/// comfortably below what softmax needs. Computed from `LN_2` (rather than
/// written as decimal literals) so each is the correctly-rounded `f32` value,
/// not a hand-copied approximation.
const EXP_POLY_C1: f32 = core::f32::consts::LN_2;
const EXP_POLY_C2: f32 = EXP_POLY_C1 * EXP_POLY_C1 / 2.0;
const EXP_POLY_C3: f32 = EXP_POLY_C1 * EXP_POLY_C1 * EXP_POLY_C1 / 6.0;
const EXP_POLY_C4: f32 = EXP_POLY_C1 * EXP_POLY_C1 * EXP_POLY_C1 * EXP_POLY_C1 / 24.0;

/// `exp(x)`, libm-free and deterministic: range-reduce to `exp(x) = 2^k · 2^f`
/// (`k` an integer, `f ∈ [−0.5, 0.5]`) via `t = x·log2(e)`, `k = round(t)`,
/// `f = t − k`; build `2^k` directly as an `f32` bit pattern (exact — no
/// rounding) and `2^f` via a degree-4 minimax-quality polynomial. Every step is
/// a correctly-rounded IEEE-754 primitive (`+ − × ÷`, `from_bits`) — no `fma`,
/// default round-to-nearest — so the result is bit-identical on any conformant
/// host, independent of which GEMM tier is active.
///
/// Only ever called from [`softmax_rows`] with `x ≤ 0` (already past the
/// row-max subtraction); clamping to [`EXP_MIN_ARG`] first guards the underflow
/// boundary, which keeps `k ≥ −126` — the `2^k` bit-construction below always
/// targets a normal, finite exponent field, never subnormal/inf/NaN.
fn exp_f32(x: f32) -> f32 {
    let x = if x < EXP_MIN_ARG { EXP_MIN_ARG } else { x };
    let t = x * LOG2E;
    let k = round_to_i32(t);
    let f = t - k as f32;
    let poly = 1.0 + f * (EXP_POLY_C1 + f * (EXP_POLY_C2 + f * (EXP_POLY_C3 + f * EXP_POLY_C4)));
    // 2^k as an f32 bit pattern: sign=0, biased exponent = k+127, mantissa=0.
    // `x >= EXP_MIN_ARG` (~ -87.3) bounds `k` to [-126, 0], so the biased
    // exponent stays in [1, 127] — always inside the valid normal-float range.
    let biased_exponent = (k + 127) as u32;
    let two_pow_k = f32::from_bits(biased_exponent << 23);
    two_pow_k * poly
}

/// Bit-hack initial-guess magic constant for the classic "fast inverse square
/// root" (Quake III, `0x5f3759df`): reinterpreting the `f32`'s bits as an
/// integer and subtracting half of them from this constant approximates
/// `log2(1/√x)` well enough that two Newton steps converge tightly.
const RSQRT_MAGIC: u32 = 0x5f37_59df;

/// `1/√x`, libm-free and deterministic: the bit-hack initial guess above,
/// refined by **two** Newton–Raphson steps (`y ← y·(1.5 − 0.5·x·y²)`, the
/// update for `f(y) = 1/y² − x`). ~1e-6 relative error; every step is a
/// correctly-rounded IEEE-754 primitive (`to_bits`/`from_bits`, `+ − × ÷`), so
/// the result is bit-identical on any conformant host.
///
/// Only ever called from [`layernorm_rows`] with `x = σ² + eps`, positive by
/// the caller's contract (`eps > 0`), so the bit-hack guess always starts from
/// a positive, finite input. `wrapping_sub` (not `-`) matches the classic
/// hack's integer-wraparound behaviour exactly, so this never panics even on a
/// pathological input.
#[must_use]
fn rsqrt_f32(x: f32) -> f32 {
    let guess_bits = RSQRT_MAGIC.wrapping_sub(x.to_bits() >> 1);
    let mut y = f32::from_bits(guess_bits);
    y *= 1.5 - 0.5 * x * y * y;
    y *= 1.5 - 0.5 * x * y * y;
    y
}

// ── softmax / layernorm (public primitives) ──────────────────────────────────

/// The maximum element of a nonempty row (linear scan; `core` has no
/// `f32::max`, so compare directly — the same style [`quant_scale`] uses for
/// `abs`).
///
/// # Panics
/// If `row` is empty (a caller contract; [`softmax_rows`] validates `width > 0`
/// before ever calling this).
#[must_use]
fn row_max(row: &[f32]) -> f32 {
    let mut max = row[0];
    for &v in &row[1..] {
        if v > max {
            max = v;
        }
    }
    max
}

/// Stable softmax over each contiguous `width`-length row of `rows` rows of
/// `x`, in place: `yᵢ = exp(xᵢ − maxⱼxⱼ) / Σⱼexp(xⱼ − maxⱼ)`. Rows are
/// independent.
///
/// Every row's denominator is at least `1.0` (the row's own maximum element
/// contributes `exp(0) = 1`), so once the zero-width guard below passes, the
/// final division can never see a zero (or negative/NaN) denominator.
///
/// # Errors
/// - [`MlError::ZeroDimension`] if `rows == 0` or `width == 0`.
/// - [`MlError::ShapeOverflow`] if `rows * width` overflows `usize`.
/// - [`MlError::LengthMismatch`] if `x.len() != rows * width`.
pub fn softmax_rows(x: &mut [f32], rows: usize, width: usize) -> Result<(), MlError> {
    if rows == 0 || width == 0 {
        return Err(MlError::ZeroDimension);
    }
    let total = checked_shape(&[rows, width])?;
    if x.len() != total {
        return Err(MlError::LengthMismatch);
    }
    for row in x.chunks_mut(width) {
        let max = row_max(row);
        let mut sum = 0.0f32;
        for v in row.iter_mut() {
            let e = exp_f32(*v - max);
            *v = e;
            sum += e;
        }
        let inv_sum = 1.0 / sum;
        for v in row.iter_mut() {
            *v *= inv_sum;
        }
    }
    Ok(())
}

/// Row-wise (per-token) layernorm: for each contiguous `dim`-length row (token)
/// of `x`, `yᵢ = (xᵢ − μ)·rsqrt(σ² + eps)·γᵢ + βᵢ`, with `μ`/`σ²` that row's own
/// mean and (biased, `/dim`) variance. `gamma`/`beta` are length `dim`,
/// broadcast to every token row.
///
/// # Errors
/// - [`MlError::ZeroDimension`] if `tokens == 0` or `dim == 0`.
/// - [`MlError::ShapeOverflow`] if `tokens * dim` overflows `usize`.
/// - [`MlError::LengthMismatch`] if `x`/`out`'s length isn't `tokens * dim`, or
///   `gamma`/`beta`'s length isn't `dim`.
pub fn layernorm_rows(
    x: &[f32],
    gamma: &[f32],
    beta: &[f32],
    out: &mut [f32],
    tokens: usize,
    dim: usize,
    eps: f32,
) -> Result<(), MlError> {
    if tokens == 0 || dim == 0 {
        return Err(MlError::ZeroDimension);
    }
    let total = checked_shape(&[tokens, dim])?;
    if x.len() != total || out.len() != total || gamma.len() != dim || beta.len() != dim {
        return Err(MlError::LengthMismatch);
    }
    let dim_f = dim as f32;
    for (x_row, out_row) in x.chunks(dim).zip(out.chunks_mut(dim)) {
        let mut sum = 0.0f32;
        for &v in x_row {
            sum += v;
        }
        let mean = sum / dim_f;
        let mut var_sum = 0.0f32;
        for &v in x_row {
            let d = v - mean;
            var_sum += d * d;
        }
        let variance = var_sum / dim_f;
        let inv_std = rsqrt_f32(variance + eps);
        for i in 0..dim {
            out_row[i] = (x_row[i] - mean) * inv_std * gamma[i] + beta[i];
        }
    }
    Ok(())
}

// ── private packers (transpose / per-head split) ─────────────────────────────

/// Quantize `values` (`[rows × cols]`, row-major) into `out`, **transposing**
/// to `[cols × rows]` as it copies — the fused "transpose while quantizing"
/// packer that feeds each projection GEMM (see the design doc's data-flow
/// note). Returns the scale used ([`quant_scale`] over `values`; unaffected by
/// the transpose, since it only reorders elements).
///
/// # Panics
/// If `values.len() != rows * cols` or `out.len() != rows * cols` (a caller
/// contract; [`transformer_block`] validates every scratch length before
/// calling this).
fn quantize_transpose(values: &[f32], rows: usize, cols: usize, out: &mut [i8]) -> f32 {
    assert_eq!(
        values.len(),
        rows * cols,
        "quantize_transpose: values must be rows*cols"
    );
    assert_eq!(
        out.len(),
        rows * cols,
        "quantize_transpose: out must be rows*cols (transposed)"
    );
    let scale = quant_scale(values);
    for r in 0..rows {
        for c in 0..cols {
            out[c * rows + r] = quantize_one(values[r * cols + c], scale);
        }
    }
    scale
}

/// Transpose an `[r × c]` row-major int8 matrix into `out` (`[c × r]`) — the
/// per-head packer [`transformer_block`] uses for `Qhᵀ` and `p_hᵀ` (a square
/// `r == c` transpose in the `p_hᵀ` case).
///
/// # Panics
/// If `input.len() != r * c` or `out.len() != r * c` (a caller contract;
/// `transformer_block` validates every scratch length before calling this).
fn transpose_i8(input: &[i8], r: usize, c: usize, out: &mut [i8]) {
    assert_eq!(input.len(), r * c, "transpose_i8: input must be r*c");
    assert_eq!(
        out.len(),
        r * c,
        "transpose_i8: out must be r*c (transposed)"
    );
    for i in 0..r {
        for j in 0..c {
            out[j * r + i] = input[i * c + j];
        }
    }
}

/// Borrow one attention head's `[d_head × seq]` contiguous block from a
/// `[d_model × seq]` tensor (`Q`, `K`, or `V`): head `h` occupies the row range
/// `[h*d_head, (h+1)*d_head)`, which is exactly the contiguous element range
/// `[h*d_head*seq, (h+1)*d_head*seq)` in row-major storage — no copy needed.
///
/// # Panics
/// If `buf` is too short for this head's slot (a caller contract;
/// `transformer_block` validates every scratch/derived length up front).
fn split_head(buf: &[i8], head: usize, d_head: usize, seq: usize) -> &[i8] {
    let start = head * d_head * seq;
    &buf[start..start + d_head * seq]
}

/// Run an int8 GEMM through the tiered [`gemm_i8`] dispatch, then dequantize the
/// resulting `i32` accumulator to `f32` with a single combined scale (the
/// caller folds e.g. `s_w * s_x` for a bias-free projection, or
/// `s_q * s_k * rsqrt_f32(d_head)` for the attention scores, into one factor).
/// The "matmul then dequantize" step every [`transformer_block`] matmul shares.
///
/// # Panics
/// If any slice length disagrees with `m`/`k`/`n` (a caller contract; via
/// [`gemm_i8_scalar`]'s asserts and this function's own on `acc`/`y`).
#[allow(clippy::too_many_arguments)]
fn gemm_dequant(
    a: &[i8],
    b: &[i8],
    acc: &mut [i32],
    m: usize,
    k: usize,
    n: usize,
    scale: f32,
    y: &mut [f32],
) {
    assert_eq!(acc.len(), m * n, "gemm_dequant: acc must be m*n");
    assert_eq!(y.len(), m * n, "gemm_dequant: y must be m*n");
    gemm_i8(a, b, acc, m, k, n);
    for (dst, &v) in y.iter_mut().zip(acc.iter()) {
        *dst = v as f32 * scale;
    }
}

// ── quantized transformer block ───────────────────────────────────────────────

/// The `eps` [`transformer_block`] passes to both its `layernorm_rows` calls —
/// small enough to leave a near-zero-variance token's normalized output
/// meaningful, large enough to keep `σ² + eps` comfortably positive for
/// [`rsqrt_f32`].
const LN_EPS: f32 = 1.0e-5;

/// Dimensions for one [`transformer_block`] call: `seq` tokens, `d_model`
/// features, `n_heads` attention heads (each `d_model / n_heads` wide), and
/// `d_ff` FFN hidden width. The design's boot-proof/test shape is
/// `seq=16, d_model=32, n_heads=2, d_ff=64`; the function itself is generic
/// over any dimension combination that passes [`validate`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TransformerBlockDims {
    /// Sequence length (number of tokens), `S`.
    pub seq: usize,
    /// Model/embedding width, `D`.
    pub d_model: usize,
    /// Number of attention heads, `H`. Must evenly divide `d_model`.
    pub n_heads: usize,
    /// FFN hidden width, `d_ff`.
    pub d_ff: usize,
}

/// The block's fixed (per-call) weights — every field a caller-owned, f32,
/// row-major tensor. [`transformer_block`] quantizes each one internally (no
/// pre-quantized weight caching across calls). `wq`/`wk`/`wv`/`wo` are
/// bias-free projections; only the FFN dense layers carry a bias, matching the
/// existing [`dense_pre_activation`] contract.
pub struct TransformerBlockWeights<'a> {
    /// Query projection, `[d_model × d_model]`.
    pub wq: &'a [f32],
    /// Key projection, `[d_model × d_model]`.
    pub wk: &'a [f32],
    /// Value projection, `[d_model × d_model]`.
    pub wv: &'a [f32],
    /// Output projection, `[d_model × d_model]`.
    pub wo: &'a [f32],
    /// FFN first dense layer's weight, `[d_ff × d_model]`.
    pub w1: &'a [f32],
    /// FFN first dense layer's bias, `[d_ff]`.
    pub b1: &'a [f32],
    /// FFN second dense layer's weight, `[d_model × d_ff]`.
    pub w2: &'a [f32],
    /// FFN second dense layer's bias, `[d_model]`.
    pub b2: &'a [f32],
    /// Pre-attention layernorm scale, `[d_model]`.
    pub ln1_g: &'a [f32],
    /// Pre-attention layernorm shift, `[d_model]`.
    pub ln1_b: &'a [f32],
    /// Pre-FFN layernorm scale, `[d_model]`.
    pub ln2_g: &'a [f32],
    /// Pre-FFN layernorm shift, `[d_model]`.
    pub ln2_b: &'a [f32],
}

/// Caller-owned scratch buffers for one [`transformer_block`] call, sized from
/// its [`TransformerBlockDims`] (see each field's doc for its required
/// length). Every field must have **exactly** the documented length or
/// `transformer_block` returns [`MlError::LengthMismatch`] before computing
/// anything.
///
/// Allocation-free by design: a caller backs every field with either a
/// fixed-size stack array (the host tests do) or a `static`-backed arena (the
/// boot proof does — see `infer_block_forward_checksum`, used because the
/// block's tens-of-KB working set is far too large for the small boot stack
/// Limine hands `kmain`).
pub struct TransformerBlockScratch<'a> {
    /// Pre-attention layernorm output, `a`, `[seq × d_model]`.
    pub ln1_out: &'a mut [f32],
    /// `a`, transposed + quantized to `[d_model × seq]` — the shared input to
    /// the Q/K/V projections.
    pub attn_in_q: &'a mut [i8],
    /// Quantized `Wq`, `[d_model × d_model]`.
    pub wq_q: &'a mut [i8],
    /// Quantized `Wk`, `[d_model × d_model]`.
    pub wk_q: &'a mut [i8],
    /// Quantized `Wv`, `[d_model × d_model]`.
    pub wv_q: &'a mut [i8],
    /// Quantized `Wo`, `[d_model × d_model]`.
    pub wo_q: &'a mut [i8],
    /// Quantized `W1` (FFN), `[d_ff × d_model]`.
    pub w1_q: &'a mut [i8],
    /// Quantized `W2` (FFN), `[d_model × d_ff]`.
    pub w2_q: &'a mut [i8],
    /// Dequantized Q projection, `[d_model × seq]`.
    pub q: &'a mut [f32],
    /// Dequantized K projection, `[d_model × seq]`.
    pub k: &'a mut [f32],
    /// Dequantized V projection, `[d_model × seq]`.
    pub v: &'a mut [f32],
    /// Requantized Q, `[d_model × seq]`.
    pub q_q: &'a mut [i8],
    /// Requantized K, `[d_model × seq]`.
    pub k_q: &'a mut [i8],
    /// Requantized V, `[d_model × seq]`.
    pub v_q: &'a mut [i8],
    /// Per-head `Qhᵀ` transpose scratch, reused each head, `[d_head × seq]`.
    pub head_q_t: &'a mut [i8],
    /// Per-head dequantized attention scores, then the softmax output (in
    /// place); reused each head, `[seq × seq]`.
    pub scores: &'a mut [f32],
    /// Per-head quantized attention probabilities, reused each head,
    /// `[seq × seq]`.
    pub scores_q: &'a mut [i8],
    /// Per-head `p_hᵀ` transpose scratch, reused each head, `[seq × seq]`.
    pub scores_t_q: &'a mut [i8],
    /// Concatenated per-head context, `[d_model × seq]`.
    pub ctx: &'a mut [f32],
    /// Quantized `ctx`, `[d_model × seq]`.
    pub ctx_q: &'a mut [i8],
    /// Dequantized output-projection result, `[d_model × seq]`.
    pub attn: &'a mut [f32],
    /// Pre-FFN layernorm output, `b`, `[seq × d_model]`.
    pub ln2_out: &'a mut [f32],
    /// `b`, transposed + quantized to `[d_model × seq]` — the FFN input.
    pub ffn_in_q: &'a mut [i8],
    /// FFN hidden activations (post-ReLU, in place), `[d_ff × seq]`.
    pub ffn_hidden: &'a mut [f32],
    /// Requantized FFN hidden activations, `[d_ff × seq]`.
    pub ffn_hidden_q: &'a mut [i8],
    /// FFN second dense layer's dequantized output, `[d_model × seq]`.
    pub ffn_out: &'a mut [f32],
    /// Shared `i32` GEMM accumulator for every `[d_model × seq]`-shaped matmul
    /// (Q/K/V/O projections, FFN dense-2) — reused; not meaningful between
    /// calls.
    pub acc_ds: &'a mut [i32],
    /// Shared accumulator for each head's `[seq × seq]` QKᵀ scores.
    pub acc_ss: &'a mut [i32],
    /// Shared accumulator for each head's `[d_head × seq]` P·V context.
    pub acc_dhs: &'a mut [i32],
    /// Accumulator for the FFN's `[d_ff × seq]` first dense layer.
    pub acc_fs: &'a mut [i32],
}

/// Validate `dims`/`w`/`x`/`s` against every documented invariant — (1) zero
/// dims, (2) ragged heads, (3) overflowing size products, (4) every slice
/// length — in that order, returning the derived `d_head` on success.
/// [`transformer_block`] calls this before touching any buffer, so a bad shape
/// always fails fast with the right [`MlError`] instead of panicking deep in a
/// GEMM or index.
fn validate(
    dims: TransformerBlockDims,
    w: &TransformerBlockWeights<'_>,
    x_len: usize,
    s: &TransformerBlockScratch<'_>,
) -> Result<usize, MlError> {
    let TransformerBlockDims {
        seq,
        d_model,
        n_heads,
        d_ff,
    } = dims;

    // (1) zero dims.
    if seq == 0 || d_model == 0 || n_heads == 0 || d_ff == 0 {
        return Err(MlError::ZeroDimension);
    }
    // (2) ragged heads.
    if d_model % n_heads != 0 {
        return Err(MlError::HeadsIndivisible);
    }
    let d_head = d_model / n_heads;

    // (3) size products, checked_mul-guarded.
    let sd = checked_shape(&[seq, d_model])?;
    let dd = checked_shape(&[d_model, d_model])?;
    let fd = checked_shape(&[d_ff, d_model])?;
    let ss = checked_shape(&[seq, seq])?;
    let dhs = checked_shape(&[d_head, seq])?;
    let fs = checked_shape(&[d_ff, seq])?;

    // (4) every slice length.
    let ok = x_len == sd
        && w.wq.len() == dd
        && w.wk.len() == dd
        && w.wv.len() == dd
        && w.wo.len() == dd
        && w.w1.len() == fd
        && w.b1.len() == d_ff
        && w.w2.len() == fd
        && w.b2.len() == d_model
        && w.ln1_g.len() == d_model
        && w.ln1_b.len() == d_model
        && w.ln2_g.len() == d_model
        && w.ln2_b.len() == d_model
        && s.ln1_out.len() == sd
        && s.attn_in_q.len() == sd
        && s.wq_q.len() == dd
        && s.wk_q.len() == dd
        && s.wv_q.len() == dd
        && s.wo_q.len() == dd
        && s.w1_q.len() == fd
        && s.w2_q.len() == fd
        && s.q.len() == sd
        && s.k.len() == sd
        && s.v.len() == sd
        && s.q_q.len() == sd
        && s.k_q.len() == sd
        && s.v_q.len() == sd
        && s.head_q_t.len() == dhs
        && s.scores.len() == ss
        && s.scores_q.len() == ss
        && s.scores_t_q.len() == ss
        && s.ctx.len() == sd
        && s.ctx_q.len() == sd
        && s.attn.len() == sd
        && s.ln2_out.len() == sd
        && s.ffn_in_q.len() == sd
        && s.ffn_hidden.len() == fs
        && s.ffn_hidden_q.len() == fs
        && s.ffn_out.len() == sd
        && s.acc_ds.len() == sd
        && s.acc_ss.len() == ss
        && s.acc_dhs.len() == dhs
        && s.acc_fs.len() == fs;
    if !ok {
        return Err(MlError::LengthMismatch);
    }

    Ok(d_head)
}

/// One pre-norm transformer block forward pass, computed **in place** on `x`
/// (`[seq × d_model]`, token-major): pre-attention layernorm → multi-head
/// self-attention (per-head int8 `QKᵀ`/`P·V`) → output projection → residual →
/// pre-FFN layernorm → the existing quantized MLP FFN
/// ([`dense_pre_activation`] ×2 + [`relu_inplace`]) → residual. See the design
/// doc's data-flow diagram for the full derivation.
///
/// Every buffer (`w`'s weights, `x`, every `s` scratch field) is caller-owned;
/// this function allocates nothing. All dims/lengths are validated up front
/// (see [`validate`]) before any GEMM or index runs, so a bad shape always
/// returns `Err` rather than panicking mid-computation.
///
/// # Errors
/// See [`MlError`]'s variants; always returned by [`validate`] before any
/// computation starts.
pub fn transformer_block(
    dims: TransformerBlockDims,
    w: &TransformerBlockWeights<'_>,
    x: &mut [f32],
    s: &mut TransformerBlockScratch<'_>,
) -> Result<(), MlError> {
    let d_head = validate(dims, w, x.len(), s)?;
    let TransformerBlockDims {
        seq,
        d_model,
        n_heads,
        ..
    } = dims;

    // ── pre-attention layernorm, then quantize+transpose for the Q/K/V proj ──
    layernorm_rows(x, w.ln1_g, w.ln1_b, s.ln1_out, seq, d_model, LN_EPS)?;
    let s_a = quantize_transpose(s.ln1_out, seq, d_model, s.attn_in_q);

    // ── Q/K/V projections (bias-free): Y[D×S] = dequant(W[D×D]·aᵀ[D×S]) ──────
    let s_wq = quantize_tensor(w.wq, s.wq_q);
    let s_wk = quantize_tensor(w.wk, s.wk_q);
    let s_wv = quantize_tensor(w.wv, s.wv_q);
    gemm_dequant(
        s.wq_q,
        s.attn_in_q,
        s.acc_ds,
        d_model,
        d_model,
        seq,
        s_wq * s_a,
        s.q,
    );
    gemm_dequant(
        s.wk_q,
        s.attn_in_q,
        s.acc_ds,
        d_model,
        d_model,
        seq,
        s_wk * s_a,
        s.k,
    );
    gemm_dequant(
        s.wv_q,
        s.attn_in_q,
        s.acc_ds,
        d_model,
        d_model,
        seq,
        s_wv * s_a,
        s.v,
    );
    let s_q = quantize_tensor(s.q, s.q_q);
    let s_k = quantize_tensor(s.k, s.k_q);
    let s_v = quantize_tensor(s.v, s.v_q);

    // ── per-head scaled-dot-product attention ────────────────────────────────
    let inv_sqrt_dh = rsqrt_f32(d_head as f32);
    for h in 0..n_heads {
        let qh = split_head(s.q_q, h, d_head, seq);
        let kh = split_head(s.k_q, h, d_head, seq);
        let vh = split_head(s.v_q, h, d_head, seq);

        // Qhᵀ: transpose this head's [d_head×seq] block to [seq×d_head] (GEMM A).
        transpose_i8(qh, d_head, seq, s.head_q_t);
        // s_h = dequant(Qhᵀ·Kh) * (s_q·s_k·rsqrt(d_head)) — the scaled scores.
        gemm_dequant(
            s.head_q_t,
            kh,
            s.acc_ss,
            seq,
            d_head,
            seq,
            s_q * s_k * inv_sqrt_dh,
            s.scores,
        );
        softmax_rows(s.scores, seq, seq)?;
        let s_p_h = quantize_tensor(s.scores, s.scores_q);
        // p_hᵀ: transpose the quantized probabilities for the context GEMM.
        transpose_i8(s.scores_q, seq, seq, s.scores_t_q);
        // c_h = dequant(Vh·p_hᵀ) * (s_v·s_p_h), written straight into this
        // head's slot in `ctx` — the "concat heads" step needs no separate
        // buffer/copy because each head's [d_head×seq] block is already the
        // contiguous sub-range `split_head` reads (see its docs).
        let base = h * d_head * seq;
        let dhs = d_head * seq;
        gemm_dequant(
            vh,
            s.scores_t_q,
            s.acc_dhs,
            d_head,
            seq,
            seq,
            s_v * s_p_h,
            &mut s.ctx[base..base + dhs],
        );
    }

    // ── output projection + residual 1 ───────────────────────────────────────
    let s_ctx = quantize_tensor(s.ctx, s.ctx_q);
    let s_wo = quantize_tensor(w.wo, s.wo_q);
    gemm_dequant(
        s.wo_q,
        s.ctx_q,
        s.acc_ds,
        d_model,
        d_model,
        seq,
        s_wo * s_ctx,
        s.attn,
    );
    // x1 = x0 + attnᵀ, in place: `attn` is [d_model×seq] (feature-major) while
    // `x` is [seq×d_model] (token-major), so the residual add transposes as it
    // accumulates.
    for tok in 0..seq {
        for d in 0..d_model {
            x[tok * d_model + d] += s.attn[d * seq + tok];
        }
    }

    // ── pre-FFN layernorm + FFN (existing dense_pre_activation ×2) ───────────
    layernorm_rows(x, w.ln2_g, w.ln2_b, s.ln2_out, seq, d_model, LN_EPS)?;
    let s_b = quantize_transpose(s.ln2_out, seq, d_model, s.ffn_in_q);
    let s_w1 = quantize_tensor(w.w1, s.w1_q);
    dense_pre_activation(
        s.w1_q,
        s_w1,
        s.ffn_in_q,
        s_b,
        w.b1,
        dims.d_ff,
        d_model,
        seq,
        s.acc_fs,
        s.ffn_hidden,
    );
    relu_inplace(s.ffn_hidden);
    let s_h = quantize_tensor(s.ffn_hidden, s.ffn_hidden_q);
    let s_w2 = quantize_tensor(w.w2, s.w2_q);
    dense_pre_activation(
        s.w2_q,
        s_w2,
        s.ffn_hidden_q,
        s_h,
        w.b2,
        d_model,
        dims.d_ff,
        seq,
        s.acc_ds,
        s.ffn_out,
    );

    // ── residual 2 ────────────────────────────────────────────────────────────
    for tok in 0..seq {
        for d in 0..d_model {
            x[tok * d_model + d] += s.ffn_out[d * seq + tok];
        }
    }

    Ok(())
}

// ── transformer-block boot proof (fixed d_model=32, n_heads=2, seq=16, d_ff=64) ──

/// Sequence length for the fixed boot-proof/checksum-stability-test block.
const TFB_SEQ: usize = 16;
/// Model width for the fixed boot-proof/checksum-stability-test block.
const TFB_D: usize = 32;
/// Head count for the fixed boot-proof/checksum-stability-test block.
const TFB_H: usize = 2;
/// FFN hidden width for the fixed boot-proof/checksum-stability-test block.
const TFB_FF: usize = 64;
/// Per-head width (`TFB_D / TFB_H`) for the fixed instantiation.
const TFB_DH: usize = TFB_D / TFB_H;
/// `TFB_SEQ * TFB_D` — every `[seq×d_model]`/`[d_model×seq]` buffer's length.
const TFB_SD: usize = TFB_SEQ * TFB_D;
/// `TFB_D * TFB_D` — each of `wq`/`wk`/`wv`/`wo`'s length.
const TFB_DD: usize = TFB_D * TFB_D;
/// `TFB_FF * TFB_D` — `w1`'s and `w2`'s length.
const TFB_FD: usize = TFB_FF * TFB_D;
/// `TFB_SEQ * TFB_SEQ` — each head's score/probability matrix length.
const TFB_SS: usize = TFB_SEQ * TFB_SEQ;
/// `TFB_DH * TFB_SEQ` — each head's Q/K/V/context block length.
const TFB_DHS: usize = TFB_DH * TFB_SEQ;
/// `TFB_FF * TFB_SEQ` — the FFN hidden activation length.
const TFB_FS: usize = TFB_FF * TFB_SEQ;

/// All buffers the fixed boot-proof/checksum-stability-test block needs
/// (weights + activations + scratch), held in one `static`-backed arena
/// ([`TFB_ARENA`]) rather than as call-stack locals: the combined working set
/// is tens of KB, and [`infer_block_prove`] runs on the small stack Limine
/// hands `kmain` (no explicit `stack_size_request` is made, so the bootloader's
/// default applies) — nowhere near enough to hold this many buffers as locals.
/// Zero-initialized (`TfbArena::new`), so it lives in `.bss` (no image-size
/// cost); guarded by [`hal::sync::SpinMutex`] (an existing safe `hal` API), so
/// this stays `#![forbid(unsafe_code)]` with no new TCB. A second concurrent
/// caller (e.g. two host `#[test]`s racing) just spins briefly — never a data
/// race, since only one [`hal::sync::SpinGuard`] can exist at a time.
struct TfbArena {
    x: [f32; TFB_SD],
    wq: [f32; TFB_DD],
    wk: [f32; TFB_DD],
    wv: [f32; TFB_DD],
    wo: [f32; TFB_DD],
    w1: [f32; TFB_FD],
    b1: [f32; TFB_FF],
    w2: [f32; TFB_FD],
    b2: [f32; TFB_D],
    ln1_g: [f32; TFB_D],
    ln1_b: [f32; TFB_D],
    ln2_g: [f32; TFB_D],
    ln2_b: [f32; TFB_D],

    ln1_out: [f32; TFB_SD],
    attn_in_q: [i8; TFB_SD],
    wq_q: [i8; TFB_DD],
    wk_q: [i8; TFB_DD],
    wv_q: [i8; TFB_DD],
    wo_q: [i8; TFB_DD],
    w1_q: [i8; TFB_FD],
    w2_q: [i8; TFB_FD],
    q: [f32; TFB_SD],
    k: [f32; TFB_SD],
    v: [f32; TFB_SD],
    q_q: [i8; TFB_SD],
    k_q: [i8; TFB_SD],
    v_q: [i8; TFB_SD],
    head_q_t: [i8; TFB_DHS],
    scores: [f32; TFB_SS],
    scores_q: [i8; TFB_SS],
    scores_t_q: [i8; TFB_SS],
    ctx: [f32; TFB_SD],
    ctx_q: [i8; TFB_SD],
    attn: [f32; TFB_SD],
    ln2_out: [f32; TFB_SD],
    ffn_in_q: [i8; TFB_SD],
    ffn_hidden: [f32; TFB_FS],
    ffn_hidden_q: [i8; TFB_FS],
    ffn_out: [f32; TFB_SD],
    acc_ds: [i32; TFB_SD],
    acc_ss: [i32; TFB_SS],
    acc_dhs: [i32; TFB_DHS],
    acc_fs: [i32; TFB_FS],
}

impl TfbArena {
    /// All-zero arena — every buffer is fully (re-)written by
    /// `infer_block_forward_checksum` before it is read, so the initial
    /// content never matters.
    const fn new() -> Self {
        Self {
            x: [0.0; TFB_SD],
            wq: [0.0; TFB_DD],
            wk: [0.0; TFB_DD],
            wv: [0.0; TFB_DD],
            wo: [0.0; TFB_DD],
            w1: [0.0; TFB_FD],
            b1: [0.0; TFB_FF],
            w2: [0.0; TFB_FD],
            b2: [0.0; TFB_D],
            ln1_g: [0.0; TFB_D],
            ln1_b: [0.0; TFB_D],
            ln2_g: [0.0; TFB_D],
            ln2_b: [0.0; TFB_D],

            ln1_out: [0.0; TFB_SD],
            attn_in_q: [0; TFB_SD],
            wq_q: [0; TFB_DD],
            wk_q: [0; TFB_DD],
            wv_q: [0; TFB_DD],
            wo_q: [0; TFB_DD],
            w1_q: [0; TFB_FD],
            w2_q: [0; TFB_FD],
            q: [0.0; TFB_SD],
            k: [0.0; TFB_SD],
            v: [0.0; TFB_SD],
            q_q: [0; TFB_SD],
            k_q: [0; TFB_SD],
            v_q: [0; TFB_SD],
            head_q_t: [0; TFB_DHS],
            scores: [0.0; TFB_SS],
            scores_q: [0; TFB_SS],
            scores_t_q: [0; TFB_SS],
            ctx: [0.0; TFB_SD],
            ctx_q: [0; TFB_SD],
            attn: [0.0; TFB_SD],
            ln2_out: [0.0; TFB_SD],
            ffn_in_q: [0; TFB_SD],
            ffn_hidden: [0.0; TFB_FS],
            ffn_hidden_q: [0; TFB_FS],
            ffn_out: [0.0; TFB_SD],
            acc_ds: [0; TFB_SD],
            acc_ss: [0; TFB_SS],
            acc_dhs: [0; TFB_DHS],
            acc_fs: [0; TFB_FS],
        }
    }
}

/// The fixed boot-proof/checksum-stability-test arena — see [`TfbArena`]'s docs
/// for why this is `static` rather than call-stack locals.
static TFB_ARENA: hal::sync::SpinMutex<TfbArena> = hal::sync::SpinMutex::new(TfbArena::new());

/// Checksum of the transformer-block boot proof's requantized output — a
/// stable, tier-independent regression anchor: the int8 GEMMs are bit-exact
/// across every tier and every intervening `f32` step (layernorm, softmax,
/// dequant, residual) is a deterministic, correctly-rounded scalar computation,
/// so this integer is fixed. Guarded against drift by the host test
/// `tfb_boot_proof_checksum_is_stable`.
const INFER_BLOCK_CHECKSUM: i64 = 4_332;

/// The fixed `d_model=32, n_heads=2, seq=16, d_ff=64` transformer-block forward
/// pass shared by [`infer_block_prove`] and its host test: fills the
/// [`TFB_ARENA`] with deterministic weights/input (reusing [`infer_fill`]),
/// runs [`transformer_block`], then requantizes the `[seq×d_model]` output and
/// returns `Σ (x2q[i] as i64)` over all `512` elements — the design's
/// determinism anchor (exact because it is taken *after* requantize;
/// tier-independent because the block's output is bit-identical across tiers).
fn infer_block_forward_checksum() -> Result<i64, MlError> {
    let mut arena = TFB_ARENA.lock();
    let a = &mut *arena;

    for (t, v) in a.x.iter_mut().enumerate() {
        *v = infer_fill(t);
    }
    for (t, v) in a.wq.iter_mut().enumerate() {
        *v = infer_fill(t * 3 + 1);
    }
    for (t, v) in a.wk.iter_mut().enumerate() {
        *v = infer_fill(t * 5 + 2);
    }
    for (t, v) in a.wv.iter_mut().enumerate() {
        *v = infer_fill(t * 7 + 3);
    }
    for (t, v) in a.wo.iter_mut().enumerate() {
        *v = infer_fill(t * 9 + 4);
    }
    for (t, v) in a.w1.iter_mut().enumerate() {
        *v = infer_fill(t * 11 + 5);
    }
    for (t, v) in a.w2.iter_mut().enumerate() {
        *v = infer_fill(t * 13 + 6);
    }
    // FFN biases stay zero, matching the MLP boot proof's convention.
    for (t, v) in a.ln1_g.iter_mut().enumerate() {
        *v = infer_fill(t * 15 + 7);
    }
    for (t, v) in a.ln1_b.iter_mut().enumerate() {
        *v = infer_fill(t * 17 + 8);
    }
    for (t, v) in a.ln2_g.iter_mut().enumerate() {
        *v = infer_fill(t * 19 + 9);
    }
    for (t, v) in a.ln2_b.iter_mut().enumerate() {
        *v = infer_fill(t * 21 + 10);
    }

    let dims = TransformerBlockDims {
        seq: TFB_SEQ,
        d_model: TFB_D,
        n_heads: TFB_H,
        d_ff: TFB_FF,
    };
    let weights = TransformerBlockWeights {
        wq: &a.wq,
        wk: &a.wk,
        wv: &a.wv,
        wo: &a.wo,
        w1: &a.w1,
        b1: &a.b1,
        w2: &a.w2,
        b2: &a.b2,
        ln1_g: &a.ln1_g,
        ln1_b: &a.ln1_b,
        ln2_g: &a.ln2_g,
        ln2_b: &a.ln2_b,
    };
    let mut scratch = TransformerBlockScratch {
        ln1_out: &mut a.ln1_out,
        attn_in_q: &mut a.attn_in_q,
        wq_q: &mut a.wq_q,
        wk_q: &mut a.wk_q,
        wv_q: &mut a.wv_q,
        wo_q: &mut a.wo_q,
        w1_q: &mut a.w1_q,
        w2_q: &mut a.w2_q,
        q: &mut a.q,
        k: &mut a.k,
        v: &mut a.v,
        q_q: &mut a.q_q,
        k_q: &mut a.k_q,
        v_q: &mut a.v_q,
        head_q_t: &mut a.head_q_t,
        scores: &mut a.scores,
        scores_q: &mut a.scores_q,
        scores_t_q: &mut a.scores_t_q,
        ctx: &mut a.ctx,
        ctx_q: &mut a.ctx_q,
        attn: &mut a.attn,
        ln2_out: &mut a.ln2_out,
        ffn_in_q: &mut a.ffn_in_q,
        ffn_hidden: &mut a.ffn_hidden,
        ffn_hidden_q: &mut a.ffn_hidden_q,
        ffn_out: &mut a.ffn_out,
        acc_ds: &mut a.acc_ds,
        acc_ss: &mut a.acc_ss,
        acc_dhs: &mut a.acc_dhs,
        acc_fs: &mut a.acc_fs,
    };

    transformer_block(dims, &weights, &mut a.x, &mut scratch)?;

    // Requantize the block's output (now sitting in `a.x`) and checksum it.
    let scale = quant_scale(&a.x);
    let mut xq = [0i8; TFB_SD];
    quantize(&a.x, scale, &mut xq);
    Ok(xq.iter().map(|&v| v as i64).sum())
}

/// Run a real **quantized transformer block** (`d_model=32, n_heads=2, seq=16,
/// d_ff=64` — the design's second inference workload) through the live
/// inference path and log the result, proving one full pre-norm block
/// (layernorm → multi-head attention → residual → layernorm → FFN → residual)
/// end-to-end in the booted kernel. Self-validates by checksumming the
/// requantized output (exact + tier-independent) against
/// [`INFER_BLOCK_CHECKSUM`]. Prints via the fmt-free serial helpers (integer
/// `println!` faults on this target — see `memory.rs`).
pub fn infer_block_prove() {
    let active = active_tier();
    let (checksum, ok) = match infer_block_forward_checksum() {
        Ok(c) => (c, c == INFER_BLOCK_CHECKSUM),
        Err(_) => (0, false),
    };

    hal::serial::write_str("[ml] tfb: d32-h2-s16 int8 block via ");
    hal::serial::write_str(active.label());
    hal::serial::write_str(if ok { " ok" } else { " FAIL" });
    hal::serial::write_str("; tfb checksum=");
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

    // ── quantized transformer block (workload 2) ────────────────────────────

    // The transposing packers are the classic index-swap bug site (per the
    // design doc), so these are the first new tests: hand-checked, non-square,
    // written before anything downstream depends on them.

    #[test]
    fn transpose_i8_hand_checked() {
        // 2×3 -> 3×2: [[1,2,3],[4,5,6]] transposes to [[1,4],[2,5],[3,6]].
        let input = [1i8, 2, 3, 4, 5, 6];
        let mut out = [0i8; 6];
        transpose_i8(&input, 2, 3, &mut out);
        assert_eq!(out, [1, 4, 2, 5, 3, 6]);
    }

    #[test]
    fn transpose_i8_square_is_self_inverse() {
        // Transposing a square matrix twice must recover the original.
        let input = [1i8, 2, 3, 4, 5, 6, 7, 8, 9];
        let mut once = [0i8; 9];
        transpose_i8(&input, 3, 3, &mut once);
        let mut twice = [0i8; 9];
        transpose_i8(&once, 3, 3, &mut twice);
        assert_eq!(twice, input);
    }

    #[test]
    fn quantize_transpose_hand_checked() {
        // values [rows=2 x cols=3] = [[1,2,3],[4,5,6]] (max|x|=6 -> scale=6/127).
        // Transposed+quantized out is [cols=3 x rows=2] = [[1,4],[2,5],[3,6]]
        // (in quantized units): out[c*rows+r] must equal quantize(values[r*cols+c]).
        let values = [1.0f32, 2.0, 3.0, 4.0, 5.0, 6.0];
        let mut out = [0i8; 6];
        let scale = quantize_transpose(&values, 2, 3, &mut out);
        let expected_scale = 6.0 / 127.0;
        assert!((scale - expected_scale).abs() < 1e-9);
        let mut direct = [0i8; 6];
        quantize(&values, scale, &mut direct);
        // direct[r*cols+c] should equal out[c*rows+r] for every (r,c).
        for r in 0..2 {
            for c in 0..3 {
                assert_eq!(direct[r * 3 + c], out[c * 2 + r]);
            }
        }
    }

    #[test]
    fn split_head_reads_contiguous_block() {
        // [d_model=4 x seq=2], 2 heads of d_head=2: head 0 = rows [0,2), head 1 =
        // rows [2,4) — each a contiguous 2*2=4-element run in row-major storage.
        let buf = [1i8, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(split_head(&buf, 0, 2, 2), &[1, 2, 3, 4]);
        assert_eq!(split_head(&buf, 1, 2, 2), &[5, 6, 7, 8]);
    }

    #[test]
    fn softmax_rows_two_equal_elements_is_uniform() {
        let mut x = [0.0f32, 0.0];
        softmax_rows(&mut x, 1, 2).unwrap();
        assert!((x[0] - 0.5).abs() < 1e-6);
        assert!((x[1] - 0.5).abs() < 1e-6);
    }

    #[test]
    fn softmax_rows_each_row_sums_to_one() {
        let mut x = [1.0f32, 2.0, 3.0, -1.0, 0.5, 4.0];
        softmax_rows(&mut x, 2, 3).unwrap();
        for row in x.chunks(3) {
            let sum: f32 = row.iter().sum();
            assert!((sum - 1.0).abs() < 1e-5, "row sum {sum} != 1");
        }
        // Every probability is in [0, 1].
        for &p in &x {
            assert!((0.0..=1.0).contains(&p));
        }
    }

    #[test]
    fn softmax_rows_large_inputs_stay_stable() {
        // Large-magnitude inputs must not overflow/NaN once max-subtracted.
        let mut x = [1000.0f32, 1000.0, -1000.0, 999.0];
        softmax_rows(&mut x, 1, 4).unwrap();
        let sum: f32 = x.iter().sum();
        assert!((sum - 1.0).abs() < 1e-4, "sum={sum}");
        for &v in &x {
            assert!(v.is_finite(), "non-finite softmax output: {v}");
        }
        // The two equal maximum-magnitude entries (1000.0) should dominate,
        // roughly evenly; the far-smaller entries should be near zero.
        assert!(x[0] > 0.4 && x[1] > 0.4);
        assert!(x[2] < 1e-6);
    }

    #[test]
    fn softmax_rows_rejects_bad_shapes() {
        let mut x = [0.0f32, 1.0];
        assert_eq!(softmax_rows(&mut x, 0, 2), Err(MlError::ZeroDimension));
        assert_eq!(softmax_rows(&mut x, 1, 0), Err(MlError::ZeroDimension));
        assert_eq!(softmax_rows(&mut x, 1, 3), Err(MlError::LengthMismatch));
        assert_eq!(
            softmax_rows(&mut x, usize::MAX, 2),
            Err(MlError::ShapeOverflow)
        );
    }

    #[test]
    fn layernorm_rows_normalizes_mean_and_variance() {
        let x = [1.0f32, 2.0, 3.0, 4.0];
        let gamma = [1.0f32, 1.0, 1.0, 1.0];
        let beta = [0.0f32, 0.0, 0.0, 0.0];
        let mut out = [0.0f32; 4];
        layernorm_rows(&x, &gamma, &beta, &mut out, 1, 4, 1.0e-5).unwrap();

        let mean: f32 = out.iter().sum::<f32>() / 4.0;
        let var: f32 = out.iter().map(|&v| (v - mean) * (v - mean)).sum::<f32>() / 4.0;
        assert!(mean.abs() < 1e-3, "mean={mean}");
        assert!((var - 1.0).abs() < 1e-2, "var={var}");
    }

    #[test]
    fn layernorm_rows_rejects_bad_shapes() {
        let x = [1.0f32, 2.0];
        let gamma = [1.0f32, 1.0];
        let beta = [0.0f32, 0.0];
        let mut out = [0.0f32; 2];
        assert_eq!(
            layernorm_rows(&x, &gamma, &beta, &mut out, 0, 2, 1e-5),
            Err(MlError::ZeroDimension)
        );
        assert_eq!(
            layernorm_rows(&x, &gamma, &beta, &mut out, 1, 0, 1e-5),
            Err(MlError::ZeroDimension)
        );
        let short_gamma = [1.0f32];
        assert_eq!(
            layernorm_rows(&x, &short_gamma, &beta, &mut out, 1, 2, 1e-5),
            Err(MlError::LengthMismatch)
        );
        assert_eq!(
            layernorm_rows(&x, &gamma, &beta, &mut out, usize::MAX, usize::MAX, 1e-5),
            Err(MlError::ShapeOverflow)
        );
    }

    #[test]
    fn exp_f32_matches_a_coarse_table() {
        // Known exp(x) values (computed offline); exp_f32 targets ~5.6e-5
        // relative error, so a 1e-3 relative tolerance is comfortably loose.
        let table: [(f32, f32); 5] = [
            (0.0, 1.0),
            (-1.0, 0.367_879_44),
            (-2.0, 0.135_335_28),
            (-5.0, 0.006_737_947),
            (-10.0, 0.000_045_399_9),
        ];
        for (x, expected) in table {
            let got = exp_f32(x);
            let rel_err = (got - expected).abs() / expected;
            assert!(
                rel_err < 1e-3,
                "exp_f32({x}) = {got}, expected {expected} (rel_err={rel_err})"
            );
        }
    }

    #[test]
    fn exp_f32_is_monotonically_increasing() {
        let xs = [-87.3, -20.0, -10.0, -5.0, -2.0, -1.0, -0.5, -0.1, 0.0];
        let mut prev = exp_f32(xs[0]);
        for &x in &xs[1..] {
            let cur = exp_f32(x);
            assert!(
                cur > prev,
                "exp_f32 not increasing at x={x}: {cur} <= {prev}"
            );
            prev = cur;
        }
    }

    #[test]
    fn exp_f32_clamps_below_the_minimum_argument() {
        // Anything below EXP_MIN_ARG must behave exactly like EXP_MIN_ARG
        // itself (the clamp), never underflow to 0 or misbehave.
        assert_eq!(exp_f32(-1000.0), exp_f32(EXP_MIN_ARG));
        assert!(exp_f32(-1000.0) > 0.0);
    }

    #[test]
    fn rsqrt_f32_matches_known_values() {
        let table: [(f32, f32); 4] = [(1.0, 1.0), (4.0, 0.5), (0.25, 2.0), (100.0, 0.1)];
        for (x, expected) in table {
            let got = rsqrt_f32(x);
            let rel_err = (got - expected).abs() / expected;
            assert!(
                rel_err < 1e-4,
                "rsqrt_f32({x}) = {got}, expected {expected} (rel_err={rel_err})"
            );
        }
    }

    /// Build the fixed tiny (`seq=4, d_model=4, n_heads=2, d_ff=4`) weight set
    /// [`transformer_block_matches_f32_reference`] uses, from [`infer_fill`]
    /// (the same deterministic generator the MLP proof uses). Returns a plain
    /// tuple (single call site, host-test-only) rather than a named struct.
    #[allow(clippy::too_many_lines, clippy::type_complexity)]
    fn tiny_block_fixture() -> (
        [f32; 16], // x0            [S*D] = 4*4
        [f32; 16], // wq            [D*D]
        [f32; 16], // wk
        [f32; 16], // wv
        [f32; 16], // wo
        [f32; 16], // w1            [FF*D] = 4*4
        [f32; 4],  // b1            [FF]
        [f32; 16], // w2            [D*FF]
        [f32; 4],  // b2            [D]
        [f32; 4],  // ln1_g
        [f32; 4],  // ln1_b
        [f32; 4],  // ln2_g
        [f32; 4],  // ln2_b
    ) {
        let mut x0 = [0f32; 16];
        for (t, v) in x0.iter_mut().enumerate() {
            *v = infer_fill(t + 1);
        }
        let mut wq = [0f32; 16];
        for (t, v) in wq.iter_mut().enumerate() {
            *v = infer_fill(t * 3 + 2);
        }
        let mut wk = [0f32; 16];
        for (t, v) in wk.iter_mut().enumerate() {
            *v = infer_fill(t * 5 + 3);
        }
        let mut wv = [0f32; 16];
        for (t, v) in wv.iter_mut().enumerate() {
            *v = infer_fill(t * 7 + 4);
        }
        let mut wo = [0f32; 16];
        for (t, v) in wo.iter_mut().enumerate() {
            *v = infer_fill(t * 9 + 5);
        }
        let mut w1 = [0f32; 16];
        for (t, v) in w1.iter_mut().enumerate() {
            *v = infer_fill(t * 11 + 6);
        }
        let b1 = [0f32; 4];
        let mut w2 = [0f32; 16];
        for (t, v) in w2.iter_mut().enumerate() {
            *v = infer_fill(t * 13 + 7);
        }
        let b2 = [0f32; 4];
        let mut ln1_g = [0f32; 4];
        for (t, v) in ln1_g.iter_mut().enumerate() {
            *v = infer_fill(t * 15 + 8);
        }
        let mut ln1_b = [0f32; 4];
        for (t, v) in ln1_b.iter_mut().enumerate() {
            *v = infer_fill(t * 17 + 9);
        }
        let mut ln2_g = [0f32; 4];
        for (t, v) in ln2_g.iter_mut().enumerate() {
            *v = infer_fill(t * 19 + 10);
        }
        let mut ln2_b = [0f32; 4];
        for (t, v) in ln2_b.iter_mut().enumerate() {
            *v = infer_fill(t * 21 + 11);
        }
        (
            x0, wq, wk, wv, wo, w1, b1, w2, b2, ln1_g, ln1_b, ln2_g, ln2_b,
        )
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn transformer_block_matches_f32_reference() {
        const S: usize = 4;
        const D: usize = 4;
        const H: usize = 2;
        const DH: usize = D / H;
        const FF: usize = 4;
        // 1/sqrt(d_head) for d_head=2, hard-coded independently of `rsqrt_f32`
        // (the block itself computes this via `rsqrt_f32`, so reusing it here
        // would make the test unable to catch a scale bug in that primitive).
        const INV_SQRT_DH_REF: f32 = 0.707_106_77;

        let (x0, wq, wk, wv, wo, w1, b1, w2, b2, ln1_g, ln1_b, ln2_g, ln2_b) = tiny_block_fixture();

        // ── pure f32 reference forward (independent of the quantized path) ──
        let mut a = [0f32; S * D];
        layernorm_rows(&x0, &ln1_g, &ln1_b, &mut a, S, D, LN_EPS).unwrap();

        // Token-major projection: out[s*D+d] = sum_k w[d*D+k] * input[s*D+k].
        let proj = |w: &[f32; D * D], input: &[f32; S * D]| -> [f32; S * D] {
            let mut out = [0f32; S * D];
            for s in 0..S {
                for d in 0..D {
                    let mut acc = 0f32;
                    for k in 0..D {
                        acc += w[d * D + k] * input[s * D + k];
                    }
                    out[s * D + d] = acc;
                }
            }
            out
        };
        let q_ref = proj(&wq, &a);
        let k_ref = proj(&wk, &a);
        let v_ref = proj(&wv, &a);

        let mut ctx = [0f32; S * D];
        for h in 0..H {
            let mut scores = [0f32; S * S];
            for si in 0..S {
                for sj in 0..S {
                    let mut acc = 0f32;
                    for dh in 0..DH {
                        acc += q_ref[si * D + h * DH + dh] * k_ref[sj * D + h * DH + dh];
                    }
                    scores[si * S + sj] = acc * INV_SQRT_DH_REF;
                }
            }
            softmax_rows(&mut scores, S, S).unwrap();
            for si in 0..S {
                for dh in 0..DH {
                    let mut acc = 0f32;
                    for sj in 0..S {
                        acc += scores[si * S + sj] * v_ref[sj * D + h * DH + dh];
                    }
                    ctx[si * D + h * DH + dh] = acc;
                }
            }
        }

        let attn_ref = proj(&wo, &ctx);
        let mut x1_ref = [0f32; S * D];
        for i in 0..S * D {
            x1_ref[i] = x0[i] + attn_ref[i];
        }

        let mut b = [0f32; S * D];
        layernorm_rows(&x1_ref, &ln2_g, &ln2_b, &mut b, S, D, LN_EPS).unwrap();

        let mut hidden = [0f32; S * FF];
        for s in 0..S {
            for f in 0..FF {
                let mut acc = b1[f];
                for k in 0..D {
                    acc += w1[f * D + k] * b[s * D + k];
                }
                hidden[s * FF + f] = if acc < 0.0 { 0.0 } else { acc };
            }
        }
        let mut ffn_ref = [0f32; S * D];
        for s in 0..S {
            for d in 0..D {
                let mut acc = b2[d];
                for f in 0..FF {
                    acc += w2[d * FF + f] * hidden[s * FF + f];
                }
                ffn_ref[s * D + d] = acc;
            }
        }
        let mut x2_ref = [0f32; S * D];
        for i in 0..S * D {
            x2_ref[i] = x1_ref[i] + ffn_ref[i];
        }

        // ── quantized transformer_block, through the real pipeline ──────────
        let dims = TransformerBlockDims {
            seq: S,
            d_model: D,
            n_heads: H,
            d_ff: FF,
        };
        let weights = TransformerBlockWeights {
            wq: &wq,
            wk: &wk,
            wv: &wv,
            wo: &wo,
            w1: &w1,
            b1: &b1,
            w2: &w2,
            b2: &b2,
            ln1_g: &ln1_g,
            ln1_b: &ln1_b,
            ln2_g: &ln2_g,
            ln2_b: &ln2_b,
        };

        let mut ln1_out = [0f32; S * D];
        let mut attn_in_q = [0i8; D * S];
        let mut wq_q = [0i8; D * D];
        let mut wk_q = [0i8; D * D];
        let mut wv_q = [0i8; D * D];
        let mut wo_q = [0i8; D * D];
        let mut w1_q = [0i8; FF * D];
        let mut w2_q = [0i8; D * FF];
        let mut q = [0f32; D * S];
        let mut k = [0f32; D * S];
        let mut v = [0f32; D * S];
        let mut q_q = [0i8; D * S];
        let mut k_q = [0i8; D * S];
        let mut v_q = [0i8; D * S];
        let mut head_q_t = [0i8; DH * S];
        let mut sc = [0f32; S * S];
        let mut sc_q = [0i8; S * S];
        let mut sc_t_q = [0i8; S * S];
        let mut ctx_buf = [0f32; D * S];
        let mut ctx_q = [0i8; D * S];
        let mut attn_buf = [0f32; D * S];
        let mut ln2_out = [0f32; S * D];
        let mut ffn_in_q = [0i8; D * S];
        let mut ffn_hidden = [0f32; FF * S];
        let mut ffn_hidden_q = [0i8; FF * S];
        let mut ffn_out = [0f32; D * S];
        let mut acc_ds = [0i32; D * S];
        let mut acc_ss = [0i32; S * S];
        let mut acc_dhs = [0i32; DH * S];
        let mut acc_fs = [0i32; FF * S];

        let mut scratch = TransformerBlockScratch {
            ln1_out: &mut ln1_out,
            attn_in_q: &mut attn_in_q,
            wq_q: &mut wq_q,
            wk_q: &mut wk_q,
            wv_q: &mut wv_q,
            wo_q: &mut wo_q,
            w1_q: &mut w1_q,
            w2_q: &mut w2_q,
            q: &mut q,
            k: &mut k,
            v: &mut v,
            q_q: &mut q_q,
            k_q: &mut k_q,
            v_q: &mut v_q,
            head_q_t: &mut head_q_t,
            scores: &mut sc,
            scores_q: &mut sc_q,
            scores_t_q: &mut sc_t_q,
            ctx: &mut ctx_buf,
            ctx_q: &mut ctx_q,
            attn: &mut attn_buf,
            ln2_out: &mut ln2_out,
            ffn_in_q: &mut ffn_in_q,
            ffn_hidden: &mut ffn_hidden,
            ffn_hidden_q: &mut ffn_hidden_q,
            ffn_out: &mut ffn_out,
            acc_ds: &mut acc_ds,
            acc_ss: &mut acc_ss,
            acc_dhs: &mut acc_dhs,
            acc_fs: &mut acc_fs,
        };

        let mut x = x0;
        transformer_block(dims, &weights, &mut x, &mut scratch).unwrap();

        let mut range = 0.0f32;
        for &r in &x2_ref {
            let a = if r < 0.0 { -r } else { r };
            if a > range {
                range = a;
            }
        }
        let mut max_err = 0.0f32;
        for (&xq, &xr) in x.iter().zip(&x2_ref) {
            let e = xq - xr;
            let e = if e < 0.0 { -e } else { e };
            if e > max_err {
                max_err = e;
            }
        }
        assert!(
            range > 0.05,
            "reference block output is degenerate (range={range})"
        );
        assert!(
            max_err < 0.1 * range,
            "quantized transformer block diverged from f32 reference: \
             max_err={max_err}, range={range}"
        );
    }

    #[test]
    fn transformer_block_rejects_zero_dims() {
        let dims = TransformerBlockDims {
            seq: 0,
            d_model: 2,
            n_heads: 1,
            d_ff: 2,
        };
        let w = empty_weights();
        let mut x: [f32; 0] = [];
        let mut s = empty_scratch();
        assert_eq!(
            transformer_block(dims, &w, &mut x, &mut s),
            Err(MlError::ZeroDimension)
        );
    }

    #[test]
    fn transformer_block_rejects_ragged_heads() {
        // d_model=5 is not divisible by n_heads=2.
        let dims = TransformerBlockDims {
            seq: 1,
            d_model: 5,
            n_heads: 2,
            d_ff: 1,
        };
        let w = empty_weights();
        let mut x: [f32; 0] = [];
        let mut s = empty_scratch();
        assert_eq!(
            transformer_block(dims, &w, &mut x, &mut s),
            Err(MlError::HeadsIndivisible)
        );
    }

    #[test]
    fn transformer_block_rejects_overflowing_shapes() {
        // seq * d_model overflows usize (d_model = usize::MAX), before any
        // buffer is ever touched.
        let dims = TransformerBlockDims {
            seq: 2,
            d_model: usize::MAX,
            n_heads: 1,
            d_ff: 1,
        };
        let w = empty_weights();
        let mut x: [f32; 0] = [];
        let mut s = empty_scratch();
        assert_eq!(
            transformer_block(dims, &w, &mut x, &mut s),
            Err(MlError::ShapeOverflow)
        );
    }

    #[test]
    fn transformer_block_rejects_length_mismatch() {
        // Valid, non-overflowing, evenly-headed dims (seq=2, d_model=2,
        // n_heads=1, d_ff=2, d_head=2) with correctly-sized scratch, but `x`
        // one element short of `seq*d_model`.
        const S: usize = 2;
        const D: usize = 2;
        const FF: usize = 2;
        let dims = TransformerBlockDims {
            seq: S,
            d_model: D,
            n_heads: 1,
            d_ff: FF,
        };
        let wq = [0f32; D * D];
        let w1 = [0f32; FF * D];
        let b1 = [0f32; FF];
        let w2 = [0f32; D * FF];
        let b2 = [0f32; D];
        let ln = [0f32; D];
        let w = TransformerBlockWeights {
            wq: &wq,
            wk: &wq,
            wv: &wq,
            wo: &wq,
            w1: &w1,
            b1: &b1,
            w2: &w2,
            b2: &b2,
            ln1_g: &ln,
            ln1_b: &ln,
            ln2_g: &ln,
            ln2_b: &ln,
        };
        let mut x = [0f32; S * D - 1]; // deliberately too short

        let mut ln1_out = [0f32; S * D];
        let mut attn_in_q = [0i8; D * S];
        let mut wq_q = [0i8; D * D];
        let mut wk_q = [0i8; D * D];
        let mut wv_q = [0i8; D * D];
        let mut wo_q = [0i8; D * D];
        let mut w1_q = [0i8; FF * D];
        let mut w2_q = [0i8; D * FF];
        let mut q = [0f32; D * S];
        let mut k = [0f32; D * S];
        let mut v = [0f32; D * S];
        let mut q_q = [0i8; D * S];
        let mut k_q = [0i8; D * S];
        let mut v_q = [0i8; D * S];
        let mut head_q_t = [0i8; D * S];
        let mut sc = [0f32; S * S];
        let mut sc_q = [0i8; S * S];
        let mut sc_t_q = [0i8; S * S];
        let mut ctx_buf = [0f32; D * S];
        let mut ctx_q = [0i8; D * S];
        let mut attn_buf = [0f32; D * S];
        let mut ln2_out = [0f32; S * D];
        let mut ffn_in_q = [0i8; D * S];
        let mut ffn_hidden = [0f32; FF * S];
        let mut ffn_hidden_q = [0i8; FF * S];
        let mut ffn_out = [0f32; D * S];
        let mut acc_ds = [0i32; D * S];
        let mut acc_ss = [0i32; S * S];
        let mut acc_dhs = [0i32; D * S];
        let mut acc_fs = [0i32; FF * S];
        let mut s = TransformerBlockScratch {
            ln1_out: &mut ln1_out,
            attn_in_q: &mut attn_in_q,
            wq_q: &mut wq_q,
            wk_q: &mut wk_q,
            wv_q: &mut wv_q,
            wo_q: &mut wo_q,
            w1_q: &mut w1_q,
            w2_q: &mut w2_q,
            q: &mut q,
            k: &mut k,
            v: &mut v,
            q_q: &mut q_q,
            k_q: &mut k_q,
            v_q: &mut v_q,
            head_q_t: &mut head_q_t,
            scores: &mut sc,
            scores_q: &mut sc_q,
            scores_t_q: &mut sc_t_q,
            ctx: &mut ctx_buf,
            ctx_q: &mut ctx_q,
            attn: &mut attn_buf,
            ln2_out: &mut ln2_out,
            ffn_in_q: &mut ffn_in_q,
            ffn_hidden: &mut ffn_hidden,
            ffn_hidden_q: &mut ffn_hidden_q,
            ffn_out: &mut ffn_out,
            acc_ds: &mut acc_ds,
            acc_ss: &mut acc_ss,
            acc_dhs: &mut acc_dhs,
            acc_fs: &mut acc_fs,
        };

        assert_eq!(
            transformer_block(dims, &w, &mut x, &mut s),
            Err(MlError::LengthMismatch)
        );
    }

    /// All-empty weights, valid for exactly the error paths that return before
    /// any buffer is examined (zero dims / ragged heads / shape overflow).
    fn empty_weights() -> TransformerBlockWeights<'static> {
        TransformerBlockWeights {
            wq: &[],
            wk: &[],
            wv: &[],
            wo: &[],
            w1: &[],
            b1: &[],
            w2: &[],
            b2: &[],
            ln1_g: &[],
            ln1_b: &[],
            ln2_g: &[],
            ln2_b: &[],
        }
    }

    /// All-empty scratch, valid for the same early-return error paths as
    /// [`empty_weights`].
    fn empty_scratch() -> TransformerBlockScratch<'static> {
        TransformerBlockScratch {
            ln1_out: &mut [],
            attn_in_q: &mut [],
            wq_q: &mut [],
            wk_q: &mut [],
            wv_q: &mut [],
            wo_q: &mut [],
            w1_q: &mut [],
            w2_q: &mut [],
            q: &mut [],
            k: &mut [],
            v: &mut [],
            q_q: &mut [],
            k_q: &mut [],
            v_q: &mut [],
            head_q_t: &mut [],
            scores: &mut [],
            scores_q: &mut [],
            scores_t_q: &mut [],
            ctx: &mut [],
            ctx_q: &mut [],
            attn: &mut [],
            ln2_out: &mut [],
            ffn_in_q: &mut [],
            ffn_hidden: &mut [],
            ffn_hidden_q: &mut [],
            ffn_out: &mut [],
            acc_ds: &mut [],
            acc_ss: &mut [],
            acc_dhs: &mut [],
            acc_fs: &mut [],
        }
    }

    #[test]
    fn tfb_boot_proof_checksum_is_stable() {
        // Guards INFER_BLOCK_CHECKSUM against drift. The pipeline is
        // deterministic and tier-independent (int8 GEMMs are bit-exact across
        // tiers; every intervening f32 step is a correctly-rounded scalar
        // computation), so this holds on whatever tier the host runs.
        assert_eq!(infer_block_forward_checksum(), Ok(INFER_BLOCK_CHECKSUM));
    }
}

/// Kani proof — the pure tier-selection logic is total (never panics) over all
/// flag combinations. Compiled only under `cargo kani`; excluded from the stable
/// build and `cargo test`. Run with `cargo kani -p kernel`.
#[cfg(kani)]
mod proofs {
    use super::{capability_from_flags, checked_shape, MlError, Tier};

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

    /// Kani proof — `checked_shape`'s two-factor case (the shape validator every
    /// new `Result`-based `ml` entry runs, e.g. `seq*d_model`) is total (never
    /// panics) and agrees with `checked_mul` for every possible `usize` pair:
    /// `Ok(product)` exactly when the multiplication does not overflow, else
    /// `Err(ShapeOverflow)`. Matches the `capability_from_flags` precedent above.
    #[kani::proof]
    fn checked_shape_matches_checked_mul() {
        let a: usize = kani::any();
        let b: usize = kani::any();
        let result = checked_shape(&[a, b]);
        match a.checked_mul(b) {
            Some(product) => assert!(result == Ok(product)),
            None => assert!(result == Err(MlError::ShapeOverflow)),
        }
    }
}
