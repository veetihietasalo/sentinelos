//! SIMD acceleration — AVX vector-state enablement + an AVX2 int8 GEMM kernel.
//!
//! This is the first vector code in the TCB. It has two responsibilities:
//!
//! 1. [`enable`] — turn on AVX (`YMM`) state so `avx`/`avx2` instructions do not
//!    `#UD`: set `CR4.OSXSAVE`, then OR the x87|SSE|AVX component bits into `XCR0`
//!    via `xsetbv`. Gated on `cpuid` (`xsave` + `avx`), idempotent, called once at
//!    boot. Mirrors [`crate::cpu_security::enable`] in shape and safety argument.
//! 2. [`gemm_i8_avx2`] — a **safe** wrapper over an `#[target_feature(enable =
//!    "avx2")]` int8·int8 → i32 matrix multiply. It self-checks (cpuid `avx2` +
//!    `CR4.OSXSAVE` + `XCR0.AVX`) and only runs the vector kernel when the CPU and
//!    OS state both allow it, returning `false` otherwise so the caller falls back
//!    to its scalar reference. So it can never `#UD`, and the `kernel` crate stays
//!    `#![forbid(unsafe_code)]`.
//!
//! **Correctness contract.** The AVX2 kernel is **bit-identical** to a scalar
//! `wrapping_add` accumulation: for each output cell it sums the products over the
//! K dimension in ascending order, exactly as the scalar reference does. Integer
//! addition is associative, so the SIMD-over-columns reordering cannot change any
//! result. This is asserted by the host differential test below (AVX2 vs. a scalar
//! reference over many shapes, including non-multiples-of-8 and negatives).
//!
//! **Interrupt/vector-state note.** The kernel is not compiled with a global AVX
//! target-feature, so only [`gemm_i8_avx2`]'s inner kernel touches `YMM`; no
//! interrupt handler uses vector registers, so `YMM` is preserved across any
//! interrupt that lands mid-kernel. At boot the GEMM runs with interrupts disabled
//! anyway. Proper `XSAVE`-based vector-state save/restore only becomes necessary
//! with preemptive scheduling (a future concern; see the design doc).

use crate::cpu;
use crate::cpuid;
use core::sync::atomic::{AtomicU8, Ordering};

/// `CR4.OSXSAVE` (bit 18): enables `xgetbv`/`xsetbv` and OS management of XSAVE
/// state components (a prerequisite for using AVX `YMM` registers).
const CR4_OSXSAVE: u64 = 1 << 18;

/// `XCR0` bit 0 — x87 FPU state (architecturally always enabled; must stay set).
const XCR0_X87: u64 = 1 << 0;
/// `XCR0` bit 1 — SSE (`XMM`) state.
const XCR0_SSE: u64 = 1 << 1;
/// `XCR0` bit 2 — AVX (`YMM` high halves) state — what `avx`/`avx2` needs.
const XCR0_AVX: u64 = 1 << 2;

/// `cpuid` leaf 1 ECX bit 26 — `XSAVE`/`XRSTOR` + the `XCR` registers.
const CPUID_ECX_XSAVE: u32 = 1 << 26;
/// `cpuid` leaf 1 ECX bit 28 — AVX (256-bit vector) instructions.
const CPUID_ECX_AVX: u32 = 1 << 28;
/// `cpuid` leaf 7 sub-leaf 0 EBX bit 5 — AVX2 integer instructions.
const CPUID_EBX7_AVX2: u32 = 1 << 5;

/// Cached AVX2 usability: `0` = unverified / unavailable, `1` = verified usable.
/// Set to `1` by [`enable`] **only** after the boot-time self-test passes; read by
/// [`avx2_ready`]. A single-writer-at-boot atomic (also correct once SMP lands).
static AVX2_STATUS: AtomicU8 = AtomicU8::new(0);

/// Enable AVX (`YMM`) vector state on this core and, if `avx2` is advertised,
/// **self-test** the AVX2 kernel before trusting it. Returns `true` if AVX state
/// was enabled (`false` on a CPU without `xsave`+`avx`).
///
/// The self-test ([`self_test`]) runs the AVX2 int8 GEMM on fixed input and
/// compares it against a scalar computation; [`avx2_ready`] reports the tier usable
/// **only** if they match bit-for-bit. This makes the ML path robust to a broken
/// vector unit — e.g. QEMU **TCG mis-emulates `VPMULLD`**, so under TCG the
/// self-test fails and the kernel transparently uses the scalar reference instead
/// of computing garbage; on real hardware / KVM the self-test passes and the AVX2
/// kernel is used. Detection-gated on `xsave` + `avx`. Idempotent.
#[must_use]
pub fn enable() -> bool {
    let ecx1 = cpuid::raw(1, 0).ecx;
    if ecx1 & CPUID_ECX_XSAVE == 0 || ecx1 & CPUID_ECX_AVX == 0 {
        return false;
    }
    // SAFETY: `xsave` + `avx` are confirmed present via cpuid above. Setting
    // `CR4.OSXSAVE` only enables `xgetbv`/`xsetbv` and OS XSAVE management (it
    // preserves every other CR4 bit — read-modify-write). After it, `xgetbv(0)` is
    // legal; we OR the x87|SSE|AVX component bits (all architectural on any
    // avx-capable CPU, so `xsetbv` cannot `#GP`; AVX requires SSE, both set) into
    // XCR0. Enabling vector state only makes `YMM` usable/saveable — it cannot
    // alias or corrupt Rust-managed memory. Registered in hal-tcb.md.
    unsafe {
        let cr4 = cpu::read_cr4();
        cpu::write_cr4(cr4 | CR4_OSXSAVE);
        let xcr0 = cpu::xgetbv(0);
        cpu::xsetbv(0, xcr0 | XCR0_X87 | XCR0_SSE | XCR0_AVX);
    }
    // AVX state is on. Enable the AVX2 tier only if the CPU advertises avx2 AND the
    // kernel passes its differential self-test on this (possibly emulated) core.
    if avx2_advertised() && self_test() {
        AVX2_STATUS.store(1, Ordering::Relaxed);
    }
    true
}

/// Whether `cpuid` advertises AVX2 integer instructions (leaf 7 EBX bit 5).
fn avx2_advertised() -> bool {
    cpuid::max_standard_leaf() >= 7 && cpuid::raw(7, 0).ebx & CPUID_EBX7_AVX2 != 0
}

/// Whether the AVX2 int8 GEMM is **verified usable** on this core — AVX state
/// enabled *and* the boot-time [`self_test`] passed. Cheap (one relaxed atomic
/// load); this is the sole gate [`gemm_i8_avx2`] consults, so it never re-touches
/// privileged `CR4`/`XCR0` state (making the wrapper callable from any context).
#[must_use]
pub fn avx2_ready() -> bool {
    AVX2_STATUS.load(Ordering::Relaxed) == 1
}

/// Boot-time differential self-test of the AVX2 kernel: run a fixed small GEMM
/// (`n >= 8` so the 256-bit vector path executes, with mixed signs and a zero) via
/// both the AVX2 kernel and an inline scalar loop, and return whether they agree
/// bit-for-bit. Called by [`enable`] only after AVX state is on and `avx2` is
/// advertised, so the intrinsics are legal to execute.
fn self_test() -> bool {
    const M: usize = 2;
    const K: usize = 8;
    const N: usize = 8;
    #[rustfmt::skip]
    let a: [i8; M * K] = [
        1, -2, 3, -4, 5, -6, 7, 0,
        -8, 9, -10, 11, -12, 13, -14, 15,
    ];
    #[rustfmt::skip]
    let b: [i8; K * N] = [
         0,  1, -1,  2, -2,  3, -3,  4,
         5, -5,  6, -6,  7, -7,  8, -8,
         9, 10, -9,-10, 11, 12,-11,-12,
        13,-13, 14,-14, 15,-15, 16,-16,
       -17, 17,-18, 18,-19, 19,-20, 20,
        21, 22, 23,-21,-22,-23, 24,-24,
        25,-25, 26,-26, 27,-27, 28,-28,
        29, 30,-29,-30, 31,-31, 32,-32,
    ];
    let mut c_ref = [0i32; M * N];
    for i in 0..M {
        for j in 0..N {
            let mut acc: i32 = 0;
            for p in 0..K {
                acc = acc.wrapping_add(a[i * K + p] as i32 * b[p * N + j] as i32);
            }
            c_ref[i * N + j] = acc;
        }
    }
    let mut c_avx = [0i32; M * N];
    // SAFETY: reached only from `enable` after AVX state is enabled and with `avx2`
    // advertised (checked by the caller), so the avx2 intrinsics are legal to run;
    // the fixed dimensions are internally consistent (`M*K`, `K*N`, `M*N`).
    unsafe {
        gemm_i8_avx2_impl(&a, &b, &mut c_avx, M, K, N);
    }
    c_avx == c_ref
}

/// AVX2 int8 GEMM: `C[m×n] = A[m×k] · B[k×n]`, int8·int8 with i32 accumulation,
/// **bit-identical** to a scalar `wrapping_add` reference.
///
/// Returns `true` if the vector kernel ran, or `false` — without touching `c` past
/// what it computed — when AVX2 is unavailable ([`avx2_ready`] is false) or the
/// slice lengths are inconsistent, so the caller can fall back to scalar. Never
/// `#UD`s and never panics.
#[must_use]
pub fn gemm_i8_avx2(a: &[i8], b: &[i8], c: &mut [i32], m: usize, k: usize, n: usize) -> bool {
    if a.len() != m * k || b.len() != k * n || c.len() != m * n {
        return false;
    }
    if !avx2_ready() {
        return false;
    }
    // SAFETY: `avx2_ready()` is `true` only after `enable` both turned on AVX
    // (`YMM`) state AND the self-test executed the AVX2 kernel correctly on this
    // core, so the avx2 intrinsics are legal (no `#UD`) and known-good here. The
    // lengths were validated above, so every in-kernel load/store stays within
    // `a`/`b`/`c`; `a`/`b` are shared and `c` exclusive (distinct GEMM buffers).
    unsafe {
        gemm_i8_avx2_impl(a, b, c, m, k, n);
    }
    true
}

/// The AVX2 kernel. Broadcasts each `A[i][p]` and multiply-accumulates a whole row
/// of `B` into a row of `C`, eight int32 columns per vector step, scalar tail for
/// the remaining `< 8` columns.
///
/// # Safety
///
/// The caller must guarantee the CPU supports `avx2` and the OS has enabled AVX
/// state (both ensured by [`gemm_i8_avx2`] via [`avx2_ready`]), and that the slice
/// lengths match `m`/`k`/`n` (so the internal bounded pointer accesses are valid).
#[target_feature(enable = "avx2")]
unsafe fn gemm_i8_avx2_impl(a: &[i8], b: &[i8], c: &mut [i32], m: usize, k: usize, n: usize) {
    use core::arch::x86_64::{
        __m128i, __m256i, _mm256_add_epi32, _mm256_cvtepi8_epi32, _mm256_loadu_si256,
        _mm256_mullo_epi32, _mm256_set1_epi32, _mm256_storeu_si256, _mm_loadl_epi64,
    };
    for i in 0..m {
        let crow = &mut c[i * n..i * n + n];
        for v in crow.iter_mut() {
            *v = 0;
        }
        for p in 0..k {
            let a_ip = a[i * k + p] as i32;
            let brow = &b[p * n..p * n + n];
            // SAFETY: `avx2` is enabled (fn precondition). Every pointer access
            // below is bounded by `j + 8 <= n` (vector path) or `j < n` (scalar
            // tail), so it stays inside the `n`-element `brow`/`crow` sub-slices;
            // all vector loads/stores are the unaligned variants.
            unsafe {
                let a_vec = _mm256_set1_epi32(a_ip);
                let mut j = 0usize;
                while j + 8 <= n {
                    // 8 int8 from B, sign-extended to 8 × i32.
                    let b8 = _mm_loadl_epi64(brow.as_ptr().add(j) as *const __m128i);
                    let b32 = _mm256_cvtepi8_epi32(b8);
                    let prod = _mm256_mullo_epi32(a_vec, b32);
                    let cptr = crow.as_mut_ptr().add(j) as *mut __m256i;
                    let cur = _mm256_loadu_si256(cptr as *const __m256i);
                    _mm256_storeu_si256(cptr, _mm256_add_epi32(cur, prod));
                    j += 8;
                }
                while j < n {
                    crow[j] = crow[j].wrapping_add(a_ip * brow[j] as i32);
                    j += 1;
                }
            }
        }
    }
}

// ── unit tests (host) ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    extern crate std;
    use super::gemm_i8_avx2_impl;
    use std::vec;
    use std::vec::Vec;

    /// Scalar reference with the exact `wrapping_add` semantics the AVX2 kernel
    /// must reproduce bit-for-bit.
    fn scalar_ref(a: &[i8], b: &[i8], c: &mut [i32], m: usize, k: usize, n: usize) {
        for i in 0..m {
            for j in 0..n {
                let mut acc: i32 = 0;
                for p in 0..k {
                    acc = acc.wrapping_add(a[i * k + p] as i32 * b[p * n + j] as i32);
                }
                c[i * n + j] = acc;
            }
        }
    }

    /// Deterministic int8 fill in `[-127, 127]` (no external rng dependency).
    fn fill(t: usize) -> i8 {
        // Hash `t`, take it mod 255 (0..=254), then map to [-127, 127].
        let v = (t.wrapping_mul(2_654_435_761) >> 5) % 255;
        (v as i64 - 127) as i8
    }

    #[test]
    fn avx2_matches_scalar_bit_for_bit() {
        if !std::is_x86_feature_detected!("avx2") {
            std::eprintln!("host lacks AVX2 — skipping the AVX2 differential test");
            return;
        }
        // Shapes chosen to cover: 1×1, non-square, exact multiples of 8, and
        // several with n NOT a multiple of 8 (exercising the scalar tail), plus
        // k=1 and large-ish k.
        let shapes = [
            (1usize, 1usize, 1usize),
            (2, 3, 4),
            (5, 5, 5),
            (8, 8, 8),
            (7, 9, 13),
            (3, 16, 10),
            (1, 32, 17),
            (4, 1, 8),
            (6, 7, 8),
            (2, 2, 23),
        ];
        for (idx, &(m, k, n)) in shapes.iter().enumerate() {
            let a: Vec<i8> = (0..m * k).map(|t| fill(t + idx * 7)).collect();
            let b: Vec<i8> = (0..k * n).map(|t| fill(t * 3 + idx * 5 + 1)).collect();
            let mut c_scalar = vec![0i32; m * n];
            let mut c_avx2 = vec![0i32; m * n];
            scalar_ref(&a, &b, &mut c_scalar, m, k, n);
            // SAFETY: host AVX2 confirmed above; dims are internally consistent.
            unsafe { gemm_i8_avx2_impl(&a, &b, &mut c_avx2, m, k, n) };
            assert_eq!(c_scalar, c_avx2, "AVX2 != scalar for shape {:?}", (m, k, n));
        }
    }

    #[test]
    fn avx2_extremes_do_not_diverge() {
        if !std::is_x86_feature_detected!("avx2") {
            return;
        }
        // All -127 and all 127 over a wide K — large magnitudes, both signs.
        let (m, k, n) = (3usize, 40usize, 11usize);
        for &val in &[-127i8, 127i8, -1, 1] {
            let a = vec![val; m * k];
            let b = vec![val; k * n];
            let mut c_scalar = vec![0i32; m * n];
            let mut c_avx2 = vec![0i32; m * n];
            scalar_ref(&a, &b, &mut c_scalar, m, k, n);
            // SAFETY: host AVX2 confirmed; dims consistent.
            unsafe { gemm_i8_avx2_impl(&a, &b, &mut c_avx2, m, k, n) };
            assert_eq!(c_scalar, c_avx2, "mismatch for uniform value {val}");
        }
    }
}
