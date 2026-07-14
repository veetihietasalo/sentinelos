//! SIMD acceleration — AVX/AVX-512 vector-state enablement + tiered int8 GEMM.
//!
//! This is the first vector code in the TCB. It has two responsibilities:
//!
//! 1. [`enable`] — turn on vector state so `avx`/`avx2`/`avx512*` instructions do
//!    not `#UD`: set `CR4.OSXSAVE`, then OR the x87|SSE|AVX component bits into
//!    `XCR0` via `xsetbv` (plus the three AVX-512 component bits where `avx512f` is
//!    advertised). Gated on `cpuid` (`xsave` + `avx`), idempotent, called once at
//!    boot. Mirrors [`crate::cpu_security::enable`] in shape and safety argument.
//! 2. Three **safe** wrappers over an int8·int8 → i32 matrix multiply, best-to-worst
//!    throughput: [`gemm_i8_avx512vnni`] (512-bit fused `VPDPBUSD`),
//!    [`gemm_i8_avx512`] (512-bit `VPMULLD` broadcast), and [`gemm_i8_avx2`]
//!    (256-bit). Each inner step is hand-written inline `asm!` (VEX/EVEX) and only
//!    runs once the boot-time self-test has verified it usable
//!    ([`avx512vnni_ready`]/[`avx512_ready`]/[`avx2_ready`]), returning `false`
//!    otherwise so the caller falls back to a narrower tier / its scalar reference.
//!    So none can ever `#UD`, and the `kernel` crate stays `#![forbid(unsafe_code)]`.
//!
//! **Why `asm!`, not `core::arch` intrinsics.** The target `x86_64-unknown-none`
//! has SSE/AVX disabled in its baseline (soft-float). On it, the SIMD *intrinsics*
//! do **not** codegen to VEX/EVEX instructions — a debug build emits them as calls
//! that never lower to `vpmulld`, and passing `__m256i`/`__m512i` across that call
//! on the soft-float ABI corrupts the vector values (the kernel then computes wrong
//! results on real hardware, which the self-test caught during bring-up). Inline
//! `asm!` emits the exact instructions unconditionally, and the vectors live
//! entirely inside each `asm!` block (only `i32`/pointers cross the call boundary),
//! so there is no vector-ABI dependency. See [`avx2_madd8`].
//!
//! **Correctness contract.** Every tier is **bit-identical** to a scalar
//! `wrapping_add` accumulation over the K dimension: integer `wrapping_add` is
//! associative + mod-2³², so the SIMD-over-columns reordering cannot change any
//! result. The VNNI tier additionally uses an unsigned/signed **bias correction**
//! (`Σ (a+128)·b − 128·Σ b = Σ a·b`, a ring identity mod 2³²) to drive the
//! unsigned×signed `VPDPBUSD`; see [`gemm_i8_avx512vnni`]. All are asserted by the
//! host differential test below (each vector kernel vs. scalar over many shapes —
//! non-multiples of the step width, negatives, ±127 extremes, `k` not ÷ 4, and a
//! large-`k` accumulator-wrap case) and re-checked at every boot by [`enable`].
//!
//! **Interrupt precondition (hard).** The interrupt stubs ([`crate::idt`]) save
//! only the general-purpose registers, **not** `XMM`/`YMM`/`ZMM`. So the GEMM
//! wrappers must run with interrupts **disabled** until `XSAVE`-based save/restore
//! lands: an IRQ landing mid-kernel whose handler the compiler emitted any vector
//! use into (a `memcpy`/struct copy suffices) would clobber the in-flight
//! accumulators → silently wrong output. Both current callers run in the
//! interrupts-off boot window; see [`gemm_i8_avx2`].
//!
//! **SMP note.** Vector state (`CR4.OSXSAVE` + `XCR0`) is **per-core**; [`enable`]
//! must run on each AP before any GEMM on that AP once SMP lands (the `*_ready`
//! flags are global, so an AP must not run a kernel on the BSP's flag before
//! enabling its own vector state).

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
/// `XCR0` bit 5 — AVX-512 opmask (`k0`–`k7`) state.
const XCR0_OPMASK: u64 = 1 << 5;
/// `XCR0` bit 6 — AVX-512 `ZMM_Hi256` (upper 256 bits of `ZMM0`–`ZMM15`).
const XCR0_ZMM_HI256: u64 = 1 << 6;
/// `XCR0` bit 7 — AVX-512 `Hi16_ZMM` (`ZMM16`–`ZMM31`).
const XCR0_HI16_ZMM: u64 = 1 << 7;
/// The three AVX-512 component bits, enabled together (all or nothing).
const XCR0_AVX512: u64 = XCR0_OPMASK | XCR0_ZMM_HI256 | XCR0_HI16_ZMM;

/// `cpuid` leaf 1 ECX bit 26 — `XSAVE`/`XRSTOR` + the `XCR` registers.
const CPUID_ECX_XSAVE: u32 = 1 << 26;
/// `cpuid` leaf 1 ECX bit 28 — AVX (256-bit vector) instructions.
const CPUID_ECX_AVX: u32 = 1 << 28;
/// `cpuid` leaf 7 sub-leaf 0 EBX bit 5 — AVX2 integer instructions.
const CPUID_EBX7_AVX2: u32 = 1 << 5;
/// `cpuid` leaf 7 sub-leaf 0 EBX bit 16 — AVX-512 Foundation (the 512-bit `ZMM`
/// integer ops `VPMOVSXBD`/`VPMULLD`/`VPADDD`/`VPBROADCASTD` this tier uses).
const CPUID_EBX7_AVX512F: u32 = 1 << 16;
/// `cpuid` leaf 7 sub-leaf 0 ECX bit 11 — AVX-512 VNNI (`VPDPBUSD`, the fused
/// unsigned×signed 4×int8 dot-product-accumulate the throughput tier uses).
const CPUID_ECX7_AVX512VNNI: u32 = 1 << 11;

/// Cached AVX2 usability: `0` = unverified / unavailable, `1` = verified usable.
/// Set to `1` by [`enable`] **only** after the boot-time self-test passes; read by
/// [`avx2_ready`]. A single-writer-at-boot atomic. **SMP:** this is global but AVX
/// state is per-core, so once SMP lands each AP must call [`enable`] before running
/// the kernel — it must not act on the BSP-set flag with its own AVX state off.
static AVX2_STATUS: AtomicU8 = AtomicU8::new(0);

/// Cached AVX-512F usability, same contract as [`AVX2_STATUS`] but for the 512-bit
/// `ZMM` kernel: set by [`enable`] only after the AVX-512 self-test passes.
static AVX512_STATUS: AtomicU8 = AtomicU8::new(0);

/// Cached AVX-512 VNNI usability, same contract as [`AVX2_STATUS`] but for the
/// `VPDPBUSD` kernel: set by [`enable`] only after the VNNI self-test passes. VNNI
/// reuses the AVX-512 `ZMM` vector state (`XCR0`) already enabled for `avx512f`, so
/// no extra privileged setup is needed — only a `cpuid` gate + the self-test.
static AVX512VNNI_STATUS: AtomicU8 = AtomicU8::new(0);

/// Enable AVX (`YMM`, and — where present — AVX-512 `ZMM`) vector state on this
/// core and **self-test** each vector kernel before trusting it. Returns `true` if
/// AVX state was enabled (`false` on a CPU without `xsave`+`avx`).
///
/// The self-test ([`self_test`]) runs a vector int8 GEMM on fixed input and
/// compares it against a scalar computation; [`avx2_ready`] / [`avx512_ready`]
/// report a tier usable **only** if they match bit-for-bit. This makes the ML path
/// robust to a vector unit that computes incorrectly — during bring-up it caught a
/// soft-float-target codegen problem (see the module docs) before the inline-`asm!`
/// fix, falling back rather than shipping garbage; it also backstops any future
/// CPU/emulator/toolchain regression. Detection-gated (`xsave`+`avx` for AVX,
/// plus `avx512f` for the 512-bit tier). Idempotent (per core — see [`AVX2_STATUS`]).
#[must_use]
pub fn enable() -> bool {
    let ecx1 = cpuid::raw(1, 0).ecx;
    if ecx1 & CPUID_ECX_XSAVE == 0 || ecx1 & CPUID_ECX_AVX == 0 {
        return false;
    }
    let want_avx512 = avx512f_advertised();
    // SAFETY: `xsave` + `avx` are confirmed present via cpuid above. Setting
    // `CR4.OSXSAVE` only enables `xgetbv`/`xsetbv` and OS XSAVE management (it
    // preserves every other CR4 bit — read-modify-write). After it, `xgetbv(0)` is
    // legal; we OR the x87|SSE|AVX component bits (all architectural on any
    // avx-capable CPU, so `xsetbv` cannot `#GP`; AVX requires SSE, both set), and —
    // only when `avx512f` is advertised — the three AVX-512 component bits (opmask +
    // ZMM_Hi256 + Hi16_ZMM, all supported iff avx512f, enabled together) into XCR0.
    // Enabling vector state only makes the registers usable/saveable — it cannot
    // alias or corrupt Rust-managed memory. Registered in hal-tcb.md.
    unsafe {
        let cr4 = cpu::read_cr4();
        cpu::write_cr4(cr4 | CR4_OSXSAVE);
        let xcr0 = cpu::xgetbv(0);
        let mut new = xcr0 | XCR0_X87 | XCR0_SSE | XCR0_AVX;
        if want_avx512 {
            new |= XCR0_AVX512;
        }
        cpu::xsetbv(0, new);
    }
    // Vector state is on. Enable each tier only if the CPU advertises it AND the
    // kernel passes its differential self-test on this (possibly emulated) core.
    if avx2_advertised() && self_test(gemm_i8_avx2_impl) {
        AVX2_STATUS.store(1, Ordering::Relaxed);
    }
    if want_avx512 && self_test(gemm_i8_avx512_impl) {
        AVX512_STATUS.store(1, Ordering::Relaxed);
    }
    // VNNI (`VPDPBUSD`) runs on the same `ZMM` state as `avx512f`, so it needs no
    // extra `XCR0` setup — only that state is on (`want_avx512`) and the op is
    // advertised. `avx512_vnni` implies `avx512f`, so `want_avx512` is already true
    // here; the explicit conjunction documents the ZMM-state dependency.
    if want_avx512 && avx512vnni_advertised() && self_test(gemm_i8_avx512vnni_impl) {
        AVX512VNNI_STATUS.store(1, Ordering::Relaxed);
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

/// Whether `cpuid` advertises AVX-512 Foundation (leaf 7 EBX bit 16).
fn avx512f_advertised() -> bool {
    cpuid::max_standard_leaf() >= 7 && cpuid::raw(7, 0).ebx & CPUID_EBX7_AVX512F != 0
}

/// Whether the AVX-512F int8 GEMM is **verified usable** on this core — AVX-512
/// state enabled *and* the boot-time [`self_test`] passed. Same contract and
/// cheapness as [`avx2_ready`]; the sole gate [`gemm_i8_avx512`] consults.
#[must_use]
pub fn avx512_ready() -> bool {
    AVX512_STATUS.load(Ordering::Relaxed) == 1
}

/// Whether `cpuid` advertises AVX-512 VNNI (leaf 7 ECX bit 11).
fn avx512vnni_advertised() -> bool {
    cpuid::max_standard_leaf() >= 7 && cpuid::raw(7, 0).ecx & CPUID_ECX7_AVX512VNNI != 0
}

/// Whether the AVX-512 VNNI int8 GEMM is **verified usable** on this core — AVX-512
/// state enabled *and* the boot-time [`self_test`] passed. Same contract and
/// cheapness as [`avx2_ready`]; the sole gate [`gemm_i8_avx512vnni`] consults.
#[must_use]
pub fn avx512vnni_ready() -> bool {
    AVX512VNNI_STATUS.load(Ordering::Relaxed) == 1
}

/// A vector int8 GEMM kernel signature (AVX2 or AVX-512) for the self-test and the
/// host differential harness. `unsafe`: the CPU must support the tier and its
/// vector state must be enabled (both ensured by [`enable`] before it is called).
type Kernel = unsafe fn(&[i8], &[i8], &mut [i32], usize, usize, usize);

/// Boot-time differential self-test of a vector `kernel`: run several fixed GEMMs
/// through both it and an inline scalar loop, returning whether they agree
/// bit-for-bit. The cases cover the paths a broken vector unit could affect for the
/// 8-wide (AVX2), 16-wide (AVX-512F), and VNNI (`VPDPBUSD`, 4-wide-K) steps: a
/// single sub-block with mixed signs + a zero, a shape with a scalar tail at the
/// **±127** extremes, a **multi-block** shape (`n = 33`), and a **`k` not a multiple
/// of 4** shape (`k = 6`) that exercises VNNI's K-group zero-padding + its
/// unsigned/signed bias correction. Called by [`enable`] only after the tier's
/// vector state is on and it is `cpuid`-advertised, so the instructions are legal.
///
/// An i32-accumulator *wrap* would need `k > 133k` with int8 operands — far too
/// large for a boot check — so `VPADDD`/`VPDPBUSD == wrapping_add` over a wrapping
/// `k` is confirmed in the host differential test instead, not here.
fn self_test(kernel: Kernel) -> bool {
    self_test_case(kernel, 2, 8, 8, false)
        && self_test_case(kernel, 3, 8, 17, true)
        && self_test_case(kernel, 2, 8, 33, false)
        && self_test_case(kernel, 2, 6, 17, false)
}

/// One self-test case: fill `A`/`B` deterministically (`extremes` ⇒ a ±127
/// pattern, else a mixed-sign hash), compute `C = A·B` via `kernel` and a scalar
/// loop into fixed max-size stack buffers, and compare. Sized for the cases
/// [`self_test`] uses (`m*k ≤ 24`, `k*n ≤ 264`, `m*n ≤ 99`).
fn self_test_case(kernel: Kernel, m: usize, k: usize, n: usize, extremes: bool) -> bool {
    const A_MAX: usize = 3 * 8;
    const B_MAX: usize = 8 * 33;
    const C_MAX: usize = 3 * 33;
    let mut a_buf = [0i8; A_MAX];
    let mut b_buf = [0i8; B_MAX];
    for (t, x) in a_buf[..m * k].iter_mut().enumerate() {
        *x = if extremes {
            if t % 2 == 0 {
                127
            } else {
                -127
            }
        } else {
            self_test_fill(t)
        };
    }
    for (t, x) in b_buf[..k * n].iter_mut().enumerate() {
        *x = if extremes {
            if t % 3 == 0 {
                -127
            } else {
                127
            }
        } else {
            self_test_fill(t * 7 + 3)
        };
    }
    let a = &a_buf[..m * k];
    let b = &b_buf[..k * n];
    let mut c_ref = [0i32; C_MAX];
    let mut c_avx = [0i32; C_MAX];
    let cr = &mut c_ref[..m * n];
    let ca = &mut c_avx[..m * n];
    for i in 0..m {
        for j in 0..n {
            let mut acc: i32 = 0;
            for p in 0..k {
                acc = acc.wrapping_add(a[i * k + p] as i32 * b[p * n + j] as i32);
            }
            cr[i * n + j] = acc;
        }
    }
    // SAFETY: reached only from `enable` after the tier's vector state is enabled
    // and it is cpuid-advertised, so `kernel`'s instructions are legal; the
    // sub-slice lengths are exactly `m*k` / `k*n` / `m*n`.
    unsafe {
        kernel(a, b, ca, m, k, n);
    }
    ca == cr
}

/// Deterministic int8 in `[-127, 127]` for the non-extremes self-test fill.
fn self_test_fill(t: usize) -> i8 {
    let v = ((t.wrapping_mul(2_654_435_761) >> 5) % 255) as i32; // 0..=254
    (v - 127) as i8
}

/// AVX2 int8 GEMM: `C[m×n] = A[m×k] · B[k×n]`, int8·int8 with i32 accumulation,
/// **bit-identical** to a scalar `wrapping_add` reference.
///
/// Returns `true` if the vector kernel ran, or `false` — without touching `c` past
/// what it computed — when AVX2 is unavailable ([`avx2_ready`] is false) or the
/// slice lengths are inconsistent (incl. a `usize` overflow in `m*k`/`k*n`/`m*n`),
/// so the caller can fall back to scalar. Never `#UD`s and never panics.
///
/// # Precondition — interrupts must be disabled
///
/// The interrupt stubs ([`crate::idt`]) save only the general-purpose registers,
/// **not** `XMM`/`YMM`. So this must run with interrupts **disabled** until
/// `XSAVE`-based vector save/restore lands: otherwise an IRQ landing mid-kernel,
/// whose handler the compiler emitted any `XMM` use into (a `memcpy`/struct copy
/// is enough — it need not touch vectors in source), would clobber the in-flight
/// accumulators → silently wrong output. Today both callers (the boot self-test in
/// [`enable`], and `kernel::ml::prove`) run in the interrupts-off boot window; any
/// future interrupts-on use needs the save/restore first.
#[must_use]
pub fn gemm_i8_avx2(a: &[i8], b: &[i8], c: &mut [i32], m: usize, k: usize, n: usize) -> bool {
    // Validate dimensions with `checked_mul` so a `usize` overflow can never make a
    // wrong `len == m*k` comparison pass — it returns `false` (→ scalar fallback).
    let (Some(mk), Some(kn), Some(mn)) = (m.checked_mul(k), k.checked_mul(n), m.checked_mul(n))
    else {
        return false;
    };
    if a.len() != mk || b.len() != kn || c.len() != mn {
        return false;
    }
    if !avx2_ready() {
        return false;
    }
    // SAFETY: `avx2_ready()` is `true` only after `enable` both turned on AVX
    // (`YMM`) state AND the self-test executed the AVX2 kernel correctly on this
    // core, so the kernel's VEX instructions are legal (no `#UD`) and known-good
    // here. The lengths were validated above (overflow-checked), so every in-kernel
    // load/store stays within `a`/`b`/`c`; `a`/`b` are shared and `c` exclusive
    // (distinct GEMM buffers). Caller runs with interrupts disabled (see above).
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
unsafe fn gemm_i8_avx2_impl(a: &[i8], b: &[i8], c: &mut [i32], m: usize, k: usize, n: usize) {
    for i in 0..m {
        let crow = &mut c[i * n..i * n + n];
        for v in crow.iter_mut() {
            *v = 0;
        }
        for p in 0..k {
            let a_ip = a[i * k + p] as i32;
            let brow = &b[p * n..p * n + n];
            let mut j = 0usize;
            while j + 8 <= n {
                // SAFETY: `j + 8 <= n`, so `brow[j..j+8]` (8 bytes) and
                // `crow[j..j+8]` (8×i32) are both in-bounds; `avx2_madd8`'s AVX2
                // instructions are legal (fn precondition: avx2 + AVX state on).
                unsafe {
                    avx2_madd8(a_ip, brow.as_ptr().add(j), crow.as_mut_ptr().add(j));
                }
                j += 8;
            }
            while j < n {
                crow[j] = crow[j].wrapping_add(a_ip * brow[j] as i32);
                j += 1;
            }
        }
    }
}

/// `c[0..8] += a_ip * sign_extend(b[0..8])` — one 256-bit AVX2 multiply-accumulate
/// of eight int32 columns, written in inline `asm!` (VEX) rather than `core::arch`
/// intrinsics.
///
/// **Why `asm!` and not intrinsics:** the target `x86_64-unknown-none` has SSE/AVX
/// disabled in its baseline (soft-float), and its `core::arch` SIMD intrinsics do
/// **not** codegen to VEX instructions there (they emit as calls that never lower
/// to `vpmulld`, and passing `__m256i` across a call on the soft-float ABI is
/// broken). `asm!` emits the exact instructions unconditionally; the vectors live
/// entirely inside the block (only `i32`/pointers cross the call boundary), so
/// there is no vector-ABI dependency. Verified: the disassembly now contains real
/// `vpmulld`/`vpmovsxbd`, and the boot-time self-test passes on a real vector unit.
///
/// # Safety
///
/// The CPU must support `avx2` and the OS must have enabled AVX (`YMM`) state
/// (both ensured by [`gemm_i8_avx2`] via [`avx2_ready`]), and `b`/`c` must point at
/// ≥ 8 valid int8 / ≥ 8 valid `i32` respectively (ensured by the `j + 8 <= n`
/// bound in the sole caller). `c` is read and written; `b` is read.
#[inline]
unsafe fn avx2_madd8(a_ip: i32, b: *const i8, c: *mut i32) {
    // SAFETY: preconditions per the doc — avx2 + AVX state enabled make the VEX
    // instructions legal; `b`/`c` address the required 8 int8 / 8 i32. `ymm0`/`ymm1`
    // are declared clobbered; the block reads `[b]` and read-writes `[c]` (so no
    // `nomem`); it uses no stack and sets no flags.
    unsafe {
        core::arch::asm!(
            "vmovd xmm0, {a:e}",                      // xmm0.lo = a_ip
            "vpbroadcastd ymm0, xmm0",               // ymm0 = a_ip × 8
            "vpmovsxbd ymm1, qword ptr [{b}]",       // ymm1 = sext(b[0..8]) → 8×i32
            "vpmulld ymm1, ymm1, ymm0",              // ymm1 = a_ip * b
            "vpaddd ymm1, ymm1, ymmword ptr [{c}]",  // ymm1 += c[0..8]
            "vmovdqu ymmword ptr [{c}], ymm1",       // c[0..8] = ymm1
            a = in(reg) a_ip,
            b = in(reg) b,
            c = in(reg) c,
            out("ymm0") _,
            out("ymm1") _,
            options(nostack, preserves_flags),
        );
    }
}

/// AVX-512F int8 GEMM: `C[m×n] = A[m×k] · B[k×n]`, **bit-identical** to the scalar
/// reference — the 512-bit sibling of [`gemm_i8_avx2`] (same broadcast scheme, 16
/// int32 columns per `ZMM` step). Returns `true` if it ran, or `false` (→ caller
/// falls back to a narrower tier / scalar) when AVX-512 is not verified usable
/// ([`avx512_ready`]) or the dims are inconsistent. Never `#UD`s, never panics.
/// Same hard **interrupts-disabled** precondition as [`gemm_i8_avx2`].
#[must_use]
pub fn gemm_i8_avx512(a: &[i8], b: &[i8], c: &mut [i32], m: usize, k: usize, n: usize) -> bool {
    let (Some(mk), Some(kn), Some(mn)) = (m.checked_mul(k), k.checked_mul(n), m.checked_mul(n))
    else {
        return false;
    };
    if a.len() != mk || b.len() != kn || c.len() != mn {
        return false;
    }
    if !avx512_ready() {
        return false;
    }
    // SAFETY: `avx512_ready()` is `true` only after `enable` turned on AVX-512
    // (`ZMM`) state AND the self-test executed this kernel correctly on this core,
    // so the EVEX instructions are legal (no `#UD`). The lengths were validated
    // above (overflow-checked), so every in-kernel load/store stays within
    // `a`/`b`/`c`; `a`/`b` shared, `c` exclusive; caller runs with interrupts off.
    unsafe {
        gemm_i8_avx512_impl(a, b, c, m, k, n);
    }
    true
}

/// The AVX-512F kernel — the 16-columns-per-step analogue of [`gemm_i8_avx2_impl`].
///
/// # Safety
///
/// The CPU must support `avx512f`, the OS must have enabled AVX-512 (`ZMM`) state
/// (both ensured by [`gemm_i8_avx512`] via [`avx512_ready`]), and the slice lengths
/// must match `m`/`k`/`n` (so the internal bounded pointer accesses are valid).
unsafe fn gemm_i8_avx512_impl(a: &[i8], b: &[i8], c: &mut [i32], m: usize, k: usize, n: usize) {
    for i in 0..m {
        let crow = &mut c[i * n..i * n + n];
        for v in crow.iter_mut() {
            *v = 0;
        }
        for p in 0..k {
            let a_ip = a[i * k + p] as i32;
            let brow = &b[p * n..p * n + n];
            let mut j = 0usize;
            while j + 16 <= n {
                // SAFETY: `j + 16 <= n`, so `brow[j..j+16]` (16 bytes) and
                // `crow[j..j+16]` (16×i32) are in-bounds; `avx512_madd16`'s AVX-512F
                // instructions are legal (fn precondition: avx512f + ZMM state on).
                unsafe {
                    avx512_madd16(a_ip, brow.as_ptr().add(j), crow.as_mut_ptr().add(j));
                }
                j += 16;
            }
            while j < n {
                crow[j] = crow[j].wrapping_add(a_ip * brow[j] as i32);
                j += 1;
            }
        }
    }
}

/// `c[0..16] += a_ip * sign_extend(b[0..16])` — one 512-bit AVX-512F multiply-
/// accumulate of sixteen int32 columns, inline `asm!` (EVEX) for the same
/// soft-float-target codegen reason as [`avx2_madd8`].
///
/// # Safety
///
/// The CPU must support `avx512f` and the OS must have enabled AVX-512 (`ZMM`)
/// state (both ensured by [`gemm_i8_avx512`] via [`avx512_ready`]), and `b`/`c`
/// must point at ≥ 16 valid int8 / ≥ 16 valid `i32` (ensured by the `j + 16 <= n`
/// bound in the sole caller). `c` is read and written; `b` is read.
#[inline]
unsafe fn avx512_madd16(a_ip: i32, b: *const i8, c: *mut i32) {
    // SAFETY: preconditions per the doc — avx512f + ZMM state enabled make the EVEX
    // instructions legal; `b`/`c` address the required 16 int8 / 16 i32. `zmm0`/
    // `zmm1` are declared clobbered; the block reads `[b]` and read-writes `[c]`
    // (so no `nomem`); it uses no stack and sets no flags.
    unsafe {
        core::arch::asm!(
            "vmovd xmm0, {a:e}",                       // xmm0.lo = a_ip
            "vpbroadcastd zmm0, xmm0",                // zmm0 = a_ip × 16
            "vpmovsxbd zmm1, xmmword ptr [{b}]",      // zmm1 = sext(b[0..16]) → 16×i32
            "vpmulld zmm1, zmm1, zmm0",               // zmm1 = a_ip * b
            "vpaddd zmm1, zmm1, zmmword ptr [{c}]",   // zmm1 += c[0..16]
            "vmovdqu32 zmmword ptr [{c}], zmm1",      // c[0..16] = zmm1
            a = in(reg) a_ip,
            b = in(reg) b,
            c = in(reg) c,
            out("zmm0") _,
            out("zmm1") _,
            options(nostack, preserves_flags),
        );
    }
}

/// AVX-512 **VNNI** int8 GEMM: `C[m×n] = A[m×k] · B[k×n]`, **bit-identical** to the
/// scalar reference — the throughput tier, using `VPDPBUSD` (a fused
/// unsigned×signed 4×int8 dot-product-accumulate, 64 int8 MACs per 512-bit step).
/// Returns `true` if it ran, or `false` (→ caller falls back to a narrower tier)
/// when VNNI is not verified usable ([`avx512vnni_ready`]) or the dims are
/// inconsistent. Never `#UD`s, never panics. Same hard **interrupts-disabled**
/// precondition as [`gemm_i8_avx2`].
///
/// # The unsigned/signed bias correction (why this is bit-exact)
///
/// `VPDPBUSD` multiplies **unsigned** bytes (operand 1) by **signed** bytes
/// (operand 2). Our operands are both *signed* int8. So we bias `A` into unsigned
/// range — `au = a + 128` (a `^ 0x80` on the byte) — accumulate `Σ_k au·b` with
/// `VPDPBUSD`, then subtract the correction `128·Σ_k B[k][j]` (per output column
/// `j`). Per term `au·b − 128·b = (a+128−128)·b = a·b` exactly in ℤ; since every op
/// is `wrapping` (mod 2³²) and `VPDPBUSD` wraps (it is *not* the saturating
/// `VPDPBUSDS`), the whole reordering is a ring identity mod 2³² → bit-identical to
/// the ascending-`k` scalar `wrapping_add`. Verified against the scalar reference in
/// the host differential test (incl. `k` not ÷ 4, `n` not ÷ 16, ±127, and an i32
/// wrap) and re-checked at every boot by the [`enable`] self-test.
#[must_use]
pub fn gemm_i8_avx512vnni(a: &[i8], b: &[i8], c: &mut [i32], m: usize, k: usize, n: usize) -> bool {
    let (Some(mk), Some(kn), Some(mn)) = (m.checked_mul(k), k.checked_mul(n), m.checked_mul(n))
    else {
        return false;
    };
    if a.len() != mk || b.len() != kn || c.len() != mn {
        return false;
    }
    if !avx512vnni_ready() {
        return false;
    }
    // SAFETY: `avx512vnni_ready()` is `true` only after `enable` turned on AVX-512
    // (`ZMM`) state AND the self-test executed this kernel correctly on this core, so
    // the `VPDPBUSD` instruction is legal (no `#UD`). The lengths were validated
    // above (overflow-checked), so every in-kernel load/store stays within
    // `a`/`b`/`c`; `a`/`b` shared, `c` exclusive; caller runs with interrupts off.
    unsafe {
        gemm_i8_avx512vnni_impl(a, b, c, m, k, n);
    }
    true
}

/// The AVX-512 VNNI kernel. Processes 16 output columns per block; within a block,
/// accumulates over `⌈k/4⌉` groups of four K values via `VPDPBUSD` (broadcasting the
/// biased 4-byte `A` group across all 16 lanes and reading a packed 16×4 `B` panel),
/// then applies the `−128·Σ_k B[k][j]` bias correction; a scalar tail handles the
/// final `< 16` columns. All scratch is stack-resident (a 64-byte `B` panel + a
/// 16-lane column-sum), so the kernel allocates nothing.
///
/// # Safety
///
/// The CPU must support `avx512_vnni` and the OS must have enabled AVX-512 (`ZMM`)
/// state (both ensured by [`gemm_i8_avx512vnni`] via [`avx512vnni_ready`]), and the
/// slice lengths must match `m`/`k`/`n` (so the internal bounded accesses are valid).
unsafe fn gemm_i8_avx512vnni_impl(a: &[i8], b: &[i8], c: &mut [i32], m: usize, k: usize, n: usize) {
    let kgroups = k.div_ceil(4); // 4-wide K groups; the last is zero-padded if k%4≠0
    let mut jb = 0usize;
    while jb + 16 <= n {
        // Per-column bias correction term: colsum[cc] = Σ_k B[k][jb+cc] (real k only).
        let mut colsum = [0i32; 16];
        for p in 0..k {
            let brow = &b[p * n + jb..p * n + jb + 16];
            for (cc, &bv) in brow.iter().enumerate() {
                colsum[cc] = colsum[cc].wrapping_add(bv as i32);
            }
        }
        // Zero the 16-column accumulator region for every row (VPDPBUSD accumulates).
        for i in 0..m {
            for v in &mut c[i * n + jb..i * n + jb + 16] {
                *v = 0;
            }
        }
        for g in 0..kgroups {
            // Pack the B panel: lane cc holds the 4 bytes B[4g..4g+4][jb+cc], zero
            // where 4g+r ≥ k (that padding contributes 0 to both VPDPBUSD and colsum).
            let mut panel = [0u8; 64];
            for r in 0..4 {
                let kk = 4 * g + r;
                if kk >= k {
                    break;
                }
                let brow = &b[kk * n + jb..kk * n + jb + 16];
                for (cc, &bv) in brow.iter().enumerate() {
                    panel[cc * 4 + r] = bv as u8;
                }
            }
            for i in 0..m {
                // Biased A dword: au = a ^ 0x80 (= a + 128, unsigned); pad 0 past k.
                let mut ad = [0u8; 4];
                for (r, slot) in ad.iter_mut().enumerate() {
                    let kk = 4 * g + r;
                    if kk < k {
                        *slot = (a[i * k + kk] as u8) ^ 0x80;
                    }
                }
                let a_dword = u32::from_le_bytes(ad);
                // SAFETY: `jb + 16 <= n`, so `c[i*n+jb .. +16]` (16×i32) is in bounds;
                // `panel` is 64 valid bytes; `vnni_dp16`'s VPDPBUSD is legal (fn
                // precondition: avx512_vnni + ZMM state on).
                unsafe {
                    vnni_dp16(a_dword, panel.as_ptr(), c[i * n + jb..].as_mut_ptr());
                }
            }
        }
        // Apply the bias correction: C[i][jb+cc] -= 128 · colsum[cc].
        for i in 0..m {
            let crow = &mut c[i * n + jb..i * n + jb + 16];
            for (cc, v) in crow.iter_mut().enumerate() {
                *v = v.wrapping_sub(128i32.wrapping_mul(colsum[cc]));
            }
        }
        jb += 16;
    }
    // Scalar tail for the remaining < 16 columns (plain signed int8, no VNNI).
    while jb < n {
        for i in 0..m {
            let mut acc: i32 = 0;
            for p in 0..k {
                acc = acc.wrapping_add(a[i * k + p] as i32 * b[p * n + jb] as i32);
            }
            c[i * n + jb] = acc;
        }
        jb += 1;
    }
}

/// `c[0..16] += VPDPBUSD(broadcast(a_dword), b_panel[0..64])` — one 512-bit VNNI
/// step: for each of 16 int32 lanes, add the 4-int8 dot product of the biased
/// (unsigned) `A` group against the packed (signed) `B` panel column. Inline `asm!`
/// (EVEX) for the same soft-float-target codegen reason as [`avx2_madd8`].
///
/// # Safety
///
/// The CPU must support `avx512_vnni` and the OS must have enabled AVX-512 (`ZMM`)
/// state (both ensured by [`gemm_i8_avx512vnni`] via [`avx512vnni_ready`]); `b` must
/// point at ≥ 64 valid bytes (the packed panel) and `c` at ≥ 16 valid `i32` (ensured
/// by the `j + 16 <= n` bound in the sole caller). `c` is read and written; `b` read.
#[inline]
unsafe fn vnni_dp16(a_dword: u32, b: *const u8, c: *mut i32) {
    // SAFETY: preconditions per the doc — avx512_vnni + ZMM state enabled make the
    // EVEX instruction legal; `b` addresses 64 packed bytes, `c` the 16 i32 lanes.
    // `zmm0`/`zmm1` are declared clobbered; the block reads `[b]` and read-writes
    // `[c]` (so no `nomem`); it uses no stack and sets no flags. VPDPBUSD wraps (not
    // the saturating VPDPBUSDS), matching the scalar `wrapping_add`.
    unsafe {
        core::arch::asm!(
            "vmovd xmm0, {a:e}",                        // xmm0.lo = biased A dword
            "vpbroadcastd zmm0, xmm0",                 // zmm0 = A dword × 16 (unsigned)
            "vmovdqu32 zmm1, zmmword ptr [{c}]",       // zmm1 = c[0..16] accumulators
            "vpdpbusd zmm1, zmm0, zmmword ptr [{b}]",  // zmm1 += u8(zmm0)·i8(panel)
            "vmovdqu32 zmmword ptr [{c}], zmm1",       // c[0..16] = zmm1
            a = in(reg) a_dword,
            b = in(reg) b,
            c = in(reg) c,
            out("zmm0") _,
            out("zmm1") _,
            options(nostack, preserves_flags),
        );
    }
}

/// Pure arithmetic **model** of what [`gemm_i8_avx512vnni_impl`] computes for one
/// output cell: the unsigned/signed bias-corrected dot product `Σ_p (au_p · b_p) −
/// 128·Σ_p b_p`, where `au_p = a_p + 128` (the `^ 0x80` unsigned bias), everything
/// `wrapping` mod 2³² — exactly the `VPDPBUSD` accumulation (`au` unsigned × `b`
/// signed, wrapping, *not* saturating) plus the column-sum correction, but with **no
/// `asm!`**. Extracted so the **ring identity** that makes it equal the signed scalar
/// dot product — `Σ (a+128)·b − 128·Σ b = Σ a·b` (mod 2³²) — can be checked
/// exhaustively/independently of any AVX-512 hardware: by the Kani proof
/// [`proofs::vnni_bias_correction_is_exact`] (symbolic bytes) and the always-on host
/// test [`tests::vnni_bias_model_matches_scalar`] (both run on **any** CPU, unlike
/// the hardware differential tests which need `avx512vnni`). This is a re-derivation
/// of the kernel's arithmetic, not the code path itself; the hardware differential
/// test guards the `asm!`/packing against this model drifting from reality.
#[cfg(any(test, kani))]
fn vnni_cell_bias(a: &[i8], b: &[i8]) -> i32 {
    let mut acc: i32 = 0; // VPDPBUSD accumulation of au·b
    let mut colsum: i32 = 0; // Σ b, for the −128·Σb correction
    for (&av, &bv) in a.iter().zip(b) {
        let au = ((av as u8) ^ 0x80) as i32; // a + 128, unsigned byte in 0..=255
        acc = acc.wrapping_add(au * (bv as i32));
        colsum = colsum.wrapping_add(bv as i32);
    }
    acc.wrapping_sub(128i32.wrapping_mul(colsum))
}

/// The signed scalar dot product `Σ_p a_p·b_p` (i32 `wrapping_add`) — the oracle
/// [`vnni_cell_bias`] must equal bit-for-bit.
#[cfg(any(test, kani))]
fn scalar_cell(a: &[i8], b: &[i8]) -> i32 {
    let mut acc: i32 = 0;
    for (&av, &bv) in a.iter().zip(b) {
        acc = acc.wrapping_add((av as i32) * (bv as i32));
    }
    acc
}

// ── unit tests (host) ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    extern crate std;
    use super::{
        gemm_i8_avx2_impl, gemm_i8_avx512_impl, gemm_i8_avx512vnni_impl, scalar_cell,
        vnni_cell_bias, Kernel,
    };
    use std::vec;
    use std::vec::Vec;

    /// The vector kernels this host CPU can actually execute, each labelled. A tier
    /// whose feature is absent is skipped (not failed) — CI hosts vary, and both
    /// kernels are proven identically against the scalar reference below, so running
    /// whichever the host supports still exercises the differential contract.
    ///
    /// Emits a per-tier ran/skipped line to stderr (visible under
    /// `cargo test -- --nocapture`) so a green run distinguishes "the AVX-512 kernel
    /// was verified here" from "the host lacks avx512f and it was silently skipped" —
    /// the two look identical from an exit code otherwise. Standard GitHub runners
    /// often lack `avx512f`, so the ZMM kernel's coverage must be confirmed on an
    /// avx512f host (see the design doc's Phase 3 testing note), not assumed from CI.
    fn host_kernels() -> Vec<(&'static str, Kernel)> {
        let mut ks: Vec<(&'static str, Kernel)> = Vec::new();
        let avx2 = std::is_x86_feature_detected!("avx2");
        let avx512f = std::is_x86_feature_detected!("avx512f");
        let avx512vnni = std::is_x86_feature_detected!("avx512vnni");
        if avx2 {
            ks.push(("avx2", gemm_i8_avx2_impl as Kernel));
        }
        if avx512f {
            ks.push(("avx512f", gemm_i8_avx512_impl as Kernel));
        }
        if avx512vnni {
            ks.push(("avx512vnni", gemm_i8_avx512vnni_impl as Kernel));
        }
        let show = |present: bool| if present { "RAN" } else { "skipped (absent)" };
        std::eprintln!(
            "[simd host-diff] avx2: {}  avx512f: {}  avx512vnni: {}",
            show(avx2),
            show(avx512f),
            show(avx512vnni),
        );
        ks
    }

    /// Run `kernel` into a fresh `C` buffer and return it.
    ///
    /// # Safety
    /// The caller must have confirmed the host supports `kernel`'s tier (via
    /// [`host_kernels`]); `m`/`k`/`n` must match the `a`/`b` lengths.
    unsafe fn run(kernel: Kernel, a: &[i8], b: &[i8], m: usize, k: usize, n: usize) -> Vec<i32> {
        let mut c = vec![0i32; m * n];
        // SAFETY: tier confirmed by the caller; dims match the slices.
        unsafe { kernel(a, b, &mut c, m, k, n) };
        c
    }

    /// Scalar reference with the exact `wrapping_add` semantics both vector kernels
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
    fn kernels_match_scalar_bit_for_bit() {
        let kernels = host_kernels();
        if kernels.is_empty() {
            std::eprintln!("host lacks AVX2/AVX-512 — skipping the differential test");
            return;
        }
        // Shapes chosen to cover: 1×1, non-square, exact multiples of 8 and 16, and
        // several with n NOT a multiple of the step (exercising each kernel's scalar
        // tail), plus k=1, large-ish k, and n spanning multiple 16-wide ZMM blocks.
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
            (3, 5, 32),
            (2, 4, 40),
        ];
        for (idx, &(m, k, n)) in shapes.iter().enumerate() {
            let a: Vec<i8> = (0..m * k).map(|t| fill(t + idx * 7)).collect();
            let b: Vec<i8> = (0..k * n).map(|t| fill(t * 3 + idx * 5 + 1)).collect();
            let mut c_scalar = vec![0i32; m * n];
            scalar_ref(&a, &b, &mut c_scalar, m, k, n);
            for &(name, kernel) in &kernels {
                // SAFETY: `host_kernels` confirmed this tier; dims match the buffers.
                let c_vec = unsafe { run(kernel, &a, &b, m, k, n) };
                assert_eq!(
                    c_scalar,
                    c_vec,
                    "{name} != scalar for shape {:?}",
                    (m, k, n)
                );
            }
        }
    }

    #[test]
    fn kernels_extremes_do_not_diverge() {
        let kernels = host_kernels();
        if kernels.is_empty() {
            return;
        }
        // All -127 and all 127 over a wide K — large magnitudes, both signs; n spans
        // both a 16-wide block and a tail so each kernel's vector and scalar paths run.
        let (m, k, n) = (3usize, 40usize, 27usize);
        for &val in &[-127i8, 127i8, -1, 1] {
            let a = vec![val; m * k];
            let b = vec![val; k * n];
            let mut c_scalar = vec![0i32; m * n];
            scalar_ref(&a, &b, &mut c_scalar, m, k, n);
            for &(name, kernel) in &kernels {
                // SAFETY: tier confirmed by `host_kernels`; dims consistent.
                let c_vec = unsafe { run(kernel, &a, &b, m, k, n) };
                assert_eq!(c_scalar, c_vec, "{name} mismatch for uniform value {val}");
            }
        }
    }

    #[test]
    fn kernels_i32_accumulator_wraps_like_scalar() {
        let kernels = host_kernels();
        if kernels.is_empty() {
            return;
        }
        // K large enough that the ascending int32 sum overflows 2^31: 127*127 =
        // 16129 per term, so ~150k terms wraps well past i32::MAX. This is the one
        // case that stresses VPADDD == wrapping_add across the 32-bit boundary
        // (impractical in the boot self-test, hence covered here). n=16 → a pure
        // vector step for both kernels (two 8-wide for AVX2, one 16-wide for
        // AVX-512); the result must still match the scalar wrapping reference.
        let (m, k, n) = (1usize, 150_000usize, 16usize);
        let a = vec![127i8; m * k];
        let b = vec![127i8; k * n];
        let mut c_scalar = vec![0i32; m * n];
        scalar_ref(&a, &b, &mut c_scalar, m, k, n);
        // Sanity: the reference actually wrapped into negative territory.
        assert!(c_scalar[0] < 0, "test did not exercise a wrap");
        for &(name, kernel) in &kernels {
            // SAFETY: tier confirmed by `host_kernels`; dims consistent.
            let c_vec = unsafe { run(kernel, &a, &b, m, k, n) };
            assert_eq!(c_scalar, c_vec, "{name} != scalar across an i32 wrap");
        }
    }

    #[test]
    fn kernels_match_scalar_over_pseudo_random_sweep() {
        let kernels = host_kernels();
        if kernels.is_empty() {
            return;
        }
        // A lightweight fuzz substitute (no rng dependency): a deterministic LCG
        // drives many random (m,k,n) shapes and full-range i8 values, diffing each
        // available kernel against the scalar reference. Broad coverage of the
        // bounded vector/tail pointer arithmetic and sign handling.
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as u32
        };
        for _ in 0..300 {
            let m = (next() % 6) as usize + 1; // 1..=6
            let k = (next() % 20) as usize + 1; // 1..=20
            let n = (next() % 40) as usize + 1; // 1..=40 (spans multi-block + tail)
            let a: Vec<i8> = (0..m * k).map(|_| next() as i8).collect();
            let b: Vec<i8> = (0..k * n).map(|_| next() as i8).collect();
            let mut c_scalar = vec![0i32; m * n];
            scalar_ref(&a, &b, &mut c_scalar, m, k, n);
            for &(name, kernel) in &kernels {
                // SAFETY: tier confirmed by `host_kernels`; dims match the buffers.
                let c_vec = unsafe { run(kernel, &a, &b, m, k, n) };
                assert_eq!(
                    c_scalar,
                    c_vec,
                    "{name} != scalar for random shape {:?}",
                    (m, k, n)
                );
            }
        }
    }

    // The bias-correction identity is what makes VNNI harder than a direct widening
    // (SM1/SM2). The two tests below check it on the **pure model** (`vnni_cell_bias`,
    // no `asm!`), so they run on **every** host — including Miri and non-`avx512vnni`
    // CI runners where the hardware differential tests skip the VNNI kernel — giving
    // the ring identity an always-on, hardware-independent regression guard. (The
    // Kani proof `proofs::vnni_bias_correction_is_exact` covers it exhaustively over
    // symbolic bytes.)

    #[test]
    fn vnni_bias_model_matches_scalar() {
        // A deterministic LCG drives many random `k` and full-range i8 values through
        // both the bias model and the signed scalar dot product; any divergence is a
        // bug in the unsigned/signed correction (wrong bias, colsum, or sign handling).
        let mut state: u64 = 0xD1B5_4A32_D192_ED03;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as u32
        };
        for _ in 0..2000 {
            let k = (next() % 64) as usize; // 0..=63, incl. empty and k%4≠0
            let a: Vec<i8> = (0..k).map(|_| next() as i8).collect();
            let b: Vec<i8> = (0..k).map(|_| next() as i8).collect();
            assert_eq!(
                vnni_cell_bias(&a, &b),
                scalar_cell(&a, &b),
                "VNNI bias model != scalar for k={k}, a={a:?}, b={b:?}"
            );
        }
    }

    // The one thing the small-`k` cases can't reach: a 32-bit accumulator wrap. Uses
    // a large `k`, so it is skipped under Miri (which would interpret the whole loop
    // far too slowly) — native `cargo test` covers it, and Kani proves the identity
    // symbolically for the non-wrapping regime.
    #[test]
    #[cfg(not(miri))]
    fn vnni_bias_model_wraps_like_scalar() {
        // 127*127 per term, ~150k terms wraps well past i32::MAX; the correction
        // 128*colsum also wraps. The model must still match the scalar reference.
        let k = 150_000usize;
        let a = vec![127i8; k];
        let b = vec![127i8; k];
        let s = scalar_cell(&a, &b);
        assert!(s < 0, "test did not exercise a wrap");
        assert_eq!(
            vnni_cell_bias(&a, &b),
            s,
            "VNNI bias model != scalar across a wrap"
        );
    }
}

/// Kani proof — the VNNI bias-correction model ([`vnni_cell_bias`]) computes the
/// signed scalar dot product ([`scalar_cell`]) bit-for-bit for **all** int8 inputs:
/// the ring identity `Σ (a+128)·b − 128·Σ b = Σ a·b` (mod 2³²). This is the one part
/// of the VNNI tier not covered by a direct widening of a proven kernel, so it gets
/// an exhaustive, hardware-independent proof here. Symbolic over the full byte space
/// for a fixed `k` (the identity is a per-term equality plus a linear `wrapping_add`
/// reduction, so a small `k` witnesses the general case); the large-`k` accumulator-
/// wrap regime is covered by the host test [`tests::vnni_bias_model_wraps_like_scalar`].
/// Compiled only under `cargo kani -p hal`; excluded from the stable build and tests.
#[cfg(kani)]
mod proofs {
    use super::{scalar_cell, vnni_cell_bias};

    #[kani::proof]
    fn vnni_bias_correction_is_exact() {
        const K: usize = 4;
        let a: [i8; K] = kani::any();
        let b: [i8; K] = kani::any();
        assert_eq!(vnni_cell_bias(&a, &b), scalar_cell(&a, &b));
    }
}
