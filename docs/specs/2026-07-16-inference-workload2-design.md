# Inference Workload v2 — Quantized Transformer Block — Design

Status: **proposed** · Track C (AI/ML compute), step 2 · Author: kernel / compute track
Depends on: `kernel::ml` int8 GEMM tiers + quantization (`2026-07-14-aiml-inference-compute-design.md`)
and vector-state-across-interrupts (`2026-07-15-vector-state-interrupts-design.md`), both shipped.
Escalation: **none** — entirely **safe** Rust in the `#![forbid(unsafe_code)]` kernel
crate composing the existing tiered `gemm_i8`. No new TCB (softmax/layernorm are
scalar-`f32` loops the soft-float target lowers to GP-register calls, so `xtask
check-no-vector` still passes). Normal kernel-engineer review.

## Goal

Grow the AI/ML path from the toy 2-layer MLP to the **canonical modern-inference
unit: one quantized transformer block** — pre-norm multi-head self-attention (MHA)
then the existing MLP as the position-wise FFN. This exercises the int8 GEMM tiers in
the *attention* shapes (QKᵀ, P·V), adds the two primitives every transformer needs
(**softmax**, **layernorm**), and rides M4 hardening: new entries return `Result`, not
asserts. Fixed dims (one block, fixed weights, MLP spirit): `seq = 16` (S),
`d_model = 32` (D), `n_heads = 2` (H), `d_head = 16` (Dh), `d_ff = 64`. Every GEMM
lands `n = S = 16`, so the active vector tier engages (MLP `batch = 16` lesson).

## Framekernel classification

All **safe kernel crate** (`kernel::ml`). No HAL change, no new `unsafe`. The only
privileged code reached is the existing `hal::simd` GEMM dispatch (already in the TCB
registry). softmax/layernorm/`exp`/`rsqrt` are pure `f32`/bit-cast scalar math (no
libm, no vector instructions), so `xtask check-no-vector` is unaffected and the block
is safe to run interrupts-on today.

## Module layout

Extend `kernel/crates/kernel/src/ml.rs` (no new crate/file):

| Item | Kind | Purpose |
|---|---|---|
| `MlError` | pub enum | fail-safe error for the new `Result` entries |
| `softmax_rows` | pub fn | row-wise stable softmax (new primitive) |
| `layernorm_rows` | pub fn | row-wise layernorm (new primitive) |
| `exp_f32` / `rsqrt_f32` | priv fn | libm-free deterministic transcendentals |
| `TransformerBlockDims` / `…Weights` / `…Scratch` | pub structs | dims, weights, caller-owned work buffers |
| `transformer_block` | pub fn `-> Result` | the workload: one pre-norm block forward |
| `infer_block_prove` | pub fn | boot proof (mirrors `infer_prove`) |

## Data flow (pre-norm block; residual stream `x` is `[S × D]`, token-major)

```
x0 : [S × D]                       block input (f32, token-major = S contiguous D-rows)
a  = layernorm_rows(x0, γ1, β1)    per-token over D
q,k,v = proj(a)                    Q,K,V = Wq,Wk,Wv · aᵀ    (int8 GEMM, see table)
for h in 0..H:                     per head (Dh rows)
    s_h = Qhᵀ · Kh        [S × S]  int8 GEMM; dequant · (1/√Dh)
    p_h = softmax_rows(s_h)         each query-row sums to 1
    c_h = Vh · p_hᵀ      [Dh × S]  int8 GEMM
ctx = concat_heads(c_h) : [D × S]
attn = Wo · ctx                    int8 GEMM (output projection)
x1 = x0 + attnᵀ                    residual (f32)
b  = layernorm_rows(x1, γ2, β2)
ffn = dense(D→d_ff) → relu → dense(d_ff→D)   the EXISTING MLP (dense_pre_activation×2)
x2 = x1 + ffn                      residual → block output, [S × D]
```

Layout note: the residual stream stays `[S × D]` (token-major) so `layernorm_rows`
is a contiguous `D`-length reduction per token; the quantize step feeding each
projection GEMM **transposes while it copies** to `[D × S]` (the MLP's `[k_in × batch]`
shape). QKᵀ and P·V each need one per-head transpose (`Qhᵀ`, `p_hᵀ`), packed on the
**stack** — alloc-free.

## Attention shapes → `gemm_i8(A[m×k], B[k×n]) = C[m×n]` (n engages the vector tier)

| Step | A `[m×k]` | B `[k×n]` | C `[m×n]` | m,k,**n** |
|---|---|---|---|---|
| Q/K/V/O proj | `W [D×D]` | `actᵀ [D×S]` | `[D×S]` | 32,32,**16** |
| scores QKᵀ (per head) | `Qhᵀ [S×Dh]` | `Kh [Dh×S]` | `s_h [S×S]` | 16,16,**16** |
| context P·V (per head) | `Vh [Dh×S]` | `p_hᵀ [S×S]` | `c_h [Dh×S]` | 16,16,**16** |

FFN dense 1/2 reuse `dense_pre_activation` (also `n = S = 16`). Every `n = S = 16` ≥
the 16-wide `ZMM`/8-wide `YMM` block → a real vector body, not just the scalar tail.

## Quantization points & scales (symmetric int8, reuse `quant_scale`/`quantize`)

| Boundary | Quantized tensor | Scale | Dequant scale |
|---|---|---|---|
| proj input | `a` (LN1 out) → `aq` | `s_a` | — |
| proj weights (static) | `Wq/Wk/Wv/Wo` | `s_wq…` | Q/K/V/O = `s_a·s_w` |
| scores | `Q`,`K` (per-tensor) → int8 | `s_q`,`s_k` | `s_q·s_k · (1/√Dh)` |
| context | `p_h` (per head), `V` | `s_p_h`,`s_v` | `s_p_h·s_v` |
| FFN | (existing MLP scales) | — | — |

`1/√Dh = 0.25` (exact `f32`) folds into the score dequant; softmax `p ∈ [0,1]` ⇒ `s_p_h ≈ 1/127`.

## New numeric primitives (libm-free, deterministic across IEEE-754 hosts)

```rust
/// Stable softmax over each contiguous `width`-length row of `rows` rows, in place:
/// yᵢ = exp(xᵢ − maxⱼ xⱼ) / Σⱼ exp(xⱼ − maxⱼ). Rows are independent.
pub fn softmax_rows(x: &mut [f32], rows: usize, width: usize) -> Result<(), MlError>;

/// Layernorm each contiguous `dim`-length row (token): yᵢ = (xᵢ − μ)·rsqrt(σ²+eps)·γᵢ + βᵢ,
/// μ,σ² the row's mean/variance. `gamma`,`beta` are length `dim`.
pub fn layernorm_rows(
    x: &[f32], gamma: &[f32], beta: &[f32], out: &mut [f32],
    tokens: usize, dim: usize, eps: f32,
) -> Result<(), MlError>;
```

**`exp_f32(x)` (private).** `exp(x) = 2^(x·log2e)`: `t = x·LOG2E`, `k = round(t)`,
`f = t − k ∈ [−0.5, 0.5]`; `2^k` by writing `k+127` into an `f32` exponent via
`f32::from_bits` (safe), `2^f` by a fixed **degree-4 minimax polynomial**. Softmax
always passes `x = xᵢ − max ≤ 0` and we **clamp `x ≥ −87.3`** (below which `2^k`
underflows to 0), so `k` stays bounded — no overflow, no NaN. Every step is a
correctly-rounded IEEE-754 primitive (`+ − × ÷`, `from_bits`), no `fma`, default
round-to-nearest → **bit-identical on any conformant host**.

**`rsqrt_f32(x)` (private).** `0x5f37_59df` bit-hack guess + **two Newton steps**
`y ← y·(1.5 − 0.5·x·y²)`; ~1e-6 rel. error, deterministic. Caller `eps` (e.g. `1e-5`)
keeps `σ²+eps > 0`.

Determinism (why the integer anchor stays exact): int8 GEMMs are bit-exact across
tiers; softmax/layernorm are **scalar `f32`** from correctly-rounded primitives only,
identical on every tier and host. So `x2` is bit-identical everywhere and its int8
requantization (the anchor) is exact — the same oracle the MLP proof uses.

## Public interface — fail-safe entries (M4 hardening)

```rust
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MlError {
    /// A tensor buffer length did not match the length its dims imply.
    LengthMismatch,
    /// A required dimension (seq/d_model/n_heads/d_ff) was zero.
    ZeroDimension,
    /// d_model is not divisible by n_heads (ragged heads).
    HeadsIndivisible,
    /// A dimension product overflowed `usize` (checked_mul last-line guard).
    ShapeOverflow,
}

pub struct TransformerBlockDims { pub seq: usize, pub d_model: usize, pub n_heads: usize, pub d_ff: usize }
pub struct TransformerBlockWeights<'a> { /* wq,wk,wv,wo [D×D]; w1,b1,w2,b2 (FFN); ln1_g/b, ln2_g/b [D] */ }
pub struct TransformerBlockScratch<'a> { /* caller-owned i8/i32/f32 work buffers, sized from dims */ }

/// One pre-norm transformer block forward, in place on `x` (`[seq × d_model]`).
/// Returns `Err` on any dim/length/overflow inconsistency — never panics on bad input.
pub fn transformer_block(
    dims: TransformerBlockDims,
    w: &TransformerBlockWeights<'_>,
    x: &mut [f32],
    s: &mut TransformerBlockScratch<'_>,
) -> Result<(), MlError>;
```

The grouping structs keep the signature small (dodges `clippy::too_many_arguments`).
Existing APIs (`gemm_i8`, `quantize`, `dense_pre_activation`, …) are **unchanged** —
assert-based contracts kept; only the new entries add `Result`. Validation order:
(1) zero dims → `ZeroDimension`; (2) `n_heads ∤ d_model` → `HeadsIndivisible`;
(3) each size product (`seq·d_model`, `d_model²`, `d_ff·d_model`, `seq²`) via
`checked_mul` → `ShapeOverflow`; (4) each slice length → `LengthMismatch`. Then compute.

## Determinism anchor & boot proof

**Anchor (exact, tier-independent).** After the block output `x2` (`[S×D]` f32),
**requantize** it to symmetric int8 (`quant_scale` + `quantize`) and checksum:
`INFER_BLOCK_CHECKSUM = Σ (x2q[i] as i64)` over all `S·D = 512` elements. Exact
because it is taken *after* requantize; tier-independent because `x2` is bit-identical
across tiers. The implementer freezes the literal; `tfb_boot_proof_checksum_is_stable`
guards it against drift.

**Boot proof** (`infer_block_prove`, in `kmain` after `infer_prove`). Runs the fixed
`D=32,H=2,S=16` block with deterministic weights (reuse `infer_fill`) on stack
buffers, checks the anchor, prints fmt-free:

```
[ml] tfb: d32-h2-s16 int8 block via <tier> ok; tfb checksum=<N>
```

`" ok"` vs `" FAIL"` branches on the anchor match; the checksum prints
unconditionally (like `infer_prove`). New xtask marker (matching `ML_MLP_OK` style —
non-vacuous, spans the pass-branch word through the exact digits):

```rust
const ML_TFB_OK: &str = "ok; tfb checksum=<N>";
```

Asserted in `kernel/xtask/src/main.rs` on both the always-on TCG boot test and the
KVM job. Runs on **any** host with no feature gates: GEMMs fall back to scalar where
no vector tier exists; softmax/layernorm are pure scalar.

## Invariants

- No new `unsafe`; `kernel` stays `#![forbid(unsafe_code)]`; TCB registry unchanged.
- Every GEMM has `n = S`; the block allocates nothing (stack-only). `softmax_rows`
  rows sum to 1 within `f32` tolerance, never NaN/overflow.
- The int8 anchor is identical on scalar/AVX2/AVX-512F/VNNI and on any IEEE-754 host.
- New entries never panic on caller input — all bad shapes return `Err(MlError)`.

## Testing (house convention — runs on any host, no feature gates)

- **f32-reference match** (`transformer_block_matches_f32_reference`): quantized block
  vs a pure-`f32` forward (LN, MHA, softmax, residual, FFN); assert `max_err <
  0.1·range`. Catches transposed weights, wrong softmax axis, wrong `1/√Dh`, wrong scale.
- **Primitive units:** `softmax_rows` (`[0,0]→[0.5,0.5]`, rows sum to 1, large-input
  stable), `layernorm_rows` (zero-mean/unit-var), `exp_f32`/`rsqrt_f32` vs a reference.
- **Error tests** (M4): mismatch/zero-dim/indivisible-heads each return `Err`, not panic.
- **Checksum stability** (`tfb_boot_proof_checksum_is_stable`): anchor == constant.
- **Boot proof**: xtask asserts `ML_TFB_OK` (TCG + KVM) — end-to-end block inference.

## Limits (scope OUT)

One block, fixed deterministic weights, one forward pass — MLP-proof spirit. **No**
model loading, **no** KV cache / incremental decode, **no** multi-block stacking,
**no** bf16, **no** causal masking (full bidirectional attention), per-tensor (not
per-channel) quant. Follow-on steps.

## Implementation plan / PR checklist (owner: **kernel-engineer**; verify: **verification-engineer**)

1. Add `MlError` + a private `checked_shape` helper (`checked_mul` chain →
   `ShapeOverflow`).
2. Implement `exp_f32` (2^x reduction + degree-4 poly + clamp) and `rsqrt_f32`
   (bit-hack + 2 Newton); private, no `Result`.
3. Implement `softmax_rows` / `layernorm_rows` (public, `Result`) on them; validate
   dims first.
4. Add private packers: transposing `quantize` (`[S×D]→[D×S]`), per-head `Qhᵀ`/`p_hᵀ`
   stack packers, `concat_heads`. All safe, alloc-free.
5. Define `TransformerBlockDims`/`Weights`/`Scratch` + `transformer_block` (`Result`);
   wire the data-flow (LN1 → QKV proj → per-head scores/softmax/context → O proj →
   residual → LN2 → `dense_pre_activation`×2 + `relu_inplace` → residual), reusing
   `gemm_i8` for all five matmul kinds.
6. Add `INFER_BLOCK_CHECKSUM` + `infer_block_forward_checksum()` (shared by proof and
   host test); compute the literal and freeze it.
7. Add `infer_block_prove()` (fmt-free, `[ml] tfb: … ok; tfb checksum=<N>`); call in
   `kmain` after `infer_prove`.
8. Host tests: f32-reference match, primitive units, error/`Result` cases,
   checksum-stability guard.
9. Add `ML_TFB_OK` marker + assertion in `kernel/xtask/src/main.rs` (TCG + KVM),
   mirroring `ML_MLP_OK`. **(owner: build-engineer)**
10. Update `2026-07-14-aiml-inference-compute-design.md` "Inference workloads" to cite
    this as workload #2; note softmax/layernorm added.
11. Gate (**verification-engineer**): `clippy -D warnings`, `cargo test -p kernel`,
    `cargo xtask test`, `cargo xtask check-no-vector` (must still pass). Optionally an
    in-tree `#[cfg(kani)]` totality harness for the shape validators (not the enforced
    gate — host tests are), matching the `ml` precedent.

## Open questions

- **Per-head vs per-tensor Q/K/V scales.** Chosen per-tensor for simplicity; revisit
  per-head if the f32-reference tolerance test proves tight on scores accuracy.
- **`exp_f32` polynomial order.** Degree-4 to start; the primitive test's error bound
  decides degree-3 vs -5. Deterministic + correct either way.
- **Causal mask / KV cache.** Deferred to v3 (autoregressive decode; ties to Track B
  NVMe/CXL KV state); a mask arg can be added without breaking the signature.
