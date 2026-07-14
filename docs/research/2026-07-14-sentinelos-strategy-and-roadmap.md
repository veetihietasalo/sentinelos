# SentinelOS — strategy & literature-grounded roadmap

_Status: **strategy note** (living). Synthesizes two research handoffs — a
1,592-paper arXiv systems literature map (Sep 2025–Jul 2026) and a SentinelOS-
specific improvement map keyed to our tracks — into a north-star, a wedge, and a
sequenced plan. Cited arXiv IDs are **design references** (recent, relevant,
real), not benchmarked endorsements; read before adopting._

## 1. Vision, stated honestly

The ambition: a **from-scratch, security-first Rust OS** that is (a) **private by
construction**, (b) a **full desktop** — eventually including games, (c) a
**top-tier AI/ML platform**, all on a tiny verifiable TCB.

As a literal, all-at-once end state on any near horizon, that is too big — and
chasing it frontally is how ambitious OSes die. "Run everyone's games / all their
apps" is the **app-gap + GPU/game-compat moat** (Linux needed ~30 years + Valve's
Proton + vendor drivers; Fuchsia had Google's budget and still isn't a desktop).
"Extreme AI/ML" head-on is the **CUDA moat**. Five infinite fronts, one small
team, finish none.

So we separate **vision (the "why", a horizon)** from **strategy (the "what", a
wedge)**. The vision is fine to say out loud; the plan commits to a wedge.

## 2. The wedge: the sovereign, private AI-native OS

Pick the one thing SentinelOS can be **best in the world at**, where the
security-first architecture is a **moat, not a tax**:

> **The OS where your models and your data stay encrypted and isolated from the
> host itself** — confidential AI compute on a `#![forbid(unsafe_code)]` kernel
> with a tiny, machine-checked TCB.

This is a real, growing, *underserved* niche — no consumer OS is "AI-private by
construction" — and the research front is forming around exactly it: confidential
AI spanning CPU **and** GPU TEEs ([arXiv:2606.31408](https://arxiv.org/abs/2606.31408)),
kernel-level inference primitives for "AI-native operating systems"
(`ProbeLogits`, arXiv:2604.11943), and "sovereignty kernels" for verifiable agent
execution (arXiv:2602.20214). Niche ≠ failure: **Tock** (a from-scratch Rust OS,
arXiv:2603.22585) secures ~10M devices and never ran a game; **Redox**,
**SerenityOS** are real, respected Rust OSes. Mattering is not replacing Windows.

"Full desktop / games" then becomes the honest **long tail** layered on top —
which is exactly how our own README already frames GPU/games/browser ("the long
road, #9").

## 3. Where we sit vs. the front

The systems research front is **captured by systems-for-AI**: 41% of the corpus
cross-lists with an ML category; the largest LLM-specific cluster is inference
serving. Our near-term tracks live in the smaller, slower, higher-rigor corners —
security/isolation, Rust/verified systems, tiered memory/CXL. The lesson (and the
shape of this plan):

> **Foundations borrow from the verification + confidential-computing literature.
> The endgame borrows from the serving literature.**

Recent-work depth per track (papers in the corpus touching each area) shows where
there's the most to learn from: real-time/determinism 316 · SMP/scheduling 301 ·
security/isolation 81 · Rust/verified 65 · device I/O 40 · CPU/SIMD inference 39 ·
tiered-memory/CXL 32 · memory-encryption/TEE 20.

## 4. The two "get-it-right-once" decisions (highest leverage)

A from-scratch kernel makes these **once**; retrofitting either is the pain most
of the cited papers exist to survive.

1. **Formalize the `unsafe` HAL/TCB boundary now, while it is small.** We already
   catalogue every unsafe op in `kernel/docs/hal-tcb.md` and just added the
   CR4/MSR primitives (C7–C10). The next step is **machine-checked contracts** on
   those primitives before the TCB outgrows a human reviewer — agent-assisted
   verification of Rust systems code is an active method (`VeruSAGE`,
   arXiv:2512.18436). Concretely: Kani proof harnesses + a Miri lane in CI as a
   merge gate for anything touching `hal`.
2. **Make tiered-memory / CXL a first-class abstraction from the start.** Small in
   the literature (32 papers) but every one is a systems paper and it is where
   hardware is going. Design the frame allocator / page policy around a
   **tiering control loop** and **multi-tenant fairness** now
   ([arXiv:2604.12165](https://arxiv.org/abs/2604.12165) adaptive tuning;
   [arXiv:2602.08800](https://arxiv.org/abs/2602.08800) fair multi-tenant CXL),
   with CXL-hybrid/disaggregated memory for inference/KV as the bridge to Track C
   ([arXiv:2606.12556](https://arxiv.org/abs/2606.12556),
   [arXiv:2606.19746](https://arxiv.org/abs/2606.19746)).

## 5. Per-track plan, keyed to the literature

### Track A — CPU security foundations (shipped: detect → enforce)
Done: CPUID vendor + security/ML detection; NX/SMEP/SMAP/UMIP enforced at boot,
with SMAP-before-userland forcing a `stac`/`clac`-guarded `copy_to/from_user`.
Next:
- **Formalize the TCB** (decision #1 above; `VeruSAGE` arXiv:2512.18436).
- **Design the userland ABI capability-style up front** so bounds/isolation are
  not retrofitted — the CHERI-style object-bounds lesson on stock x86_64
  ([arXiv:2606.19055](https://arxiv.org/abs/2606.19055)); same reasoning we
  applied to SMAP.
- **Wire performance counters early** to *test* isolation empirically, not just
  assert it ([arXiv:2601.01265](https://arxiv.org/abs/2601.01265)).
- **SMP (x2APIC → AP bring-up):** decide lock-free/NUMA-aware per-CPU data and
  run-queue layout **at bring-up**, not bolted on
  ([arXiv:2601.20435](https://arxiv.org/abs/2601.20435)); keep speculation-barrier
  primitives available in the HAL.

### Track A/C — SME/TME → confidential AI (the wedge's core)
Raw memory encryption is only half; the differentiator is **end-to-end
confidential AI**:
- CPU **and** GPU TEEs together ([arXiv:2606.31408](https://arxiv.org/abs/2606.31408)) — the north star.
- Confidential compute has a **real throughput cost**; design the data path to
  minimize host↔TEE serialization ([arXiv:2606.23969](https://arxiv.org/abs/2606.23969)).
- The **world-switch / syscall path is the bottleneck** — read before designing
  the SME/TME enablement policy ([arXiv:2601.16448](https://arxiv.org/abs/2601.16448)).

### Track B — device I/O: skip to the modern, accelerator-centric model
Don't reimplement a 2005-era block stack:
- Make the accelerator a **first-class I/O initiator** (GPU-centered NVMe-oF,
  [arXiv:2607.04415](https://arxiv.org/abs/2607.04415)).
- **NVMe as a tier for model/KV state** ([arXiv:2604.26557](https://arxiv.org/abs/2604.26557)) — ties Track B directly to Track C.
- **Computational storage on CXL SSDs** as the forward-looking bet
  ([arXiv:2604.02442](https://arxiv.org/abs/2604.02442)).

### Track C — CPU/SIMD inference is the pragmatic near-term AI play
Before any GPU/CUDA:
- **Quantization + memory layout make CPU/SIMD inference competitive** — int4 KV
  beating fp16 ([arXiv:2605.05699](https://arxiv.org/abs/2605.05699)).
- **AMX-aware inference path**: we already have the CPUID detection framework —
  add AMX/AVX-512 detection and a matrix-extension inference kernel for a
  concrete, differentiated feature ([arXiv:2606.16332](https://arxiv.org/abs/2606.16332)).
- **Cold-start / first-token latency is an OS concern** (paging, prefault,
  pinning) — squarely our wheelhouse ([arXiv:2604.09083](https://arxiv.org/abs/2604.09083)).
- Long-horizon: OS orchestrates, accelerator executes ([arXiv:2604.07609](https://arxiv.org/abs/2604.07609)).

### Cross-cutting angle — real-time / determinism (reclaim "Sentinel")
A **time-predictable** posture would differentiate us from general-purpose
kernels (316 papers to borrow from): adopt WCET / mixed-criticality vocabulary
([arXiv:2606.26177](https://arxiv.org/abs/2606.26177)) and a **stall-aware memory
allocator** that pairs with the tiered-memory design
([arXiv:2511.19991](https://arxiv.org/abs/2511.19991)).

### Track D — ASIC (pending)
Still blocked on the concrete device + interface + purpose. When specified, it
plugs into the **accelerator-centric I/O model** (Track B) and the **compute
abstraction** (Track C) rather than being a bespoke stack.

## 6. Sequencing

1. **Foundation** — formalize the TCB; land the tiered-memory abstraction;
   SMP/x2APIC with per-CPU + run-queue done right. *(borrows: verification, RT)*
2. **Confidential AI compute** — SME/SEV/TME enablement aimed at confidential
   inference; CPU/SIMD (AMX) inference path. *(the wedge)*
3. **Device breadth** — accelerator-centric NVMe/xHCI, ACPI/PCIe. *(usable HW)*
4. **Desktop / games** — GPU/graphics stack, compositor, apps. *(honest long tail)*

## 7. Immediate next actions

- **A1 — TCB formalization:** add Kani proof harness(es) for the `hal::cpu`
  CR4/MSR primitives and a Miri lane in CI as a merge gate for `hal` changes.
- **X1 — tiered-memory design doc:** a `docs/specs/` spec for a tiering-aware
  frame allocator / page policy (control loop + fairness), before the allocator
  ossifies.
- **C1 — extend CPUID detection with AMX/AVX-512 family bits** (cheap, we have the
  framework) to unblock the near-term inference path.

## 8. Provenance & caveats

- Grounded in two user-provided research handoffs (the literature map + the
  SentinelOS improvement map). Citations are **design references**, not validated
  endorsements; arXiv metadata only (submission-volume "front", not settled
  consensus). Some IDs fall inside the harvest window and were not independently
  re-fetched here.
- This note is strategy, not commitment — tracks re-aim as reality lands.
