# AI-Augmented Engineering for a From-Scratch Rust OS — Research Briefing

- **Date:** 2026-06-03 · **For:** SentinelOS kernel planning
- **Method:** deep-research (5 angles → 25 sources → 119 claims → 25 adversarially verified; 21 confirmed, 4 refuted). Run `wf_5905daaa-a05`.
- **How to read:** every claim below was 3-vote verified unless marked. **Refuted/hype claims are listed at the end — don't skip them.**

## TL;DR

AI is most reliable for **structured, spec-driven scaffolding** and for **orchestrating verification/fuzzing** — and **dangerous to trust on raw `unsafe` Rust in a kernel.** The winning strategy for a solo+AI OS build is *architectural*, not magical: **shrink the `unsafe` surface to a tiny trusted core, then throw layered verification at that small core.** Full seL4-style proof is not realistic solo (~11 person-years, ~20:1 proof-to-code); aim for *minimized unsafe + targeted verification + fuzzing + Miri in CI*, not total functional-correctness proofs.

---

## Part 1 — Practical playbook (solo + agentic AI)

- **Spec-driven workflow is the backbone.** Adopt **spec → plan → tasks → implement** (GitHub **Spec Kit**) so the agent builds from durable Markdown artifacts, not ad-hoc prompts. *(3-0. Sources: github.github.com/spec-kit, github.com/github/spec-kit. Caveat: critics dispute its effectiveness vs. iterative prompting — the **structure** is what helps, not the ceremony.)* — **Note: this is exactly the spec→plan→implement flow we already used for the dashboard; it validates continuing it for the kernel.**
- **AI division of labor:** reliable for spec-driven scaffolding, **safe-Rust** services, and *running* verification/fuzzing tools; **not** to be trusted writing raw `unsafe` kernel code without a gate.
- **Budget note (per your authority/budget rule):** closed-source proof/verification LLMs incur real usage cost — estimate + approve before spend. The locally-deployable **7B AutoReal-Prover** is the cost-avoidance path. *(see Part 2)*

## Part 2 — Verification & safety for kernel-grade Rust

- **The #1 structural defense: bound the `unsafe` surface (framekernel).** Asterinas confines its memory-safety TCB to **~14%** of code (vs Tock 44%, Theseus 62%, RedLeaf 66%) — only the `OSTD` core may use `unsafe`; services must be safe Rust. This containment holds **regardless of who/what authors the code**, which is precisely why it's the right architecture when AI is writing parts of the kernel. *(3-0. arXiv:2506.03876, USENIX ATC 2025.)*
- **No single verification tool suffices for `unsafe`.** Combine **bounded model checking (Kani)** + **separation logic (VeriFast)** + **refinement types (Flux)** — concurrency, unbounded data (linked lists), and generics need different proof obligations. *(3-0. verify-rust-std, arXiv:2510.01072.)*
- **Kani is the natural first tool** (only one targeting std + built for `unsafe`; MIR→Goto-C→CBMC) **but has blind spots: it silently misses data races, mutation of immutable data, and aliasing/lifetime violations.** Data-race UB is central to kernels and is **out of scope as of 2026** — so Kani-only is *false confidence*. Pair with **Miri/KernMiri**. *(3-0. arXiv:2410.01981, Kani docs.)*
- **Deductive verification is feasible on real Rust microkernels:** **Atmosphere** functional correctness was machine-proven with **Verus** (SMT/Z3, lighter than Isabelle). A realistic path for *selected* core invariants. *(3-0. SOSP 2025. Caveat: "full-featured" = research microkernel, not seL4 maturity.)*
- **AI can assist verification itself:** **AutoVerus** orchestrates LLM agents across generate→refine→debug to write Verus proofs; **AutoReal-Prover** (fine-tuned **7B**, locally deployable) hit **51.7%** automated success on 660 seL4 theorems (≈2× prior). Useful, but ~48% still fails — **not** full automation. *(3-0. arXiv:2409.13082, arXiv:2602.08384.)*
- **AI-augmented fuzzing works:** **deepSURF** found **12 previously-unknown** memory-safety bugs across 63 crates and beat non-LLM harness generators; LLM-generated harnesses need a **compiler validity oracle + retry**. *(3-0. arXiv:2506.15648, github.com/purseclab/deepSURF. Caveat: demonstrated on user-space crates, not kernels — transfer is extrapolation.)*
- **Reality check on cost:** **seL4** = ~200k lines of Isabelle proof for an 8.7k-line C kernel (**~20:1**), ~**11 person-years** for the seL4-specific proof vs ~2.2 py to build it. Full machine-checked proof is **not** a solo-feasible goal. *(3-0. CACM, trustworthy.systems.)*
- **Study Theseus** — a from-scratch Rust OS (~96% Rust) using **intralingual design**: push OS responsibilities (resource management) into the compiler via affine/ownership types (e.g. `MappedPages` enforcing bijective virtual↔physical mapping at compile time). *(3-0. theseus-os/Theseus, OSDI 2020. Caveat: up to 22.5% heap bookkeeping overhead.)*

## Part 3 — Landscape (UNDER-COVERED — treat as unsettled)

⚠️ The research's own caveats flag Part 3 as **barely substantiated by surviving verified claims** — almost everything that survived verification concerns verification tooling and Rust-OS prior art, not general AI-SWE productivity. Sources *were* fetched but their claims didn't make the verified cut, so treat these as **leads to follow up, not conclusions**:
- **METR 2025** randomized study suggesting AI **slowed** experienced open-source developers (contradicts vendor productivity claims) — `metr.org/blog/2025-07-10-...`.
- **GitClear 2025** code-quality concerns — `gitclear.com/ai_assistant_code_quality_2025_research`.
- **Veracode** — AI-generated code carried security flaws in ~half of tasks — via sdtimes.
- **Miri** (POPL 2026) as the practical UB-detection workhorse — `research.ralfj.de/papers/2026-popl-miri.pdf`.

## Refuted / hype flags (don't repeat these)

- ❌ AutoVerus ">90% of 150 tasks" — **refuted 0-3**. Don't cite the headline rate.
- ❌ Atmosphere verified in "<2.5 person-years ≈ unverified-dev speed" — **refuted 1-2**. SMT verification is **not** near unverified-dev speed.
- ❌ "LLMs can't even half-automate seL4 proofs" — **refuted 0-3** (the ~52% success is real).
- ❌ seL4 proof = "will never crash / never unsafe" — **refuted 1-2** (overstates the C-refinement proof).
- ⚠️ Citation note: the verify-rust-std coverage stats (~4% of core `unsafe` has Kani contracts) come from **arXiv:2510.01072**, not the 2024 AWS blog (numbers correct, URL was misattributed in one cluster).

## Recommended SentinelOS approach (synthesis)

1. **Architecture first:** framekernel — a minimal `unsafe` core (OSTD-style), everything else safe Rust. Cap the TCB you have to scrutinize.
2. **CI verification gate** — *no `unsafe` merges without passing:* compiler oracle + **Miri/KernMiri** + **Kani contracts** + **deepSURF-style fuzzing**. Treat Kani's blind spots (races, aliasing) as explicitly covered by Miri + fuzzing.
3. **Selective deductive proof (Verus)** on the few core invariants that matter most — not whole-kernel proof.
4. **AI usage:** agentic spec→plan→tasks→implement for scaffolding + safe-Rust services; AI to *operate* the verifiers/fuzzers; **human-gated** review on every `unsafe` block.
5. **Expectations:** target "small audited unsafe + layered checks," **not** seL4-grade total proof.

## Open questions (for the kernel session)

1. What does the real 2026 productivity/quality evidence (METR etc.) net out to for *low-level systems* Rust specifically? (Unanswered here.)
2. Can a **solo** dev practically run AutoVerus/AutoReal-Prover on local hardware, and at what real success rate / human overhead on *net-new* kernel code?
3. Concrete containment+verification stack & realistic assurance level for SentinelOS given seL4's 11-py / 20:1 benchmarks.
4. Exact CI gating design for AI-written `unsafe` (oracle + Miri + Kani + fuzz) and the false-confidence risk from Kani's UB blind spots.

---
*Raw verified-claim set + sources: deep-research run `wf_5905daaa-a05`. 25 sources, 21 confirmed / 4 refuted.*
