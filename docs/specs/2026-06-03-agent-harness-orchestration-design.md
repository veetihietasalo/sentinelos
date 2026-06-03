# SentinelOS Agent Harness — Orchestration & Handoffs Design

- **Date:** 2026-06-03 · **Status:** design approved, pre-implementation
- **Scope:** Improve the *development* agent harness (the machinery that builds the OS), not a product feature.
- **Focus (chosen):** (2) orchestration/automation + (4) agent definitions & handoffs. Staged delivery (Approach C).

## Context

The harness today is: 14 custom subagents in `.claude/agents/` with a documented DAG
(`spec → architect → implement → verify+test → review → merge`) and 7 invariants; a manual
dashboard (`tools/agent-dashboard/set-status` → `status.json` → `index.html`); spec-driven docs
(`docs/specs`, `docs/plans`); and CI (`.github/workflows/kernel.yml`: build + clippy + fmt + boot-test).

Three gaps motivated this work: orchestration is a prose DAG, not runnable; handoffs are implicit;
the dashboard is hand-maintained and `status.json` churns git. (A separate gap — the Miri/Kani/fuzz
verification gate being documented-but-unbuilt — is **explicitly out of scope** here.)

## Goal

Make the build pipeline actually *run* as a **hybrid Workflow with human gates** — automation where
it's safe, human approval where it matters (merge, TCB/security) — with **sharp, typed handoffs**
between agents. Subscription-covered (runs from an interactive session; not headless/programmatic).

## Non-goals (deferred to later staged cycles)

- The full pre-implementation **security-escalation gate** (invariant #6). This round only *surfaces*
  the `tcbTouch` flag loudly; it does not block before implementation.
- Building the real **Miri/Kani/fuzz verification stack** (that is the separate "verification gate" effort).
- Sharpening the **8 idle specialist agents** (driver/scheduler/security/userland/ui/docs/toolchain + reviewer-of-those).
  Each is sharpened when its subsystem first comes up.
- Dashboard UI redesign / history-timeline (observability track).
- Headless/autonomous execution (`claude -p` / Agent SDK) — deliberately avoided (metered from 2026-06-15).

## Backbone decision

- **Durable source of truth = the plan file in git.** Each sub-project's `docs/plans/<id>.md` carries the
  definition-of-work plus a machine-readable **gate block**: `architect / implemented / verified / tested / reviewed`.
  This is the contract and the human-review surface; it survives across runs.
- **Intra-run handoffs = the Workflow's own control flow.** Within a run, each stage's *typed* output
  (schema-validated) feeds the next. No external task-ledger — the Workflow is the scheduler.
- **Live status = the dashboard, auto-written by the Workflow.** `status.json` becomes a runtime view,
  written atomically by the Workflow as stages run, and is **gitignored** (ends the churn).

## Architecture (4 pieces)

| Piece | Location | Job |
|---|---|---|
| Orchestration Workflow | `.claude/workflows/build-subproject.js` | Drives one sub-project through the pipeline; invokable by name; run from an interactive session. |
| Plan file (contract) | `docs/plans/<id>.md` | Durable definition-of-work + machine-readable gate block. Git-tracked. |
| Dashboard (live view) | `tools/agent-dashboard/` | `status.json` auto-written by the Workflow; `index.html` renders it; `status.json` gitignored. |
| Agent contracts | `.claude/agents/*.md` | The 7 core agents gain typed I/O + tool boundaries + Definition of Done. |

The Workflow dispatches existing custom agents via `agent(prompt, {agentType: '<name>', schema})` — same
registry as the Task tool, so no new agent infrastructure.

## Pipeline & human gate (control flow)

`build-subproject(<id>)` runs on a dedicated branch `feat/<id>` (created from `main`, never on `main`):

```
preflight → architect → implement → (verify ∥ test) → review → ⛔ HALT (review-ready)
   branch+    design +    right       Miri/clippy +     kernel-reviewer
   read spec  TCB flag    engineer    QEMU boot/integ   APPROVED / BLOCKED + findings
                          (memory-eng (typed verdicts)  (typed)
                           for #2b)
```

- **The merge gate is a STOP, not an interactive pause.** A Workflow runs to completion and returns, so
  the gate = run everything *up to* a review-ready state, then **halt without merging or pushing**. The
  Workflow returns: branch, diff stat, verify+test verdicts, reviewer verdict, updated plan-file gate block.
  The human reviews; if approved, **merge to `main` is a separate explicit step** the human triggers.
  (Respects invariant #5: reviewer is read-only; and the no-auto-push rule.)
- **BLOCKED** → bounded retry loop (`implement → verify → review`, max 2), then halt to the human.
- **Unverified-`unsafe` hard stop:** `unsafeIntroduced && verify ≠ pass` → halt; never reaches review-ready.
- **TCB-touch surfacing:** architect `tcbTouch:true` → flagged loudly in the halt summary.
- First real run: **sub-project #2b frame allocator** (architect → `memory-engineer` → verify∥test → review).

## Agent contracts (typed handoffs)

Each core agent's `.md` gains an **Inputs** note, an **Output schema** (validated by `agent(…, {schema})`),
a **tool boundary**, and a one-line **Definition of Done**.

| Agent | Output schema | Boundary | DoD |
|---|---|---|---|
| kernel-architect | `{designDocPath, modules[{name,publicApi}], tcbTouch, unsafeRequired, openQuestions[]}` | design only, no impl | design doc committed + interfaces enumerated + TCB flag set |
| memory-engineer (impl) | `{filesChanged[], publicApi[], unsafeIntroduced, buildsClean, needsHal?, notesForReview[]}` | `forbid(unsafe)`; must not edit HAL crate — sets `needsHal` | builds clean + author-run tests + schema filled |
| hal-specialist (if `needsHal`) | same shape, `unsafeIntroduced:true`, each site `// SAFETY:` ref | only agent allowed to author `unsafe` | every `unsafe` block has a SAFETY justification |
| verification-engineer | `{ranTools[], verdict:pass\|fail, unsafeCovered, findings[]}` | runs tools; no `src/` edits | verdict emitted; any unsafe covered or flagged |
| test-engineer | `{ranTests[], verdict:pass\|fail, qemuExit, failures[]}` | QEMU boot/integration only | verdict emitted with QEMU exit code |
| kernel-reviewer | `{verdict:APPROVED\|BLOCKED, blockers[], nits[]}` | read-only (no Edit/Write) | verdict + findings emitted |

## Guardrails

- Never merges/pushes `main`; works only on `feat/<id>` (ends concurrent-collision problems).
- Schema-mismatch auto-retries (built into `agent(schema)`); whole-stage failure surfaces partial state, merges nothing.
- `status.json` written atomically (reusing `set-status`'s temp-file-then-`os.replace` pattern); gitignored.
- All hard stops above (unverified-unsafe, BLOCKED-after-retries) leave a review-ready or clearly-failed state, never a silent merge.

## Testing the harness

Proven on the real **#2b frame allocator** run, then asserted with evidence:

1. Pipeline drives `architect → memory-engineer → verify∥test → review` and halts review-ready.
2. Result is on `feat/2b-frame-allocator`; **`main` HEAD unchanged**; no merge/push occurred.
3. Plan-file gate block updated to reached stages; `status.json` written + dashboard renders; `git status` shows it ignored.
4. Reviewer + verify/test verdicts present in the Workflow output.
5. (Optional negative check) inject an `unsafe` with no verification → confirm the hard-stop fires.

## File-change summary (for the implementation plan)

- **New:** `.claude/workflows/build-subproject.js` (orchestration Workflow).
- **New/Modified:** `docs/plans/2026-06-03-2b-frame-allocator.md` (plan file with gate block) — produced by the architect stage from the sub-project #2 decomposition (no standalone #2b spec exists yet; the architect stage generates the design).
- **Modified:** `.claude/agents/{kernel-architect,memory-engineer,hal-specialist,verification-engineer,test-engineer,kernel-reviewer}.md` (contracts).
- **Modified:** `tools/agent-dashboard/index.html` (render auto-written run state) + `.gitignore` (ignore `status.json`).
- **Modified:** `tools/agent-dashboard/set-status` may be refactored into a small shared writer the Workflow reuses.

## Future stages (after this proves out on #2b)

1. Add the full pre-implementation security-escalation gate (invariant #6).
2. Sharpen each specialist agent as its subsystem first runs through the pipeline.
3. Deepen the verification step into the real Miri/Kani/fuzz gate.
4. Dashboard history/timeline + richer live view.
