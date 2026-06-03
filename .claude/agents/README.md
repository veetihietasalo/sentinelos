# SentinelOS Agent Team Charter

SentinelOS is a from-scratch, security-first x86_64 Rust OS. This team of 7 Claude Code subagents covers the full development lifecycle — from architecture through formal verification to adversarial review.

---

## The Team

| Agent | Model | Role |
|-------|-------|------|
| **kernel-architect** | Opus | Turns specs into concrete module/interface designs; enforces the framekernel TCB boundary; writes design docs; does NOT write implementation code |
| **hal-specialist** | Opus | Owns all `unsafe` HAL/arch code (port I/O, MMIO, CPU instructions, paging); wraps every `unsafe` block behind a safe API with rigorous `// SAFETY:` justifications |
| **kernel-engineer** | Sonnet | Implements the bulk of the kernel as safe Rust (`#![forbid(unsafe_code)]`); consumes HAL's safe APIs; never writes `unsafe` |
| **verification-engineer** | Opus | Runs Miri, writes Kani proof harnesses and fuzz targets for the unsafe core; owns the CI verification gate; blocks merge of unverified `unsafe` |
| **test-engineer** | Sonnet | Builds and maintains the test harness: QEMU integration/boot tests (isa-debug-exit + serial), unit tests, regression suites |
| **toolchain-engineer** | Sonnet | Owns Limine setup, linker scripts, `x86_64-unknown-none` target config, xtask/cargo runner, QEMU invocation, and CI workflows |
| **kernel-reviewer** | Opus | Adversarial read-only reviewer; final merge gate for soundness, UB, idiomatic Rust, and framekernel discipline; approves or blocks |

---

## Workflow

```
Requirement / spec
       |
       v
kernel-architect  ──→  docs/<subsystem>.md + implementation plan
       |
       ├──→  hal-specialist    (unsafe HAL code, safe API surface)
       |
       └──→  kernel-engineer   (safe Rust kernel crates)
                    |
                    v
       verification-engineer   (Miri + Kani + fuzz gate on unsafe code)
       test-engineer           (unit tests + QEMU integration tests)
                    |
                    v
       kernel-reviewer         (adversarial review → APPROVED / BLOCKED)
                    |
                    v
                  merge
```

Verification and testing run in parallel after implementation. kernel-reviewer is the final gate and requires both verification-engineer sign-off (for any `unsafe`) and test-engineer confirmation before approving.

---

## Model Split Rationale

**Opus** handles work where judgment, thoroughness, and adversarial reasoning are paramount:
- `kernel-architect` — architecture decisions are hard to reverse; a wrong TCB boundary is a security flaw.
- `hal-specialist` — every `unsafe` block is a potential CVE; Opus's deeper reasoning catches subtle aliasing and provenance issues.
- `verification-engineer` — writing sound Kani harnesses and interpreting Miri output requires careful formal reasoning.
- `kernel-reviewer` — adversarial review benefits from Opus's ability to construct failure scenarios.

**Sonnet** handles work that is well-defined, volume-heavy, and benefits from speed:
- `kernel-engineer` — implementing safe Rust from a clear design doc is execution-heavy, not judgment-heavy.
- `test-engineer` — test writing is structured and iterative; speed matters for CI feedback cycles.
- `toolchain-engineer` — build tooling is largely mechanical; correctness is verified by "does it build and run."

---

## Key Invariants

1. **One TCB, minimum surface.** Only the HAL crate contains `unsafe`. Every other crate carries `#![forbid(unsafe_code)]`.
2. **No `unsafe` merges unverified.** verification-engineer sign-off is a hard prerequisite for kernel-reviewer approval.
3. **Design before code.** kernel-architect produces a `docs/<subsystem>.md` before any implementation begins.
4. **Stable toolchain only.** No `#![feature(...)]` without a documented, justified exception reviewed by kernel-architect and toolchain-engineer.
5. **kernel-reviewer is read-only.** The reviewer reports findings; authors fix them. This separation prevents reviewers from introducing new bugs while "helping."
