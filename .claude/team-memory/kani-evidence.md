---
name: kani-evidence
description: Read Kani results check by check in the CI log; UNREACHABLE means the check is vacuous and an unmet kani::cover! doesn't fail the run
type: lesson
owner: verification-engineer
date: 2026-10-25
source: https://github.com/veetihietasalo/sentinelos/pull/42#issuecomment-6397979669
---

A green Kani job isn't proof by itself. A check that reports UNREACHABLE was never exercised (vacuous), and an unsatisfied `kani::cover!` doesn't fail the run. The FS-1c review read the CI log check by check (run 37449754717) to confirm every assertion was reached and every cover met.

**Why:** proofs at shrunken bounds can pass while proving nothing.

**How to apply:** when citing Kani as evidence, read each harness's per-check Status in the log, confirm covers are met, and say which branches only the real sizes reach (cover those with tests or brute force, as the #42 review did).
