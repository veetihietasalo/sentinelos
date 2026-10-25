---
name: hal-needs-veeti-signoff
description: Any change under kernel/crates/hal (the unsafe TCB) needs Veeti's own sign-off; reviews approve the rest and give him a numbered file:line list of what to judge
type: decision
owner: kernel-reviewer
date: 2026-10-25
source: https://github.com/veetihietasalo/sentinelos/pull/44#issuecomment-6397944991
---

`kernel/crates/hal` is the unsafe TCB, documented row by row in `kernel/docs/hal-tcb.md`. A PR that touches it merges only after Veeti signs off the hal part himself. Agent reviews (kernel-reviewer, verification-engineer, the company staff and security engineers) cover everything else and end with a numbered `file:line` list for him: new ports or values, contract changes, premises such as "no cross-core migration".

**Why:** set in the merge-queue brief for #44 (FS-1b) on 2026-10-25.

**How to apply:** the verdict on a hal-touching PR reads "merge after your hal sign-off" plus the list. PR branches here are `venomity/*`, Veeti's own sessions: never push to them (company memory branch-ownership).
