---
name: storage-caps-fs4-checks
description: Before FS-4 enforces storage caps, settle two FS-1c items - SnapshotRo binds by name only (bind the gen), and unusable op bits still install (refuse them in is_well_formed)
type: gotcha
owner: security-engineer
date: 2026-10-25
source: https://github.com/veetihietasalo/sentinelos/pull/42#issuecomment-6397979669
---

The FS-1c storage-capability lattice (#42, `kernel/crates/kernel/src/cap/storage.rs`) was reviewed sound on 2026-10-25: no amplification. Latent until FS-4 routes storage operations through `CapSpace::check`:
1. `Tree::SnapshotRo(SnapshotName)` (`storage.rs:419`) names a snapshot by name only. After a delete or Format and a new snapshot with the same name, an old capability reads the new snapshot. Fix: carry the snapshot's `gen` in `SnapshotRo` and in the kind-1 wire form, cheaper before kind 1 is hashed into ComponentIds.
2. `is_well_formed` (`cap/mod.rs:571`) accepts op bits that can't apply: `{Write, Rollback, Format}` over `/app`, `Write` on a `SnapshotRo`. They do nothing only because `admits` (`storage.rs:804`) checks prefix and tree. Fix: refuse Snapshot/Rollback/Format unless the prefix is root and the tree is `Live`, and `Write` unless the tree is `Live`.
3. Quota fan-out (T-STO-6) is open by design until FS-4.

**Why:** staff and security review after #42 merged, 2026-10-25.

**How to apply:** an FS-4 design or review checks these three first. FS-4 must never act on a capability's `ops` alone.
