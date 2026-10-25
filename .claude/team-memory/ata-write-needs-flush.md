---
name: ata-write-needs-flush
description: hal ATA write_sectors no longer flushes; durability needs an explicit flush() (kernel::fs once per save, SentinelFS twice per commit); skipping it loses data silently
type: gotcha
owner: hal-specialist
date: 2026-10-25
source: https://github.com/veetihietasalo/sentinelos/pull/44#issuecomment-6397944991
---

Since FS-1b (#44), `write_sectors` (`kernel/crates/hal/src/ata.rs:616`) doesn't flush the drive cache. Durability needs `flush()` (`ata.rs:664`). Today `kernel::fs` calls it once per save (`fs.rs:749`) and SentinelFS twice per commit (`write_commit`, `volume.rs:414`).

**Why:** the flush split lets a commit order its writes; the staff review on 2026-10-25 flagged that a new caller that skips `flush()` loses durability with no error.

**How to apply:** any new code that writes through the ATA driver and needs the data to survive power loss calls `flush()` at its durability points, and the crash sweep (`xtask`) should cover it. Reviewers check new `write_sectors` callers for it.
