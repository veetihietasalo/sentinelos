---
name: ata-wait-premises
description: ATA deadlines are uncalibrated TSC cycles sized for 5 GHz (a wedged drive can hold CHANNEL ~41 s at 5 GHz, ~7 min at 0.5 GHz), and TCB row C16 assumes a wait never changes core
type: gotcha
owner: hal-specialist
date: 2026-10-25
source: https://github.com/veetihietasalo/sentinelos/pull/44#issuecomment-6397944991
---

- Deadlines in `ata.rs:144-150` are raw TSC cycles sized for 5 GHz: SECTOR_BUDGET 4e9, FLUSH_BUDGET 4e10, RESET_BUDGET 1.6e11, SRST_SETTLE 1e7. On a slower TSC they stretch. A wedged drive holds `CHANNEL` for up to about 41 s at 5 GHz and about 7 min at 0.5 GHz, and `identify` at boot blocks that long. Failure path only.
- `reset_channel` (`ata.rs:407`) writes `0x3F6` (SRST|nIEN, then nIEN), which resets both drives on the primary channel; only the master is used.
- hal-tcb row C16 assumes an ATA wait never changes core. True today (`sfs-commit` is `spawn_on(0)`, the toy FS runs on kmain).

**Why:** the hal items in the staff review of #44, 2026-10-25.

**How to apply:** revisit the budgets when TSC calibration lands, and C16 the moment the scheduler can migrate tasks or a second drive is used. Those changes are hal changes and need Veeti's sign-off.
