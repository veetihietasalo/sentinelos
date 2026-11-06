---
name: ata-wait-premises
description: ATA deadlines are durations at the PIT-measured TSC rate + 25 % (5 GHz cycle fallback before or without a measurement), and TCB row C16 assumes a wait never changes core
type: gotcha
owner: hal-specialist
date: 2026-10-25
source: https://github.com/veetihietasalo/sentinelos/pull/44#issuecomment-6397944991
---

- Since 2026-11-06 the deadlines are durations (`SECTOR_US`, `FLUSH_US`, `RESET_US`, `SRST_*_US` in `ata.rs`) converted at the TSC rate `kernel::interrupts::calibrate_tsc` measures against the PIT, + 25 %. Before that (or if the rate is refused: outside 100 MHz–10 GHz) they fall back to cycles sized for 5 GHz, the old FS-1b numbers, where a wedged drive held `CHANNEL` ~41 s at 5 GHz and ~7 min at 0.5 GHz. Measured, it is ~50 s on any TSC. The boot log says which: `[tsc] N MHz measured…` or `[tsc] measurement refused…`.
- `reset_channel` (`ata.rs:407`) writes `0x3F6` (SRST|nIEN, then nIEN), which resets both drives on the primary channel; only the master is used.
- hal-tcb row C16 assumes an ATA wait never changes core. True today (`sfs-commit` is `spawn_on(0)`, the toy FS runs on kmain).

**Why:** the hal items in the staff review of #44, 2026-10-25.

**How to apply:** keep the 25 % margin unless the boot test under host write load says otherwise; revisit C16 the moment the scheduler can migrate tasks or a second drive is used. Those changes are hal changes and need Veeti's sign-off.
