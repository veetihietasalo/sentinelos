# Team memory: SentinelOS
- [hal-needs-veeti-signoff](hal-needs-veeti-signoff.md) — Any change under kernel/crates/hal (the unsafe TCB) needs Veeti's own sign-off; reviews approve the rest and give him a numbered file:line list of what to judge
- [ata-write-needs-flush](ata-write-needs-flush.md) — hal ATA write_sectors no longer flushes; durability needs an explicit flush() (kernel::fs once per save, SentinelFS twice per commit); skipping it loses data silently
- [ata-wait-premises](ata-wait-premises.md) — ATA deadlines are durations at the PIT-measured TSC rate + 25 % (5 GHz cycle fallback before or without a measurement), and TCB row C16 assumes a wait never changes core
- [storage-caps-fs4-checks](storage-caps-fs4-checks.md) — Before FS-4 enforces storage caps, settle two FS-1c items - SnapshotRo binds by name only (bind the gen), and unusable op bits still install (refuse them in is_well_formed)
- [kani-evidence](kani-evidence.md) — Read Kani results check by check in the CI log; UNREACHABLE means the check is vacuous and an unmet kani::cover! doesn't fail the run
- [local-gates](local-gates.md) — The QEMU boot test runs locally in a Debian bookworm podman container (QEMU TCG, xorriso, Limine v11.4.1-binary); Miri and Kani run only in CI
