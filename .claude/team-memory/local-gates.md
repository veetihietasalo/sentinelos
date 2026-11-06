---
name: local-gates
description: The QEMU boot test runs locally in a Debian bookworm podman container (QEMU TCG, xorriso, Limine v11.4.1-binary); Miri and Kani run only in CI
type: reference
owner: test-engineer
date: 2026-10-25
source: https://github.com/veetihietasalo/sentinelos/pull/44#issuecomment-6397944991
---

Gates that ran locally for #44 on 2026-10-25 (Rust 1.99.1 per `rust-toolchain.toml`): `cargo fmt --all --check`, `cargo clippy --target x86_64-unknown-none -- -D warnings`, `cargo clippy -p boot --features test-hooks`, `cargo build`, `cargo test -p hal`, `cargo test -p kernel --lib`, the xtask tests, `make check-no-vector`, `make check-ata-callers`, `make check-component-imports`, and `make test` (4 QEMU boots incl. the torn-commit stage) inside a Debian bookworm container with QEMU TCG, xorriso and Limine `v11.4.1-binary`. Miri and Kani weren't installed and run only in CI.

**Why:** Veeti's box has no cargo or xorriso (company memory workstation-toolchain); the repo's SessionStart hook bootstraps a cloud container instead.

**How to apply:** run the same list before asking for review and name the CI run for Miri and Kani. The Limine tag must match `.github/workflows/kernel.yml`.

2026-11-06: `make test-kvm` runs locally too. Fedora WSL2 on Veeti's box has `/dev/kvm` (nested AMD-V); pass `--device /dev/kvm` to the same Debian container. It passed on `fix/ap-park-early` (#48).
