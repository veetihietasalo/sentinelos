# SentinelOS kernel

Bare-metal x86-64 kernel crate.  Workspace root: `kernel/`.

## Layout

```
kernel/
  Makefile               # portable runner: make build|run|test|screenshot
  .cargo/config.toml     # workspace-wide: build.target = x86_64-unknown-none + linker flags
  rust-toolchain.toml    # stable (no nightly) + x86_64-unknown-none, rustfmt/clippy/llvm-tools
  Cargo.toml             # workspace members: crates/{hal, kernel, boot, ui}
  xtask/                 # host-side build driver (standalone workspace — see below)
  limine/                # Limine bootloader binaries + host tool (fetched, gitignored)
  crates/
    hal/                 # hardware abstraction layer — the unsafe TCB (no_std)
    kernel/              # kernel logic: shell, drivers, net stack — forbid(unsafe_code) (no_std)
    boot/                # boot entry (_start) + Limine handoff → the `sentinelos` ELF (no_std)
    ui/                  # framebuffer + compositor rendering — forbid(unsafe_code) (no_std)
```

Uses the `limine` crate `0.5.x`, which builds on stable Rust — no nightly.

## Build commands

All commands run from `kernel/`. Use the **Makefile** — it detects the host
triple (`rustc -vV`) so the same commands work on Linux (CI / Claude Code on the
web) and macOS alike:

```sh
make build        # cross-compile the boot ELF for x86_64-unknown-none
make run          # build ISO + launch QEMU (serial on stdout)
make test         # build ISO + boot headless in QEMU, assert the banner
make screenshot   # build ISO + capture a framebuffer PNG via QMP
```

`make build` produces `target/x86_64-unknown-none/debug/sentinelos`. The
`run` / `test` / `screenshot` targets additionally need `qemu-system-x86_64`,
`xorriso`, and `kernel/limine/` (see below).

To type-check the kernel crates without booting, `cargo build` also works — it
picks up `build.target = x86_64-unknown-none` from `.cargo/config.toml`.

---

## Why xtask is a standalone workspace (and needs the Makefile)

`kernel/.cargo/config.toml` sets `build.target = "x86_64-unknown-none"` for the entire
kernel workspace. If `xtask` were a workspace member, Cargo would compile it for the
bare-metal target too, causing `can't find crate for 'std'`.

Two things keep xtask building for the host:

1. `xtask/` is NOT in `kernel/Cargo.toml`'s `members` — it is its own standalone
   workspace (`xtask/Cargo.toml` contains `[workspace]`).
2. xtask must still be told to build for the **host**, because Cargo reads config from
   the current working directory (`kernel/`), where `build.target` is the bare-metal
   target. A cargo alias cannot expand the host triple, so the Makefile detects it and
   passes it explicitly:

```sh
cargo run --manifest-path xtask/Cargo.toml \
          --target "$(rustc -vV | sed -n 's/^host: //p')" \
          --target-dir target/xtask \
          -- build
```

The `cargo xtask` alias in `kernel/.cargo/config.toml` is a macOS-only shortcut that
hard-codes `--target aarch64-apple-darwin`; prefer `make` for a portable build.

---

## QEMU / Limine setup

`make run` / `make test` / `make screenshot` need `qemu-system-x86_64`, `xorriso`,
and the Limine bootloader checked out at `kernel/limine/`:

| Tool | macOS | Debian/Ubuntu |
|------|-------|---------------|
| `qemu-system-x86_64` | `brew install qemu` | `sudo apt install qemu-system-x86` |
| `xorriso` | `brew install xorriso` | `sudo apt install xorriso` |

### Limine (pinned to match CI)

Clone the pinned tag and build the host tool — the same `v11.4.1-binary` the CI
workflow (`.github/workflows/kernel.yml`) uses, so local and CI builds agree:

```sh
git clone --branch v11.4.1-binary --depth 1 \
  https://github.com/limine-bootloader/limine.git kernel/limine
make -C kernel/limine
```

`kernel/limine/` is gitignored (fetched, not tracked).

> **Claude Code on the web:** the `SessionStart` hook
> (`.claude/hooks/session-setup.sh`) adds the bare-metal target and best-effort
> installs QEMU + xorriso and builds Limine automatically, so a fresh session can
> `make test` without manual setup.

### What `make test` checks

`make test` builds the ISO, boots it headless in QEMU (COM1 serial →
`target/serial.log`), and polls that log for the `SentinelOS — boot bring-up OK`
banner and the `boot-bringup-ok` end-marker (up to 60 s). It prints `TEST PASSED`
and exits `0` on success, or dumps the serial log and exits non-zero otherwise.
