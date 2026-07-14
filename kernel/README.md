# SentinelOS kernel

Bare-metal x86-64 kernel crate.  Workspace root: `kernel/`.

## Layout

```
kernel/
  .cargo/config.toml     # workspace-wide: build.target = x86_64-unknown-none + linker flags
  rust-toolchain.toml    # nightly (required by the limine 0.6.x crate)
  Cargo.toml             # workspace members: crates/hal, crates/kernel
  xtask/                 # host-side build driver (standalone workspace — see below)
  crates/
    hal/                 # hardware abstraction layer (no_std)
    kernel/              # kernel binary (no_std)
```

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

## QEMU / Limine — pending installation

`make run` and `make test` require:

| Tool | Install |
|------|---------|
| `qemu-system-x86_64` | `brew install qemu` |
| `xorriso` | `brew install xorriso` |
| `limine` binary | see below |

### Fetching a pinned Limine release

```sh
LIMINE_VER=8.0.4
curl -Lo /usr/local/bin/limine \
  "https://github.com/limine-bootloader/limine/releases/download/v${LIMINE_VER}/limine-$(uname -m)-unknown-linux"
chmod +x /usr/local/bin/limine
```

Once both `qemu-system-x86_64` and `limine` are on `$PATH`, implement the TODO stubs
in `xtask/src/main.rs` (`run()` and `test_kernel()`) using the QEMU invocation:

```sh
qemu-system-x86_64 \
  -serial stdio \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
  -display none \
  -no-reboot \
  -cdrom target/sentinelos.iso
```

Exit code interpretation for `isa-debug-exit`:
- `33` (0x21 = `0x10 << 1 | 1`) → tests passed
- anything else → tests failed
