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

All commands run from `kernel/`.

### Cross-compile the kernel (bare-metal, x86_64-unknown-none)

```sh
cargo build
```

Produces `target/x86_64-unknown-none/debug/kernel`.

### Build via xtask (recommended — mirrors CI)

```sh
cargo xtask build
```

### Run under QEMU (pending deps — see below)

```sh
cargo xtask run
```

### Run tests under QEMU (pending deps — see below)

```sh
cargo xtask test
```

---

## Why xtask is a standalone workspace

`kernel/.cargo/config.toml` sets `build.target = "x86_64-unknown-none"` for the entire
kernel workspace.  If `xtask` were a workspace member, Cargo would compile it for the
bare-metal target too, causing `can't find crate for 'std'`.

The fix has two parts:

1. `xtask/` is NOT listed in `kernel/Cargo.toml`'s `members` list — it is its own
   standalone workspace (`xtask/Cargo.toml` contains `[workspace]`).
2. The `cargo xtask` alias in `kernel/.cargo/config.toml` passes
   `--target aarch64-apple-darwin` explicitly, overriding the workspace default for
   that one invocation.

On CI with an x86_64-Linux runner, override the alias target:

```sh
CARGO_BUILD_TARGET=x86_64-unknown-linux-gnu cargo xtask build
```

Or invoke directly:

```sh
cargo run --manifest-path xtask/Cargo.toml \
          --target x86_64-unknown-linux-gnu \
          --target-dir target/xtask \
          -- build
```

---

## QEMU / Limine — pending installation

`cargo xtask run` and `cargo xtask test` require:

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
