# SentinelOS kernel

Bare-metal x86-64 kernel crate.  Workspace root: `kernel/`.

## Layout

```
kernel/
  .cargo/config.toml     # workspace-wide: [target.x86_64-unknown-none] rustflags + xtask alias
  rust-toolchain.toml    # stable toolchain pinned by version
  Cargo.toml             # workspace members: crates/hal, crates/ui, crates/kernel, crates/boot
  xtask/                 # host-side build driver (standalone workspace — see below)
  crates/
    hal/                 # hardware abstraction layer (no_std)
    ui/                  # UI/rendering crate (no_std)
    kernel/              # kernel crate (no_std)
    boot/                # kernel entry point binary (no_std)
```

## Build commands

All commands run from `kernel/`.

### Build and boot via xtask (recommended — mirrors CI exactly)

```sh
cargo xtask build      # cross-compile the boot binary for x86_64-unknown-none
cargo xtask run        # build ISO, launch QEMU with serial output on stdout
cargo xtask test       # build ISO, run QEMU up to 90 s, assert boot banner
cargo xtask screenshot # build ISO, boot headless, capture PNG via QMP
```

`cargo xtask` builds the host-side driver binary automatically for whatever host
triple is active (`x86_64-unknown-linux-gnu` on CI/Linux, `aarch64-apple-darwin`
on an M-series Mac, etc.).  No per-host hand-editing is needed.

### Cross-compile the kernel directly (without xtask)

```sh
cargo build --target x86_64-unknown-none
```

> Note: a bare `cargo build` (without `--target`) now compiles for the **host**,
> not the bare-metal kernel target, because `kernel/.cargo/config.toml` no longer
> sets a global `[build] target`.  Always pass `--target x86_64-unknown-none`
> explicitly, or use `cargo xtask build` which does this for you.

### Lint / format

```sh
cargo fmt --all --check
cargo clippy --target x86_64-unknown-none -- -D warnings
```

---

## Why xtask is a standalone workspace

`xtask/` is NOT listed in `kernel/Cargo.toml`'s `members` list — it is its own
standalone workspace (`xtask/Cargo.toml` contains `[workspace]`).

Previously `kernel/.cargo/config.toml` set `build.target = "x86_64-unknown-none"`
for the entire workspace, which forced xtask to be compiled for the bare-metal
target too (causing `can't find crate for 'std'`).  That global default has been
removed.  The `xtask` alias in `.cargo/config.toml` no longer passes `--target`,
so Cargo resolves the host triple automatically on every platform:

| Platform        | xtask host triple              |
|-----------------|-------------------------------|
| Linux x86_64    | `x86_64-unknown-linux-gnu`    |
| macOS M-series  | `aarch64-apple-darwin`        |
| macOS Intel     | `x86_64-apple-darwin`         |

The `[target.x86_64-unknown-none]` rustflags block in `.cargo/config.toml` is
untouched — it only activates when that specific target is requested (e.g. by
xtask or by an explicit `--target x86_64-unknown-none`), so host builds are
unaffected.

---

## QEMU / Limine — prerequisites

`cargo xtask run`, `cargo xtask test`, and `cargo xtask screenshot` require:

| Tool | macOS | Linux |
|------|-------|-------|
| `qemu-system-x86_64` | `brew install qemu` | `apt-get install qemu-system-x86` |
| `xorriso` | `brew install xorriso` | `apt-get install xorriso` |
| `kernel/limine/` | see below | see below |

### Fetching Limine (pinned to v11.4.1)

```sh
git clone --branch v11.4.1-binary --depth 1 \
    https://github.com/limine-bootloader/limine.git \
    kernel/limine
make -C kernel/limine
```

The `kernel/limine/` directory is gitignored; CI clones it as part of the
"Clone Limine" step in `.github/workflows/kernel.yml`.

### QEMU invocation (for reference)

```sh
qemu-system-x86_64 \
  -M q35 -m 256M \
  -cdrom target/sentinelos.iso \
  -serial stdio \
  -display none \
  -no-reboot
```
