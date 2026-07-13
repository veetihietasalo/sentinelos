# Portable runner for the SentinelOS kernel build/boot driver (xtask).
#
# Why this exists: `cargo xtask …` (the alias in .cargo/config.toml) has to
# name the host triple explicitly, because a cargo alias cannot expand it and
# kernel/.cargo/config.toml pins build.target to the bare-metal
# x86_64-unknown-none for the kernel crates — so xtask would otherwise be
# cross-compiled to a target with no std. Hard-coding one host triple only
# works on that one OS. This Makefile detects the host with `rustc -vV` and
# passes it through, so the same commands work on Linux (CI / Claude Code on
# the web) and macOS alike.
#
#   make build       # cross-compile the boot ELF for x86_64-unknown-none
#   make run         # build ISO + launch QEMU (serial on stdout)
#   make test        # build ISO + boot headless in QEMU, assert the banner
#   make screenshot  # build ISO + capture a framebuffer PNG via QMP
#
# Requires: qemu-system-x86_64, xorriso, and kernel/limine (see README).

HOST := $(shell rustc -vV | sed -n 's/^host: //p')
XTASK := cargo run --manifest-path xtask/Cargo.toml --target $(HOST) --target-dir target/xtask --

.PHONY: build run test screenshot
build:
	$(XTASK) build
run:
	$(XTASK) run
test:
	$(XTASK) test
screenshot:
	$(XTASK) screenshot
