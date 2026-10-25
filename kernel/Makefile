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
#   make test        # build ISO + boot headless in QEMU (TCG) twice on a fresh
#                    #   test disk; assert every boot line + the persistence chain
#                    #   (SENTINELOS_KEEP_TEST_DISK=1 keeps the test disk)
#                    #   then the SentinelFS torn-commit stage: a boot cut mid-
#                    #   commit (cache=writeback, SIGKILL) + a recovery boot
#   make test-kvm    # build ISO + boot under KVM (-cpu host), assert the x2APIC
#                    #   ENABLE path ran — the C1 evidence TCG cannot produce.
#                    #   Requires /dev/kvm (real hardware or a KVM-capable runner).
#   make check-no-vector # disassemble the kernel; assert vector instructions live
#                    #   ONLY in the audited hal::simd GEMM/xsave symbols, so no
#                    #   interrupt handler can clobber an in-flight GEMM.
#   make check-ata-callers # assert only kernel::blk::ata names hal::ata, so every
#                    #   ATA command holds the IDE channel lock.
#   make check-component-imports # scan the component modules: they may name
#                    #   only bus::{Ctx, BusError, Delegation} — never the host
#                    #   or the capability tables (threat T-NAT-1).
#   make screenshot  # build ISO + capture a framebuffer PNG via QMP
#
# Requires: qemu-system-x86_64, xorriso, and kernel/limine (see README).

HOST := $(shell rustc -vV | sed -n 's/^host: //p')
XTASK := cargo run --manifest-path xtask/Cargo.toml --target $(HOST) --target-dir target/xtask --

.PHONY: build run test test-kvm check-no-vector check-ata-callers check-component-imports screenshot boot-timing
build:
	$(XTASK) build
run:
	$(XTASK) run
test:
	$(XTASK) test
test-kvm:
	$(XTASK) test-kvm
check-no-vector:
	$(XTASK) check-no-vector
check-ata-callers:
	$(XTASK) check-ata-callers

check-component-imports:
	$(XTASK) check-component-imports
screenshot:
	$(XTASK) screenshot

boot-timing:
	$(XTASK) boot-timing $(RUNS)
