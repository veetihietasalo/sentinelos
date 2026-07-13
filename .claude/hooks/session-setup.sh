#!/usr/bin/env bash
# SentinelOS — Claude Code SessionStart bootstrap.
#
# Makes a fresh (e.g. Claude Code on the web) session able to build and
# boot-test the kernel. The documented dev setup is macOS-oriented; a Linux
# session container starts without the bare-metal target or the QEMU/xorriso/
# Limine toolchain, so `cargo build --target x86_64-unknown-none` and
# `cargo xtask test` cannot run until this has run.
#
# It does two tiers of work:
#   1. Install the bare-metal Rust target + llvm-tools (fast, no sudo) so
#      cargo build / clippy / fmt work on the kernel workspace.
#   2. Best-effort install QEMU + xorriso and clone/build Limine so the
#      headless QEMU boot test can run.
#
# Every step is idempotent and NON-FATAL: the script always exits 0, so a
# blocked network / missing apt / no sudo can never wedge the session. It
# prints a short summary of what is (and isn't) available.
set -u

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
say() { printf '  %s\n' "$*"; }

echo "[sentinelos] SessionStart setup…"

# ── 1. Bare-metal Rust target + components (cheap, always attempt) ────────────
if command -v rustup >/dev/null 2>&1; then
  if rustup target add x86_64-unknown-none >/dev/null 2>&1; then
    say "rust target x86_64-unknown-none ✓"
  else
    say "rust target x86_64-unknown-none — could not add (offline?)"
  fi
  rustup component add llvm-tools >/dev/null 2>&1 || true
else
  say "rustup not found — skipping target install"
fi

# ── 2. Boot-test system deps (best-effort) ───────────────────────────────────
need_pkgs=0
command -v qemu-system-x86_64 >/dev/null 2>&1 || need_pkgs=1
command -v xorriso          >/dev/null 2>&1 || need_pkgs=1
if [ "$need_pkgs" = 1 ] && command -v apt-get >/dev/null 2>&1; then
  SUDO=""
  if [ "$(id -u)" != 0 ] && command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi
  $SUDO apt-get update -qq                              >/dev/null 2>&1 || true
  $SUDO apt-get install -y -qq qemu-system-x86 xorriso  >/dev/null 2>&1 || true
fi
if command -v qemu-system-x86_64 >/dev/null 2>&1; then say "qemu ✓"; else say "qemu — unavailable (boot test will be skipped)"; fi
if command -v xorriso >/dev/null 2>&1; then say "xorriso ✓"; else say "xorriso — unavailable (ISO build will be skipped)"; fi

# ── 3. Limine bootloader (pinned tag — must match .github/workflows/kernel.yml)
LIMINE_TAG="v11.4.1-binary"
LIMINE_REPO="https://github.com/limine-bootloader/limine.git"
limine_dir="$repo_root/kernel/limine"
if [ ! -x "$limine_dir/limine" ]; then
  if command -v git >/dev/null 2>&1 && command -v make >/dev/null 2>&1; then
    rm -rf "$limine_dir" 2>/dev/null || true
    if git clone --branch "$LIMINE_TAG" --depth 1 "$LIMINE_REPO" "$limine_dir" >/dev/null 2>&1; then
      make -C "$limine_dir" >/dev/null 2>&1 || true
    fi
  fi
fi
if [ -x "$limine_dir/limine" ]; then say "limine ✓ ($LIMINE_TAG)"; else say "limine — not built (clone/make unavailable)"; fi

echo "[sentinelos] setup done."
exit 0
