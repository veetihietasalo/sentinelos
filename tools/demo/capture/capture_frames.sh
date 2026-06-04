#!/usr/bin/env bash
#
# capture_frames.sh — boot the EXISTING SentinelOS ISO in headless QEMU and
# capture a numbered PNG sequence of the boot → unlock → type-a-command flow
# into tools/demo/frames/.
#
# This is Part A of the SentinelOS demo-video pipeline. It:
#   1. Locates (or builds) the SentinelOS ISO.
#   2. Boots it in headless QEMU at 1280x800, with:
#        - a serial log file (so we can wait for the `boot-bringup-ok` marker),
#        - a QMP unix socket (so qmp_driver.py can screendump + send-key).
#      This mirrors the QMP/screendump approach used by the kernel's
#      `cargo xtask screenshot` subcommand (kernel/xtask/src/main.rs) — we read
#      that pattern but do NOT modify it.
#   3. Runs qmp_driver.py to drive the flow and dump frames.
#   4. Tears QEMU down.
#
# Usage:
#   tools/demo/capture/capture_frames.sh [--iso PATH] [--build]
#
# Environment overrides:
#   SOS_ISO        path to the ISO (default: kernel/target/sentinelos.iso,
#                  falling back to the repo's shared checkout)
#   SOS_WIDTH      framebuffer width  (default 1280)
#   SOS_HEIGHT     framebuffer height (default 800)
#
# Requirements: qemu-system-x86_64, python3. (Same host deps as xtask.)

set -euo pipefail

# --- locate paths ------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"           # tools/demo
REPO_ROOT="$(cd "$DEMO_DIR/../.." && pwd)"          # repo root
FRAMES_DIR="$DEMO_DIR/frames"
DRIVER="$SCRIPT_DIR/qmp_driver.py"

WIDTH="${SOS_WIDTH:-1280}"
HEIGHT="${SOS_HEIGHT:-800}"

DO_BUILD=0
ISO_OVERRIDE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --iso)   ISO_OVERRIDE="$2"; shift 2 ;;
    --build) DO_BUILD=1; shift ;;
    -h|--help)
      sed -n '2,30p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# --- resolve the ISO ---------------------------------------------------------
# Prefer an explicit override, then $SOS_ISO, then this checkout's
# kernel/target, then the canonical shared checkout (the ISO is gitignored and
# lives only where it was built). We never rebuild unless asked.

resolve_iso() {
  if [[ -n "$ISO_OVERRIDE" ]]; then echo "$ISO_OVERRIDE"; return; fi
  if [[ -n "${SOS_ISO:-}" ]]; then echo "$SOS_ISO"; return; fi
  local candidates=(
    "$REPO_ROOT/kernel/target/sentinelos.iso"
    "$HOME/Archives/sentinelos/kernel/target/sentinelos.iso"
  )
  for c in "${candidates[@]}"; do
    if [[ -f "$c" ]]; then echo "$c"; return; fi
  done
  echo ""   # not found
}

ISO="$(resolve_iso)"

if [[ "$DO_BUILD" == "1" || -z "$ISO" ]]; then
  echo "==> ISO not found or --build requested; building via cargo xtask ..."
  ( cd "$REPO_ROOT/kernel" && cargo xtask build && cargo xtask run >/dev/null 2>&1 || true )
  # `cargo xtask build` only builds the ELF; the ISO is assembled by run/test/
  # screenshot. Easiest reliable path: ask xtask to build the ISO via screenshot
  # (headless) if a plain build didn't leave one. Fall back to resolve again.
  if [[ ! -f "$REPO_ROOT/kernel/target/sentinelos.iso" ]]; then
    ( cd "$REPO_ROOT/kernel" && cargo xtask screenshot >/dev/null 2>&1 || true )
  fi
  ISO="$(resolve_iso)"
fi

if [[ -z "$ISO" || ! -f "$ISO" ]]; then
  echo "ERROR: could not find or build the SentinelOS ISO." >&2
  echo "       Build it first:  (cd kernel && cargo xtask run)  then re-run." >&2
  echo "       Or pass --iso /path/to/sentinelos.iso" >&2
  exit 1
fi

echo "==> ISO:        $ISO"
echo "==> Frames dir: $FRAMES_DIR"
echo "==> Resolution: ${WIDTH}x${HEIGHT}"

# --- prepare run artifacts ---------------------------------------------------

mkdir -p "$FRAMES_DIR"
# Clear any stale frames so the sequence is clean.
rm -f "$FRAMES_DIR"/frame_*.png

RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/sos-demo.XXXXXX")"
SERIAL_LOG="$RUN_DIR/serial.log"
QMP_SOCK="$RUN_DIR/qmp.sock"
: > "$SERIAL_LOG"

cleanup() {
  if [[ -n "${QEMU_PID:-}" ]] && kill -0 "$QEMU_PID" 2>/dev/null; then
    kill "$QEMU_PID" 2>/dev/null || true
    wait "$QEMU_PID" 2>/dev/null || true
  fi
  rm -rf "$RUN_DIR"
}
trap cleanup EXIT

# --- boot QEMU headless with QMP + serial ------------------------------------
# Flags mirror `cargo xtask screenshot` EXACTLY (q35, 256M, -display none, QMP
# socket, serial->file). We deliberately do NOT pass any `-vga`/`-device VGA`
# override: under QEMU's default std-VGA adapter, Limine hands the kernel a
# 1280x800 GOP framebuffer (verified — that's the resolution `cargo xtask
# screenshot` produces). Forcing a legacy VGA mode instead drops it to a blank
# 640x480 text console, so we let the default ride. WIDTH/HEIGHT are kept for the
# log line and the Remotion side, which both expect 1280x800.

echo "==> Launching QEMU (headless, QMP socket, serial log) ..."
qemu-system-x86_64 \
  -M q35 \
  -m 256M \
  -cdrom "$ISO" \
  -display none \
  -no-reboot \
  -serial "file:$SERIAL_LOG" \
  -qmp "unix:$QMP_SOCK,server,nowait" &
QEMU_PID=$!

# --- drive the capture -------------------------------------------------------

echo "==> Driving capture via QMP ..."
set +e
python3 "$DRIVER" "$QMP_SOCK" "$SERIAL_LOG" "$FRAMES_DIR"
RC=$?
set -e

echo "==> Serial log tail:"
tail -n 12 "$SERIAL_LOG" 2>/dev/null || true

if [[ "$RC" -ne 0 ]]; then
  echo "ERROR: capture failed (rc=$RC). See QMP/serial output above." >&2
  exit "$RC"
fi

FRAME_COUNT="$(ls -1 "$FRAMES_DIR"/frame_*.png 2>/dev/null | wc -l | tr -d ' ')"
echo "==> Done. Captured $FRAME_COUNT frames into $FRAMES_DIR"
