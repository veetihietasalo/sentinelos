#!/usr/bin/env python3
"""
qmp_driver.py — drive a running headless QEMU over QMP to capture a numbered PNG
sequence of the SentinelOS boot → unlock → type-a-command flow.

This is the Python half of `capture_frames.sh`. The shell script boots the
EXISTING SentinelOS ISO in headless QEMU with a QMP unix socket and a serial
log, then hands this script the socket path, the serial-log path, and the output
frames directory. We:

  1. Connect to the QMP socket (retrying — QEMU may not be ready yet), read the
     greeting, and `qmp_capabilities` into command mode. (Same handshake as
     `kernel/xtask/src/main.rs`'s screenshot subcommand — we deliberately mirror
     its QMP/screendump approach rather than touching that file.)
  2. Wait for the boot end-marker (`boot-bringup-ok`) in the serial log, then a
     few extra seconds for the slow per-pixel software framebuffer draw under
     TCG, exactly like the kernel xtask does.
  3. Walk the flow, dumping a numbered PNG (`frame_0001.png`, ...) at each step:
       a. the locked Cyber Dusk boot screen,
       b. send `right` (the unlock gesture, scancode 0xE0 0x4D) and capture a few
          frames across the ~0.7 s unlock animation,
       c. the desktop with the empty console,
       d. type `about<enter>` then `help<enter>` ONE KEY AT A TIME via QMP
          `send-key`, capturing frames as text appears,
       e. the final output.

Every PNG is a REAL screendump of the actual OS framebuffer — no synthesis.

QMP key naming: QEMU's `send-key` takes `qcode` names (a `right` arrow becomes
the 0xE0 0x4D extended scancode the kernel decodes as the unlock gesture; letters
are `a`..`z`, Enter is `ret`, space is `spc`). See the `QCODE` map below.

Usage:
    python3 qmp_driver.py <qmp_sock> <serial_log> <frames_dir> [options]
"""

import argparse
import json
import os
import socket
import sys
import time

# --- QMP socket plumbing -----------------------------------------------------


def connect(sock_path: str, timeout_s: float = 30.0) -> socket.socket:
    """Connect to the QMP unix socket, retrying until QEMU has created it."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            s.connect(sock_path)
            return s
        except (FileNotFoundError, ConnectionRefusedError):
            if time.monotonic() > deadline:
                print(f"QMP_ERROR: socket {sock_path} not available after "
                      f"{timeout_s:.0f}s", file=sys.stderr)
                sys.exit(1)
            time.sleep(0.25)


class Qmp:
    """A minimal line-oriented QMP client over the unix socket."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.buf = b""

    def _recv_obj(self) -> dict:
        """Read one complete JSON object (QMP is newline-delimited JSON)."""
        while True:
            nl = self.buf.find(b"\n")
            if nl >= 0:
                line = self.buf[:nl]
                self.buf = self.buf[nl + 1:]
                line = line.strip()
                if not line:
                    continue
                return json.loads(line.decode())
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("QMP socket closed")
            self.buf += chunk

    def execute(self, command: str, arguments: dict | None = None) -> dict:
        """Send a command and return its `return` payload.

        QMP interleaves asynchronous `event` messages with command responses;
        we skip events until the matching `return`/`error` arrives.
        """
        msg: dict = {"execute": command}
        if arguments:
            msg["arguments"] = arguments
        self.sock.sendall((json.dumps(msg) + "\n").encode())
        while True:
            obj = self._recv_obj()
            if "return" in obj or "error" in obj:
                if "error" in obj:
                    raise RuntimeError(f"QMP error on {command}: {obj['error']}")
                return obj["return"]
            # else: an async `event` — ignore and keep reading.

    def handshake(self) -> None:
        """Read the greeting and enter command mode."""
        greeting = self._recv_obj()
        ver = greeting.get("QMP", {}).get("version", {}).get("qemu", {})
        print(f"QMP greeting: QEMU "
              f"{ver.get('major', '?')}.{ver.get('minor', '?')}."
              f"{ver.get('micro', '?')}", flush=True)
        self.execute("qmp_capabilities")


# --- key sending -------------------------------------------------------------

# Map an ASCII character to QEMU's `send-key` qcode name. Only the characters the
# demo types (`about`, `help`, space, newline) strictly need to be present, but
# the full lowercase alphabet + digits are included so the script is reusable.
QCODE = {
    " ": "spc", "\n": "ret",
    "-": "minus", "=": "equal", ".": "dot", ",": "comma", "/": "slash",
}
for _c in "abcdefghijklmnopqrstuvwxyz":
    QCODE[_c] = _c
for _c in "0123456789":
    QCODE[_c] = _c


def send_qcode(qmp: Qmp, qcode: str, hold_ms: int = 40) -> None:
    """Press and release a single key by qcode name via QMP `send-key`.

    `send-key` emits the make scancode, holds `hold-time` ms, then emits the
    break — exactly the make/break pair the kernel's SET-1 decoder expects. For
    `right` this is the 0xE0 0x4D / 0xE0 0xCD extended pair that the lock screen
    accepts as the unlock gesture.
    """
    qmp.execute("send-key", {
        "keys": [{"type": "qcode", "data": qcode}],
        "hold-time": hold_ms,
    })


def type_char(qmp: Qmp, ch: str) -> None:
    """Type one character, resolving it to a qcode (ignored if unmapped)."""
    qcode = QCODE.get(ch)
    if qcode is None:
        return
    send_qcode(qmp, qcode)


# --- screendump --------------------------------------------------------------


class FrameWriter:
    """Numbered PNG screendump writer, monotonically increasing."""

    def __init__(self, qmp: Qmp, frames_dir: str) -> None:
        self.qmp = qmp
        self.dir = frames_dir
        self.n = 0
        os.makedirs(frames_dir, exist_ok=True)

    def capture(self, label: str = "") -> str:
        """Take one PNG screendump into the next numbered frame slot."""
        self.n += 1
        path = os.path.join(self.dir, f"frame_{self.n:04d}.png")
        # Absolute path so QEMU (whatever its cwd) writes where we expect.
        self.qmp.execute("screendump",
                         {"filename": os.path.abspath(path), "format": "png"})
        # QEMU writes the file asynchronously after the command returns; give the
        # framebuffer encode a brief moment so the file is complete on disk.
        _wait_for_png(path)
        size = os.path.getsize(path) if os.path.exists(path) else 0
        print(f"  frame {self.n:04d}  {size:>8} B  {label}", flush=True)
        return path


def _wait_for_png(path: str, timeout_s: float = 5.0) -> None:
    """Wait until the PNG exists and its size stops growing (write finished)."""
    deadline = time.monotonic() + timeout_s
    last = -1
    stable = 0
    while time.monotonic() < deadline:
        if os.path.exists(path):
            size = os.path.getsize(path)
            if size > 0 and size == last:
                stable += 1
                if stable >= 2:
                    return
            else:
                stable = 0
            last = size
        time.sleep(0.05)


# --- serial-log boot wait ----------------------------------------------------

END_MARKER = "boot-bringup-ok"


def wait_for_boot(serial_log: str, timeout_s: float = 30.0) -> bool:
    """Poll the serial log until the kernel's boot end-marker appears."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            with open(serial_log, "r", errors="ignore") as fh:
                if END_MARKER in fh.read():
                    return True
        except FileNotFoundError:
            pass
        time.sleep(0.2)
    return False


# --- the flow ----------------------------------------------------------------


def run(args: argparse.Namespace) -> int:
    sock = connect(args.qmp_sock)
    qmp = Qmp(sock)
    qmp.handshake()

    print(f"Waiting for boot marker '{END_MARKER}' in {args.serial_log} ...",
          flush=True)
    if not wait_for_boot(args.serial_log, timeout_s=args.boot_timeout):
        print(f"QMP_ERROR: boot marker '{END_MARKER}' not seen in "
              f"{args.boot_timeout:.0f}s", file=sys.stderr)
        return 1
    print(f"Boot marker found; waiting {args.draw_wait:.0f}s for the slow "
          f"software framebuffer draw ...", flush=True)
    time.sleep(args.draw_wait)

    fw = FrameWriter(qmp, args.frames_dir)

    # --- (a) the locked Cyber Dusk boot screen -------------------------------
    # Capture a couple so we have a clean, settled locked frame (the hint pulses
    # gently between them — both are real).
    fw.capture("locked boot screen")
    time.sleep(0.5)
    fw.capture("locked boot screen (hint pulse)")

    # --- (b) unlock: send `right`, capture across the ~0.7s animation --------
    print("Sending unlock gesture (right arrow) ...", flush=True)
    send_qcode(qmp, "right")
    # The unlock animation runs ~0.7s of OS time, but under TCG the per-pixel
    # redraw is slow, so frames land progressively. Sample several times.
    for i in range(args.unlock_frames):
        time.sleep(args.unlock_interval)
        fw.capture(f"unlocking ({i + 1}/{args.unlock_frames})")

    # --- (c) the desktop with the empty console ------------------------------
    # Let the desktop + console panel settle, then capture it clean.
    time.sleep(args.settle)
    fw.capture("desktop + empty console")

    # --- (d) type `about` then `help`, one key at a time ---------------------
    def type_command(cmd: str, label: str) -> None:
        print(f"Typing '{cmd}' ...", flush=True)
        for ch in cmd:
            type_char(qmp, ch)
            time.sleep(args.keystroke_interval)
            fw.capture(f"typing '{cmd}' -> '{ch}'")
        # Submit with Enter and capture the command output.
        type_char(qmp, "\n")
        time.sleep(args.output_wait)
        fw.capture(f"{label} output")

    type_command("about", "about")
    type_command("help", "help")

    # --- (e) the final output ------------------------------------------------
    time.sleep(args.settle)
    fw.capture("final desktop with shell output")

    print(f"\nCAPTURE_OK: wrote {fw.n} frames to {args.frames_dir}", flush=True)
    sock.close()
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("qmp_sock", help="path to the QEMU QMP unix socket")
    p.add_argument("serial_log", help="path to the QEMU serial log file")
    p.add_argument("frames_dir", help="output directory for numbered PNG frames")
    p.add_argument("--boot-timeout", type=float, default=40.0)
    p.add_argument("--draw-wait", type=float, default=12.0,
                   help="seconds to wait after the boot marker for the framebuffer")
    p.add_argument("--unlock-frames", type=int, default=5)
    p.add_argument("--unlock-interval", type=float, default=0.6)
    # The console panel does a slow top-down per-pixel repaint under TCG software
    # rendering, so each capture must wait long enough for that repaint to SETTLE
    # — otherwise the screendump catches a half-painted panel. These intervals are
    # generous on purpose: a clean, fully-rendered frame at every step beats a
    # fast-but-torn one. (~2.0s/keystroke comfortably covers the full-panel
    # repaint on this host.)
    p.add_argument("--settle", type=float, default=2.5)
    p.add_argument("--keystroke-interval", type=float, default=2.0)
    p.add_argument("--output-wait", type=float, default=2.5)
    args = p.parse_args()
    try:
        return run(args)
    except (RuntimeError, ConnectionError) as exc:
        print(f"QMP_ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
