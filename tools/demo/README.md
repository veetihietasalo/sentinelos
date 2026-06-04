# SentinelOS demo video

A shareable ~28-second clip of SentinelOS — **boot → unlock → typing a shell
command** — for Show HN / r/rust / the README.

**Honest framing:** every frame of the OS in this video is a **real screendump**
captured off the actual SentinelOS running headless in QEMU. The Remotion project
only adds a title card, an end card, lower-third captions, and smooth pacing /
cross-fades. It does **not** re-create, re-draw, or fake any of the UI — the OS
you see is the OS.

```
  title card  →  [ locked boot screen → unlock → desktop → type `about` / `help` ]  →  end card
```

Output: **1920×1080, 30 fps, ~28 s.**

---

## Two stages

### Part A — capture real frames (`capture/`)

`capture/capture_frames.sh` boots the existing SentinelOS ISO in **headless
QEMU** with a QMP control socket and a serial log, then `capture/qmp_driver.py`
drives the whole flow over QMP — `send-key right` to unlock, then typing `about`
and `help` one key at a time — taking a PNG `screendump` at each step. This
mirrors the QMP/screendump approach in `kernel/xtask/src/main.rs`'s `screenshot`
subcommand (we read that pattern; we do not modify it).

Frames land in `tools/demo/frames/` as `frame_0001.png … frame_0020.png`, each
**1280×800** (the resolution Limine hands the kernel under QEMU's default
std-VGA — no `-vga` override; forcing a legacy VGA mode would blank the GOP
framebuffer).

```sh
# From the repo root. Reuses kernel/target/sentinelos.iso if present; otherwise
# pass --build to (re)build it via `cargo xtask`, or --iso PATH to point at one.
tools/demo/capture/capture_frames.sh
tools/demo/capture/capture_frames.sh --build              # build the ISO first
tools/demo/capture/capture_frames.sh --iso /path/to.iso   # explicit ISO
```

Requirements: `qemu-system-x86_64` and `python3` (the same host deps as
`cargo xtask`). Capture runs under TCG software emulation, so it is slow
(~1–2 min) — the script waits for each per-pixel framebuffer repaint to settle
before every screendump so no frame is caught half-drawn.

### Part B — compose the video (Remotion)

A standard [Remotion](https://www.remotion.dev/) project. The captured PNGs are
imported as static assets and sequenced by `src/frames.ts` (the storyboard) into
the clip. Rendering is **fully local and free** — Remotion drives a bundled
headless Chromium and a bundled ffmpeg; there is no cloud, no paid API, no
Remotion Lambda, nothing that incurs spend. (Remotion is free for individual /
solo use.)

```sh
cd tools/demo
npm install          # installs Remotion (~180 pkgs); first render fetches a
                     # local headless Chromium (~90 MB) — still free & offline

npm run preview      # open Remotion Studio to scrub the timeline
npm run render       # render BOTH out/sentinelos-demo.mp4 and .gif
npm run render:mp4   # just the MP4  (1920×1080, h264)
npm run render:gif   # just the GIF  (480px, every 3rd frame — README-friendly)
npm run still        # a poster PNG  (out/poster.png)
```

The render scripts run `sync-frames` first, copying `frames/` →
`public/frames/` (Remotion serves static assets from `public/`).

---

## Project layout

```
tools/demo/
  capture/
    capture_frames.sh   # boots QEMU headless + QMP, drives the capture
    qmp_driver.py       # QMP client: send-key + screendump, walks the flow
  src/
    index.ts            # Remotion entry (registerRoot)
    Root.tsx            # registers the SentinelDemo composition
    SentinelDemo.tsx    # the timeline: title → footage beats → end card
    timeline.ts         # title/end durations + total-length math
    frames.ts           # the storyboard (which frame plays when + captions)
    theme.ts            # Cyber Dusk design tokens (mirrored from the OS)
    components/
      TitleCard.tsx     # opening card
      EndCard.tsx       # closing card
      Caption.tsx       # lower-third step captions
      FrameShot.tsx     # one captured frame, letterboxed + cross-faded
  frames/               # captured PNG sequence (gitignored; regenerable)
  public/frames/        # render-time copy of frames/ (gitignored)
  out/                  # rendered mp4 / gif (gitignored)
  remotion.config.ts
  package.json
```

## End-to-end (from a clean checkout)

```sh
# 1. Build the OS ISO (if you don't already have kernel/target/sentinelos.iso)
cd kernel && cargo xtask run      # assembles the ISO; Ctrl-C once it boots
cd ..

# 2. Capture real frames off the running OS
tools/demo/capture/capture_frames.sh

# 3. Compose + render the video
cd tools/demo
npm install
npm run render                    # → out/sentinelos-demo.mp4 + .gif
```

## Notes

- The frames are **1280×800 (16:10)**; the video is **1920×1080 (16:9)**. Each
  frame is scaled to fit by width and centred, with the Cyber-Dusk gradient
  filling the thin letterbox bars so they read as intentional chrome.
- `imageRendering: pixelated` keeps the OS's 8×8 bitmap font crisp at scale.
- To re-time the clip, edit the `hold` values (and captions) in `src/frames.ts`;
  the composition length recomputes automatically.
- Captured `frames/` and rendered `out/` are gitignored (regenerable, and large).
  A small hero GIF can be force-added — see the commented lines in `.gitignore`.
```
