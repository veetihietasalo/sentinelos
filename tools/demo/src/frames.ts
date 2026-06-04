/**
 * frames.ts — the storyboard: which captured OS frame plays when, and what
 * caption (if any) overlays it.
 *
 * Every `src` here is a REAL screendump taken off the running SentinelOS in
 * QEMU by `capture/capture_frames.sh` (see frame numbering there). Remotion only
 * sequences these frames and adds title/end cards, captions, and cross-fades —
 * it never re-creates or re-draws the OS UI. The frames are the OS; the rest is
 * just pacing and titling.
 *
 * Frames are served from `public/frames/` via Remotion's `staticFile()`. Run
 * `npm run sync-frames` (or the capture script) to populate that folder.
 */

/** One beat of the OS footage: a captured frame, how long it holds, its caption. */
export interface Beat {
  /** Filename under public/frames/, e.g. "frame_0001.png". */
  readonly src: string;
  /** How long this frame holds on screen, in seconds. */
  readonly hold: number;
  /** Optional caption shown over the frame ("" = no caption). */
  readonly caption?: string;
  /** Optional sub-caption (smaller, under the caption). */
  readonly sub?: string;
}

/**
 * The boot → unlock → type-a-command storyboard.
 *
 * Mapping to the captured sequence (frame_0001 … frame_0020):
 *  - 0001/0002  locked Cyber Dusk boot screen
 *  - 0003–0007  the ~0.7s unlock animation (card dissolves)
 *  - 0008       desktop with the empty SENTINEL CONSOLE
 *  - 0009–0013  typing `about` one key at a time
 *  - 0014       `about` output (name + tagline + version)
 *  - 0015–0018  typing `help`
 *  - 0019/0020  `help` output + the final settled console
 *
 * We pick the cleanest, fully-settled frames for the hero beats and let the
 * typing frames flick by quickly so it reads as live keystrokes.
 */
export const STORYBOARD: readonly Beat[] = [
  // ── Locked boot screen ──────────────────────────────────────────────────
  { src: "frame_0001.png", hold: 2.4, caption: "booting…", sub: "Cyber Dusk lock screen" },
  { src: "frame_0002.png", hold: 1.6, caption: "press → to unlock" },

  // ── Unlock animation (real frames across the dissolve) ──────────────────
  { src: "frame_0003.png", hold: 0.5 },
  { src: "frame_0004.png", hold: 0.5 },
  { src: "frame_0005.png", hold: 0.5 },
  { src: "frame_0006.png", hold: 0.5 },
  { src: "frame_0007.png", hold: 0.5 },

  // ── Desktop + empty console ─────────────────────────────────────────────
  { src: "frame_0008.png", hold: 2.4, caption: "unlocked", sub: "the SentinelOS desktop" },

  // ── Type `about`, one key at a time ─────────────────────────────────────
  { src: "frame_0009.png", hold: 0.42, caption: "type a command" },
  { src: "frame_0010.png", hold: 0.42, caption: "type a command" },
  { src: "frame_0011.png", hold: 0.42, caption: "type a command" },
  { src: "frame_0012.png", hold: 0.42, caption: "type a command" },
  { src: "frame_0013.png", hold: 0.6, caption: "type a command" },
  { src: "frame_0014.png", hold: 2.8, caption: "about", sub: "a real built-in command" },

  // ── Type `help`, one key at a time ──────────────────────────────────────
  { src: "frame_0015.png", hold: 0.42 },
  { src: "frame_0016.png", hold: 0.42 },
  { src: "frame_0017.png", hold: 0.42 },
  { src: "frame_0018.png", hold: 0.6 },
  { src: "frame_0019.png", hold: 3.0, caption: "help", sub: "the shell built-ins" },

  // ── Final settled console ───────────────────────────────────────────────
  { src: "frame_0020.png", hold: 2.6 },
] as const;

/** Frames-per-second of the rendered video. */
export const FPS = 30;

/** Convert a seconds duration to whole frames at {@link FPS}. */
export const secondsToFrames = (seconds: number): number =>
  Math.max(1, Math.round(seconds * FPS));

/** Total OS-footage duration, in frames (excludes the title/end cards). */
export const footageDurationInFrames = (): number =>
  STORYBOARD.reduce((acc, beat) => acc + secondsToFrames(beat.hold), 0);
