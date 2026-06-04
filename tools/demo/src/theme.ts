/**
 * theme.ts — the "Cyber Dusk" design tokens, mirrored from the OS so the demo's
 * title cards and captions sit seamlessly against the real frames.
 *
 * These hex values come straight from the OS UI crate
 * (kernel/crates/ui/src/lib.rs §"Cyber Dusk design tokens"): the same
 * indigo→violet→magenta gradient, the same accent pink and cyan. Matching them
 * makes the added titling feel like part of the OS, not a sticker on top.
 */

export const COLORS = {
  /** Backdrop gradient stop 1 — deep indigo #2a1a4a. */
  gradStart: "#2a1a4a",
  /** Backdrop gradient stop 2 — violet #5b2a8c. */
  gradMid: "#5b2a8c",
  /** Backdrop gradient stop 3 — magenta #c43e8f. */
  gradEnd: "#c43e8f",
  /** Primary text — pure white. */
  textPrimary: "#ffffff",
  /** Secondary text — light cyan-grey. */
  textSecondary: "#c7c2d6",
  /** Accent pink #ff5fae — wordmark glow / emphasis. */
  accentPink: "#ff5fae",
  /** Secondary accent cyan #7ad7ff. */
  accentCyan: "#7ad7ff",
  /** Near-black for letterboxing and shadows. */
  ink: "#100820",
} as const;

/** The signature three-stop Cyber Dusk backdrop, as a CSS gradient. */
export const CYBER_DUSK_GRADIENT =
  `linear-gradient(135deg, ${COLORS.gradStart} 0%, ${COLORS.gradMid} 55%, ${COLORS.gradEnd} 100%)`;

/**
 * Font stack. We use a monospace stack everywhere so the titling echoes the
 * OS's pixel/monospace console aesthetic (the OS itself uses an 8x8 bitmap
 * font; a clean monospace is the closest web equivalent that ships everywhere).
 */
export const MONO_FONT =
  '"SF Mono", "JetBrains Mono", "Fira Code", "Cascadia Code", Menlo, Consolas, monospace';
