/**
 * FrameShot — renders ONE captured OS frame, letterboxed into the 16:9 canvas
 * over the Cyber Dusk gradient, with a per-beat fade so adjacent beats
 * cross-fade. The optional caption is overlaid on top.
 *
 * The OS frames are 1280x800 (16:10); the video is 1920x1080 (16:9). We scale
 * the frame to fit by width and centre it, with the gradient filling the thin
 * top/bottom bars so the letterbox reads as intentional Cyber-Dusk chrome, not
 * black bars. `imageRendering: pixelated` keeps the 8x8 bitmap font crisp.
 */
import React from "react";
import {
  AbsoluteFill,
  Img,
  interpolate,
  staticFile,
  useCurrentFrame,
  useVideoConfig,
} from "remotion";
import { CYBER_DUSK_GRADIENT } from "../theme";
import { Caption } from "./Caption";

/** Number of frames each beat spends cross-fading at its head and tail. */
export const CROSSFADE_FRAMES = 8;

export const FrameShot: React.FC<{
  readonly src: string;
  readonly caption?: string;
  readonly sub?: string;
  /** Fade the head in (false for the very first beat after the title). */
  readonly fadeIn?: boolean;
  /** Fade the tail out (false for the last beat before the end card). */
  readonly fadeOut?: boolean;
}> = ({ src, caption, sub, fadeIn = true, fadeOut = true }) => {
  const frame = useCurrentFrame();
  const { durationInFrames } = useVideoConfig();

  // Compute the head fade-in and tail fade-out as independent factors and
  // multiply them. Each interpolate gets its own strictly-increasing 2-point
  // range, so short beats (where a single 4-point range could collide) and the
  // no-fade edge beats (first/last) are both handled without a non-monotonic
  // input range. The fade span is clamped to at most half the beat so even very
  // short beats keep a valid head<tail ordering.
  const span = Math.max(1, Math.min(CROSSFADE_FRAMES, Math.floor(durationInFrames / 2)));

  const headFade = fadeIn
    ? interpolate(frame, [0, span], [0, 1], {
        extrapolateLeft: "clamp",
        extrapolateRight: "clamp",
      })
    : 1;

  const tailFade = fadeOut
    ? interpolate(frame, [durationInFrames - span, durationInFrames], [1, 0], {
        extrapolateLeft: "clamp",
        extrapolateRight: "clamp",
      })
    : 1;

  const opacity = headFade * tailFade;

  return (
    <AbsoluteFill style={{ background: CYBER_DUSK_GRADIENT }}>
      <AbsoluteFill
        style={{
          opacity,
          justifyContent: "center",
          alignItems: "center",
        }}
      >
        <Img
          src={staticFile(`frames/${src}`)}
          style={{
            width: "100%",
            height: "auto",
            maxHeight: "100%",
            objectFit: "contain",
            imageRendering: "pixelated",
            // A soft glass shadow lifts the frame off the gradient.
            boxShadow: "0 20px 60px rgba(0,0,0,0.45)",
          }}
        />
      </AbsoluteFill>
      {caption ? <Caption text={caption} sub={sub} /> : null}
    </AbsoluteFill>
  );
};
