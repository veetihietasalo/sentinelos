/**
 * TitleCard — the opening card: the SentinelOS wordmark + one-line pitch over
 * the Cyber Dusk gradient, with a soft entrance and a fade-out tail so it
 * cross-fades into the first real OS frame.
 */
import React from "react";
import {
  AbsoluteFill,
  interpolate,
  spring,
  useCurrentFrame,
  useVideoConfig,
} from "remotion";
import { COLORS, CYBER_DUSK_GRADIENT, MONO_FONT } from "../theme";

export const TitleCard: React.FC<{
  readonly title: string;
  readonly subtitle: string;
}> = ({ title, subtitle }) => {
  const frame = useCurrentFrame();
  const { fps, durationInFrames } = useVideoConfig();

  // Wordmark springs up and in.
  const enter = spring({ frame, fps, config: { damping: 200 }, durationInFrames: 30 });
  const translateY = interpolate(enter, [0, 1], [24, 0]);

  // Subtitle fades in slightly after the title.
  const subOpacity = interpolate(frame, [12, 30], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  // Whole card fades out over its final 15 frames for the cross-fade.
  const cardOpacity = interpolate(
    frame,
    [0, 8, durationInFrames - 15, durationInFrames],
    [0, 1, 1, 0],
    { extrapolateLeft: "clamp", extrapolateRight: "clamp" }
  );

  return (
    <AbsoluteFill
      style={{
        background: CYBER_DUSK_GRADIENT,
        opacity: cardOpacity,
        justifyContent: "center",
        alignItems: "center",
        fontFamily: MONO_FONT,
      }}
    >
      {/* Soft pink corner bloom, echoing the OS lock screen's top-right glow. */}
      <AbsoluteFill
        style={{
          background:
            "radial-gradient(60% 45% at 72% 12%, rgba(255,120,220,0.28), transparent 60%)",
        }}
      />

      <div style={{ textAlign: "center", transform: `translateY(${translateY}px)` }}>
        <div
          style={{
            fontSize: 92,
            fontWeight: 700,
            color: COLORS.textPrimary,
            letterSpacing: 2,
            textShadow: `0 0 28px ${COLORS.accentPink}`,
          }}
        >
          SentinelOS
        </div>
        <div
          style={{
            marginTop: 28,
            fontSize: 32,
            color: COLORS.textSecondary,
            opacity: subOpacity,
            letterSpacing: 1,
          }}
        >
          {subtitle}
        </div>
        <div
          style={{
            marginTop: 18,
            fontSize: 22,
            color: COLORS.accentCyan,
            opacity: subOpacity,
            letterSpacing: 3,
          }}
        >
          private · secure · yours
        </div>
      </div>

      {/* Honest footnote: these are real frames. */}
      <div
        style={{
          position: "absolute",
          bottom: 40,
          fontSize: 18,
          color: COLORS.textSecondary,
          opacity: subOpacity * 0.85,
          letterSpacing: 1,
        }}
      >
        real frames, captured from the OS running in QEMU
      </div>

      {/* `title` is the long-form headline; keep it available for accessibility
          without crowding the card. */}
      <span style={{ display: "none" }}>{title}</span>
    </AbsoluteFill>
  );
};
