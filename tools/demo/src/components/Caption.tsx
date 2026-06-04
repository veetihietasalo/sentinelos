/**
 * Caption — a tasteful lower-third caption that fades in/out over a real OS
 * frame. Kept minimal and translucent so it never hides the OS itself; it only
 * narrates the step ("booting…", "press → to unlock", "type a command").
 */
import React from "react";
import { interpolate, useCurrentFrame, useVideoConfig } from "remotion";
import { COLORS, MONO_FONT } from "../theme";

export const Caption: React.FC<{
  readonly text: string;
  readonly sub?: string;
}> = ({ text, sub }) => {
  const frame = useCurrentFrame();
  const { durationInFrames } = useVideoConfig();

  // Fade in over the first 8 frames, hold, fade out over the last 8.
  const opacity = interpolate(
    frame,
    [0, 8, durationInFrames - 8, durationInFrames],
    [0, 1, 1, 0],
    { extrapolateLeft: "clamp", extrapolateRight: "clamp" }
  );
  const translateY = interpolate(frame, [0, 8], [10, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  return (
    <div
      style={{
        position: "absolute",
        left: 0,
        right: 0,
        bottom: 64,
        display: "flex",
        justifyContent: "center",
        opacity,
        transform: `translateY(${translateY}px)`,
        fontFamily: MONO_FONT,
        pointerEvents: "none",
      }}
    >
      <div
        style={{
          padding: "14px 28px",
          borderRadius: 16,
          background: "rgba(16,8,32,0.55)",
          border: `1px solid ${COLORS.accentCyan}55`,
          boxShadow: "0 10px 34px rgba(0,0,0,0.4)",
          backdropFilter: "blur(6px)",
          textAlign: "center",
        }}
      >
        <div
          style={{
            fontSize: 30,
            color: COLORS.textPrimary,
            letterSpacing: 1,
            textShadow: `0 0 12px ${COLORS.accentPink}88`,
          }}
        >
          {text}
        </div>
        {sub ? (
          <div style={{ marginTop: 6, fontSize: 18, color: COLORS.textSecondary }}>
            {sub}
          </div>
        ) : null}
      </div>
    </div>
  );
};
