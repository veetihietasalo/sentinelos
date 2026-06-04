/**
 * EndCard — the closing card: "private · secure · yours" with the project tag,
 * fading up from the Cyber Dusk gradient.
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

export const EndCard: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const enter = spring({ frame, fps, config: { damping: 200 }, durationInFrames: 28 });
  const scale = interpolate(enter, [0, 1], [0.94, 1]);
  const fadeIn = interpolate(frame, [0, 12], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const tagOpacity = interpolate(frame, [18, 34], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  return (
    <AbsoluteFill
      style={{
        background: CYBER_DUSK_GRADIENT,
        justifyContent: "center",
        alignItems: "center",
        fontFamily: MONO_FONT,
        opacity: fadeIn,
      }}
    >
      <AbsoluteFill
        style={{
          background:
            "radial-gradient(55% 40% at 50% 88%, rgba(122,215,255,0.20), transparent 65%)",
        }}
      />
      <div style={{ textAlign: "center", transform: `scale(${scale})` }}>
        <div
          style={{
            fontSize: 64,
            fontWeight: 700,
            color: COLORS.textPrimary,
            letterSpacing: 2,
            textShadow: `0 0 24px ${COLORS.accentPink}`,
          }}
        >
          private · secure · yours
        </div>
        <div
          style={{
            marginTop: 30,
            fontSize: 28,
            color: COLORS.accentCyan,
            opacity: tagOpacity,
            letterSpacing: 1,
          }}
        >
          SentinelOS — built from scratch in Rust
        </div>
        <div
          style={{
            marginTop: 14,
            fontSize: 20,
            color: COLORS.textSecondary,
            opacity: tagOpacity,
            letterSpacing: 2,
          }}
        >
          #![forbid(unsafe_code)] · a framekernel
        </div>
      </div>
    </AbsoluteFill>
  );
};
