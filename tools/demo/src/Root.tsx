/**
 * Root.tsx — registers the `SentinelDemo` composition with Remotion.
 *
 * The composition's `durationInFrames` is computed from the storyboard so the
 * clip is exactly as long as the beats demand (typically ~28–32s) — no manual
 * frame count to keep in sync.
 */
import React from "react";
import { Composition } from "remotion";
import { SentinelDemo } from "./SentinelDemo";
import {
  FPS,
  VIDEO_WIDTH,
  VIDEO_HEIGHT,
  totalDurationInFrames,
} from "./timeline";

export const RemotionRoot: React.FC = () => {
  return (
    <Composition
      id="SentinelDemo"
      component={SentinelDemo}
      durationInFrames={totalDurationInFrames()}
      fps={FPS}
      width={VIDEO_WIDTH}
      height={VIDEO_HEIGHT}
    />
  );
};
