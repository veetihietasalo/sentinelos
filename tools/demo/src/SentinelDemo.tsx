/**
 * SentinelDemo — the full ~20–35s shareable clip:
 *
 *   title card  →  [ boot → unlock → type a command ]  →  end card
 *
 * The middle section is the REAL OS footage: each beat in {@link STORYBOARD} is
 * a captured QEMU screendump, played for its hold and cross-fading into the
 * next. The title and end cards, and the lower-third captions, are the only
 * synthetic elements — the OS UI itself is never re-created.
 *
 * Timeline is assembled from frame counts so it is exact and deterministic; the
 * total duration is computed in `Root.tsx` from the same storyboard.
 */
import React from "react";
import { AbsoluteFill, Sequence } from "remotion";
import { TitleCard } from "./components/TitleCard";
import { EndCard } from "./components/EndCard";
import { FrameShot, CROSSFADE_FRAMES } from "./components/FrameShot";
import { STORYBOARD, secondsToFrames } from "./frames";
import { TITLE_SECONDS, END_SECONDS } from "./timeline";
import { COLORS } from "./theme";

export const SentinelDemo: React.FC = () => {
  const titleFrames = secondsToFrames(TITLE_SECONDS);
  const endFrames = secondsToFrames(END_SECONDS);

  // Walk the storyboard, placing each beat back-to-back. Beats overlap the title
  // and end cards (and each other) by CROSSFADE_FRAMES so the fades blend rather
  // than cutting to black.
  let cursor = titleFrames - CROSSFADE_FRAMES;
  const beatSequences = STORYBOARD.map((beat, i) => {
    const dur = secondsToFrames(beat.hold) + CROSSFADE_FRAMES; // +overlap tail
    const from = cursor;
    cursor += dur - CROSSFADE_FRAMES;
    const isFirst = i === 0;
    const isLast = i === STORYBOARD.length - 1;
    return (
      <Sequence key={beat.src + i} from={from} durationInFrames={dur}>
        <FrameShot
          src={beat.src}
          caption={beat.caption}
          sub={beat.sub}
          fadeIn={!isFirst}
          fadeOut={!isLast}
        />
      </Sequence>
    );
  });

  const endFrom = cursor; // end card overlaps the last beat's tail

  return (
    <AbsoluteFill style={{ backgroundColor: COLORS.ink }}>
      <Sequence durationInFrames={titleFrames}>
        <TitleCard
          title="SentinelOS — a private OS built from scratch in Rust"
          subtitle="a private OS built from scratch in Rust"
        />
      </Sequence>

      {beatSequences}

      <Sequence from={endFrom} durationInFrames={endFrames}>
        <EndCard />
      </Sequence>
    </AbsoluteFill>
  );
};
