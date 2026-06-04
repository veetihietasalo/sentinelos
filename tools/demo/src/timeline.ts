/**
 * timeline.ts — the single source of truth for the demo's timing: the title and
 * end-card durations, and the helper that computes the EXACT total composition
 * length (in frames) from the storyboard plus the cross-fade overlaps.
 *
 * Keeping this math in one place means `SentinelDemo.tsx` (which lays out the
 * sequences) and `Root.tsx` (which declares the composition's
 * `durationInFrames`) can never disagree about how long the video is.
 */
import { STORYBOARD, FPS, secondsToFrames } from "./frames";
import { CROSSFADE_FRAMES } from "./components/FrameShot";

export { FPS, secondsToFrames };

/** How long the opening title card holds (seconds). */
export const TITLE_SECONDS = 3.2;
/** How long the closing end card holds (seconds). */
export const END_SECONDS = 3.4;

/** 16:9 1080p — the standard shareable resolution for Show HN / README embeds. */
export const VIDEO_WIDTH = 1920;
export const VIDEO_HEIGHT = 1080;

/**
 * Total composition length in frames.
 *
 * Layout (matching `SentinelDemo.tsx`): the title card runs `titleFrames`; each
 * beat then advances the cursor by its hold (the +CROSSFADE tail is pure
 * overlap, so it doesn't extend the running length); the end card overlaps the
 * final beat's tail by one cross-fade and then runs its full duration.
 */
export const totalDurationInFrames = (): number => {
  const titleFrames = secondsToFrames(TITLE_SECONDS);
  const endFrames = secondsToFrames(END_SECONDS);

  let cursor = titleFrames - CROSSFADE_FRAMES;
  for (const beat of STORYBOARD) {
    cursor += secondsToFrames(beat.hold);
  }
  // The end card starts at `cursor` and runs `endFrames`.
  return cursor + endFrames;
};
