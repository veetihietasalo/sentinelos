/**
 * index.ts — Remotion entry point. Registers the root component so `remotion
 * studio` / `remotion render` can discover the `SentinelDemo` composition.
 */
import { registerRoot } from "remotion";
import { RemotionRoot } from "./Root";

registerRoot(RemotionRoot);
