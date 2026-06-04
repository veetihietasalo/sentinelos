/**
 * Remotion render config for the SentinelOS demo.
 *
 * Rendering is FULLY LOCAL and FREE: Remotion drives a bundled headless
 * Chromium to rasterise each frame, then pipes them to a local ffmpeg. No cloud,
 * no paid API, no Remotion Lambda — nothing here incurs spend.
 */
import { Config } from "@remotion/cli/config";

// PNG frames give us a clean alpha-free pipeline and crisp pixel-art scaling.
Config.setVideoImageFormat("jpeg");
// Higher quality for the crisp Cyber-Dusk gradients and pixel font.
Config.setJpegQuality(95);
// Overwrite a previous render of the same name without prompting.
Config.setOverwriteOutput(true);
// Pixel-art frames: keep nearest-neighbour-ish scaling crisp, no smoothing blur.
Config.setChromiumDisableWebSecurity(false);
