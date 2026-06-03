# SentinelOS UI Design Language — "Cyber Dusk"

- **Date:** 2026-06-03 · **Status:** Approved (design language) / Draft (implementation plan)
- **Owner agent:** ui-engineer · **Component of:** SentinelOS (sub-project #5 — the GUI — and everything that renders to a screen)

## 1. Summary

SentinelOS's interface language is **"Cyber Dusk"** — a **Y2K Aero / vaporwave** aesthetic (frosted glass, gloss, big rounded corners, gradients, soft motion) rendered in a **dark, privacy-forward** palette. It is designed to feel *awesome to a younger generation* — expressive, nostalgic, customizable — while staying on-brand for a security-first OS: dark, calm, and trustworthy, not clinical.

This document is the single source of truth for how SentinelOS looks. The **dev-tooling** (the agent dashboard under `tools/`) keeps its **matte security-ops** theme; the **OS itself** uses Cyber Dusk.

## 2. The aesthetic

- **Family:** Y2K Aero — translucent "glass" surfaces, glossy highlights, generous rounding, gradient backdrops, gentle shimmer/drift motion.
- **Mode:** dark, dusk-toned (purple→magenta), so glass and neon read beautifully and it's easy on the eyes.
- **Personality:** soft, playful, premium, *personal* — the OS should feel like it's yours (customization is a first-class goal per VISION.md).

## 3. Design tokens

| Token | Value |
|---|---|
| **Backdrop gradient** | `linear-gradient(160deg, #2a1a4a 0%, #5b2a8c 45%, #c43e8f 100%)` — slow drift |
| **Glass panel** | fill `rgba(255,255,255,.10–.14)` · border `1px rgba(255,255,255,.28)` · inner top highlight `inset 0 1px 0 rgba(255,255,255,.3)` · soft drop shadow · backdrop-blur *where supported* |
| **Accent (primary)** | neon pink `#ff5fae` (with glow) |
| **Accent (secondary)** | cyan `#7ad7ff` |
| **Text** | primary `#ffffff` · secondary `rgba(255,255,255,.78)` · emphasis = pink glow |
| **Radii** | 14–18px panels · pill (full) for controls |
| **Icons** | glossy gradient rounded-square tiles with a top sheen |
| **Type** | rounded humanist sans for UI; expressive but legible wordmark |
| **Motion** | slow gradient drift · gentle glass shimmer · springy (ease-out) transitions |

## 4. Honest implementation note (look vs. order)

True **real-time backdrop-blur** (live frosted glass over moving content) is a **compositor/GPU capability**. On a from-scratch software framebuffer it is expensive, so:
- **Early builds approximate** glass with semi-transparent panels over the gradient + crisp borders + gloss highlights (no live blur).
- **Full glass blur** arrives once the compositor (and eventually a GPU path) exists.
The *aesthetic* is the committed target throughout; only the blur fidelity ramps with capability. This must not block shipping the look.

## 5. Reference screen — the boot/lock screen

The locked reference (see brainstorm mockups): centered date + large clock; a central **glass card** with the `SentinelOS` wordmark, a `🛡 private · secure · yours` line, and a pill "swipe to unlock"; a bottom **glass dock** of glossy gradient app tiles; over the Cyber Dusk gradient with a soft pink glow top-right.

## 6. Near-term implementation — the first *real* pixels

The first UI we can actually build: replace the serial-only boot banner with a **graphical Cyber Dusk boot/lock screen on the Limine framebuffer**. Decomposed:

1. **Framebuffer surface** — hal exposes the Limine framebuffer response as a safe `Framebuffer` (pointer/pitch/format wrapped; the `unsafe` is hal's). *(hal-specialist + driver-engineer)*
2. **2D raster lib** — safe Rust: `fill_rect`, vertical/diagonal `gradient`, `rounded_rect`, alpha-blended `blit`, pixel plotting. `#![forbid(unsafe_code)]`, drawing only through the `Framebuffer` API. *(ui-engineer)*
3. **Text + wordmark** — embed a compact font (bitmap or simple vector), draw the clock + `SentinelOS`. *(ui-engineer)*
4. **Compose the Cyber Dusk boot screen** — gradient backdrop, the glass card, the dock; render in QEMU. *(ui-engineer)*

This is the first slice of sub-project #5 and a satisfying milestone: SentinelOS goes from "prints text on a serial line" to "shows a gorgeous boot screen." It depends on #2a (interrupts, done) but not on the rest of the kernel.

## 7. Longer-term UI decomposition

Framebuffer boot screen → **compositor** (layers, damage tracking, eventually blur/GPU) → **desktop shell** (status bar, dock, launcher) → **window management** → **apps** (incl. the Sentinel security center) → **theming/customization engine** (the "make it yours" goal). Each is its own spec → plan → build.

## 8. Acceptance (this spec)

- The tokens above are the authoritative palette/treatment for all SentinelOS (non-dev-tooling) UI.
- The first implementation slice is the framebuffer Cyber Dusk boot screen (§6).
- The honest-blur ramp (§4) is documented so the team never blocks on live blur.

## 9. Open questions

- Font: embed a bitmap font (simple, fast) vs. a tiny vector/SDF renderer (smoother, more work) for the first screen?
- Animated gradient drift in the boot screen now, or static first then animate once we have a timer/compositor?
- Customization scope for v1 (accent color swap? wallpaper gradient picker?) — likely later, flagged for the theming engine.
