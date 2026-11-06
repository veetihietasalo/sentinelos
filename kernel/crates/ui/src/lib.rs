//! SentinelOS UI — the first pixels: the **"Cyber Dusk"** boot/lock screen.
//!
//! This crate is a small, safe (`#![forbid(unsafe_code)]`), `no_std` 2D toolkit
//! that renders directly to the bootloader framebuffer through the bounds-checked
//! [`hal::framebuffer::Framebuffer`] API. It owns no `unsafe`, no heap, and no
//! back-buffer; translucency is done by recomputing the gradient backdrop and
//! compositing analytically (see [`raster`]).
//!
//! The public entry point is [`draw_boot_screen`], which paints the approved
//! Cyber Dusk mockup: a full-screen purple→magenta gradient, a centered date and
//! large clock, a translucent glass card with the `SentinelOS` wordmark, a
//! tagline and an "swipe to unlock" pill, and a bottom dock of glossy tiles.
//!
//! Tokens (from `docs/specs/2026-06-03-ui-design-language.md` §3):
//! - Backdrop gradient `#2a1a4a → #5b2a8c → #c43e8f`.
//! - Glass: ~10–14 % white fill + ~28 % white 1px border.
//! - Accent pink `#ff5fae`, secondary cyan `#7ad7ff`.
//! - Radii 14–18 px for panels, pill for controls.

#![no_std]
#![forbid(unsafe_code)]

pub mod console;
pub mod cursor;
pub mod font;
pub mod raster;
pub mod window;

pub use console::{
    console_cols, console_geometry, console_geometry_in, console_rows, draw_console,
    draw_console_in, ConsoleGeometry, CursorStyle,
};
pub use cursor::{cursor_rect, draw_cursor, CURSOR_H, CURSOR_W};
pub use window::{clear_rect, content_rect, draw_window_chrome, Rect, WindowChrome};

use hal::framebuffer::Framebuffer;
use raster::{Gradient, Rgb};

// --- Cyber Dusk design tokens -------------------------------------------------

/// Backdrop gradient stop 1 — deep indigo `#2a1a4a`.
pub(crate) const GRAD_START: Rgb = Rgb::hex(0x2a_1a_4a);
/// Backdrop gradient stop 2 — violet `#5b2a8c`.
pub(crate) const GRAD_MID: Rgb = Rgb::hex(0x5b_2a_8c);
/// Backdrop gradient stop 3 — magenta `#c43e8f`.
pub(crate) const GRAD_END: Rgb = Rgb::hex(0xc4_3e_8f);

/// Primary text — pure white.
const TEXT_PRIMARY: Rgb = Rgb::hex(0xff_ff_ff);
/// Secondary text — ~78 % white (approximated as a light grey).
const TEXT_SECONDARY: Rgb = Rgb::hex(0xc7_c2_d6);
/// Accent pink `#ff5fae` (wordmark glow / pill text).
const ACCENT_PINK: Rgb = Rgb::hex(0xff_5f_ae);
/// Secondary accent cyan `#7ad7ff`.
const ACCENT_CYAN: Rgb = Rgb::hex(0x7a_d7_ff);
/// Glass surface tint — white (applied at low alpha over the gradient).
const GLASS_WHITE: Rgb = Rgb::hex(0xff_ff_ff);

/// Glass fill alpha (~12 % white, per token 0.10–0.14).
const GLASS_FILL_ALPHA: u8 = 31; // 0.12 * 255 ≈ 31
/// Glass border alpha (~28 % white).
const GLASS_BORDER_ALPHA: u8 = 71; // 0.28 * 255 ≈ 71
/// Pill fill alpha — a touch brighter so the control reads as actionable.
const PILL_FILL_ALPHA: u8 = 46; // ~0.18

/// Card drop-shadow vertical offset (token `box-shadow: 0 10px …`).
const SHADOW_OFFSET_Y: usize = 10;
/// Number of rounded rings used to fake the shadow blur (~34px spread).
const SHADOW_RINGS: usize = 12;
/// Innermost-ring shadow alpha (~0.18 black; fades outward to 0).
const SHADOW_PEAK_ALPHA: u8 = 46; // 0.18 * 255 ≈ 46

/// Inner top highlight thickness (token `inset 0 1px 0 …`, ~2px here).
const HIGHLIGHT_THICKNESS: usize = 2;
/// Inner top highlight alpha (~0.30 white).
const HIGHLIGHT_ALPHA: u8 = 78; // 0.30 * 255 ≈ 78

/// Geometry of the central glass card and its unlock pill, derived purely from
/// the framebuffer size so every drawing pass (the card, the hint, the unlock
/// animation) agrees on exact pixel positions without sharing mutable state.
///
/// All fields are absolute framebuffer coordinates. Returned by [`layout`].
#[derive(Clone, Copy, Debug)]
struct Layout {
    /// Card top-left x.
    card_x: usize,
    /// Card top-left y.
    card_y: usize,
    /// Card width.
    card_w: usize,
    /// Card height.
    card_h: usize,
    /// Unlock pill top-left x.
    pill_x: usize,
    /// Unlock pill top-left y.
    pill_y: usize,
    /// Unlock pill width.
    pill_w: usize,
    /// Unlock pill height.
    pill_h: usize,
    /// Unlock pill corner radius (a full pill: `pill_h / 2`).
    pill_radius: usize,
}

/// Compute the card + pill [`Layout`] for a screen of size `w × h`.
///
/// This mirrors the geometry inside [`draw_glass_card`] exactly (the card sizing
/// and the pill anchoring), so the hint and the unlock animation land precisely
/// over the pill the lock screen drew. Kept as one source of truth: change the
/// card/pill layout in both this function and [`draw_glass_card`] together.
fn layout(w: usize, h: usize) -> Layout {
    let card_w = (w * 46 / 100).clamp(220, w.saturating_sub(40).max(220));
    let card_h = (h * 30 / 100).clamp(150, h.saturating_sub(40).max(150));
    let card_x = (w.saturating_sub(card_w)) / 2;
    let card_y = (h.saturating_sub(card_h)) / 2;
    let cx = card_x + card_w / 2;

    // Pill sizing — must match `draw_glass_card`.
    let pill_label = UNLOCK_PILL_LABEL;
    let pill_text_scale = 2usize;
    let label_w = font::text_width(pill_label, pill_text_scale);
    let pad_x = 18usize;
    let pad_y = 10usize;
    let pill_w = (label_w + pad_x * 2).min(card_w.saturating_sub(card_w / 12));
    let pill_h = font::GLYPH_SIZE * pill_text_scale + pad_y * 2;
    let pill_x = cx.saturating_sub(pill_w / 2);
    let pill_y = (card_y + card_h).saturating_sub(pill_h + card_h / 8);
    let pill_radius = pill_h / 2;

    Layout {
        card_x,
        card_y,
        card_w,
        card_h,
        pill_x,
        pill_y,
        pill_w,
        pill_h,
        pill_radius,
    }
}

/// The unlock pill's label — also the geometry anchor for the hint/animation.
const UNLOCK_PILL_LABEL: &str = "swipe to unlock →";

/// Compose the full Cyber Dusk boot/lock screen onto `fb`.
///
/// Everything is centered to the live `fb.width()/height()`, so the layout
/// adapts to whatever resolution Limine handed us. The whole screen is drawn
/// once (it is a static boot frame); per-pixel work is bounded by the framebuffer
/// area. `date` is the line above the clock (the kernel passes the RTC date, or
/// [`CLOCK_DATE`] without one) and `(hh, mm, ss)` the clock's first reading.
pub fn draw_boot_screen(fb: &Framebuffer, date: &str, hh: u8, mm: u8, ss: u8) {
    let w = fb.width();
    let h = fb.height();
    if w == 0 || h == 0 {
        return;
    }

    let gradient = Gradient::three_stop(GRAD_START, GRAD_MID, GRAD_END, w, h);

    // 1) Full-screen gradient backdrop.
    gradient.fill(fb);

    // 2) Soft pink glow in the top-right corner (token: "soft pink glow
    //    top-right"). Additive-ish lift toward the accent pink, strongest at the
    //    corner and fading with distance.
    draw_corner_glow(fb, &gradient, w, h);

    // 3) Centered date + large clock above the card.
    let cx = w / 2;
    draw_clock_block(fb, cx, h, date, (hh, mm, ss));

    // 4) Centered translucent glass card.
    draw_glass_card(fb, &gradient, w, h);

    // 5) Bottom dock of glossy tiles.
    draw_dock(fb, w, h);

    // 6) The "press → to unlock" hint under the pill. Drawn at its brightest for
    //    the static initial frame; the idle loop re-draws it pulsing thereafter.
    draw_unlock_hint(fb, HINT_PULSE_PERIOD_TICKS / 4);
}

/// Peak alpha of the top-right pink corner glow (~0.30 of `GLOW_PINK`).
const GLOW_PEAK_ALPHA: u32 = 78; // 0.30 * 255 ≈ 78
/// Pink used for the corner bloom — the mockup's `rgba(255,120,220,…)`.
const GLOW_PINK: Rgb = Rgb::new(255, 120, 220);

/// A soft pink bloom in the top-right, matching the mockup's
/// `radial-gradient(80% 50% at 70% 8%, rgba(255,120,220,.25), transparent 60%)`.
///
/// The glow is an axis-aligned *elliptical* radial: centred at ~70 % width /
/// ~8 % height, with radii ~80 % of width by ~50 % of height. We measure the
/// normalised elliptical distance `d` from the centre, ramp the alpha from the
/// peak at the centre down to 0 by `d == 0.6` (the `transparent 60%` stop), and
/// composite the pink over the recomputed gradient backdrop. A smoothstep keeps
/// the falloff soft (no banding, no hard edge).
fn draw_corner_glow(fb: &Framebuffer, gradient: &Gradient, w: usize, h: usize) {
    // The glow vanishes at d == 0.6, so only scan the bounding box of that
    // sub-ellipse (centre ± 0.6·r) — everything outside is fully transparent.
    let cx = (w * 70 / 100) as i64;
    let cy = (h * 8 / 100) as i64;
    let rx = ((w * 80 / 100).max(1)) as i64;
    let ry = ((h * 50 / 100).max(1)) as i64;
    let edge_x = (rx * 6) / 10;
    let edge_y = (ry * 6) / 10;
    let x0 = (cx - edge_x).max(0) as usize;
    let x1 = ((cx + edge_x + 1).max(0) as usize).min(w);
    let y0 = (cy - edge_y).max(0) as usize;
    let y1 = ((cy + edge_y + 1).max(0) as usize).min(h);

    for py in y0..y1 {
        for px in x0..x1 {
            // `backdrop_at` already composites the glow over the gradient, so the
            // initial paint and any later region-repaint (e.g. the live clock)
            // are pixel-identical.
            let out = backdrop_at(gradient, px, py, w, h);
            fb.put_pixel(px, py, out.pack(fb));
        }
    }
}

/// The fully-composited boot-screen backdrop colour at `(px, py)`: the
/// three-stop gradient with the top-right pink corner glow blended over it.
///
/// This is the single source of truth for "what colour is the background here",
/// so both the initial paint ([`draw_corner_glow`]) and any partial repaint
/// (the live [`draw_clock`] erasing old digits) agree exactly — no seams.
pub(crate) fn backdrop_at(gradient: &Gradient, px: usize, py: usize, w: usize, h: usize) -> Rgb {
    let backdrop = gradient.color_at(px, py);

    // Glow ellipse centre and radii, in pixels (must match `draw_corner_glow`).
    let cx = (w * 70 / 100) as i64;
    let cy = (h * 8 / 100) as i64;
    let rx = ((w * 80 / 100).max(1)) as i64;
    let ry = ((h * 50 / 100).max(1)) as i64;

    // Work in fixed-point: d2 is the squared normalised elliptical distance
    // scaled by DEN² so we can compare against the 0.6 cutoff without floats.
    const DEN: i64 = 1024;
    let cutoff2 = (6 * DEN / 10) * (6 * DEN / 10); // (0.6)² in DEN² units

    let dx = px as i64 - cx;
    let dy = py as i64 - cy;
    let nx = dx * DEN / rx;
    let ny = dy * DEN / ry;
    let d2 = nx * nx + ny * ny;
    if d2 >= cutoff2 {
        return backdrop; // outside the glow: pure gradient
    }
    // Linear falloff in *distance*: t = 1 - d/0.6, with a smoothstep
    // (t²·(3-2t)) for a soft, edge-free bloom.
    let d = isqrt_u64(d2 as u64) as i64; // d·DEN
    let t = (DEN - (d * DEN / (6 * DEN / 10))).clamp(0, DEN); // 0..DEN over [0.6 → 0]
    let s = (t * t / DEN) * (3 * DEN - 2 * t) / DEN; // smoothstep, 0..DEN
    let alpha = ((s as u32) * GLOW_PEAK_ALPHA / DEN as u32) as u8;
    if alpha == 0 {
        return backdrop;
    }
    raster::blend(backdrop, GLOW_PINK, alpha)
}

/// Integer square root (Newton's method) — `no_std`, no float, for the glow's
/// distance ramp.
#[inline]
fn isqrt_u64(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = x.div_ceil(2);
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

/// The date line the boot screen falls back to when the kernel has no RTC
/// reading.
pub const CLOCK_DATE: &str = "TUESDAY  JUNE 3";
/// Text scale of the date line.
const DATE_SCALE: usize = 2;
/// Text scale of the large `HH:MM:SS` clock.
const CLOCK_SCALE: usize = 8;
/// Fallback wall-clock start (21:04:00) when the kernel has no RTC reading. The
/// live timer advances from here as PIT ticks accumulate.
pub const CLOCK_START_H: u8 = 21;
/// Initial minute (see [`CLOCK_START_H`]).
pub const CLOCK_START_M: u8 = 4;
/// Initial second (see [`CLOCK_START_H`]).
pub const CLOCK_START_S: u8 = 0;

/// `y` of the date line's top edge for a screen of height `h` (~14 % down).
#[inline]
const fn date_y(h: usize) -> usize {
    h / 8
}

/// `y` of the clock's top edge for a screen of height `h`.
#[inline]
const fn clock_y(h: usize) -> usize {
    date_y(h) + font::GLYPH_SIZE * DATE_SCALE + h / 40
}

/// Centered date line and a large clock, placed in the upper third.
fn draw_clock_block(fb: &Framebuffer, cx: usize, h: usize, date: &str, start: (u8, u8, u8)) {
    let date_w = font::text_width(date, DATE_SCALE);
    let date_x = cx.saturating_sub(date_w / 2);
    font::draw_text(
        fb,
        date_x,
        date_y(h),
        date,
        DATE_SCALE,
        TEXT_SECONDARY.pack(fb),
    );

    // Initial clock string, drawn through the shared formatter so the static and
    // live paths render identically.
    draw_clock(fb, start.0, start.1, start.2);
}

/// Format a two-digit field into `buf[off..off+2]` (00–99), zero-padded.
#[inline]
fn write_two(buf: &mut [u8; 8], off: usize, value: u8) {
    buf[off] = b'0' + (value / 10) % 10;
    buf[off + 1] = b'0' + value % 10;
}

/// Redraw **only** the clock region with the time `h:m:s`, fast.
///
/// Repaints the tight bounding box behind the `HH:MM:SS` digits from the
/// gradient backdrop (so the previous digits are erased without a full-screen
/// repaint), then draws the new time centered over it. This is the per-second
/// update the kernel's idle loop calls; the rest of the boot screen is left
/// untouched, keeping each tick cheap.
///
/// The region is centered horizontally and positioned with the same geometry as
/// the static boot frame, so it lands exactly where [`draw_boot_screen`] drew
/// the clock. Fields wider than two digits are clamped by the `%`-formatting.
pub fn draw_clock(fb: &Framebuffer, h: u8, m: u8, s: u8) {
    let w = fb.width();
    let screen_h = fb.height();
    if w == 0 || screen_h == 0 {
        return;
    }
    let cx = w / 2;

    // Build "HH:MM:SS" without any heap or format machinery.
    let mut text = *b"00:00:00";
    write_two(&mut text, 0, h);
    text[2] = b':';
    write_two(&mut text, 3, m);
    text[5] = b':';
    write_two(&mut text, 6, s);
    // SAFETY-free: every byte written above is ASCII, so this is valid UTF-8.
    let clock = core::str::from_utf8(&text).unwrap_or("00:00:00");

    let clock_w = font::text_width(clock, CLOCK_SCALE);
    let clock_x = cx.saturating_sub(clock_w / 2);
    let cy = clock_y(screen_h);
    let glyph_h = font::GLYPH_SIZE * CLOCK_SCALE;

    // 1) Erase the previous digits by repainting the *exact* boot-screen
    //    backdrop (gradient + corner glow, via `backdrop_at`) in the clock's
    //    bounding box, with a small pad. Using the same compositing as the
    //    initial paint means the repaint is seamless even where the top-right
    //    glow reaches into the clock region — no darker rectangle behind it.
    let gradient = Gradient::three_stop(GRAD_START, GRAD_MID, GRAD_END, w, screen_h);
    let pad = CLOCK_SCALE; // one source-pixel of slack
    let x0 = clock_x.saturating_sub(pad);
    let y0 = cy.saturating_sub(pad);
    let x1 = (clock_x + clock_w + pad).min(w);
    let y1 = (cy + glyph_h + pad).min(screen_h);
    for py in y0..y1 {
        for px in x0..x1 {
            let c = backdrop_at(&gradient, px, py, w, screen_h);
            fb.put_pixel(px, py, c.pack(fb));
        }
    }

    // 2) Draw the new time.
    font::draw_text(fb, clock_x, cy, clock, CLOCK_SCALE, TEXT_PRIMARY.pack(fb));
}

/// Redraw **only** the lock screen's date line with `date` (the kernel calls
/// this when the day rolls over).
///
/// Old and new dates differ in width, so the whole row is repainted from the
/// same backdrop as [`draw_clock`] uses, then the new line is drawn centered
/// where [`draw_boot_screen`] put it.
pub fn draw_date(fb: &Framebuffer, date: &str) {
    let w = fb.width();
    let screen_h = fb.height();
    if w == 0 || screen_h == 0 {
        return;
    }
    let gradient = Gradient::three_stop(GRAD_START, GRAD_MID, GRAD_END, w, screen_h);
    let pad = DATE_SCALE;
    let y0 = date_y(screen_h).saturating_sub(pad);
    let y1 = (date_y(screen_h) + font::GLYPH_SIZE * DATE_SCALE + pad).min(screen_h);
    for py in y0..y1 {
        for px in 0..w {
            let c = backdrop_at(&gradient, px, py, w, screen_h);
            fb.put_pixel(px, py, c.pack(fb));
        }
    }
    let date_w = font::text_width(date, DATE_SCALE);
    font::draw_text(
        fb,
        (w / 2).saturating_sub(date_w / 2),
        date_y(screen_h),
        date,
        DATE_SCALE,
        TEXT_SECONDARY.pack(fb),
    );
}

/// The central translucent glass card with the wordmark, tagline and pill.
fn draw_glass_card(fb: &Framebuffer, gradient: &Gradient, w: usize, h: usize) {
    // Card geometry: ~46 % of width, centered, sitting in the vertical middle.
    let card_w = (w * 46 / 100).clamp(220, w.saturating_sub(40).max(220));
    let card_h = (h * 30 / 100).clamp(150, h.saturating_sub(40).max(150));
    let card_x = (w.saturating_sub(card_w)) / 2;
    let card_y = (h.saturating_sub(card_h)) / 2;
    let radius = 18usize;
    let border_w = 1usize;

    // Soft drop shadow (token: `box-shadow: 0 10px 34px rgba(0,0,0,.4)`) —
    // drawn FIRST, behind the card, as stacked low-alpha black rounded rings
    // offset downward and grown outward to fake the blur.
    raster::drop_shadow_rounded_rect(
        fb,
        gradient,
        card_x,
        card_y,
        card_w,
        card_h,
        radius,
        SHADOW_OFFSET_Y,
        SHADOW_RINGS,
        SHADOW_PEAK_ALPHA,
    );

    // Glass fill (~12 % white over the gradient) + brighter ~1px border.
    raster::fill_rounded_rect_alpha(
        fb,
        gradient,
        card_x,
        card_y,
        card_w,
        card_h,
        radius,
        GLASS_WHITE,
        GLASS_FILL_ALPHA,
    );
    raster::stroke_rounded_rect_alpha(
        fb,
        gradient,
        card_x,
        card_y,
        card_w,
        card_h,
        radius,
        GLASS_WHITE,
        GLASS_BORDER_ALPHA,
    );

    // Inner top highlight (token: `inset 0 1px 0 rgba(255,255,255,.3)`) — a
    // bright ~2px white span just inside the top border, between the corners.
    raster::inner_top_highlight(
        fb,
        gradient,
        card_x,
        card_y,
        card_w,
        radius,
        border_w,
        HIGHLIGHT_THICKNESS,
        GLASS_WHITE,
        HIGHLIGHT_ALPHA,
    );

    let cx = card_x + card_w / 2;

    // --- Wordmark: big & bright -------------------------------------------
    let wordmark = "SentinelOS";
    // Choose a scale that fits the card width with margin.
    let mut wm_scale = 5usize;
    while wm_scale > 1 && font::text_width(wordmark, wm_scale) > card_w.saturating_sub(card_w / 6) {
        wm_scale -= 1;
    }
    let wm_w = font::text_width(wordmark, wm_scale);
    let wm_x = cx.saturating_sub(wm_w / 2);
    let wm_y = card_y + card_h / 6;
    // A subtle pink "glow" pass behind the white wordmark: same text drawn 1px
    // offset in accent pink, then white on top — cheap emphasis without a blur.
    font::draw_text(
        fb,
        wm_x + 1,
        wm_y + 1,
        wordmark,
        wm_scale,
        ACCENT_PINK.pack(fb),
    );
    font::draw_text(fb, wm_x, wm_y, wordmark, wm_scale, TEXT_PRIMARY.pack(fb));

    // --- Tagline -----------------------------------------------------------
    let tagline = "private · secure · yours";
    let tag_scale = 2usize;
    let tag_w = font::text_width(tagline, tag_scale);
    let tag_x = cx.saturating_sub(tag_w / 2);
    let tag_y = wm_y + font::GLYPH_SIZE * wm_scale + card_h / 12;
    font::draw_text(
        fb,
        tag_x,
        tag_y,
        tagline,
        tag_scale,
        TEXT_SECONDARY.pack(fb),
    );

    // --- Unlock pill -------------------------------------------------------
    let pill_label = UNLOCK_PILL_LABEL;
    let pill_text_scale = 2usize;
    let label_w = font::text_width(pill_label, pill_text_scale);
    let pad_x = 18usize;
    let pad_y = 10usize;
    let pill_w = (label_w + pad_x * 2).min(card_w.saturating_sub(card_w / 12));
    let pill_h = font::GLYPH_SIZE * pill_text_scale + pad_y * 2;
    let pill_x = cx.saturating_sub(pill_w / 2);
    // Anchor the pill near the bottom of the card.
    let pill_y = (card_y + card_h).saturating_sub(pill_h + card_h / 8);
    let pill_radius = pill_h / 2; // full pill

    raster::fill_rounded_rect_alpha(
        fb,
        gradient,
        pill_x,
        pill_y,
        pill_w,
        pill_h,
        pill_radius,
        GLASS_WHITE,
        PILL_FILL_ALPHA,
    );
    raster::stroke_rounded_rect_alpha(
        fb,
        gradient,
        pill_x,
        pill_y,
        pill_w,
        pill_h,
        pill_radius,
        ACCENT_CYAN,
        GLASS_BORDER_ALPHA,
    );
    let label_x = cx.saturating_sub(label_w / 2);
    let label_y = pill_y + pad_y;
    font::draw_text(
        fb,
        label_x,
        label_y,
        pill_label,
        pill_text_scale,
        TEXT_PRIMARY.pack(fb),
    );
}

/// A bottom dock of four glossy gradient rounded-square tiles.
fn draw_dock(fb: &Framebuffer, w: usize, h: usize) {
    const N: usize = 4;
    // Per-tile gradient pairs (top → bottom), glossy and on-brand.
    let tiles: [(Rgb, Rgb); N] = [
        (Rgb::hex(0xff_8a_d0), Rgb::hex(0xb0_3a_8f)), // pink
        (Rgb::hex(0x8a_c8_ff), Rgb::hex(0x35_5a_b0)), // blue
        (Rgb::hex(0x9a_ff_d6), Rgb::hex(0x2c_8f_70)), // mint
        (Rgb::hex(0xc7_a8_ff), Rgb::hex(0x5b_2a_8c)), // violet
    ];

    let tile = (h / 11).clamp(28, 96);
    let gap = tile / 2;
    let radius = tile / 4;

    let total_w = N * tile + (N - 1) * gap;
    let start_x = (w.saturating_sub(total_w)) / 2;
    // Sit the dock near the bottom edge with a margin.
    let tile_y = h.saturating_sub(tile + h / 14);

    for (i, (top, bottom)) in tiles.iter().enumerate() {
        let tx = start_x + i * (tile + gap);
        raster::glossy_tile(fb, tx, tile_y, tile, radius, *top, *bottom);
    }
}

// ── Unlock hint (pulsing) ───────────────────────────────────────────────────

/// The unlock hint shown under the pill while locked. The literal `→` glyph
/// (the font has it) makes the gesture unmistakable.
const HINT_TEXT: &str = "press  →  to unlock";
/// Text scale of the hint line.
const HINT_SCALE: usize = 2;
/// Pulse period of the hint, in PIT ticks (~100 Hz → ~1.0 s for a gentle pulse).
pub const HINT_PULSE_PERIOD_TICKS: u64 = 100;
/// Minimum alpha of the hint at the dim end of its pulse (so it never vanishes).
const HINT_MIN_ALPHA: u32 = 70;
/// Maximum alpha of the hint at the bright end of its pulse.
const HINT_MAX_ALPHA: u32 = 235;

/// `y` of the hint line's top edge: just below the unlock pill, clamped so it
/// stays clear of the dock at the very bottom of small screens.
#[inline]
fn hint_y(lay: &Layout, h: usize) -> usize {
    let below_pill = lay.pill_y + lay.pill_h + h / 36;
    // Keep a little breathing room above the bottom edge.
    below_pill.min(h.saturating_sub(font::GLYPH_SIZE * HINT_SCALE + h / 12))
}

/// Draw (or re-draw) the pulsing "press → to unlock" hint under the unlock pill.
///
/// `phase_ticks` is the current [`hal::pit::ticks`] value; the brightness is a
/// triangle wave of it over [`HINT_PULSE_PERIOD_TICKS`], ramping the hint's alpha
/// between [`HINT_MIN_ALPHA`] and [`HINT_MAX_ALPHA`] so it gently breathes and
/// draws the eye. The hint's bounding box is first repainted from the exact
/// Cyber-Dusk backdrop (gradient + corner glow), so successive frames don't
/// smear — identical to how [`draw_clock`] erases the old digits. Cheap: only the
/// tight text box is touched each frame.
///
/// Call this every tick **only while locked**; the unlock animation and the
/// desktop draw over this region and take ownership of it.
pub fn draw_unlock_hint(fb: &Framebuffer, phase_ticks: u64) {
    let w = fb.width();
    let h = fb.height();
    if w == 0 || h == 0 {
        return;
    }
    let lay = layout(w, h);

    // Triangle-wave brightness over the pulse period: 0 → 1 → 0.
    let period = HINT_PULSE_PERIOD_TICKS.max(1);
    let half = period / 2;
    let p = phase_ticks % period;
    let tri = if p < half {
        p * 255 / half.max(1)
    } else {
        255 - ((p - half) * 255 / (period - half).max(1))
    };
    let alpha =
        (HINT_MIN_ALPHA + (HINT_MAX_ALPHA - HINT_MIN_ALPHA) * tri as u32 / 255).min(255) as u8;

    let text_w = font::text_width(HINT_TEXT, HINT_SCALE);
    let cx = w / 2;
    let text_x = cx.saturating_sub(text_w / 2);
    let text_y = hint_y(&lay, h);
    let glyph_h = font::GLYPH_SIZE * HINT_SCALE;

    // 1) Erase the previous frame by repainting the exact backdrop in the hint's
    //    bounding box (with a small pad), so the pulse never leaves ghosting.
    let gradient = Gradient::three_stop(GRAD_START, GRAD_MID, GRAD_END, w, h);
    let pad = HINT_SCALE;
    let x0 = text_x.saturating_sub(pad);
    let y0 = text_y.saturating_sub(pad);
    let x1 = (text_x + text_w + pad).min(w);
    let y1 = (text_y + glyph_h + pad).min(h);
    for py in y0..y1 {
        for px in x0..x1 {
            let c = backdrop_at(&gradient, px, py, w, h);
            fb.put_pixel(px, py, c.pack(fb));
        }
    }

    // 2) Draw the hint in cyan, alpha-modulated by blending toward the backdrop.
    //    We pre-blend the cyan over an approximate mid-backdrop so the text can be
    //    plotted with a single packed colour (text plotting is additive per glyph
    //    pixel; blending per-glyph-pixel would mean a backdrop read we avoid).
    let mid_backdrop = gradient.color_at(cx, text_y);
    let tint = raster::blend(mid_backdrop, ACCENT_CYAN, alpha);
    font::draw_text(fb, text_x, text_y, HINT_TEXT, HINT_SCALE, tint.pack(fb));
}

// ── Unlock animation ─────────────────────────────────────────────────────────

/// Total length of the unlock animation, in PIT ticks (~100 Hz → ~0.7 s).
pub const UNLOCK_ANIM_TICKS: u64 = 70;

/// Draw one frame of the unlock animation for normalised progress `p ∈ [0, 255]`
/// (0 = just started, 255 = finished). Driven by the kernel idle loop from the
/// elapsed ticks since the unlock gesture.
///
/// The animation reads as a two-beat "unlock":
///
/// 1. **Swipe wipe (p: 0 → ~0.6).** A bright cyan→pink fill sweeps the unlock
///    pill left→right, following the `→` arrow — the pill "lights up" as if the
///    swipe completed. A soft leading edge keeps it from looking like a hard bar.
/// 2. **Card dissolve (p: ~0.6 → 1).** The whole glass card (and its hint) fades
///    back to the bare Cyber-Dusk backdrop, as if the lock surface slides away,
///    revealing the gradient that the desktop will sit on.
///
/// Kept cheap: phase 1 touches only the pill's bounding box; phase 2 repaints the
/// card's bounding box from the gradient (no per-pixel card re-render). The caller
/// paints the desktop once when `p` reaches 255.
pub fn draw_unlock_frame(fb: &Framebuffer, p: u8) {
    let w = fb.width();
    let h = fb.height();
    if w == 0 || h == 0 {
        return;
    }
    let lay = layout(w, h);
    let gradient = Gradient::three_stop(GRAD_START, GRAD_MID, GRAD_END, w, h);

    // Split point between the swipe (phase 1) and the dissolve (phase 2).
    const SPLIT: u16 = 150; // ~0.59 of 255

    if (p as u16) < SPLIT {
        // ── Phase 1: cyan→pink swipe across the pill ───────────────────────
        let prog = p as usize; // 0..SPLIT
                               // The leading edge of the fill, in pill-local pixels.
        let edge = lay.pill_w * prog / SPLIT as usize;
        // A soft feather so the edge isn't a hard vertical line.
        let feather = (lay.pill_w / 12).max(4);

        for py in lay.pill_y..(lay.pill_y + lay.pill_h).min(h) {
            for px in lay.pill_x..(lay.pill_x + lay.pill_w).min(w) {
                if !raster::in_rounded_rect(
                    px,
                    py,
                    lay.pill_x,
                    lay.pill_y,
                    lay.pill_w,
                    lay.pill_h,
                    lay.pill_radius,
                ) {
                    continue;
                }
                let lx = px - lay.pill_x;
                let backdrop = gradient.color_at(px, py);
                // Fill colour shifts cyan (left) → pink (right) across the pill.
                let fill = raster::lerp_rgb(ACCENT_CYAN, ACCENT_PINK, lx, lay.pill_w.max(1));
                // Alpha: full behind the edge, feathering to 0 just ahead of it.
                let a: u8 = if lx + feather <= edge {
                    220
                } else if lx <= edge {
                    let d = edge - lx; // 0..feather
                    (220 * d / feather.max(1)) as u8
                } else {
                    0
                };
                let out = if a == 0 {
                    // Ahead of the swipe: keep the resting translucent pill look.
                    raster::blend(backdrop, GLASS_WHITE, PILL_FILL_ALPHA)
                } else {
                    raster::blend(backdrop, fill, a)
                };
                fb.put_pixel(px, py, out.pack(fb));
            }
        }
    } else {
        // ── Phase 2: dissolve the glass card back to the backdrop ──────────
        let prog = (p as u16 - SPLIT) as usize; // 0..(255-SPLIT)
        let span = (255 - SPLIT) as usize;
        // Reveal the backdrop top-down: a moving boundary wipes the card away,
        // so it reads as the lock surface sliding/dissolving off-screen.
        let reveal = lay.card_h * prog / span.max(1);

        // Bounding box covering the card plus its shadow and the hint below it.
        let bx0 = lay.card_x.saturating_sub(SHADOW_RINGS + 2);
        let by0 = lay.card_y.saturating_sub(SHADOW_RINGS + 2);
        let bx1 = (lay.card_x + lay.card_w + SHADOW_RINGS + 2).min(w);
        let hint_bottom = hint_y(&lay, h) + font::GLYPH_SIZE * HINT_SCALE + HINT_SCALE;
        let by1 = (lay.card_y + lay.card_h + SHADOW_OFFSET_Y + SHADOW_RINGS + 2)
            .max(hint_bottom)
            .min(h);

        for py in by0..by1 {
            // Only repaint rows that have been "revealed" so far (top-down wipe),
            // plus a soft 1-row leading edge, so each frame does a thin strip and
            // the card appears to peel away progressively.
            let revealed = py < lay.card_y + reveal || py >= lay.card_y + lay.card_h;
            if !revealed {
                continue;
            }
            for px in bx0..bx1 {
                let c = backdrop_at(&gradient, px, py, w, h);
                fb.put_pixel(px, py, c.pack(fb));
            }
        }
    }
}

// ── Desktop stub ─────────────────────────────────────────────────────────────

/// Height of the desktop top status bar.
const STATUS_BAR_H_DIV: usize = 16; // bar height ≈ screen_h / 16
/// Status-bar fill alpha (a translucent dark glass strip).
const STATUS_BAR_ALPHA: u8 = 70;

/// Paint the first SentinelOS desktop over the existing Cyber Dusk gradient.
///
/// Called **once**, when the unlock animation completes. It assumes the backdrop
/// is already the bare gradient (the unlock animation dissolved the card away), so
/// it only adds the desktop chrome: a slim translucent top status bar with the
/// `SentinelOS` wordmark at the left and a `Welcome` greeting centered on the
/// canvas. The dock at the bottom is left in place from the lock screen. The live
/// clock is drawn separately by [`draw_desktop_clock`], which the idle loop keeps
/// ticking.
pub fn draw_desktop(fb: &Framebuffer) {
    let w = fb.width();
    let h = fb.height();
    if w == 0 || h == 0 {
        return;
    }
    let gradient = Gradient::three_stop(GRAD_START, GRAD_MID, GRAD_END, w, h);

    // Repaint the whole canvas to the bare backdrop so any animation residue
    // (and the old lock card region) is cleared, then add desktop chrome on top.
    for py in 0..h {
        for px in 0..w {
            let c = backdrop_at(&gradient, px, py, w, h);
            fb.put_pixel(px, py, c.pack(fb));
        }
    }

    // Slim translucent status bar across the top.
    let bar_h = (h / STATUS_BAR_H_DIV).clamp(24, 56);
    raster::fill_rounded_rect_alpha(
        fb,
        &gradient,
        0,
        0,
        w,
        bar_h,
        0,
        Rgb::hex(0x10_08_20),
        STATUS_BAR_ALPHA,
    );

    // Left: the SentinelOS wordmark in the bar.
    let label = "SentinelOS";
    let label_scale = 2usize;
    let pad = w / 64;
    let label_y = (bar_h.saturating_sub(font::GLYPH_SIZE * label_scale)) / 2;
    // Subtle pink under-glow then white, mirroring the lock-screen wordmark.
    font::draw_text(
        fb,
        pad + 1,
        label_y + 1,
        label,
        label_scale,
        ACCENT_PINK.pack(fb),
    );
    font::draw_text(fb, pad, label_y, label, label_scale, TEXT_PRIMARY.pack(fb));

    // Centered "Welcome" greeting on the desktop canvas.
    let greet = "Welcome";
    let greet_scale = 6usize;
    let greet_w = font::text_width(greet, greet_scale);
    let greet_x = (w / 2).saturating_sub(greet_w / 2);
    let greet_y = h / 2 - font::GLYPH_SIZE * greet_scale / 2;
    font::draw_text(
        fb,
        greet_x + 1,
        greet_y + 1,
        greet,
        greet_scale,
        ACCENT_PINK.pack(fb),
    );
    font::draw_text(
        fb,
        greet_x,
        greet_y,
        greet,
        greet_scale,
        TEXT_PRIMARY.pack(fb),
    );

    let sub = "SentinelOS desktop";
    let sub_scale = 2usize;
    let sub_w = font::text_width(sub, sub_scale);
    let sub_x = (w / 2).saturating_sub(sub_w / 2);
    let sub_y = greet_y + font::GLYPH_SIZE * greet_scale + h / 40;
    font::draw_text(fb, sub_x, sub_y, sub, sub_scale, TEXT_SECONDARY.pack(fb));

    // Keep the familiar dock at the bottom.
    draw_dock(fb, w, h);

    // Draw the clock once now; the idle loop refreshes it each second.
    draw_desktop_clock(fb, CLOCK_START_H, CLOCK_START_M, CLOCK_START_S);
}

/// Top-right x of the desktop clock text box, for a given clock width.
#[inline]
fn desktop_clock_geom(fb: &Framebuffer) -> (usize, usize, usize, usize) {
    let w = fb.width();
    let h = fb.height();
    let bar_h = (h / STATUS_BAR_H_DIV).clamp(24, 56);
    let scale = 2usize;
    let clock_w = font::text_width("00:00:00", scale);
    let pad = w / 64;
    let x = w.saturating_sub(clock_w + pad);
    let y = (bar_h.saturating_sub(font::GLYPH_SIZE * scale)) / 2;
    (x, y, clock_w, scale)
}

/// Redraw the live clock in the desktop's top status bar (right-aligned).
///
/// Mirrors [`draw_clock`]'s "erase then draw" approach but scoped to the status
/// bar's right side, so the desktop clock keeps ticking once per second without
/// disturbing the rest of the bar. The idle loop calls this with the current
/// `HH:MM:SS` each whole second.
pub fn draw_desktop_clock(fb: &Framebuffer, h: u8, m: u8, s: u8) {
    let w = fb.width();
    let screen_h = fb.height();
    if w == 0 || screen_h == 0 {
        return;
    }
    let (x, y, clock_w, scale) = desktop_clock_geom(fb);
    let glyph_h = font::GLYPH_SIZE * scale;

    // Build "HH:MM:SS".
    let mut text = *b"00:00:00";
    write_two(&mut text, 0, h);
    text[2] = b':';
    write_two(&mut text, 3, m);
    text[5] = b':';
    write_two(&mut text, 6, s);
    let clock = core::str::from_utf8(&text).unwrap_or("00:00:00");

    // Erase the previous time by repainting the status-bar strip behind it
    // (backdrop + translucent bar fill), then draw the new time over it.
    let gradient = Gradient::three_stop(GRAD_START, GRAD_MID, GRAD_END, w, screen_h);
    let pad = scale;
    let x0 = x.saturating_sub(pad);
    let y0 = y.saturating_sub(pad);
    let x1 = (x + clock_w + pad).min(w);
    let y1 = (y + glyph_h + pad).min(screen_h);
    for py in y0..y1 {
        for px in x0..x1 {
            let backdrop = backdrop_at(&gradient, px, py, w, screen_h);
            let out = raster::blend(backdrop, Rgb::hex(0x10_08_20), STATUS_BAR_ALPHA);
            fb.put_pixel(px, py, out.pack(fb));
        }
    }
    font::draw_text(fb, x, y, clock, scale, TEXT_PRIMARY.pack(fb));
}
