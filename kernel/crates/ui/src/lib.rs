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

pub mod font;
pub mod raster;

use hal::framebuffer::Framebuffer;
use raster::{Gradient, Rgb};

// --- Cyber Dusk design tokens -------------------------------------------------

/// Backdrop gradient stop 1 — deep indigo `#2a1a4a`.
const GRAD_START: Rgb = Rgb::hex(0x2a_1a_4a);
/// Backdrop gradient stop 2 — violet `#5b2a8c`.
const GRAD_MID: Rgb = Rgb::hex(0x5b_2a_8c);
/// Backdrop gradient stop 3 — magenta `#c43e8f`.
const GRAD_END: Rgb = Rgb::hex(0xc4_3e_8f);

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

/// Compose the full Cyber Dusk boot/lock screen onto `fb`.
///
/// Everything is centered to the live `fb.width()/height()`, so the layout
/// adapts to whatever resolution Limine handed us. The whole screen is drawn
/// once (it is a static boot frame); per-pixel work is bounded by the framebuffer
/// area.
pub fn draw_boot_screen(fb: &Framebuffer) {
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
    draw_clock_block(fb, cx, h);

    // 4) Centered translucent glass card.
    draw_glass_card(fb, &gradient, w, h);

    // 5) Bottom dock of glossy tiles.
    draw_dock(fb, w, h);
}

/// A soft pink glow radiating from the top-right corner.
fn draw_corner_glow(fb: &Framebuffer, gradient: &Gradient, w: usize, h: usize) {
    // Glow region: a box in the top-right quadrant. Within it, lift the backdrop
    // toward pink with an alpha that falls off with distance from the corner.
    let span = (w.min(h) * 2) / 3;
    if span == 0 {
        return;
    }
    let max_d2 = (span * span) as u64;
    let corner_x = w.saturating_sub(1);
    for py in 0..span.min(h) {
        for px in w.saturating_sub(span)..w {
            let dx = corner_x - px;
            let dy = py;
            let d2 = (dx * dx + dy * dy) as u64;
            if d2 >= max_d2 {
                continue;
            }
            // Quadratic falloff, capped so the glow stays subtle.
            let strength = max_d2 - d2;
            let alpha = (strength * 60 / max_d2) as u8; // up to ~24 %
            let backdrop = gradient.color_at(px, py);
            let out = raster::blend(backdrop, ACCENT_PINK, alpha);
            fb.put_pixel(px, py, out.pack(fb));
        }
    }
}

/// Centered date line and a large clock, placed in the upper third.
fn draw_clock_block(fb: &Framebuffer, cx: usize, h: usize) {
    // Static placeholder time/date — there is no RTC wired in yet, so the boot
    // frame shows a representative value (the design's reference time).
    let date = "TUESDAY  JUNE 3";
    let clock = "21:04";

    let date_scale = 2usize;
    let clock_scale = 8usize;

    // Date sits ~14 % down the screen, clock just below it.
    let date_w = font::text_width(date, date_scale);
    let date_x = cx.saturating_sub(date_w / 2);
    let date_y = h / 8;
    font::draw_text(fb, date_x, date_y, date, date_scale, TEXT_SECONDARY.pack(fb));

    let clock_w = font::text_width(clock, clock_scale);
    let clock_x = cx.saturating_sub(clock_w / 2);
    let clock_y = date_y + font::GLYPH_SIZE * date_scale + h / 40;
    font::draw_text(fb, clock_x, clock_y, clock, clock_scale, TEXT_PRIMARY.pack(fb));
}

/// The central translucent glass card with the wordmark, tagline and pill.
fn draw_glass_card(fb: &Framebuffer, gradient: &Gradient, w: usize, h: usize) {
    // Card geometry: ~46 % of width, centered, sitting in the vertical middle.
    let card_w = (w * 46 / 100).clamp(220, w.saturating_sub(40).max(220));
    let card_h = (h * 30 / 100).clamp(150, h.saturating_sub(40).max(150));
    let card_x = (w.saturating_sub(card_w)) / 2;
    let card_y = (h.saturating_sub(card_h)) / 2;
    let radius = 18usize;

    // Glass fill (~12 % white over the gradient) + brighter ~1px border.
    raster::fill_rounded_rect_alpha(
        fb, gradient, card_x, card_y, card_w, card_h, radius, GLASS_WHITE, GLASS_FILL_ALPHA,
    );
    raster::stroke_rounded_rect_alpha(
        fb, gradient, card_x, card_y, card_w, card_h, radius, GLASS_WHITE, GLASS_BORDER_ALPHA,
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
    font::draw_text(fb, wm_x + 1, wm_y + 1, wordmark, wm_scale, ACCENT_PINK.pack(fb));
    font::draw_text(fb, wm_x, wm_y, wordmark, wm_scale, TEXT_PRIMARY.pack(fb));

    // --- Tagline -----------------------------------------------------------
    let tagline = "private · secure · yours";
    let tag_scale = 2usize;
    let tag_w = font::text_width(tagline, tag_scale);
    let tag_x = cx.saturating_sub(tag_w / 2);
    let tag_y = wm_y + font::GLYPH_SIZE * wm_scale + card_h / 12;
    font::draw_text(fb, tag_x, tag_y, tagline, tag_scale, TEXT_SECONDARY.pack(fb));

    // --- Unlock pill -------------------------------------------------------
    let pill_label = "swipe to unlock →";
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
        fb, gradient, pill_x, pill_y, pill_w, pill_h, pill_radius, GLASS_WHITE, PILL_FILL_ALPHA,
    );
    raster::stroke_rounded_rect_alpha(
        fb, gradient, pill_x, pill_y, pill_w, pill_h, pill_radius, ACCENT_CYAN, GLASS_BORDER_ALPHA,
    );
    let label_x = cx.saturating_sub(label_w / 2);
    let label_y = pill_y + pad_y;
    font::draw_text(fb, label_x, label_y, pill_label, pill_text_scale, TEXT_PRIMARY.pack(fb));
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
