//! Windowed-desktop rendering primitives — the **`ui`-side compositor API** the
//! in-kernel window manager (WM) consumes.
//!
//! This module owns *drawing*, not *policy*: it knows how a window panel looks
//! and how to erase a region back to the Cyber Dusk backdrop, but it holds no
//! window list, focus, or z-order state (that lives in `kernel/src/wm.rs`). Like
//! the rest of the crate it is `#![forbid(unsafe_code)]`, `no_std`, heap-free,
//! and draws exclusively through the bounds-checked
//! [`hal::framebuffer::Framebuffer`] via the [`crate::raster`] compositor — so a
//! window's translucent "glass" panel is recomputed analytically over the Cyber
//! Dusk gradient backdrop, exactly like the lock card and the console.
//!
//! It provides three things the compositor needs:
//!
//! * [`Rect`] — an absolute-framebuffer-coordinate rectangle (the spec's window
//!   bounds / content / damage-rectangle shape).
//! * [`clear_rect`] — repaint a rectangle back to the bare Cyber Dusk backdrop
//!   (gradient + corner glow). This is the **expose** primitive: when a window
//!   closes or moves, the compositor erases the region it occupied so the
//!   backdrop (and any window behind it, redrawn afterwards) shows through.
//! * [`draw_window_chrome`] + [`content_rect`] — draw a glass window panel
//!   (drop shadow, fill, title bar with the pink/cyan dots, border, inner top
//!   highlight, focus accent) at an arbitrary [`Rect`], and compute the inner
//!   content rectangle an app draws into. This generalises the console's
//!   `draw_panel_chrome` into a reusable, focus-aware window-chrome drawer.

use hal::framebuffer::Framebuffer;

use crate::raster::{self, Gradient, Rgb};
use crate::{backdrop_at, GRAD_END, GRAD_MID, GRAD_START};
use crate::font;

// --- Geometry -----------------------------------------------------------------

/// A rectangle in **absolute framebuffer coordinates**, top-left at `(x, y)`.
///
/// This is the shared shape for window bounds, content areas, and damage
/// rectangles. It mirrors the WM-side `Rect` in the windowed-desktop spec so the
/// kernel and the `ui` compositor agree on one geometry type when the kernel
/// passes a window's bounds (or a damage region) into these draw functions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rect {
    /// Left edge x, absolute framebuffer pixels.
    pub x: usize,
    /// Top edge y, absolute framebuffer pixels.
    pub y: usize,
    /// Width in pixels.
    pub w: usize,
    /// Height in pixels.
    pub h: usize,
}

impl Rect {
    /// Construct a [`Rect`] from its top-left corner and size.
    #[must_use]
    pub const fn new(x: usize, y: usize, w: usize, h: usize) -> Self {
        Self { x, y, w, h }
    }

    /// The exclusive right edge (`x + w`), saturating.
    #[inline]
    #[must_use]
    pub const fn right(&self) -> usize {
        self.x.saturating_add(self.w)
    }

    /// The exclusive bottom edge (`y + h`), saturating.
    #[inline]
    #[must_use]
    pub const fn bottom(&self) -> usize {
        self.y.saturating_add(self.h)
    }
}

// --- Expose primitive ---------------------------------------------------------

/// Repaint `rect` back to the bare Cyber Dusk desktop backdrop.
///
/// This is the compositor's **expose** primitive: it recomputes the exact
/// Cyber Dusk background (the three-stop gradient *plus* the top-right pink
/// corner glow) at every pixel in `rect` and writes it, erasing whatever was
/// there. Because it uses the same `backdrop_at` reconstruction the lock screen
/// and console already use to erase the clock/hint, the result is seamless even
/// where the corner glow reaches into `rect` — no darker rectangle, no seam.
///
/// The WM calls this to clear damage regions before redrawing the windows/chrome
/// that intersect them (e.g. when a window closes, its old rect is exposed so the
/// backdrop and any window behind it repaint cleanly). The rect is clamped to the
/// framebuffer; an off-screen or zero-size framebuffer is a no-op, and a rect
/// extending past the edges is safely clipped.
pub fn clear_rect(fb: &Framebuffer, rect: Rect) {
    let w = fb.width();
    let h = fb.height();
    if w == 0 || h == 0 {
        return;
    }
    let gradient = Gradient::three_stop(GRAD_START, GRAD_MID, GRAD_END, w, h);

    let x0 = rect.x.min(w);
    let y0 = rect.y.min(h);
    let x1 = rect.right().min(w);
    let y1 = rect.bottom().min(h);
    for py in y0..y1 {
        for px in x0..x1 {
            let c = backdrop_at(&gradient, px, py, w, h);
            fb.put_pixel(px, py, c.pack(fb));
        }
    }
}

// --- Window chrome ------------------------------------------------------------

/// Cyber Dusk window-chrome tokens: the title-bar height, border, corner radius
/// and inner padding that define a window's frame.
///
/// One [`WindowChrome`] is the single source of truth shared by
/// [`draw_window_chrome`] (which *draws* the frame) and [`content_rect`] (which
/// *insets* the bounds to the content area an app draws into), so the compositor
/// and the WM always agree on where chrome ends and content begins — mirroring
/// how the console derives its text grid from one geometry. Use
/// [`WindowChrome::default`] for the standard Cyber Dusk look, or build a custom
/// one if a window wants a different title-bar height / padding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowChrome {
    /// Height of the title-bar strip, in pixels (title text + dots live here).
    pub titlebar_h: usize,
    /// Frame border / content inset thickness, in pixels (left, right, bottom).
    pub border: usize,
    /// Outer corner radius of the glass panel, in pixels.
    pub radius: usize,
    /// Title-bar text scale (integer font magnification).
    pub title_scale: usize,
}

/// Default title-bar text scale (matches the console's chrome).
const DEFAULT_TITLE_SCALE: usize = 2;
/// Default title-bar height: one title row plus symmetric breathing room.
const DEFAULT_TITLEBAR_H: usize = font::GLYPH_SIZE * DEFAULT_TITLE_SCALE * 2;
/// Default content inset (border + padding) on the non-title sides.
const DEFAULT_BORDER: usize = font::GLYPH_SIZE * DEFAULT_TITLE_SCALE;
/// Default outer corner radius (Cyber Dusk panels are 14–18 px).
const DEFAULT_RADIUS: usize = 16;

impl WindowChrome {
    /// The standard Cyber Dusk window chrome.
    ///
    /// Title bar tall enough for one scale-2 title row with padding, a one-cell
    /// content inset on the other three sides, and a 16 px corner radius — the
    /// same proportions the console panel uses, so a windowed terminal looks
    /// identical to today's full-screen console.
    #[must_use]
    pub const fn cyber_dusk() -> Self {
        Self {
            titlebar_h: DEFAULT_TITLEBAR_H,
            border: DEFAULT_BORDER,
            radius: DEFAULT_RADIUS,
            title_scale: DEFAULT_TITLE_SCALE,
        }
    }
}

impl Default for WindowChrome {
    fn default() -> Self {
        Self::cyber_dusk()
    }
}

/// The content rectangle of a window: its `bounds` inset by the title bar at the
/// top and the [`WindowChrome::border`] on the other three sides.
///
/// This is the area an app draws into (the compositor clips drawing there; the
/// `Framebuffer` also clips, so an app overrunning is a safe no-op). Returned in
/// absolute framebuffer coordinates. If the bounds are too small to hold any
/// content, the returned rect collapses to a zero-size rect at the content
/// origin (its width/height saturate to 0) rather than wrapping.
#[must_use]
pub fn content_rect(bounds: Rect, chrome: &WindowChrome) -> Rect {
    let x = bounds.x + chrome.border;
    let y = bounds.y + chrome.titlebar_h;
    let w = bounds
        .w
        .saturating_sub(chrome.border.saturating_mul(2));
    let h = bounds
        .h
        .saturating_sub(chrome.titlebar_h)
        .saturating_sub(chrome.border);
    Rect { x, y, w, h }
}

// --- Window-chrome tokens (Cyber Dusk, matching the console panel) -------------

/// Glass body fill — a deep indigo, fairly opaque so app content stays legible.
const GLASS_DARK: Rgb = Rgb::hex(0x12_0a_28);
/// Glass body fill alpha (~0.62 — a window wants a more solid backdrop).
const GLASS_FILL_ALPHA: u8 = 158;
/// Glass surface tint for borders/highlights — white at low alpha.
const GLASS_WHITE: Rgb = Rgb::hex(0xff_ff_ff);

/// Border alpha for a **focused** window (bright, crisp ~0.30 white outline).
const BORDER_ALPHA_FOCUSED: u8 = 78;
/// Border alpha for an **unfocused** window (dimmer, recedes).
const BORDER_ALPHA_UNFOCUSED: u8 = 40;

/// Title-bar tint — a touch brighter than the body so the header reads.
const TITLEBAR_TINT: Rgb = Rgb::hex(0x1c_10_3a);
/// Title-bar fill alpha for a **focused** window (brighter chrome).
const TITLEBAR_ALPHA_FOCUSED: u8 = 190;
/// Title-bar fill alpha for an **unfocused** window (dimmer chrome).
const TITLEBAR_ALPHA_UNFOCUSED: u8 = 130;

/// Inner top highlight thickness (the glossy `inset 0 1px 0` token).
const HIGHLIGHT_THICKNESS: usize = 2;
/// Inner top highlight alpha for a **focused** window (~0.26 white).
const HIGHLIGHT_ALPHA_FOCUSED: u8 = 66;
/// Inner top highlight alpha for an **unfocused** window (dimmer).
const HIGHLIGHT_ALPHA_UNFOCUSED: u8 = 28;

/// Accent pink `#ff5fae` — the left title-bar dot.
const ACCENT_PINK: Rgb = Rgb::hex(0xff_5f_ae);
/// Accent cyan `#7ad7ff` — the right title-bar dot and the focused title text.
const ACCENT_CYAN: Rgb = Rgb::hex(0x7a_d7_ff);
/// Dim title text for an **unfocused** window — muted cyan-grey.
const TITLE_DIM: Rgb = Rgb::hex(0x7e_92_ad);

/// Drop-shadow vertical offset under the window.
const SHADOW_OFFSET_Y: usize = 10;
/// Number of faux-blur rings for the shadow.
const SHADOW_RINGS: usize = 12;
/// Innermost shadow ring alpha for a **focused** window (it sits "higher").
const SHADOW_PEAK_ALPHA_FOCUSED: u8 = 56;
/// Innermost shadow ring alpha for an **unfocused** window (a flatter shadow).
const SHADOW_PEAK_ALPHA_UNFOCUSED: u8 = 34;

/// Draw a glass **window** at `bounds` over the Cyber Dusk gradient backdrop.
///
/// Composites, bottom-to-top: a soft drop shadow, the translucent dark glass
/// body, a brighter title-bar strip (with the pink/cyan window dots on the left
/// and the centered `title`), a crisp rounded border, and a glossy inner top
/// highlight — the same Cyber Dusk vocabulary the console panel uses, lifted into
/// a reusable, focus-aware drawer.
///
/// `focused` selects the styling:
/// * **focused** — brighter border, title bar, highlight and title text (cyan),
///   plus a slightly deeper drop shadow so the active window reads as "raised".
/// * **unfocused** — dimmer border, title bar, highlight and title text, and a
///   flatter shadow, so background windows recede (the on-brand focus cue).
///
/// Only the window frame is drawn here; the app's content (inside
/// [`content_rect`]) is drawn separately by the compositor afterwards. Everything
/// is recomputed analytically over the gradient — no back-buffer — so repainting
/// the window into a damage region is seamless. An off-screen / zero-size
/// framebuffer, or a degenerate `bounds`, is a safe no-op.
pub fn draw_window_chrome(fb: &Framebuffer, bounds: Rect, title: &str, focused: bool) {
    draw_window_chrome_with(fb, bounds, title, focused, &WindowChrome::cyber_dusk());
}

/// [`draw_window_chrome`] with an explicit [`WindowChrome`] (title-bar height,
/// border, radius, title scale), for windows that want non-default proportions.
/// `draw_window_chrome` is the convenience wrapper using [`WindowChrome::cyber_dusk`].
pub fn draw_window_chrome_with(
    fb: &Framebuffer,
    bounds: Rect,
    title: &str,
    focused: bool,
    chrome: &WindowChrome,
) {
    let w = fb.width();
    let h = fb.height();
    if w == 0 || h == 0 {
        return;
    }
    let (x, y, pw, ph) = (bounds.x, bounds.y, bounds.w, bounds.h);
    // A window needs at least a title bar and some width to draw meaningfully.
    if pw < 2 || ph < 2 {
        return;
    }
    let gradient = Gradient::three_stop(GRAD_START, GRAD_MID, GRAD_END, w, h);
    let radius = chrome.radius.min(pw / 2).min(ph / 2);

    // Focus-dependent styling.
    let (border_a, titlebar_a, highlight_a, shadow_a, title_color) = if focused {
        (
            BORDER_ALPHA_FOCUSED,
            TITLEBAR_ALPHA_FOCUSED,
            HIGHLIGHT_ALPHA_FOCUSED,
            SHADOW_PEAK_ALPHA_FOCUSED,
            ACCENT_CYAN,
        )
    } else {
        (
            BORDER_ALPHA_UNFOCUSED,
            TITLEBAR_ALPHA_UNFOCUSED,
            HIGHLIGHT_ALPHA_UNFOCUSED,
            SHADOW_PEAK_ALPHA_UNFOCUSED,
            TITLE_DIM,
        )
    };

    // 1) Soft drop shadow behind the window.
    raster::drop_shadow_rounded_rect(
        fb,
        &gradient,
        x,
        y,
        pw,
        ph,
        radius,
        SHADOW_OFFSET_Y,
        SHADOW_RINGS,
        shadow_a,
    );

    // 2) Body glass fill (dark, fairly opaque).
    raster::fill_rounded_rect_alpha(
        fb, &gradient, x, y, pw, ph, radius, GLASS_DARK, GLASS_FILL_ALPHA,
    );

    // 3) Title-bar strip across the top, sharing the panel's top corner radius.
    let tb_h = chrome.titlebar_h.min(ph);
    raster::fill_rounded_rect_alpha(
        fb, &gradient, x, y, pw, tb_h, radius, TITLEBAR_TINT, titlebar_a,
    );

    // 4) Bright border + inner top highlight for the glossy glass edge.
    raster::stroke_rounded_rect_alpha(
        fb, &gradient, x, y, pw, ph, radius, GLASS_WHITE, border_a,
    );
    raster::inner_top_highlight(
        fb,
        &gradient,
        x,
        y,
        pw,
        radius,
        1,
        HIGHLIGHT_THICKNESS,
        GLASS_WHITE,
        highlight_a,
    );

    // 5) Pink + cyan "traffic light" pair on the left of the title bar.
    let dot_r = (tb_h / 6).clamp(2, 6);
    let dot_cy = y + tb_h / 2;
    let dot_x0 = x + chrome.border;
    fill_dot(fb, dot_x0 + dot_r, dot_cy, dot_r, ACCENT_PINK, focused);
    fill_dot(fb, dot_x0 + dot_r * 4, dot_cy, dot_r, ACCENT_CYAN, focused);

    // 6) Centered title text (cyan when focused, dim when not).
    let title_w = font::text_width(title, chrome.title_scale);
    // Centre the title in the space right of the dots so it never overlaps them.
    let dots_right = dot_x0 + dot_r * 6;
    let title_x = if title_w + dots_right < x + pw {
        x + (pw.saturating_sub(title_w)) / 2
    } else {
        dots_right
    };
    let title_y = y + (tb_h.saturating_sub(font::GLYPH_SIZE * chrome.title_scale)) / 2;
    font::draw_text(
        fb,
        title_x,
        title_y,
        title,
        chrome.title_scale,
        title_color.pack(fb),
    );
}

/// Draw a small filled disc of radius `r` centred at `(cx, cy)` — a title-bar
/// window dot. Unfocused windows dim the dot toward the title-bar tint so the
/// chrome recedes as a whole.
fn fill_dot(fb: &Framebuffer, cx: usize, cy: usize, r: usize, color: Rgb, focused: bool) {
    // Dim the accent toward the title-bar tint when unfocused (no backdrop read
    // needed — the dots sit on the already-painted title bar).
    let drawn = if focused {
        color
    } else {
        raster::blend(TITLEBAR_TINT, color, 150)
    };
    let packed = drawn.pack(fb);
    let r2 = (r * r) as i64;
    for dy in -(r as i64)..=(r as i64) {
        for dx in -(r as i64)..=(r as i64) {
            if dx * dx + dy * dy <= r2 {
                let px = cx as i64 + dx;
                let py = cy as i64 + dy;
                if px >= 0 && py >= 0 {
                    fb.put_pixel(px as usize, py as usize, packed);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_rect_insets_by_chrome() {
        let chrome = WindowChrome::cyber_dusk();
        let bounds = Rect::new(100, 50, 400, 300);
        let c = content_rect(bounds, &chrome);
        assert_eq!(c.x, 100 + chrome.border);
        assert_eq!(c.y, 50 + chrome.titlebar_h);
        assert_eq!(c.w, 400 - chrome.border * 2);
        assert_eq!(c.h, 300 - chrome.titlebar_h - chrome.border);
        // The content rect stays strictly inside the outer bounds.
        assert!(c.x >= bounds.x && c.y >= bounds.y);
        assert!(c.right() <= bounds.right());
        assert!(c.bottom() <= bounds.bottom());
    }

    #[test]
    fn content_rect_degenerate_bounds_dont_wrap() {
        // Bounds smaller than the chrome must collapse to zero-size, not wrap.
        let chrome = WindowChrome::cyber_dusk();
        let c = content_rect(Rect::new(0, 0, 1, 1), &chrome);
        assert_eq!(c.w, 0);
        assert_eq!(c.h, 0);
    }

    #[test]
    fn rect_edges_saturate() {
        let r = Rect::new(usize::MAX - 1, usize::MAX - 1, 10, 10);
        assert_eq!(r.right(), usize::MAX);
        assert_eq!(r.bottom(), usize::MAX);
    }
}
