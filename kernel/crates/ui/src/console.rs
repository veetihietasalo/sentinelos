//! The SentinelOS **terminal console** — a Cyber Dusk glass panel the shell
//! prints into.
//!
//! This is the visual surface only: the kernel owns the text state (scrollback
//! and the current input line) and calls [`draw_console`] to render a frame from
//! borrowed slices. Like the rest of this crate it is `#![forbid(unsafe_code)]`,
//! `no_std`, heap-free, and draws exclusively through the bounds-checked
//! [`hal::framebuffer::Framebuffer`] via the [`crate::raster`] compositor — so the
//! translucent "glass" panel is recomputed analytically over the Cyber Dusk
//! gradient, exactly like the lock card.
//!
//! # Geometry
//!
//! The panel is a monospaced character grid built from the 8×8 [`crate::font`] at
//! [`CELL_SCALE`] (so each cell is `8·scale × 8·scale` px). [`console_geometry`]
//! derives how many whole columns/rows of text fit a given framebuffer, and
//! [`console_cols`] / [`console_rows`] are thin convenience wrappers. The kernel
//! uses these to size its scrollback buffer and wrap the input line so the
//! rendered text always lands on the grid the panel draws.
//!
//! # Aesthetic
//!
//! Cyan/white text on dark translucent glass, with a Cyber Dusk pink prompt and a
//! cyan block (or underline) cursor whose visibility is **passed in**, so the
//! kernel can blink it off the PIT `TICKS` without this module owning any state.

use hal::framebuffer::Framebuffer;

use crate::font;
use crate::raster::{self, Gradient, Rgb};
use crate::window::Rect;

// --- Cyber Dusk backdrop (must match `lib.rs`) -------------------------------

/// Backdrop gradient stop 1 — deep indigo `#2a1a4a`.
const GRAD_START: Rgb = Rgb::hex(0x2a_1a_4a);
/// Backdrop gradient stop 2 — violet `#5b2a8c`.
const GRAD_MID: Rgb = Rgb::hex(0x5b_2a_8c);
/// Backdrop gradient stop 3 — magenta `#c43e8f`.
const GRAD_END: Rgb = Rgb::hex(0xc4_3e_8f);

// --- Console design tokens ----------------------------------------------------

/// Integer magnification of the 8×8 font for one console cell. Scale 2 → 16px
/// cells, which reads cleanly as a Y2K monospace terminal.
pub const CELL_SCALE: usize = 2;
/// Width of one character cell, in pixels (font cell + scale, no inter-char gap
/// so the grid is a true fixed-pitch monospace).
pub const CELL_W: usize = font::GLYPH_SIZE * CELL_SCALE;
/// Height of one character cell (= one text row), in pixels.
pub const CELL_H: usize = font::GLYPH_SIZE * CELL_SCALE;
/// One source-pixel of leading between rows so descenders/cursors breathe.
const ROW_LEADING: usize = CELL_SCALE;

/// Panel corner radius (Cyber Dusk panels are 14–18 px).
const PANEL_RADIUS: usize = 16;
/// Inner padding from the glass edge to the first character cell, in pixels.
const PANEL_PAD: usize = CELL_W; // ~16 px — one cell of breathing room

/// Glass fill: a darker, more opaque tint than the lock card so the bright
/// monospace text stays legible — a deep indigo at ~62 % alpha.
const GLASS_DARK: Rgb = Rgb::hex(0x12_0a_28);
/// Glass fill alpha (~0.62 — terminals want a more solid backdrop than a card).
const GLASS_FILL_ALPHA: u8 = 158;
/// Glass surface tint for the bright border — white, applied at low alpha.
const GLASS_WHITE: Rgb = Rgb::hex(0xff_ff_ff);
/// Border alpha (~0.30 white) for the crisp 1px outline.
const GLASS_BORDER_ALPHA: u8 = 78;

/// Title-bar tint — a touch brighter than the body so the chrome reads as a
/// header strip.
const TITLEBAR_TINT: Rgb = Rgb::hex(0x1c_10_3a);
/// Title-bar fill alpha (slightly more opaque than the body).
const TITLEBAR_ALPHA: u8 = 180;

/// Primary console text — near-white with a faint cyan cast.
const TEXT_PRIMARY: Rgb = Rgb::hex(0xe8_f6_ff);
/// Secondary/dim console text — muted cyan-grey (for older scrollback feel).
const TEXT_DIM: Rgb = Rgb::hex(0x9a_b6_d6);
/// Accent pink `#ff5fae` — the prompt glyphs.
const ACCENT_PINK: Rgb = Rgb::hex(0xff_5f_ae);
/// Secondary accent cyan `#7ad7ff` — the cursor and title chrome.
const ACCENT_CYAN: Rgb = Rgb::hex(0x7a_d7_ff);

/// Inner top highlight thickness (the glossy `inset 0 1px 0` token).
const HIGHLIGHT_THICKNESS: usize = 2;
/// Inner top highlight alpha (~0.26 white).
const HIGHLIGHT_ALPHA: u8 = 66;

/// Drop-shadow vertical offset under the panel.
const SHADOW_OFFSET_Y: usize = 10;
/// Number of faux-blur rings for the shadow.
const SHADOW_RINGS: usize = 12;
/// Innermost shadow ring alpha (fades outward to 0).
const SHADOW_PEAK_ALPHA: u8 = 52;

/// The console window's title, shown centered in the title bar.
const CONSOLE_TITLE: &str = "SENTINEL CONSOLE";
/// Title text scale (smaller than body so it reads as chrome).
const TITLE_SCALE: usize = 2;

// --- Geometry -----------------------------------------------------------------

/// The console character grid: how many whole text columns and rows fit, plus
/// the absolute pixel rectangle of the panel they live in.
///
/// Returned by [`console_geometry`]. The kernel sizes its scrollback and wraps
/// the input line to `cols`/`rows` so its text always maps onto the cells
/// [`draw_console`] paints. All pixel fields are absolute framebuffer
/// coordinates of the outer glass panel (chrome included).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsoleGeometry {
    /// Number of whole character columns the text area holds.
    pub cols: usize,
    /// Number of whole text rows the text area holds (the title bar excluded).
    pub rows: usize,
    /// Panel top-left x (outer glass), absolute pixels.
    pub panel_x: usize,
    /// Panel top-left y (outer glass), absolute pixels.
    pub panel_y: usize,
    /// Panel width including chrome, pixels.
    pub panel_w: usize,
    /// Panel height including chrome, pixels.
    pub panel_h: usize,
}

/// Height of the title-bar chrome strip, in pixels.
#[inline]
const fn titlebar_h() -> usize {
    CELL_H + PANEL_PAD // title row + symmetric padding
}

/// The text grid (whole columns/rows) that fits a console **content rectangle**.
///
/// Returned by [`console_geometry_in`]. This is the windowed analogue of
/// [`ConsoleGeometry`]: it carries only the grid dimensions for an arbitrary
/// content area (no outer-panel coordinates, because in the windowed case the
/// chrome is owned by `window::draw_window_chrome`, not the console). The WM uses
/// it to size the shell's scrollback and wrap its input line to the window's
/// content rect, so the text always lands on the cells [`draw_console_in`] paints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsoleGrid {
    /// Number of whole character columns the content area holds.
    pub cols: usize,
    /// Number of whole text rows the content area holds (scrollback + input).
    pub rows: usize,
}

/// Compute the text grid (`cols`/`rows`) that fits an arbitrary console content
/// rectangle `area`.
///
/// `area` is the inner region the text is drawn into (already inset past any
/// window chrome — e.g. the `content_rect` of a window). A symmetric
/// [`PANEL_PAD`]/2 breathing-room inset is applied inside `area` so glyphs don't
/// touch the content edge, then the whole cells that fit are counted. A content
/// area too small for even one cell yields `cols == 0` / `rows == 0` (a no-op for
/// [`draw_console_in`]).
#[must_use]
pub fn console_geometry_in(area: Rect) -> ConsoleGrid {
    let (text_w, text_h) = inner_text_extent(area);
    let cols = text_w / CELL_W;
    let rows = if text_h >= CELL_H {
        // Each row after the first also consumes the leading.
        (text_h + ROW_LEADING) / (CELL_H + ROW_LEADING)
    } else {
        0
    };
    ConsoleGrid { cols, rows }
}

/// Inner padding from a content rect's edge to the first character cell.
const CONTENT_INSET: usize = PANEL_PAD / 2;

/// The drawable text extent `(width, height)` inside a content rect, after the
/// symmetric [`CONTENT_INSET`] breathing room. Shared by [`console_geometry_in`]
/// and [`draw_console_in`] so the counted cells and the drawn cells agree.
#[inline]
const fn inner_text_extent(area: Rect) -> (usize, usize) {
    let text_w = area.w.saturating_sub(CONTENT_INSET * 2);
    let text_h = area.h.saturating_sub(CONTENT_INSET * 2);
    (text_w, text_h)
}

/// Compute the console panel + grid [`ConsoleGeometry`] for a framebuffer of
/// size `w × h`.
///
/// The panel is centred and sized to a generous slice of the screen (~76 % wide,
/// ~70 % tall), clamped so it always fits and never collapses below a single
/// cell. The text area is the panel inset by [`PANEL_PAD`] on every side and by
/// the title bar at the top; `cols`/`rows` are the whole cells that fit there.
#[must_use]
pub fn console_geometry(w: usize, h: usize) -> ConsoleGeometry {
    // Outer panel: a large centred window, clamped to the screen.
    let panel_w = (w * 76 / 100).clamp(CELL_W * 4, w.saturating_sub(8).max(CELL_W * 4));
    let panel_h = (h * 70 / 100).clamp(CELL_H * 3, h.saturating_sub(8).max(CELL_H * 3));
    let panel_x = (w.saturating_sub(panel_w)) / 2;
    let panel_y = (h.saturating_sub(panel_h)) / 2;

    // Inner text rectangle: inset by the padding all round, plus the title bar.
    let text_w = panel_w.saturating_sub(PANEL_PAD * 2);
    let text_h = panel_h
        .saturating_sub(titlebar_h())
        .saturating_sub(PANEL_PAD);

    let cols = text_w / CELL_W;
    let rows = if text_h >= CELL_H {
        // Each row after the first also consumes the leading.
        (text_h + ROW_LEADING) / (CELL_H + ROW_LEADING)
    } else {
        0
    };

    ConsoleGeometry {
        cols,
        rows,
        panel_x,
        panel_y,
        panel_w,
        panel_h,
    }
}

/// Number of whole character columns the console text area holds on `fb`.
#[must_use]
pub fn console_cols(fb: &Framebuffer) -> usize {
    console_geometry(fb.width(), fb.height()).cols
}

/// Number of whole text rows the console text area holds on `fb` (the title bar
/// is not counted — this is the scrollback + input region).
#[must_use]
pub fn console_rows(fb: &Framebuffer) -> usize {
    console_geometry(fb.width(), fb.height()).rows
}

// --- Rendering ----------------------------------------------------------------

/// Cursor shape drawn at the end of the input line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CursorStyle {
    /// A filled block covering the whole cell (classic terminal caret).
    Block,
    /// A thin underline along the bottom of the cell.
    Underline,
}

/// Render the terminal console panel onto `fb`, given the text to show.
///
/// This is a pure render-from-content entry point — it owns no state. The kernel
/// passes:
///
/// * `scrollback` — the already-wrapped history lines, oldest first. Only the
///   last rows that fit (leaving one row for the input line) are shown, so the
///   kernel can hand the whole buffer and let the panel clamp to the latest.
/// * `prompt` — the prompt string drawn before the input (e.g. `"> "`), in the
///   Cyber Dusk pink accent.
/// * `input` — the current input line text (without the prompt).
/// * `cursor_visible` — whether to draw the cursor this frame; the kernel toggles
///   this off [`hal::pit::ticks`] to make it blink.
/// * `cursor_style` — block or underline caret.
///
/// The whole panel (glass, chrome, and all text) is repainted each call from the
/// Cyber Dusk gradient backdrop, so successive frames never smear. Cost is
/// bounded by the panel area. Off-screen / zero-size framebuffers are a no-op.
pub fn draw_console(
    fb: &Framebuffer,
    scrollback: &[&str],
    prompt: &str,
    input: &str,
    cursor_visible: bool,
    cursor_style: CursorStyle,
) {
    let w = fb.width();
    let h = fb.height();
    if w == 0 || h == 0 {
        return;
    }
    let geom = console_geometry(w, h);
    if geom.cols == 0 || geom.rows == 0 {
        return;
    }
    let gradient = Gradient::three_stop(GRAD_START, GRAD_MID, GRAD_END, w, h);

    // The full-screen console owns its own glass panel chrome (title bar, dots,
    // border, shadow) — drawn here — then delegates the text grid to the shared
    // windowed renderer for the inner content rectangle.
    draw_panel_chrome(fb, &gradient, &geom);

    // Content rectangle: the panel inset past the title bar and border. This is
    // exactly the area a window's `content_rect` would yield, so the full-screen
    // and windowed consoles render their text through one code path.
    let area = Rect {
        x: geom.panel_x + (PANEL_PAD - CONTENT_INSET),
        y: geom.panel_y + titlebar_h() - CONTENT_INSET,
        w: geom.panel_w.saturating_sub((PANEL_PAD - CONTENT_INSET) * 2),
        h: geom
            .panel_h
            .saturating_sub(titlebar_h() - CONTENT_INSET)
            .saturating_sub(PANEL_PAD - CONTENT_INSET),
    };
    draw_console_in(
        fb,
        area,
        scrollback,
        prompt,
        input,
        cursor_visible,
        cursor_style,
    );
}

/// Render the console text grid into an arbitrary **content rectangle** `area`.
///
/// This is the windowed console renderer: it draws scrollback + the live input
/// line + the cursor into `area` (a window's `content_rect`), with **no panel
/// chrome of its own** — the window chrome is drawn separately by
/// [`crate::window::draw_window_chrome`]. The full-screen [`draw_console`] is a
/// thin wrapper that paints its own glass panel and then calls this for the text.
///
/// Like [`draw_console`] it owns no state; the kernel passes the same borrowed
/// slices:
///
/// * `scrollback` — already-wrapped history lines, oldest first; only the last
///   rows that fit `area` (leaving one for the input line) are shown.
/// * `prompt` — the prompt drawn before the input, in Cyber Dusk pink.
/// * `input` — the current input line text (without the prompt).
/// * `cursor_visible` — whether to draw the blinking cursor this frame.
/// * `cursor_style` — block or underline caret.
///
/// The grid (`cols`/`rows`) is derived from `area` via [`console_geometry_in`],
/// so the kernel sizes and wraps its text to the same cells drawn here. Drawing
/// is clipped by the `Framebuffer`, so an oversized `area` or overrun is a safe
/// no-op. A content rect too small for any cell, or a zero-size framebuffer, is a
/// no-op.
pub fn draw_console_in(
    fb: &Framebuffer,
    area: Rect,
    scrollback: &[&str],
    prompt: &str,
    input: &str,
    cursor_visible: bool,
    cursor_style: CursorStyle,
) {
    let w = fb.width();
    let h = fb.height();
    if w == 0 || h == 0 {
        return;
    }
    let grid = console_geometry_in(area);
    if grid.cols == 0 || grid.rows == 0 {
        return;
    }
    let gradient = Gradient::three_stop(GRAD_START, GRAD_MID, GRAD_END, w, h);

    // Text-area origin: the content rect inset by the symmetric breathing room.
    let text_x0 = area.x + CONTENT_INSET;
    let text_y0 = area.y + CONTENT_INSET;
    let row_pitch = CELL_H + ROW_LEADING;

    // Reserve the bottom row for the live input line; the rest shows scrollback.
    let body_rows = grid.rows.saturating_sub(1);
    // Show only the last `body_rows` of scrollback (the newest history).
    let start = scrollback.len().saturating_sub(body_rows);
    for (i, line) in scrollback[start..].iter().enumerate() {
        let y = text_y0 + i * row_pitch;
        // Older lines toward the top read slightly dimmer for depth.
        let color = if i + 1 == body_rows.max(1) {
            TEXT_PRIMARY
        } else {
            TEXT_DIM
        };
        draw_cells(fb, text_x0, y, grid.cols, line, color);
    }

    // --- Input line: prompt (pink) + input (white) + cursor (cyan) ----------
    let input_row = grid.rows.saturating_sub(1);
    let iy = text_y0 + input_row * row_pitch;

    // Prompt, clamped to the grid width.
    let prompt_cells = draw_cells(fb, text_x0, iy, grid.cols, prompt, ACCENT_PINK);
    // Input text continues after the prompt, within remaining columns.
    let input_cols = grid.cols.saturating_sub(prompt_cells);
    let input_used = draw_cells(
        fb,
        text_x0 + prompt_cells * CELL_W,
        iy,
        input_cols,
        input,
        TEXT_PRIMARY,
    );

    // Cursor sits in the cell right after the last input character (clamped to
    // the last visible column so it never spills outside the content area).
    if cursor_visible {
        let cursor_col = (prompt_cells + input_used).min(grid.cols.saturating_sub(1));
        let cx = text_x0 + cursor_col * CELL_W;
        draw_cursor(fb, &gradient, cx, iy, cursor_style);
    }
}

/// Draw the glass panel, drop shadow, border, title bar and title text.
fn draw_panel_chrome(fb: &Framebuffer, gradient: &Gradient, geom: &ConsoleGeometry) {
    let (x, y, pw, ph) = (geom.panel_x, geom.panel_y, geom.panel_w, geom.panel_h);

    // Soft drop shadow behind the panel.
    raster::drop_shadow_rounded_rect(
        fb,
        gradient,
        x,
        y,
        pw,
        ph,
        PANEL_RADIUS,
        SHADOW_OFFSET_Y,
        SHADOW_RINGS,
        SHADOW_PEAK_ALPHA,
    );

    // Body glass fill (dark, fairly opaque) + bright 1px border.
    raster::fill_rounded_rect_alpha(
        fb,
        gradient,
        x,
        y,
        pw,
        ph,
        PANEL_RADIUS,
        GLASS_DARK,
        GLASS_FILL_ALPHA,
    );

    // Title-bar strip across the top, sharing the panel's top corner radius.
    let tb_h = titlebar_h();
    raster::fill_rounded_rect_alpha(
        fb,
        gradient,
        x,
        y,
        pw,
        tb_h,
        PANEL_RADIUS,
        TITLEBAR_TINT,
        TITLEBAR_ALPHA,
    );

    // Bright border + inner top highlight for the glossy glass edge.
    raster::stroke_rounded_rect_alpha(
        fb,
        gradient,
        x,
        y,
        pw,
        ph,
        PANEL_RADIUS,
        GLASS_WHITE,
        GLASS_BORDER_ALPHA,
    );
    raster::inner_top_highlight(
        fb,
        gradient,
        x,
        y,
        pw,
        PANEL_RADIUS,
        1,
        HIGHLIGHT_THICKNESS,
        GLASS_WHITE,
        HIGHLIGHT_ALPHA,
    );

    // A pink + cyan "traffic light" pair on the left of the title bar — a Y2K
    // window-chrome flourish, drawn as two small filled dots.
    let dot_r = (CELL_H / 4).max(3);
    let dot_cy = y + tb_h / 2;
    let dot_x0 = x + PANEL_PAD;
    fill_dot(fb, dot_x0 + dot_r, dot_cy, dot_r, ACCENT_PINK);
    fill_dot(fb, dot_x0 + dot_r * 3 + dot_r, dot_cy, dot_r, ACCENT_CYAN);

    // Centered title text in cyan.
    let title_w = font::text_width(CONSOLE_TITLE, TITLE_SCALE);
    let title_x = x + (pw.saturating_sub(title_w)) / 2;
    let title_y = y + (tb_h.saturating_sub(font::GLYPH_SIZE * TITLE_SCALE)) / 2;
    font::draw_text(
        fb,
        title_x,
        title_y,
        CONSOLE_TITLE,
        TITLE_SCALE,
        ACCENT_CYAN.pack(fb),
    );
}

/// Draw a small filled disc of radius `r` centred at `(cx, cy)` in a solid
/// colour — the title-bar window dots.
fn fill_dot(fb: &Framebuffer, cx: usize, cy: usize, r: usize, color: Rgb) {
    let packed = color.pack(fb);
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

/// Plot up to `max_cols` characters of `text` on a fixed-pitch grid starting at
/// `(x0, y)`, one [`CELL_W`]-wide cell per character. Returns the number of cells
/// actually drawn (so callers can advance past them).
///
/// Unlike [`font::draw_text`] (which uses proportional 1px gaps), this advances
/// by exactly one cell per glyph so the console is a true monospace grid.
fn draw_cells(
    fb: &Framebuffer,
    x0: usize,
    y: usize,
    max_cols: usize,
    text: &str,
    color: Rgb,
) -> usize {
    let packed = color.pack(fb);
    let mut col = 0usize;
    // Stack buffer to encode each char into a 1-char `&str` for the font plotter,
    // keeping the grid fixed-pitch (one cell per glyph, no proportional gaps).
    let mut buf = [0u8; 4];
    for ch in text.chars() {
        if col >= max_cols {
            break;
        }
        let s: &str = ch.encode_utf8(&mut buf);
        // Draw one glyph at the cell origin (no inter-char gap → fixed pitch).
        font::draw_text(fb, x0 + col * CELL_W, y, s, CELL_SCALE, packed);
        col += 1;
    }
    col
}

/// Draw the cursor in cell `(cx, y)` — a cyan block or underline composited over
/// the glass so it reads as a glowing caret.
fn draw_cursor(fb: &Framebuffer, gradient: &Gradient, cx: usize, y: usize, style: CursorStyle) {
    let w = fb.width();
    let h = fb.height();
    match style {
        CursorStyle::Block => {
            // A translucent cyan block filling the cell — bright but you can still
            // sense the glass underneath, like a Y2K terminal caret.
            for py in y..(y + CELL_H).min(h) {
                for px in cx..(cx + CELL_W).min(w) {
                    let backdrop = composited_glass(gradient, px, py);
                    let out = raster::blend(backdrop, ACCENT_CYAN, 200);
                    fb.put_pixel(px, py, out.pack(fb));
                }
            }
        }
        CursorStyle::Underline => {
            let thick = (CELL_SCALE * 2).max(2);
            let top = (y + CELL_H).saturating_sub(thick);
            for py in top..(y + CELL_H).min(h) {
                for px in cx..(cx + CELL_W).min(w) {
                    let backdrop = composited_glass(gradient, px, py);
                    let out = raster::blend(backdrop, ACCENT_CYAN, 230);
                    fb.put_pixel(px, py, out.pack(fb));
                }
            }
        }
    }
}

/// The colour of the panel's glass body at `(px, py)`: the gradient with the
/// dark glass tint composited over it — so the cursor blends with the same
/// surface the text sits on.
#[inline]
fn composited_glass(gradient: &Gradient, px: usize, py: usize) -> Rgb {
    let backdrop = gradient.color_at(px, py);
    raster::blend(backdrop, GLASS_DARK, GLASS_FILL_ALPHA)
}
