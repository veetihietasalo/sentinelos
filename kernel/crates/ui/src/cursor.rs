//! The mouse **cursor** sprite — a crisp arrow pointer composited over whatever
//! is already on screen.
//!
//! Like the rest of the crate this is `#![forbid(unsafe_code)]`, `no_std`,
//! heap-free, and draws only through the bounds-checked
//! [`hal::framebuffer::Framebuffer`]. The cursor is a tiny opaque bitmap (a white
//! arrow with a dark outline so it stays visible over both the bright gradient and
//! the dark glass windows), drawn **last** each composite by the window manager so
//! it always sits on top. There is no back-buffer: the compositor erases the
//! cursor's previous rect back to the desktop content (by damaging it) before this
//! redraws the arrow at its new position.
//!
//! The hotspot is the top-left pixel `(0, 0)` of the sprite (the arrow tip), so a
//! click hit-tests against the pixel the tip points at — the conventional pointer
//! hotspot.

use hal::framebuffer::Framebuffer;

use crate::raster::Rgb;

/// Cursor sprite width in source pixels.
pub const CURSOR_W: usize = 12;
/// Cursor sprite height in source pixels.
pub const CURSOR_H: usize = 19;

/// The arrow bitmap, one byte per pixel, row-major, `CURSOR_W × CURSOR_H`:
/// - `0` — transparent (the existing pixel shows through).
/// - `1` — fill (white arrow body).
/// - `2` — outline (near-black edge so the arrow reads on any backdrop).
///
/// A classic north-west pointer: the tip is the top-left pixel (the hotspot), the
/// left edge runs straight down, and the tail kinks out to the lower right. The
/// outline traces the whole silhouette so it is legible over light or dark areas.
#[rustfmt::skip]
const SPRITE: [u8; CURSOR_W * CURSOR_H] = [
    2,0,0,0,0,0,0,0,0,0,0,0,
    2,2,0,0,0,0,0,0,0,0,0,0,
    2,1,2,0,0,0,0,0,0,0,0,0,
    2,1,1,2,0,0,0,0,0,0,0,0,
    2,1,1,1,2,0,0,0,0,0,0,0,
    2,1,1,1,1,2,0,0,0,0,0,0,
    2,1,1,1,1,1,2,0,0,0,0,0,
    2,1,1,1,1,1,1,2,0,0,0,0,
    2,1,1,1,1,1,1,1,2,0,0,0,
    2,1,1,1,1,1,1,1,1,2,0,0,
    2,1,1,1,1,1,2,2,2,2,2,0,
    2,1,1,2,1,1,2,0,0,0,0,0,
    2,1,2,0,2,1,1,2,0,0,0,0,
    2,2,0,0,2,1,1,2,0,0,0,0,
    2,0,0,0,0,2,1,1,2,0,0,0,
    0,0,0,0,0,2,1,1,2,0,0,0,
    0,0,0,0,0,0,2,1,1,2,0,0,
    0,0,0,0,0,0,2,1,1,2,0,0,
    0,0,0,0,0,0,0,2,2,2,0,0,
];

/// Arrow body colour — bright white so the pointer is unmistakable.
const FILL: Rgb = Rgb::hex(0xff_ff_ff);
/// Arrow outline colour — near-black, for contrast on light backdrops.
const OUTLINE: Rgb = Rgb::hex(0x10_10_18);

/// The screen rectangle the cursor sprite occupies with its hotspot at `(x, y)`.
///
/// Returned as `(x, y, w, h)` in absolute framebuffer pixels. The window manager
/// uses this to damage the cursor's old and new positions so the compositor
/// repaints the desktop under the cursor before re-drawing it on top.
#[must_use]
pub const fn cursor_rect(x: usize, y: usize) -> (usize, usize, usize, usize) {
    (x, y, CURSOR_W, CURSOR_H)
}

/// Draw the arrow cursor with its hotspot (the tip) at `(x, y)`, composited over
/// whatever is already in the framebuffer.
///
/// Opaque per-pixel: fill and outline pixels overwrite the backdrop, transparent
/// pixels are skipped (so the desktop/window content shows through the notch of
/// the arrow). All writes go through the bounds-checked `put_pixel`, so a cursor
/// near the screen edge is simply clipped — never UB. The WM calls this **last**
/// each composite so the pointer is always on top.
pub fn draw_cursor(fb: &Framebuffer, x: usize, y: usize) {
    let fill = FILL.pack(fb);
    let outline = OUTLINE.pack(fb);
    for sy in 0..CURSOR_H {
        for sx in 0..CURSOR_W {
            let texel = SPRITE[sy * CURSOR_W + sx];
            if texel == 0 {
                continue; // transparent
            }
            let color = if texel == 1 { fill } else { outline };
            // `put_pixel` is bounds-checked: off-screen pixels are dropped.
            fb.put_pixel(x + sx, y + sy, color);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sprite_has_expected_dimensions() {
        assert_eq!(SPRITE.len(), CURSOR_W * CURSOR_H);
    }

    #[test]
    fn hotspot_is_top_left() {
        // The tip pixel (0,0) must be part of the sprite (outline), so the hotspot
        // lands on a drawn pixel.
        assert_ne!(SPRITE[0], 0);
    }

    #[test]
    fn cursor_rect_matches_sprite_size() {
        let (rx, ry, rw, rh) = cursor_rect(40, 70);
        assert_eq!((rx, ry, rw, rh), (40, 70, CURSOR_W, CURSOR_H));
    }
}
