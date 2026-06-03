//! Safe 2D raster primitives for the Cyber Dusk screen.
//!
//! Everything here draws **only** through the bounds-checked
//! [`hal::framebuffer::Framebuffer`] API — there is no `get_pixel`, no heap, and
//! no back-buffer. Translucency is therefore handled by *recomputing* the
//! backdrop colour at each pixel (the gradient is a pure function of position)
//! and blending the overlay over it analytically before a single `put_pixel`.
//!
//! Colours are kept as [`Rgb`] triples until the last moment, then packed for
//! the framebuffer's actual channel layout via [`Framebuffer::pack_rgb`].

use hal::framebuffer::Framebuffer;

/// A straight 8-bit-per-channel RGB colour, before packing to the framebuffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rgb {
    /// Red channel, 0–255.
    pub r: u8,
    /// Green channel, 0–255.
    pub g: u8,
    /// Blue channel, 0–255.
    pub b: u8,
}

impl Rgb {
    /// Construct an [`Rgb`] from its three channels.
    #[must_use]
    pub const fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b }
    }

    /// Build an [`Rgb`] from a `0xRRGGBB` hex literal.
    #[must_use]
    pub const fn hex(rgb: u32) -> Self {
        Self {
            r: ((rgb >> 16) & 0xff) as u8,
            g: ((rgb >> 8) & 0xff) as u8,
            b: (rgb & 0xff) as u8,
        }
    }

    /// Pack this colour for `fb`'s native pixel format.
    #[inline]
    #[must_use]
    pub fn pack(self, fb: &Framebuffer) -> u32 {
        fb.pack_rgb(self.r, self.g, self.b)
    }
}

/// Linearly interpolate one channel: `a + (b-a) * num / den` in `u8` range.
///
/// Uses `i32` intermediates so the signed delta and the multiply never
/// overflow; `den == 0` collapses to `a`.
#[inline]
#[must_use]
fn lerp_u8(a: u8, b: u8, num: usize, den: usize) -> u8 {
    if den == 0 {
        return a;
    }
    let num = num.min(den) as i32;
    let den = den as i32;
    let a = a as i32;
    let b = b as i32;
    (a + (b - a) * num / den) as u8
}

/// Interpolate between two colours by `num/den` (clamped to `[0, 1]`).
#[inline]
#[must_use]
pub fn lerp_rgb(a: Rgb, b: Rgb, num: usize, den: usize) -> Rgb {
    Rgb {
        r: lerp_u8(a.r, b.r, num, den),
        g: lerp_u8(a.g, b.g, num, den),
        b: lerp_u8(a.b, b.b, num, den),
    }
}

/// A three-stop gradient (`#2a1a4a → #5b2a8c → #c43e8f`) evaluated as a pure
/// function of screen position — the backdrop both the fill and the glass
/// compositing read from.
#[derive(Clone, Copy, Debug)]
pub struct Gradient {
    /// First stop (top-left).
    pub start: Rgb,
    /// Middle stop.
    pub mid: Rgb,
    /// Final stop (bottom-right).
    pub end: Rgb,
    /// Screen width used to normalise the diagonal sweep.
    pub width: usize,
    /// Screen height used to normalise the diagonal sweep.
    pub height: usize,
}

impl Gradient {
    /// A three-stop gradient sized to the framebuffer.
    #[must_use]
    pub const fn three_stop(
        start: Rgb,
        mid: Rgb,
        end: Rgb,
        width: usize,
        height: usize,
    ) -> Self {
        Self {
            start,
            mid,
            end,
            width,
            height,
        }
    }

    /// The backdrop colour at `(x, y)`.
    ///
    /// The sweep runs along a ~160° diagonal (mostly top→bottom with a gentle
    /// rightward lean, matching the design token), parameterised by a single
    /// `t ∈ [0, den]`. `t` in the lower half selects `start → mid`, the upper
    /// half `mid → end`, so all three stops appear.
    #[must_use]
    pub fn color_at(&self, x: usize, y: usize) -> Rgb {
        // Weighted blend of the vertical and horizontal positions gives the
        // diagonal. Vertical dominates (3:1) so it reads as a 160°-ish sweep.
        let den = 4 * self.height.max(1) + self.width.max(1);
        let t = 4 * y + x; // 0 ..= den (approximately)
        let half = den / 2;
        if t <= half {
            // First segment: start → mid over [0, half].
            lerp_rgb(self.start, self.mid, t, half.max(1))
        } else {
            // Second segment: mid → end over [half, den].
            lerp_rgb(self.mid, self.end, t - half, (den - half).max(1))
        }
    }

    /// Fill the entire framebuffer with the gradient, one packed pixel at a time.
    pub fn fill(&self, fb: &Framebuffer) {
        for y in 0..fb.height() {
            for x in 0..fb.width() {
                let c = self.color_at(x, y);
                fb.put_pixel(x, y, c.pack(fb));
            }
        }
    }
}

/// `true` if pixel `(px, py)` lies inside a rounded rectangle whose top-left is
/// `(x, y)`, size `w × h`, with quarter-circle corners of radius `radius`.
///
/// The four corner cells are tested against the circle equation; the rest of the
/// rectangle is solid. A `radius` of 0 yields a plain rectangle.
#[inline]
#[must_use]
pub fn in_rounded_rect(
    px: usize,
    py: usize,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
    radius: usize,
) -> bool {
    if px < x || py < y || px >= x + w || py >= y + h {
        return false;
    }
    if radius == 0 {
        return true;
    }
    let r = radius.min(w / 2).min(h / 2);
    // Local coordinates within the rectangle.
    let lx = px - x;
    let ly = py - y;

    // Determine the relevant corner centre (only the four corner squares are
    // curved; everything else is inside).
    let cx = if lx < r {
        r
    } else if lx >= w - r {
        w - 1 - r
    } else {
        // Horizontally in the straight band → always inside.
        return true;
    };
    let cy = if ly < r {
        r
    } else if ly >= h - r {
        h - 1 - r
    } else {
        // Vertically in the straight band → always inside.
        return true;
    };

    // In a corner square: inside iff within the corner circle.
    let dx = lx as i64 - cx as i64;
    let dy = ly as i64 - cy as i64;
    dx * dx + dy * dy <= (r as i64) * (r as i64)
}

/// 8-bit "over" composite of one channel: `src*a + dst*(255-a)` / 255.
#[inline]
#[must_use]
fn over_u8(src: u8, dst: u8, alpha: u8) -> u8 {
    let a = alpha as u32;
    let s = src as u32 * a;
    let d = dst as u32 * (255 - a);
    ((s + d) / 255) as u8
}

/// Composite `over` (straight alpha) onto a backdrop colour.
#[inline]
#[must_use]
pub fn blend(backdrop: Rgb, over: Rgb, alpha: u8) -> Rgb {
    Rgb {
        r: over_u8(over.r, backdrop.r, alpha),
        g: over_u8(over.g, backdrop.g, alpha),
        b: over_u8(over.b, backdrop.b, alpha),
    }
}

/// Draw a filled, rounded rectangle of a translucent `color` over the `gradient`
/// backdrop — software alpha compositing with no `get_pixel` and no back-buffer.
///
/// For every covered pixel we recompute the backdrop from `gradient`, blend the
/// overlay over it at `alpha`, and write the single resulting pixel. This is how
/// the "glass" panels are realised on a bare framebuffer.
#[allow(clippy::too_many_arguments)]
pub fn fill_rounded_rect_alpha(
    fb: &Framebuffer,
    gradient: &Gradient,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
    radius: usize,
    color: Rgb,
    alpha: u8,
) {
    for py in y..y.saturating_add(h) {
        for px in x..x.saturating_add(w) {
            if in_rounded_rect(px, py, x, y, w, h, radius) {
                let backdrop = gradient.color_at(px, py);
                let out = blend(backdrop, color, alpha);
                fb.put_pixel(px, py, out.pack(fb));
            }
        }
    }
}

/// Draw an opaque, filled rounded rectangle in a solid `color`.
#[allow(clippy::too_many_arguments)]
pub fn fill_rounded_rect(
    fb: &Framebuffer,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
    radius: usize,
    color: Rgb,
) {
    let packed = color.pack(fb);
    for py in y..y.saturating_add(h) {
        for px in x..x.saturating_add(w) {
            if in_rounded_rect(px, py, x, y, w, h, radius) {
                fb.put_pixel(px, py, packed);
            }
        }
    }
}

/// Stroke a 1-pixel rounded-rectangle border, alpha-blended over the gradient.
///
/// A pixel is on the border when it is inside the outer rounded rect but outside
/// the rect inset by one pixel — giving a crisp ~1px outline that follows the
/// corner curve.
#[allow(clippy::too_many_arguments)]
pub fn stroke_rounded_rect_alpha(
    fb: &Framebuffer,
    gradient: &Gradient,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
    radius: usize,
    color: Rgb,
    alpha: u8,
) {
    if w < 2 || h < 2 {
        return;
    }
    let inner_r = radius.saturating_sub(1);
    for py in y..y.saturating_add(h) {
        for px in x..x.saturating_add(w) {
            let outer = in_rounded_rect(px, py, x, y, w, h, radius);
            let inner = in_rounded_rect(px, py, x + 1, y + 1, w - 2, h - 2, inner_r);
            if outer && !inner {
                let backdrop = gradient.color_at(px, py);
                let out = blend(backdrop, color, alpha);
                fb.put_pixel(px, py, out.pack(fb));
            }
        }
    }
}

/// A glossy gradient rounded-square tile (a dock/app icon).
///
/// Fills the rounded square with a vertical `top → bottom` gradient and adds a
/// brighter top "sheen" band, per the icon token (glossy gradient rounded square
/// with a top sheen). Fully opaque — drawn directly, no backdrop read needed.
#[allow(clippy::too_many_arguments)]
pub fn glossy_tile(
    fb: &Framebuffer,
    x: usize,
    y: usize,
    size: usize,
    radius: usize,
    top: Rgb,
    bottom: Rgb,
) {
    for py in y..y.saturating_add(size) {
        // Vertical gradient across the tile height.
        let row = py - y;
        let base = lerp_rgb(top, bottom, row, size.max(1));
        for px in x..x.saturating_add(size) {
            if !in_rounded_rect(px, py, x, y, size, size, radius) {
                continue;
            }
            // Add a glossy sheen over the top ~38% of the tile: lift toward
            // white, strongest at the very top, fading out.
            let sheen_h = (size * 38) / 100;
            let c = if row < sheen_h && sheen_h > 0 {
                let lift = 90 - (row * 90 / sheen_h);
                blend(base, Rgb::new(255, 255, 255), lift as u8)
            } else {
                base
            };
            fb.put_pixel(px, py, c.pack(fb));
        }
    }
}
