//! A compact public-domain 8×8 bitmap font and a scalable text plotter.
//!
//! The glyph table below is a hand-curated 8×8 monochrome bitmap font in the
//! lineage of the classic IBM PC / public-domain 8×8 console fonts (no licence
//! restrictions). Each glyph is 8 bytes; bit 7 (`0x80`) of each byte is the
//! left-most pixel of that row, bit 0 the right-most — so a row reads naturally
//! left-to-right when written in binary.
//!
//! Only the glyphs the boot screen actually needs are populated; every other
//! code point maps to a blank cell via [`glyph`]. Drawing goes exclusively
//! through the safe, bounds-checked [`hal::framebuffer::Framebuffer`] API, so
//! this module — like the whole crate — needs no `unsafe`.

use hal::framebuffer::Framebuffer;

/// Width and height of a single glyph cell, in source pixels (before scaling).
pub const GLYPH_SIZE: usize = 8;

/// A single 8×8 glyph: 8 rows, MSB-first per row.
type Glyph = [u8; GLYPH_SIZE];

/// Blank cell — used for spaces and any unsupported code point.
const BLANK: Glyph = [0; 8];

// Each glyph is written so the `1` bits visually spell the character when the
// bytes are read top-to-bottom in binary. This keeps the table auditable.

const GLYPH_SPACE: Glyph = BLANK;

const GLYPH_EXCLAIM: Glyph = [
    0b00011000,
    0b00011000,
    0b00011000,
    0b00011000,
    0b00011000,
    0b00000000,
    0b00011000,
    0b00000000,
];

const GLYPH_DOT: Glyph = [
    0b00000000,
    0b00000000,
    0b00000000,
    0b00000000,
    0b00000000,
    0b00011000,
    0b00011000,
    0b00000000,
];

const GLYPH_COLON: Glyph = [
    0b00000000,
    0b00011000,
    0b00011000,
    0b00000000,
    0b00000000,
    0b00011000,
    0b00011000,
    0b00000000,
];

const GLYPH_DASH: Glyph = [
    0b00000000,
    0b00000000,
    0b00000000,
    0b01111110,
    0b00000000,
    0b00000000,
    0b00000000,
    0b00000000,
];

const GLYPH_SLASH: Glyph = [
    0b00000010,
    0b00000100,
    0b00001000,
    0b00010000,
    0b00100000,
    0b01000000,
    0b10000000,
    0b00000000,
];

/// Middle dot `·` (used in `private · secure · yours`).
const GLYPH_MIDDOT: Glyph = [
    0b00000000,
    0b00000000,
    0b00011000,
    0b00111100,
    0b00111100,
    0b00011000,
    0b00000000,
    0b00000000,
];

/// Right arrow `→` (used in the unlock pill).
const GLYPH_ARROW: Glyph = [
    0b00000000,
    0b00001000,
    0b00000100,
    0b01111110,
    0b00000100,
    0b00001000,
    0b00000000,
    0b00000000,
];

/// Greater-than `>` (the shell prompt, e.g. `> help`).
const GLYPH_GT: Glyph = [
    0b00110000,
    0b00011000,
    0b00001100,
    0b00000110,
    0b00001100,
    0b00011000,
    0b00110000,
    0b00000000,
];

/// Less-than `<`.
const GLYPH_LESS: Glyph = [
    0b00000110,
    0b00001100,
    0b00011000,
    0b00110000,
    0b00011000,
    0b00001100,
    0b00000110,
    0b00000000,
];

/// Underscore `_` (used for an underline-style cursor / paths).
const GLYPH_UNDERSCORE: Glyph = [
    0b00000000,
    0b00000000,
    0b00000000,
    0b00000000,
    0b00000000,
    0b00000000,
    0b00000000,
    0b11111111,
];

/// Single quote `'` (used in console help text like `'help'`).
const GLYPH_QUOTE: Glyph = [
    0b00011000,
    0b00011000,
    0b00011000,
    0b00000000,
    0b00000000,
    0b00000000,
    0b00000000,
    0b00000000,
];

/// Comma `,`.
const GLYPH_COMMA: Glyph = [
    0b00000000,
    0b00000000,
    0b00000000,
    0b00000000,
    0b00000000,
    0b00011000,
    0b00011000,
    0b00110000,
];

// --- Digits 0-9 ---------------------------------------------------------------

const GLYPH_0: Glyph = [
    0b00111100,
    0b01100110,
    0b01101110,
    0b01110110,
    0b01100110,
    0b01100110,
    0b00111100,
    0b00000000,
];
const GLYPH_1: Glyph = [
    0b00011000,
    0b00111000,
    0b00011000,
    0b00011000,
    0b00011000,
    0b00011000,
    0b01111110,
    0b00000000,
];
const GLYPH_2: Glyph = [
    0b00111100,
    0b01100110,
    0b00000110,
    0b00001100,
    0b00110000,
    0b01100000,
    0b01111110,
    0b00000000,
];
const GLYPH_3: Glyph = [
    0b00111100,
    0b01100110,
    0b00000110,
    0b00011100,
    0b00000110,
    0b01100110,
    0b00111100,
    0b00000000,
];
const GLYPH_4: Glyph = [
    0b00001100,
    0b00011100,
    0b00111100,
    0b01101100,
    0b01111110,
    0b00001100,
    0b00001100,
    0b00000000,
];
const GLYPH_5: Glyph = [
    0b01111110,
    0b01100000,
    0b01111100,
    0b00000110,
    0b00000110,
    0b01100110,
    0b00111100,
    0b00000000,
];
const GLYPH_6: Glyph = [
    0b00011100,
    0b00110000,
    0b01100000,
    0b01111100,
    0b01100110,
    0b01100110,
    0b00111100,
    0b00000000,
];
const GLYPH_7: Glyph = [
    0b01111110,
    0b00000110,
    0b00001100,
    0b00011000,
    0b00110000,
    0b00110000,
    0b00110000,
    0b00000000,
];
const GLYPH_8: Glyph = [
    0b00111100,
    0b01100110,
    0b01100110,
    0b00111100,
    0b01100110,
    0b01100110,
    0b00111100,
    0b00000000,
];
const GLYPH_9: Glyph = [
    0b00111100,
    0b01100110,
    0b01100110,
    0b00111110,
    0b00000110,
    0b00001100,
    0b00111000,
    0b00000000,
];

// --- Uppercase A-Z ------------------------------------------------------------

const GLYPH_A: Glyph = [
    0b00011000,
    0b00111100,
    0b01100110,
    0b01100110,
    0b01111110,
    0b01100110,
    0b01100110,
    0b00000000,
];
const GLYPH_B: Glyph = [
    0b01111100,
    0b01100110,
    0b01100110,
    0b01111100,
    0b01100110,
    0b01100110,
    0b01111100,
    0b00000000,
];
const GLYPH_C: Glyph = [
    0b00111100,
    0b01100110,
    0b01100000,
    0b01100000,
    0b01100000,
    0b01100110,
    0b00111100,
    0b00000000,
];
const GLYPH_D: Glyph = [
    0b01111000,
    0b01101100,
    0b01100110,
    0b01100110,
    0b01100110,
    0b01101100,
    0b01111000,
    0b00000000,
];
const GLYPH_E: Glyph = [
    0b01111110,
    0b01100000,
    0b01100000,
    0b01111100,
    0b01100000,
    0b01100000,
    0b01111110,
    0b00000000,
];
const GLYPH_F: Glyph = [
    0b01111110,
    0b01100000,
    0b01100000,
    0b01111100,
    0b01100000,
    0b01100000,
    0b01100000,
    0b00000000,
];
const GLYPH_G: Glyph = [
    0b00111100,
    0b01100110,
    0b01100000,
    0b01101110,
    0b01100110,
    0b01100110,
    0b00111110,
    0b00000000,
];
const GLYPH_H: Glyph = [
    0b01100110,
    0b01100110,
    0b01100110,
    0b01111110,
    0b01100110,
    0b01100110,
    0b01100110,
    0b00000000,
];
const GLYPH_I: Glyph = [
    0b00111100,
    0b00011000,
    0b00011000,
    0b00011000,
    0b00011000,
    0b00011000,
    0b00111100,
    0b00000000,
];
const GLYPH_J: Glyph = [
    0b00011110,
    0b00001100,
    0b00001100,
    0b00001100,
    0b01101100,
    0b01101100,
    0b00111000,
    0b00000000,
];
const GLYPH_K: Glyph = [
    0b01100110,
    0b01101100,
    0b01111000,
    0b01110000,
    0b01111000,
    0b01101100,
    0b01100110,
    0b00000000,
];
const GLYPH_L: Glyph = [
    0b01100000,
    0b01100000,
    0b01100000,
    0b01100000,
    0b01100000,
    0b01100000,
    0b01111110,
    0b00000000,
];
const GLYPH_M: Glyph = [
    0b01100011,
    0b01110111,
    0b01111111,
    0b01101011,
    0b01100011,
    0b01100011,
    0b01100011,
    0b00000000,
];
const GLYPH_N: Glyph = [
    0b01100110,
    0b01110110,
    0b01111110,
    0b01111110,
    0b01101110,
    0b01100110,
    0b01100110,
    0b00000000,
];
const GLYPH_O: Glyph = [
    0b00111100,
    0b01100110,
    0b01100110,
    0b01100110,
    0b01100110,
    0b01100110,
    0b00111100,
    0b00000000,
];
const GLYPH_P: Glyph = [
    0b01111100,
    0b01100110,
    0b01100110,
    0b01111100,
    0b01100000,
    0b01100000,
    0b01100000,
    0b00000000,
];
const GLYPH_Q: Glyph = [
    0b00111100,
    0b01100110,
    0b01100110,
    0b01100110,
    0b01101110,
    0b00111100,
    0b00000110,
    0b00000000,
];
const GLYPH_R: Glyph = [
    0b01111100,
    0b01100110,
    0b01100110,
    0b01111100,
    0b01111000,
    0b01101100,
    0b01100110,
    0b00000000,
];
const GLYPH_S: Glyph = [
    0b00111100,
    0b01100110,
    0b01100000,
    0b00111100,
    0b00000110,
    0b01100110,
    0b00111100,
    0b00000000,
];
const GLYPH_T: Glyph = [
    0b01111110,
    0b00011000,
    0b00011000,
    0b00011000,
    0b00011000,
    0b00011000,
    0b00011000,
    0b00000000,
];
const GLYPH_U: Glyph = [
    0b01100110,
    0b01100110,
    0b01100110,
    0b01100110,
    0b01100110,
    0b01100110,
    0b00111100,
    0b00000000,
];
const GLYPH_V: Glyph = [
    0b01100110,
    0b01100110,
    0b01100110,
    0b01100110,
    0b01100110,
    0b00111100,
    0b00011000,
    0b00000000,
];
const GLYPH_W: Glyph = [
    0b01100011,
    0b01100011,
    0b01100011,
    0b01101011,
    0b01111111,
    0b01110111,
    0b01100011,
    0b00000000,
];
const GLYPH_X: Glyph = [
    0b01100110,
    0b01100110,
    0b00111100,
    0b00011000,
    0b00111100,
    0b01100110,
    0b01100110,
    0b00000000,
];
const GLYPH_Y: Glyph = [
    0b01100110,
    0b01100110,
    0b01100110,
    0b00111100,
    0b00011000,
    0b00011000,
    0b00011000,
    0b00000000,
];
const GLYPH_Z: Glyph = [
    0b01111110,
    0b00000110,
    0b00001100,
    0b00011000,
    0b00110000,
    0b01100000,
    0b01111110,
    0b00000000,
];

// --- Lowercase a-z ------------------------------------------------------------

const GLYPH_LA: Glyph = [
    0b00000000,
    0b00000000,
    0b00111100,
    0b00000110,
    0b00111110,
    0b01100110,
    0b00111110,
    0b00000000,
];
const GLYPH_LB: Glyph = [
    0b01100000,
    0b01100000,
    0b01111100,
    0b01100110,
    0b01100110,
    0b01100110,
    0b01111100,
    0b00000000,
];
const GLYPH_LC: Glyph = [
    0b00000000,
    0b00000000,
    0b00111100,
    0b01100110,
    0b01100000,
    0b01100110,
    0b00111100,
    0b00000000,
];
const GLYPH_LD: Glyph = [
    0b00000110,
    0b00000110,
    0b00111110,
    0b01100110,
    0b01100110,
    0b01100110,
    0b00111110,
    0b00000000,
];
const GLYPH_LE: Glyph = [
    0b00000000,
    0b00000000,
    0b00111100,
    0b01100110,
    0b01111110,
    0b01100000,
    0b00111100,
    0b00000000,
];
const GLYPH_LF: Glyph = [
    0b00011100,
    0b00110000,
    0b01111100,
    0b00110000,
    0b00110000,
    0b00110000,
    0b00110000,
    0b00000000,
];
const GLYPH_LG: Glyph = [
    0b00000000,
    0b00111110,
    0b01100110,
    0b01100110,
    0b00111110,
    0b00000110,
    0b00111100,
    0b00000000,
];
const GLYPH_LH: Glyph = [
    0b01100000,
    0b01100000,
    0b01111100,
    0b01100110,
    0b01100110,
    0b01100110,
    0b01100110,
    0b00000000,
];
const GLYPH_LI: Glyph = [
    0b00011000,
    0b00000000,
    0b00111000,
    0b00011000,
    0b00011000,
    0b00011000,
    0b00111100,
    0b00000000,
];
const GLYPH_LJ: Glyph = [
    0b00001100,
    0b00000000,
    0b00011100,
    0b00001100,
    0b00001100,
    0b01101100,
    0b00111000,
    0b00000000,
];
const GLYPH_LK: Glyph = [
    0b01100000,
    0b01100000,
    0b01100110,
    0b01101100,
    0b01111000,
    0b01101100,
    0b01100110,
    0b00000000,
];
const GLYPH_LL: Glyph = [
    0b00111000,
    0b00011000,
    0b00011000,
    0b00011000,
    0b00011000,
    0b00011000,
    0b00111100,
    0b00000000,
];
const GLYPH_LM: Glyph = [
    0b00000000,
    0b00000000,
    0b01100110,
    0b01111111,
    0b01111111,
    0b01101011,
    0b01100011,
    0b00000000,
];
const GLYPH_LN: Glyph = [
    0b00000000,
    0b00000000,
    0b01111100,
    0b01100110,
    0b01100110,
    0b01100110,
    0b01100110,
    0b00000000,
];
const GLYPH_LO: Glyph = [
    0b00000000,
    0b00000000,
    0b00111100,
    0b01100110,
    0b01100110,
    0b01100110,
    0b00111100,
    0b00000000,
];
const GLYPH_LP: Glyph = [
    0b00000000,
    0b00000000,
    0b01111100,
    0b01100110,
    0b01100110,
    0b01111100,
    0b01100000,
    0b01100000,
];
const GLYPH_LQ: Glyph = [
    0b00000000,
    0b00000000,
    0b00111110,
    0b01100110,
    0b01100110,
    0b00111110,
    0b00000110,
    0b00000110,
];
const GLYPH_LR: Glyph = [
    0b00000000,
    0b00000000,
    0b01111100,
    0b01100110,
    0b01100000,
    0b01100000,
    0b01100000,
    0b00000000,
];
const GLYPH_LS: Glyph = [
    0b00000000,
    0b00000000,
    0b00111110,
    0b01100000,
    0b00111100,
    0b00000110,
    0b01111100,
    0b00000000,
];
const GLYPH_LT: Glyph = [
    0b00110000,
    0b00110000,
    0b01111100,
    0b00110000,
    0b00110000,
    0b00110110,
    0b00011100,
    0b00000000,
];
const GLYPH_LU: Glyph = [
    0b00000000,
    0b00000000,
    0b01100110,
    0b01100110,
    0b01100110,
    0b01100110,
    0b00111110,
    0b00000000,
];
const GLYPH_LV: Glyph = [
    0b00000000,
    0b00000000,
    0b01100110,
    0b01100110,
    0b01100110,
    0b00111100,
    0b00011000,
    0b00000000,
];
const GLYPH_LW: Glyph = [
    0b00000000,
    0b00000000,
    0b01100011,
    0b01101011,
    0b01111111,
    0b00111110,
    0b00110110,
    0b00000000,
];
const GLYPH_LX: Glyph = [
    0b00000000,
    0b00000000,
    0b01100110,
    0b00111100,
    0b00011000,
    0b00111100,
    0b01100110,
    0b00000000,
];
const GLYPH_LY: Glyph = [
    0b00000000,
    0b00000000,
    0b01100110,
    0b01100110,
    0b00111110,
    0b00000110,
    0b00111100,
    0b00000000,
];
const GLYPH_LZ: Glyph = [
    0b00000000,
    0b00000000,
    0b01111110,
    0b00001100,
    0b00011000,
    0b00110000,
    0b01111110,
    0b00000000,
];

/// Return the 8×8 glyph for a character, or [`BLANK`] for anything unsupported.
///
/// Only the printable subset the boot screen uses is mapped; everything else
/// (control chars, accented letters, etc.) renders as an empty cell so callers
/// never have to pre-validate their strings.
#[must_use]
pub const fn glyph(c: char) -> Glyph {
    match c {
        ' ' => GLYPH_SPACE,
        '!' => GLYPH_EXCLAIM,
        '.' => GLYPH_DOT,
        ':' => GLYPH_COLON,
        '-' => GLYPH_DASH,
        '/' => GLYPH_SLASH,
        '·' => GLYPH_MIDDOT,
        '→' => GLYPH_ARROW,
        '>' => GLYPH_GT,
        '<' => GLYPH_LESS,
        '_' => GLYPH_UNDERSCORE,
        '\'' => GLYPH_QUOTE,
        ',' => GLYPH_COMMA,
        '0' => GLYPH_0,
        '1' => GLYPH_1,
        '2' => GLYPH_2,
        '3' => GLYPH_3,
        '4' => GLYPH_4,
        '5' => GLYPH_5,
        '6' => GLYPH_6,
        '7' => GLYPH_7,
        '8' => GLYPH_8,
        '9' => GLYPH_9,
        'A' => GLYPH_A,
        'B' => GLYPH_B,
        'C' => GLYPH_C,
        'D' => GLYPH_D,
        'E' => GLYPH_E,
        'F' => GLYPH_F,
        'G' => GLYPH_G,
        'H' => GLYPH_H,
        'I' => GLYPH_I,
        'J' => GLYPH_J,
        'K' => GLYPH_K,
        'L' => GLYPH_L,
        'M' => GLYPH_M,
        'N' => GLYPH_N,
        'O' => GLYPH_O,
        'P' => GLYPH_P,
        'Q' => GLYPH_Q,
        'R' => GLYPH_R,
        'S' => GLYPH_S,
        'T' => GLYPH_T,
        'U' => GLYPH_U,
        'V' => GLYPH_V,
        'W' => GLYPH_W,
        'X' => GLYPH_X,
        'Y' => GLYPH_Y,
        'Z' => GLYPH_Z,
        'a' => GLYPH_LA,
        'b' => GLYPH_LB,
        'c' => GLYPH_LC,
        'd' => GLYPH_LD,
        'e' => GLYPH_LE,
        'f' => GLYPH_LF,
        'g' => GLYPH_LG,
        'h' => GLYPH_LH,
        'i' => GLYPH_LI,
        'j' => GLYPH_LJ,
        'k' => GLYPH_LK,
        'l' => GLYPH_LL,
        'm' => GLYPH_LM,
        'n' => GLYPH_LN,
        'o' => GLYPH_LO,
        'p' => GLYPH_LP,
        'q' => GLYPH_LQ,
        'r' => GLYPH_LR,
        's' => GLYPH_LS,
        't' => GLYPH_LT,
        'u' => GLYPH_LU,
        'v' => GLYPH_LV,
        'w' => GLYPH_LW,
        'x' => GLYPH_LX,
        'y' => GLYPH_LY,
        'z' => GLYPH_LZ,
        _ => BLANK,
    }
}

/// Advance, in source pixels, between the left edges of adjacent glyph cells
/// (the 8-pixel cell plus a 1-pixel inter-character gap), before scaling.
pub const ADVANCE: usize = GLYPH_SIZE + 1;

/// Pixel width a string occupies at the given integer `scale`.
#[must_use]
pub fn text_width(text: &str, scale: usize) -> usize {
    let n = text.chars().count();
    if n == 0 {
        return 0;
    }
    // n cells of width 8, with (n-1) one-pixel gaps between them, all scaled.
    (n * GLYPH_SIZE + (n - 1)) * scale
}

/// Draw `text` with its top-left corner at `(x, y)`, magnified by `scale`
/// (each source pixel becomes a `scale × scale` block), in the packed `color`.
///
/// Drawing is purely additive: only set glyph pixels are plotted, so text
/// composites over whatever backdrop already lives in the framebuffer. All
/// plotting is bounds-checked by [`Framebuffer::put_pixel`].
pub fn draw_text(fb: &Framebuffer, x: usize, y: usize, text: &str, scale: usize, color: u32) {
    let scale = scale.max(1);
    let mut cursor_x = x;
    for c in text.chars() {
        let g = glyph(c);
        for (row, bits) in g.iter().enumerate() {
            for col in 0..GLYPH_SIZE {
                // MSB-first: column 0 is bit 7.
                if (bits >> (7 - col)) & 1 == 1 {
                    let px0 = cursor_x + col * scale;
                    let py0 = y + row * scale;
                    // Expand the source pixel into a scale×scale block.
                    for dy in 0..scale {
                        for dx in 0..scale {
                            fb.put_pixel(px0 + dx, py0 + dy, color);
                        }
                    }
                }
            }
        }
        cursor_x += ADVANCE * scale;
    }
}
