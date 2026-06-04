//! The **System** app — a small, live, read-only panel that proves the
//! compositor handles a second, independently-updating window.
//!
//! It renders a handful of labelled rows from `hal::mm::stats()` and `hal::pit`
//! into its window's content rectangle, and refreshes them once a whole second
//! from its [`App::tick`] — so it self-updates without any keystrokes, exercising
//! the WM's periodic-damage path independently of input. Like the shell it uses a
//! hand-rolled decimal formatter (no `core::fmt`, which faults on this target)
//! and draws only through the safe `ui`/`hal` API.

use alloc::string::String;
use alloc::vec::Vec;

use ui::Rect;

use crate::input::KeyEvent;

use super::App;

/// Text scale of the panel rows (matches the console's body scale).
const ROW_SCALE: usize = 2;
/// Vertical leading between rows, in source pixels (breathing room).
const ROW_LEADING: usize = 6;

/// Near-white primary text with a faint cyan cast (matches the console header).
const PRIMARY_RGB: (u8, u8, u8) = (0xe8, 0xf6, 0xff);
/// Muted cyan-grey label text for the stat rows.
const LABEL_RGB: (u8, u8, u8) = (0x9a, 0xb6, 0xd6);

/// Append the base-10 ASCII digits of `value` to `out` with no `core::fmt`
/// (which faults on this target). Zero renders as `"0"`.
fn push_dec(out: &mut String, value: u64) {
    if value == 0 {
        out.push('0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut n = value;
    let mut i = buf.len();
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    for &b in &buf[i..] {
        out.push(b as char);
    }
}

/// The System panel: live memory + uptime stats, refreshed once a second.
pub struct SystemPanel {
    /// The rendered stat lines (label-prefixed), rebuilt on each whole-second
    /// tick. Held so `render` (which is `&self`) can draw the memoised strings.
    rows: Vec<String>,
    /// The last whole-second value we rebuilt `rows` at, so `tick` only refreshes
    /// (and reports dirty) when the second changes.
    last_secs: u64,
}

impl SystemPanel {
    /// Create a fresh System panel and populate its first snapshot of the stats.
    #[must_use]
    pub fn new() -> Self {
        let mut panel = Self {
            rows: Vec::new(),
            last_secs: u64::MAX,
        };
        panel.refresh();
        panel
    }

    /// Rebuild the stat rows from the current `hal::mm::stats()` + `hal::pit`.
    fn refresh(&mut self) {
        let stats = hal::mm::stats();
        let secs = hal::pit::ticks() / hal::pit::TICK_HZ;

        self.rows.clear();

        // "uptime: NNN s"
        let mut uptime = String::from("uptime: ");
        push_dec(&mut uptime, secs);
        uptime.push_str(" s");
        self.rows.push(uptime);

        // "heap: NNN KiB"
        let mut heap = String::from("heap: ");
        push_dec(&mut heap, (stats.heap_bytes / 1024) as u64);
        heap.push_str(" KiB");
        self.rows.push(heap);

        // "frames: FREE / TOTAL"
        let mut frames = String::from("frames: ");
        push_dec(&mut frames, stats.free_frames as u64);
        frames.push_str(" / ");
        push_dec(&mut frames, stats.total_frames as u64);
        self.rows.push(frames);

        // "ram: FREE / TOTAL MiB" (4 KiB/frame).
        let free_mib = (stats.free_frames as u64) * 4 / 1024;
        let total_mib = (stats.total_frames as u64) * 4 / 1024;
        let mut ram = String::from("ram: ");
        push_dec(&mut ram, free_mib);
        ram.push_str(" / ");
        push_dec(&mut ram, total_mib);
        ram.push_str(" MiB");
        self.rows.push(ram);
    }
}

impl Default for SystemPanel {
    fn default() -> Self {
        Self::new()
    }
}

impl App for SystemPanel {
    fn title(&self) -> &str {
        "System"
    }

    fn render(&self, fb: &hal::framebuffer::Framebuffer, area: Rect) {
        // Pack the colours against the framebuffer's native pixel format so they
        // read correctly on RGB *and* BGR firmwares (no hard-coded byte order).
        let primary = fb.pack_rgb(PRIMARY_RGB.0, PRIMARY_RGB.1, PRIMARY_RGB.2);
        let label = fb.pack_rgb(LABEL_RGB.0, LABEL_RGB.1, LABEL_RGB.2);

        // One row of breathing room inset from the content edge.
        let inset = ui::font::GLYPH_SIZE * ROW_SCALE / 2;
        let x0 = area.x + inset;
        let mut y = area.y + inset;
        let row_pitch = ui::font::GLYPH_SIZE * ROW_SCALE + ROW_LEADING;

        // A short header in the brighter primary colour, then the stat rows in
        // the muted label colour.
        ui::font::draw_text(fb, x0, y, "SYSTEM", ROW_SCALE, primary);
        y += row_pitch + ROW_LEADING;

        for row in &self.rows {
            // Stop if we'd draw past the content rect (the framebuffer also clips,
            // so this is belt-and-braces against a tiny window).
            if y + ui::font::GLYPH_SIZE * ROW_SCALE > area.bottom() {
                break;
            }
            ui::font::draw_text(fb, x0, y, row, ROW_SCALE, label);
            y += row_pitch;
        }
    }

    fn on_key(&mut self, _event: KeyEvent) -> bool {
        // Read-only panel: it ignores input and never dirties from a keystroke.
        false
    }

    fn tick(&mut self, now_ticks: u64) -> bool {
        let secs = now_ticks / hal::pit::TICK_HZ;
        if secs != self.last_secs {
            self.last_secs = secs;
            self.refresh();
            true
        } else {
            false
        }
    }
}
