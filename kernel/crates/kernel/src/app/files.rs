//! The **Files** app — a read-only browser over the in-memory VFS.
//!
//! It owns its own seeded [`FileSystem`](crate::fs::FileSystem) (the kernel keeps
//! no shared global VFS — the shell likewise owns its own; see `shell.rs`), and
//! drives the filesystem's *read* API only ([`list`](crate::fs::FileSystem::list)
//! and [`read_file`](crate::fs::FileSystem::read_file)): it never mutates the tree.
//!
//! # Interaction
//!
//! The app is a tiny two-mode browser:
//!
//! * **Listing mode** — shows the current directory's entries, directories first
//!   (each suffixed `/`), with a `>` selection cursor. `Up`/`Down` move the
//!   cursor; `Enter` descends into the highlighted directory or opens a file;
//!   `Backspace` walks up one level (a no-op at the root).
//! * **Viewing mode** — shows a file's bytes as text (a bounded window of lines).
//!   `Backspace` (or `Enter`) returns to the listing.
//!
//! All drawing goes through the safe `ui::font::draw_text` plotter into the
//! window's content rect, so — like the rest of the kernel — this module needs no
//! `unsafe` and inherits the crate's `#![forbid(unsafe_code)]`.

use alloc::string::String;
use alloc::vec::Vec;

use ui::Rect;

use crate::fs::{DirEntry, FileSystem};
use crate::input::KeyEvent;

use super::App;

/// Text scale of the listing/viewer rows (matches the console body scale).
const ROW_SCALE: usize = 2;
/// Vertical leading between rows, in source pixels.
const ROW_LEADING: usize = 4;

/// Near-white primary text (matches the system panel's primary).
const PRIMARY_RGB: (u8, u8, u8) = (0xe8, 0xf6, 0xff);
/// Muted cyan-grey for non-selected rows and the header path.
const DIM_RGB: (u8, u8, u8) = (0x9a, 0xb6, 0xd6);
/// Cyan accent for the selected row and the `>` cursor.
const ACCENT_RGB: (u8, u8, u8) = (0x7a, 0xd7, 0xff);

/// Which view the browser is currently showing.
enum View {
    /// Listing the current directory's entries.
    Listing,
    /// Showing one file's contents: the file name plus its text lines.
    Viewing {
        /// The file's name (for the header).
        name: String,
        /// The file's content split into display lines (already lossy-UTF8).
        lines: Vec<String>,
    },
}

/// The Files app: a read-only browser over its own seeded in-memory filesystem.
pub struct Files {
    /// The browsed filesystem (read-only here; seeded like the shell's).
    fs: FileSystem,
    /// The current directory's entries, directories first then files, each in the
    /// filesystem's insertion order. Rebuilt whenever the directory changes.
    entries: Vec<DirEntry>,
    /// The selection cursor into `entries` (clamped to `0..entries.len()`).
    selected: usize,
    /// Whether we're listing a directory or viewing a file's contents.
    view: View,
}

impl Files {
    /// Create a fresh Files browser at `/` over a freshly seeded filesystem.
    /// Allocates on the kernel heap.
    #[must_use]
    pub fn new() -> Self {
        let fs = FileSystem::seeded();
        let mut app = Self {
            fs,
            entries: Vec::new(),
            selected: 0,
            view: View::Listing,
        };
        app.reload();
        app
    }

    /// Rebuild `entries` from the current directory, directories first then files
    /// (each group keeping the filesystem's insertion order), and clamp the
    /// selection. A failed listing (which shouldn't happen for a directory CWD)
    /// leaves an empty list rather than panicking.
    fn reload(&mut self) {
        let mut entries = self.fs.list(".").unwrap_or_default();
        // Stable partition: directories first, files after, each keeping the
        // filesystem's insertion order (a stable sort on the `is_dir` key, reversed
        // so `true` sorts ahead of `false`).
        entries.sort_by_key(|e| core::cmp::Reverse(e.is_dir));
        self.entries = entries;
        if self.selected >= self.entries.len() {
            self.selected = self.entries.len().saturating_sub(1);
        }
    }

    /// Move the selection cursor by `delta` (`-1` up, `+1` down), wrapping at the
    /// ends so a long list is easy to traverse. A no-op on an empty directory.
    fn move_cursor(&mut self, up: bool) -> bool {
        let n = self.entries.len();
        if n == 0 {
            return false;
        }
        if up {
            self.selected = if self.selected == 0 {
                n - 1
            } else {
                self.selected - 1
            };
        } else {
            self.selected = (self.selected + 1) % n;
        }
        true
    }

    /// Act on `Enter`: descend into the selected directory (reloading the listing)
    /// or open the selected file (switching to the viewer). Returns whether the
    /// view changed (so the WM repaints).
    fn enter(&mut self) -> bool {
        let Some(entry) = self.entries.get(self.selected) else {
            return false;
        };
        if entry.is_dir {
            // Descend. `change_dir` resolves against the CWD; on success reload.
            if self.fs.change_dir(&entry.name).is_ok() {
                self.selected = 0;
                self.reload();
                return true;
            }
            false
        } else {
            // Open the file's contents into the viewer.
            let name = entry.name.clone();
            match self.fs.read_file(&name) {
                Ok(bytes) => {
                    let lines = split_lines(bytes);
                    self.view = View::Viewing { name, lines };
                    true
                }
                Err(_) => false,
            }
        }
    }

    /// Act on `Backspace`: leave the file viewer back to the listing, or — when
    /// already listing — walk up one directory level. Returns whether anything
    /// changed.
    fn back(&mut self) -> bool {
        match self.view {
            View::Viewing { .. } => {
                self.view = View::Listing;
                true
            }
            View::Listing => {
                // Walk up a level. At root, `cd ..` clamps and the listing is the
                // same — report no change so we don't repaint needlessly.
                if self.fs.cwd() == "/" {
                    return false;
                }
                if self.fs.change_dir("..").is_ok() {
                    self.selected = 0;
                    self.reload();
                    return true;
                }
                false
            }
        }
    }

    /// Render the directory listing into `area`.
    fn render_listing(&self, fb: &hal::framebuffer::Framebuffer, area: Rect) {
        let primary = fb.pack_rgb(PRIMARY_RGB.0, PRIMARY_RGB.1, PRIMARY_RGB.2);
        let dim = fb.pack_rgb(DIM_RGB.0, DIM_RGB.1, DIM_RGB.2);
        let accent = fb.pack_rgb(ACCENT_RGB.0, ACCENT_RGB.1, ACCENT_RGB.2);

        let inset = ui::font::GLYPH_SIZE * ROW_SCALE / 2;
        let x0 = area.x + inset;
        let mut y = area.y + inset;
        let row_pitch = ui::font::GLYPH_SIZE * ROW_SCALE + ROW_LEADING;

        // Header: the current directory path.
        let mut header = String::from("FILES  ");
        header.push_str(&self.fs.cwd());
        ui::font::draw_text(fb, x0, y, &header, ROW_SCALE, primary);
        y += row_pitch + ROW_LEADING;

        if self.entries.is_empty() {
            ui::font::draw_text(fb, x0, y, "(empty)", ROW_SCALE, dim);
            return;
        }

        // Each entry: "> name" for the selection, "  name" otherwise; directories
        // are suffixed "/" so they read as folders.
        for (i, entry) in self.entries.iter().enumerate() {
            if y + ui::font::GLYPH_SIZE * ROW_SCALE > area.bottom() {
                break; // ran out of content rect; framebuffer also clips
            }
            let selected = i == self.selected;
            let color = if selected { accent } else { primary };
            let mut row = String::from(if selected { "> " } else { "  " });
            row.push_str(&entry.name);
            if entry.is_dir {
                row.push('/');
            }
            ui::font::draw_text(fb, x0, y, &row, ROW_SCALE, color);
            y += row_pitch;
        }
    }

    /// Render a file's contents into `area`.
    fn render_viewer(
        &self,
        fb: &hal::framebuffer::Framebuffer,
        area: Rect,
        name: &str,
        lines: &[String],
    ) {
        let primary = fb.pack_rgb(PRIMARY_RGB.0, PRIMARY_RGB.1, PRIMARY_RGB.2);
        let dim = fb.pack_rgb(DIM_RGB.0, DIM_RGB.1, DIM_RGB.2);

        let inset = ui::font::GLYPH_SIZE * ROW_SCALE / 2;
        let x0 = area.x + inset;
        let mut y = area.y + inset;
        let row_pitch = ui::font::GLYPH_SIZE * ROW_SCALE + ROW_LEADING;

        // Header: the file name and a hint to go back.
        let mut header = String::from("FILE  ");
        header.push_str(name);
        ui::font::draw_text(fb, x0, y, &header, ROW_SCALE, primary);
        y += row_pitch + ROW_LEADING;

        for line in lines {
            if y + ui::font::GLYPH_SIZE * ROW_SCALE > area.bottom() {
                break;
            }
            ui::font::draw_text(fb, x0, y, line, ROW_SCALE, dim);
            y += row_pitch;
        }
    }
}

impl Default for Files {
    fn default() -> Self {
        Self::new()
    }
}

impl App for Files {
    fn title(&self) -> &str {
        "Files"
    }

    fn render(&self, fb: &hal::framebuffer::Framebuffer, area: Rect) {
        match &self.view {
            View::Listing => self.render_listing(fb, area),
            View::Viewing { name, lines } => self.render_viewer(fb, area, name, lines),
        }
    }

    fn on_key(&mut self, event: KeyEvent) -> bool {
        match event {
            // Cursor movement only applies to the listing.
            KeyEvent::UpArrowPressed if matches!(self.view, View::Listing) => {
                self.move_cursor(true)
            }
            KeyEvent::DownArrowPressed if matches!(self.view, View::Listing) => {
                self.move_cursor(false)
            }
            KeyEvent::EnterPressed => match self.view {
                View::Listing => self.enter(),
                // In the viewer, Enter returns to the listing (same as Backspace).
                View::Viewing { .. } => self.back(),
            },
            KeyEvent::Backspace => self.back(),
            _ => false,
        }
    }

    // No `tick` override: the browser only changes on a keystroke, so idle ticks
    // stay cheap (it uses the default no-op).
}

/// Split file bytes into display lines, lossily decoding non-UTF8 bytes (the font
/// renders only a printable subset anyway). Tabs become two spaces; carriage
/// returns are dropped so `\r\n` newlines don't leave a stray glyph.
fn split_lines(bytes: &[u8]) -> Vec<String> {
    let text = core::str::from_utf8(bytes).unwrap_or("<binary>");
    let mut lines = Vec::new();
    for raw in text.split('\n') {
        let mut line = String::new();
        for c in raw.chars() {
            match c {
                '\r' => {}
                '\t' => line.push_str("  "),
                other => line.push(other),
            }
        }
        lines.push(line);
    }
    // A trailing newline yields a final empty element; drop it so the viewer
    // doesn't show a blank trailing row.
    if lines.last().map(String::is_empty).unwrap_or(false) {
        lines.pop();
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh browser lists the seeded root (`/home` dir + `/readme.txt`), with
    /// the directory sorted ahead of the file.
    #[test]
    fn new_lists_seeded_root_dirs_first() {
        let files = Files::new();
        assert_eq!(files.fs.cwd(), "/");
        // Seeded root has `readme.txt` (file) and `home` (dir); dirs come first.
        assert_eq!(files.entries.len(), 2);
        assert!(files.entries[0].is_dir);
        assert_eq!(files.entries[0].name, "home");
        assert!(!files.entries[1].is_dir);
        assert_eq!(files.entries[1].name, "readme.txt");
        assert_eq!(files.selected, 0);
    }

    /// Down/Up move (and wrap) the selection cursor.
    #[test]
    fn cursor_moves_and_wraps() {
        let mut files = Files::new();
        assert_eq!(files.selected, 0);
        assert!(files.on_key(KeyEvent::DownArrowPressed));
        assert_eq!(files.selected, 1);
        // Wrap past the end back to 0.
        assert!(files.on_key(KeyEvent::DownArrowPressed));
        assert_eq!(files.selected, 0);
        // Up from 0 wraps to the last entry.
        assert!(files.on_key(KeyEvent::UpArrowPressed));
        assert_eq!(files.selected, 1);
    }

    /// Enter on a directory descends into it; Backspace walks back up.
    #[test]
    fn enter_descends_dir_and_backspace_goes_up() {
        let mut files = Files::new();
        // Selection 0 is the `home` directory; Enter descends.
        assert!(files.on_key(KeyEvent::EnterPressed));
        assert_eq!(files.fs.cwd(), "/home");
        // /home holds notes.txt (a file).
        assert_eq!(files.entries.len(), 1);
        assert_eq!(files.entries[0].name, "notes.txt");
        assert!(!files.entries[0].is_dir);
        // Backspace walks back to root.
        assert!(files.on_key(KeyEvent::Backspace));
        assert_eq!(files.fs.cwd(), "/");
    }

    /// Backspace at the root is a no-op (reports no change).
    #[test]
    fn backspace_at_root_is_noop() {
        let mut files = Files::new();
        assert_eq!(files.fs.cwd(), "/");
        assert!(!files.on_key(KeyEvent::Backspace));
        assert_eq!(files.fs.cwd(), "/");
    }

    /// Enter on a file opens the viewer; Backspace returns to the listing.
    #[test]
    fn enter_file_opens_viewer_then_back() {
        let mut files = Files::new();
        // Move to readme.txt (index 1) and open it.
        assert!(files.on_key(KeyEvent::DownArrowPressed));
        assert!(files.on_key(KeyEvent::EnterPressed));
        match &files.view {
            View::Viewing { name, lines } => {
                assert_eq!(name, "readme.txt");
                assert!(!lines.is_empty());
                assert!(lines[0].contains("Welcome to SentinelOS"));
            }
            View::Listing => panic!("expected the viewer"),
        }
        // Backspace returns to the listing.
        assert!(files.on_key(KeyEvent::Backspace));
        assert!(matches!(files.view, View::Listing));
    }

    /// `split_lines` decodes text, expands tabs, drops `\r`, and trims a trailing
    /// blank line.
    #[test]
    fn split_lines_handles_newlines_tabs_and_cr() {
        let lines = split_lines(b"a\tb\r\nc\n");
        assert_eq!(lines, ["a  b", "c"]);
    }
}
