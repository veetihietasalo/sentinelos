//! The **Terminal** app — a thin [`App`] adapter wrapping the interactive
//! [`Shell`](crate::shell::Shell).
//!
//! The shell owns the terminal's text model (scrollback, input line, command
//! interpreter, history); this adapter makes it a window in the desktop. It:
//!
//! * renders the shell's content into the window's content rect via the windowed
//!   console renderer ([`Shell::render_in`] → `ui::draw_console_in`);
//! * forwards focused key events to [`Shell::on_key`] and reports whether the
//!   shell's content changed (its dirty flag), so the WM damages just this window.
//!
//! Following the original full-screen console's deliberate design (see
//! `shell.rs`), the caret is drawn **solid** (always visible), not blinking: a
//! blinking caret would force the WM to clear + repaint the whole window twice a
//! second under software rendering — visible flicker for no real gain. So this app
//! has no periodic [`App::tick`]; it only re-composites on a keystroke.
//!
//! The shell's text model, command set, and unit tests are entirely unchanged —
//! this is a pure adapter.

use ui::Rect;

use crate::input::KeyEvent;
use crate::shell::Shell;

use super::App;

/// The Terminal app: an interactive shell rendered into a desktop window.
pub struct Terminal {
    /// The wrapped shell — the entire text model and command interpreter.
    shell: Shell,
}

impl Terminal {
    /// Create a fresh Terminal wrapping a new [`Shell`] (with its welcome banner
    /// and seeded filesystem). Allocates on the kernel heap.
    #[must_use]
    pub fn new() -> Self {
        Self {
            shell: Shell::new(),
        }
    }
}

impl Default for Terminal {
    fn default() -> Self {
        Self::new()
    }
}

impl App for Terminal {
    fn title(&self) -> &str {
        "Terminal"
    }

    fn render(&self, fb: &hal::framebuffer::Framebuffer, area: Rect) {
        // Solid (always-visible) caret — no blink, so the window repaints only on
        // a content change, never on a timer (matching the console's design).
        self.shell.render_in(fb, area, true);
    }

    fn on_key(&mut self, event: KeyEvent) -> bool {
        self.shell.on_key(event);
        // The shell tracks its own dirtiness; clear it now that the WM has been
        // told to redraw, so the next idle tick doesn't re-composite needlessly.
        let dirtied = self.shell.is_dirty();
        if dirtied {
            self.shell.clear_dirty();
        }
        dirtied
    }

    // No `tick` override: the Terminal uses the default no-op (it self-updates
    // only on keystrokes, with a solid caret), so idle ticks stay cheap.
}
