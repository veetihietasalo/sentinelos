//! The SentinelOS interactive **shell** — the safe text state model behind the
//! desktop console.
//!
//! This module owns the terminal's *content* (scrollback history and the current
//! input line) on the kernel heap, turns decoded [`crate::input::KeyEvent`]s into
//! edits, runs a handful of built-in commands, and renders the whole thing
//! through [`ui::draw_console`]. It carries the crate's `#![forbid(unsafe_code)]`
//! and does all its work in safe Rust over `alloc` (`String`/`Vec`).
//!
//! # Why no `core::fmt`
//!
//! On this higher-half bare-metal target, `core::fmt`'s integer formatting path
//! faults (it needs `.got`/`.rela` relocations the linker script discards — see
//! `hal::serial`'s `fmt`-free helpers and `memory::init_and_prove`). So the shell
//! never uses `write!`/`format!`; numbers are rendered with the small
//! [`push_dec`] helper that appends ASCII digits to a `String` by hand.
//!
//! # State model
//!
//! A [`Shell`] holds:
//! * `scrollback: Vec<String>` — committed lines, oldest first, capped to
//!   [`SCROLLBACK_CAP`] (the oldest are dropped when it overflows).
//! * `input: String` — the line currently being typed (no prompt).
//! * `dirty: bool` — set whenever the displayed content changed, so the idle
//!   loop can redraw only when needed.
//!
//! The cursor *blink* is **not** owned here: like the lock screen, visibility is
//! derived from `hal::pit::ticks()` at render time and passed into
//! [`ui::draw_console`], so the shell owns no timer state.

use alloc::string::String;
use alloc::vec::Vec;

use ui::CursorStyle;

use crate::input::KeyEvent;

/// The prompt drawn before the input line (Cyber Dusk pink in the console).
const PROMPT: &str = "> ";

/// Maximum number of scrollback lines kept on the heap. Older lines are dropped
/// once this is exceeded — generous enough to scroll back through a session, but
/// bounded so a long-running console can never grow without limit.
const SCROLLBACK_CAP: usize = 256;

/// Append the base-10 ASCII digits of `value` to `out`, with no `core::fmt`
/// (which faults on this target). Zero renders as `"0"`.
///
/// Builds the digits into a small fixed stack buffer (a `u64` is at most 20
/// decimal digits) least-significant-first, then pushes them in order.
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
    // `buf[i..]` is all ASCII digits, so this is valid UTF-8.
    for &b in &buf[i..] {
        out.push(b as char);
    }
}

/// The interactive shell: terminal content plus the command interpreter.
///
/// Constructed with [`Shell::new`] (which seeds a friendly banner), fed decoded
/// key events with [`Shell::on_key`], and rendered with [`Shell::render`]. All
/// state lives on the kernel heap; the struct itself is just three owned fields.
pub struct Shell {
    /// Committed history lines, oldest first, capped to [`SCROLLBACK_CAP`].
    scrollback: Vec<String>,
    /// The line currently being typed (without the prompt).
    input: String,
    /// `true` when the visible content changed since the last render — lets the
    /// idle loop skip redraws when nothing happened.
    dirty: bool,
}

impl Shell {
    /// Create a fresh shell, seeded with a short welcome banner.
    ///
    /// Allocates on the kernel heap, so it must be called after `memory::init`
    /// has installed the global allocator.
    #[must_use]
    pub fn new() -> Self {
        let mut shell = Self {
            scrollback: Vec::new(),
            input: String::new(),
            dirty: true,
        };
        shell.push_line(String::from("SentinelOS shell - type 'help'"));
        shell.push_line(String::from("private · secure · yours"));
        shell
    }

    /// `true` while the visible content has changed since the last [`render`]
    /// (or since construction). The idle loop reads this to decide whether a
    /// content redraw is needed; [`render`] clears it.
    ///
    /// [`render`]: Self::render
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Push one committed line into the scrollback, dropping the oldest if the
    /// buffer is at [`SCROLLBACK_CAP`]. Marks the shell dirty.
    fn push_line(&mut self, line: String) {
        if self.scrollback.len() >= SCROLLBACK_CAP {
            // Drop the oldest line to stay within the cap.
            self.scrollback.remove(0);
        }
        self.scrollback.push(line);
        self.dirty = true;
    }

    /// Feed one decoded [`KeyEvent`] to the shell.
    ///
    /// * [`KeyEvent::Char`] appends the character to the input line.
    /// * [`KeyEvent::Backspace`] pops the last input character (no-op when empty).
    /// * [`KeyEvent::EnterPressed`] commits `prompt + input` to history, executes
    ///   the line, appends any output, and clears the input.
    /// * Other events ([`KeyEvent::Tab`], [`KeyEvent::Escape`], the arrow events)
    ///   are ignored by the shell for now.
    ///
    /// Any event that changes the visible content sets the dirty flag.
    pub fn on_key(&mut self, event: KeyEvent) {
        match event {
            KeyEvent::Char(c) => {
                self.input.push(c);
                self.dirty = true;
            }
            KeyEvent::Backspace => {
                if self.input.pop().is_some() {
                    self.dirty = true;
                }
            }
            KeyEvent::EnterPressed => {
                self.submit();
            }
            // Not yet bound in the shell — ignored.
            KeyEvent::Tab
            | KeyEvent::Escape
            | KeyEvent::RightArrowPressed
            | KeyEvent::RightArrowReleased => {}
        }
    }

    /// Commit the current input line: echo it as history (`prompt + input`),
    /// execute it, append the command's output line(s), and clear the input.
    fn submit(&mut self) {
        // Echo the typed line into history, prompt included.
        let mut echo = String::from(PROMPT);
        echo.push_str(&self.input);
        self.push_line(echo);

        // Take the input out so we can borrow `self` mutably while executing.
        let line = core::mem::take(&mut self.input);
        self.execute(&line);

        // Input was cleared by `take`; ensure the cursor/input redraws.
        self.dirty = true;
    }

    /// Parse and run one command line, pushing its output into the scrollback.
    ///
    /// The command is the first whitespace-delimited word; the remainder (after
    /// one space) is the argument string. An empty line is a no-op (just the
    /// fresh prompt, like a real shell).
    fn execute(&mut self, line: &str) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return;
        }

        // Split into the command word and the rest (the argument tail).
        let (cmd, rest) = match trimmed.split_once(char::is_whitespace) {
            Some((c, r)) => (c, r.trim_start()),
            None => (trimmed, ""),
        };

        match cmd {
            "help" => self.cmd_help(),
            "clear" => self.cmd_clear(),
            "about" => self.cmd_about(),
            "mem" => self.cmd_mem(),
            "echo" => self.push_line(String::from(rest)),
            "uptime" => self.cmd_uptime(),
            other => {
                let mut msg = String::from("command not found: ");
                msg.push_str(other);
                self.push_line(msg);
            }
        }
    }

    /// `help` — list the built-in commands.
    fn cmd_help(&mut self) {
        self.push_line(String::from("commands:"));
        self.push_line(String::from("  help    - show this list"));
        self.push_line(String::from("  clear   - clear the screen"));
        self.push_line(String::from("  about   - about SentinelOS"));
        self.push_line(String::from("  mem     - heap + frame stats"));
        self.push_line(String::from("  echo X  - print X"));
        self.push_line(String::from("  uptime  - seconds since boot"));
    }

    /// `clear` — wipe the scrollback to an empty screen.
    fn cmd_clear(&mut self) {
        self.scrollback.clear();
        self.dirty = true;
    }

    /// `about` — name, one-line description, and the crate version.
    fn cmd_about(&mut self) {
        self.push_line(String::from("SentinelOS"));
        self.push_line(String::from("a private OS built from scratch in Rust"));
        let mut ver = String::from("version ");
        ver.push_str(env!("CARGO_PKG_VERSION"));
        self.push_line(ver);
    }

    /// `mem` — live heap size and physical-frame usage from `hal::mm::stats`.
    fn cmd_mem(&mut self) {
        let stats = hal::mm::stats();

        // "heap: NNN KiB"
        let mut heap = String::from("heap: ");
        push_dec(&mut heap, (stats.heap_bytes / 1024) as u64);
        heap.push_str(" KiB");
        self.push_line(heap);

        // "frames: FREE / TOTAL free  (USED used)"
        let used = stats.total_frames.saturating_sub(stats.free_frames);
        let mut frames = String::from("frames: ");
        push_dec(&mut frames, stats.free_frames as u64);
        frames.push_str(" / ");
        push_dec(&mut frames, stats.total_frames as u64);
        frames.push_str(" free  (");
        push_dec(&mut frames, used as u64);
        frames.push_str(" used)");
        self.push_line(frames);

        // Each frame is 4 KiB, so report the free/total in MiB too for context.
        let free_mib = (stats.free_frames as u64) * 4 / 1024;
        let total_mib = (stats.total_frames as u64) * 4 / 1024;
        let mut ram = String::from("ram: ");
        push_dec(&mut ram, free_mib);
        ram.push_str(" / ");
        push_dec(&mut ram, total_mib);
        ram.push_str(" MiB free");
        self.push_line(ram);
    }

    /// `uptime` — whole seconds since boot, derived from the PIT tick counter.
    fn cmd_uptime(&mut self) {
        let secs = hal::pit::ticks() / hal::pit::TICK_HZ;
        let mut line = String::from("uptime: ");
        push_dec(&mut line, secs);
        line.push_str(" s");
        self.push_line(line);
    }

    /// Render the console to `fb`, with a solid (always-visible) block caret.
    ///
    /// Clears the dirty flag. [`ui::draw_console`] repaints the whole glass panel
    /// — an expensive per-pixel pass under software rendering — so the idle loop
    /// calls this only when the content actually changed (a keystroke or command
    /// output), never on a timer. A solid caret (rather than a blink) keeps that
    /// invariant: a blinking caret would force a full repaint several times a
    /// second and visibly flicker.
    ///
    /// Scrollback is handed to [`ui::draw_console`] as a borrowed `&[&str]`; the
    /// renderer itself clamps to the last rows that fit, so this passes the whole
    /// (capped) buffer and lets the panel show the newest lines.
    pub fn render(&mut self, fb: &hal::framebuffer::Framebuffer) {
        self.draw(fb, true);
        self.dirty = false;
    }

    /// Draw the console with an explicit cursor-visibility, building the borrowed
    /// `&[&str]` scrollback slice the renderer expects.
    fn draw(&self, fb: &hal::framebuffer::Framebuffer, cursor_visible: bool) {
        // Borrow each owned `String` as a `&str` for the renderer. Bounded by the
        // scrollback cap, so this small temporary `Vec` is cheap.
        let lines: Vec<&str> = self.scrollback.iter().map(String::as_str).collect();
        ui::draw_console(
            fb,
            &lines,
            PROMPT,
            &self.input,
            cursor_visible,
            CursorStyle::Block,
        );
    }
}

impl Default for Shell {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh shell carries the seeded banner and is dirty (needs a first draw).
    #[test]
    fn new_shell_has_banner_and_is_dirty() {
        let shell = Shell::new();
        assert!(shell.is_dirty());
        assert_eq!(shell.scrollback.len(), 2);
        assert!(shell.scrollback[0].contains("type 'help'"));
    }

    /// Typing characters accumulates into the input line and marks dirty.
    #[test]
    fn char_events_build_the_input_line() {
        let mut shell = Shell::new();
        for c in "echo hi".chars() {
            shell.on_key(KeyEvent::Char(c));
        }
        assert_eq!(shell.input, "echo hi");
        assert!(shell.is_dirty());
    }

    /// Backspace pops the last char; popping past empty is a harmless no-op.
    #[test]
    fn backspace_pops_last_char() {
        let mut shell = Shell::new();
        shell.on_key(KeyEvent::Char('a'));
        shell.on_key(KeyEvent::Char('b'));
        shell.on_key(KeyEvent::Backspace);
        assert_eq!(shell.input, "a");
        shell.on_key(KeyEvent::Backspace);
        shell.on_key(KeyEvent::Backspace); // past empty
        assert_eq!(shell.input, "");
    }

    /// Enter echoes `prompt + input` and clears the input line.
    #[test]
    fn enter_echoes_prompt_and_input_then_clears() {
        let mut shell = Shell::new();
        for c in "echo hello".chars() {
            shell.on_key(KeyEvent::Char(c));
        }
        shell.on_key(KeyEvent::EnterPressed);
        assert_eq!(shell.input, "");
        // The echoed command line and the echo output are now in scrollback.
        let last = shell.scrollback.last().unwrap();
        assert_eq!(last, "hello");
        let echoed = &shell.scrollback[shell.scrollback.len() - 2];
        assert_eq!(echoed, "> echo hello");
    }

    /// `echo` prints its argument tail verbatim (after one separating space).
    #[test]
    fn echo_prints_args() {
        let mut shell = Shell::new();
        shell.execute("echo  spaced   out");
        // `split_once` on the first whitespace, then `trim_start` of the rest.
        assert_eq!(shell.scrollback.last().unwrap(), "spaced   out");
    }

    /// `echo` with no argument prints an empty line.
    #[test]
    fn echo_with_no_args_prints_empty() {
        let mut shell = Shell::new();
        shell.execute("echo");
        assert_eq!(shell.scrollback.last().unwrap(), "");
    }

    /// An unknown command reports `command not found: <cmd>`.
    #[test]
    fn unknown_command_is_reported() {
        let mut shell = Shell::new();
        shell.execute("frobnicate now");
        assert_eq!(
            shell.scrollback.last().unwrap(),
            "command not found: frobnicate"
        );
    }

    /// `clear` empties the scrollback entirely.
    #[test]
    fn clear_empties_scrollback() {
        let mut shell = Shell::new();
        shell.execute("clear");
        assert!(shell.scrollback.is_empty());
    }

    /// `help` lists every built-in command name.
    #[test]
    fn help_lists_all_commands() {
        let mut shell = Shell::new();
        shell.execute("help");
        let body = shell.scrollback.join("\n");
        for name in ["help", "clear", "about", "mem", "echo", "uptime"] {
            assert!(body.contains(name), "help should mention `{name}`");
        }
    }

    /// `about` includes the name and the compile-time crate version.
    #[test]
    fn about_includes_name_and_version() {
        let mut shell = Shell::new();
        shell.execute("about");
        let body = shell.scrollback.join("\n");
        assert!(body.contains("SentinelOS"));
        assert!(body.contains(env!("CARGO_PKG_VERSION")));
    }

    /// An empty / whitespace-only line is a no-op beyond its echoed prompt.
    #[test]
    fn empty_line_is_a_noop() {
        let mut shell = Shell::new();
        let before = shell.scrollback.len();
        shell.execute("   ");
        assert_eq!(shell.scrollback.len(), before);
    }

    /// Scrollback never grows past the cap; the oldest lines are dropped.
    #[test]
    fn scrollback_is_capped() {
        let mut shell = Shell::new();
        for i in 0..(SCROLLBACK_CAP + 50) {
            let mut s = String::from("line ");
            push_dec(&mut s, i as u64);
            shell.push_line(s);
        }
        assert_eq!(shell.scrollback.len(), SCROLLBACK_CAP);
        // The very first banner line must have been evicted.
        assert!(!shell.scrollback[0].contains("type 'help'"));
    }

    /// `push_dec` renders integers without `core::fmt`.
    #[test]
    fn push_dec_renders_integers() {
        let mut s = String::new();
        push_dec(&mut s, 0);
        push_dec(&mut s, 1);
        push_dec(&mut s, 4096);
        assert_eq!(s, "014096");
    }
}
