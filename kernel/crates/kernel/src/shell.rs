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

use ui::{CursorStyle, Rect};

use crate::fs::FileSystem;
use crate::input::KeyEvent;

/// The prompt drawn before the input line (Cyber Dusk pink in the console).
const PROMPT: &str = "> ";

/// Maximum number of scrollback lines kept on the heap. Older lines are dropped
/// once this is exceeded — generous enough to scroll back through a session, but
/// bounded so a long-running console can never grow without limit.
const SCROLLBACK_CAP: usize = 256;

/// Maximum number of submitted command lines remembered for Up/Down recall.
/// Like [`SCROLLBACK_CAP`], oldest entries are dropped once this is exceeded.
const HISTORY_CAP: usize = 128;

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

/// Append `value` as exactly `width` lowercase hex digits (zero-padded), with no
/// `core::fmt` (which faults on this target — see [`push_dec`]). Used for PCI
/// `vendor:device` ids and class bytes in the `devices` command.
///
/// `width` is clamped to 16 (a `u64` is at most 16 hex digits); a `width` of 0
/// still emits at least the significant digits of a non-zero value.
fn push_hex(out: &mut String, value: u64, width: usize) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let width = width.min(16);
    let mut buf = [0u8; 16];
    // Fill least-significant-first.
    let mut n = value;
    let mut produced = 0;
    while produced < buf.len() && (n > 0 || produced < width) {
        buf[produced] = DIGITS[(n & 0xF) as usize];
        n >>= 4;
        produced += 1;
    }
    if produced == 0 {
        // value == 0 and width == 0: still emit a single '0'.
        out.push('0');
        return;
    }
    // Emit most-significant-first; every byte is an ASCII hex digit ⇒ valid UTF-8.
    for i in (0..produced).rev() {
        out.push(buf[i] as char);
    }
}

/// The interactive shell: terminal content plus the command interpreter.
///
/// Constructed with [`Shell::new`] (which seeds a friendly banner and an
/// in-memory filesystem), fed decoded key events with [`Shell::on_key`], and
/// rendered with [`Shell::render`]. All state lives on the kernel heap.
///
/// # Command history
///
/// Each submitted (non-empty) line is appended to `history`. The Up/Down arrows
/// walk a cursor (`history_pos`) through it the classic way: Up moves toward
/// older entries, Down toward newer ones, and stepping past the newest restores
/// an empty input line. The recalled text replaces the current input.
pub struct Shell {
    /// Committed history lines, oldest first, capped to [`SCROLLBACK_CAP`].
    scrollback: Vec<String>,
    /// The line currently being typed (without the prompt).
    input: String,
    /// `true` when the visible content changed since the last render — lets the
    /// idle loop skip redraws when nothing happened.
    dirty: bool,
    /// Submitted command lines, oldest first, capped to [`HISTORY_CAP`]. Drives
    /// Up/Down recall.
    history: Vec<String>,
    /// Cursor into `history` for Up/Down recall. `Some(i)` means the input line
    /// is currently showing `history[i]`; `None` means "at the live, un-recalled
    /// input" (so the next Up recalls the newest entry).
    history_pos: Option<usize>,
    /// The in-memory filesystem the `ls`/`cat`/`mkdir`/… commands operate on.
    fs: FileSystem,
}

impl Shell {
    /// Create a fresh shell, seeded with a short welcome banner and a starter
    /// in-memory filesystem (`/readme.txt`, `/home`).
    ///
    /// Allocates on the kernel heap, so it must be called after `memory::init`
    /// has installed the global allocator.
    #[must_use]
    pub fn new() -> Self {
        let mut shell = Self {
            scrollback: Vec::new(),
            input: String::new(),
            dirty: true,
            history: Vec::new(),
            history_pos: None,
            fs: FileSystem::seeded(),
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
    /// * [`KeyEvent::UpArrowPressed`] / [`KeyEvent::DownArrowPressed`] walk the
    ///   command history into the input line (classic shell recall).
    /// * Other events ([`KeyEvent::Tab`], [`KeyEvent::Escape`], the right-arrow)
    ///   are ignored by the shell for now.
    ///
    /// Typing or editing the line abandons any active history recall, so the next
    /// Up starts again from the newest entry.
    ///
    /// Any event that changes the visible content sets the dirty flag.
    pub fn on_key(&mut self, event: KeyEvent) {
        match event {
            KeyEvent::Char(c) => {
                self.input.push(c);
                self.history_pos = None;
                self.dirty = true;
            }
            KeyEvent::Backspace => {
                if self.input.pop().is_some() {
                    self.history_pos = None;
                    self.dirty = true;
                }
            }
            KeyEvent::EnterPressed => {
                self.submit();
            }
            KeyEvent::UpArrowPressed => self.history_prev(),
            KeyEvent::DownArrowPressed => self.history_next(),
            // Not yet bound in the shell — ignored.
            KeyEvent::Tab
            | KeyEvent::Escape
            | KeyEvent::RightArrowPressed
            | KeyEvent::RightArrowReleased => {}
        }
    }

    /// Up arrow: recall the previous (older) command into the input line.
    ///
    /// From the live input the first Up jumps to the newest history entry; each
    /// further Up steps toward older entries and stops at the oldest. A no-op when
    /// the history is empty.
    fn history_prev(&mut self) {
        if self.history.is_empty() {
            return;
        }
        let next = match self.history_pos {
            // At the live input → newest entry.
            None => self.history.len() - 1,
            // Already at the oldest → stay put.
            Some(0) => 0,
            // Step one older.
            Some(i) => i - 1,
        };
        self.history_pos = Some(next);
        self.input = self.history[next].clone();
        self.dirty = true;
    }

    /// Down arrow: recall the next (newer) command into the input line.
    ///
    /// Stepping past the newest entry restores an empty input line (back to the
    /// live, un-recalled state). A no-op when no recall is active.
    fn history_next(&mut self) {
        let Some(i) = self.history_pos else {
            return;
        };
        if i + 1 < self.history.len() {
            self.history_pos = Some(i + 1);
            self.input = self.history[i + 1].clone();
        } else {
            // Past the newest entry → back to a fresh, empty input line.
            self.history_pos = None;
            self.input.clear();
        }
        self.dirty = true;
    }

    /// Commit the current input line: echo it as scrollback (`prompt + input`),
    /// remember it for Up/Down recall, execute it, append the command's output
    /// line(s), and clear the input.
    fn submit(&mut self) {
        // Echo the typed line into the scrollback, prompt included.
        let mut echo = String::from(PROMPT);
        echo.push_str(&self.input);
        self.push_line(echo);

        // Take the input out so we can borrow `self` mutably while executing.
        let line = core::mem::take(&mut self.input);
        self.record_history(&line);
        self.execute(&line);

        // Any recall is finished; the next Up starts from the newest entry again.
        self.history_pos = None;
        // Input was cleared by `take`; ensure the cursor/input redraws.
        self.dirty = true;
    }

    /// Append a submitted line to the command history (oldest first), capped to
    /// [`HISTORY_CAP`]. Blank lines and an exact repeat of the most recent entry
    /// are skipped, matching common shell behaviour.
    fn record_history(&mut self, line: &str) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return;
        }
        if self.history.last().map(String::as_str) == Some(trimmed) {
            return;
        }
        if self.history.len() >= HISTORY_CAP {
            self.history.remove(0);
        }
        self.history.push(String::from(trimmed));
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

        // AUDIT (spec §9.2): one emit at the top of `execute` uniformly records
        // every command as a `Principal::Shell / Action::Command` event
        // (`target = cmd`, `summary = rest`). The audit `append` is best-effort and
        // can never fail the command it records.
        crate::security::audit::append(
            crate::security::audit::Principal::Shell,
            crate::security::audit::Action::Command,
            cmd,
            rest,
        );

        match cmd {
            "help" => self.cmd_help(),
            "audit" => self.cmd_audit(rest),
            "clear" => self.cmd_clear(),
            "about" => self.cmd_about(),
            "mem" => self.cmd_mem(),
            "cpuinfo" => self.cmd_cpuinfo(),
            "devices" => self.cmd_devices(),
            "echo" => self.push_line(String::from(rest)),
            "uptime" => self.cmd_uptime(),
            "ls" => self.cmd_ls(rest),
            "cat" => self.cmd_cat(rest),
            "mkdir" => self.cmd_mkdir(rest),
            "write" => self.cmd_write(rest),
            "rm" => self.cmd_rm(rest),
            "cd" => self.cmd_cd(rest),
            "pwd" => self.cmd_pwd(),
            other => {
                let mut msg = String::from("command not found: ");
                msg.push_str(other);
                self.push_line(msg);
            }
        }
    }

    /// Push an `<command>: <path> - <message>` error line for a failed fs op.
    fn push_fs_error(&mut self, cmd: &str, path: &str, err: crate::fs::FsError) {
        let mut msg = String::from(cmd);
        msg.push_str(": ");
        msg.push_str(path);
        msg.push_str(" - ");
        msg.push_str(err.message());
        self.push_line(msg);
    }

    /// `help` — list the built-in commands.
    fn cmd_help(&mut self) {
        self.push_line(String::from("commands:"));
        self.push_line(String::from("  help          - show this list"));
        self.push_line(String::from("  clear         - clear the screen"));
        self.push_line(String::from("  about         - about SentinelOS"));
        self.push_line(String::from("  mem           - heap + frame stats"));
        self.push_line(String::from("  cpuinfo       - CPU vendor + features"));
        self.push_line(String::from("  devices       - fb, RAM, PCI list"));
        self.push_line(String::from("  echo X        - print X"));
        self.push_line(String::from("  uptime        - seconds since boot"));
        self.push_line(String::from("  ls [path]     - list a directory"));
        self.push_line(String::from("  cat <file>    - print a file"));
        self.push_line(String::from("  mkdir <dir>   - create a directory"));
        self.push_line(String::from("  write <f> X   - write X to file f"));
        self.push_line(String::from("  rm <path>     - remove a file/dir"));
        self.push_line(String::from("  cd <dir>      - change directory"));
        self.push_line(String::from("  pwd           - print working dir"));
        self.push_line(String::from(
            "  audit         - recent audit log + chain status",
        ));
        self.push_line(String::from(
            "  audit verify  - re-walk the tamper-evidence chain",
        ));
        self.push_line(String::from("history: Up/Down arrows recall commands"));
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

    /// `cpuinfo` — what the CPU reports about itself via `cpuid`.
    ///
    /// Prints the vendor id, the processor brand string (when the CPU exposes
    /// it), the decoded family/model/stepping, and the detected feature flags —
    /// all read live from the hardware through [`hal::cpuid::info`].
    fn cmd_cpuinfo(&mut self) {
        let info = hal::cpuid::info();

        // "vendor: GenuineIntel"
        let mut vendor = String::from("vendor: ");
        vendor.push_str(info.vendor.as_str());
        self.push_line(vendor);

        // "brand: <48-byte brand string>" — only if the CPU provided one.
        let brand = info.brand.as_str().trim();
        if !brand.is_empty() {
            let mut line = String::from("brand: ");
            line.push_str(brand);
            self.push_line(line);
        }

        // "family: NN  model: NN  stepping: NN" (decimal, like /proc/cpuinfo).
        let mut fms = String::from("family: ");
        push_dec(&mut fms, info.fms.family as u64);
        fms.push_str("  model: ");
        push_dec(&mut fms, info.fms.model as u64);
        fms.push_str("  stepping: ");
        push_dec(&mut fms, info.fms.stepping as u64);
        self.push_line(fms);

        // "features: sse sse2 ... avx2" — only the flags the CPU advertises,
        // space-separated, wrapped to a handful per line so a wide feature set
        // stays readable in the console.
        self.push_line(String::from("features:"));
        let mut line = String::from("  ");
        let mut on_line = 0;
        for feat in info.features() {
            if !feat.present {
                continue;
            }
            if on_line == 8 {
                self.push_line(core::mem::take(&mut line));
                line.push_str("  ");
                on_line = 0;
            }
            line.push_str(feat.name);
            line.push(' ');
            on_line += 1;
        }
        if on_line == 0 {
            // No flags at all (a very minimal CPU) — say so rather than a blank.
            line.push_str("(none reported)");
        }
        self.push_line(line);
    }

    /// `devices` — the hardware the OS actually detected.
    ///
    /// Reports the framebuffer resolution (via [`hal::framebuffer`]), the detected
    /// RAM and the fixed kernel heap (via [`hal::mm::stats`]), and the enumerated
    /// PCI device list (via [`hal::pci::list_devices`]). Together this answers
    /// "does the kernel know the machine's specs" for the non-CPU hardware.
    fn cmd_devices(&mut self) {
        // Framebuffer resolution + colour depth.
        match hal::framebuffer::get() {
            Some(fb) => {
                // "framebuffer: WIDTHxHEIGHT @ BPP bpp"
                let mut line = String::from("framebuffer: ");
                push_dec(&mut line, fb.width() as u64);
                line.push('x');
                push_dec(&mut line, fb.height() as u64);
                line.push_str(" @ ");
                push_dec(&mut line, fb.bpp() as u64);
                line.push_str(" bpp");
                self.push_line(line);
            }
            None => self.push_line(String::from("framebuffer: none")),
        }

        // Detected RAM (from the frame allocator) vs the fixed heap window.
        let stats = hal::mm::stats();
        let total_mib = (stats.total_frames as u64) * 4 / 1024;
        let free_mib = (stats.free_frames as u64) * 4 / 1024;
        let mut ram = String::from("ram detected: ");
        push_dec(&mut ram, total_mib);
        ram.push_str(" MiB (");
        push_dec(&mut ram, free_mib);
        ram.push_str(" MiB free)");
        self.push_line(ram);

        let mut heap = String::from("heap (fixed): ");
        push_dec(&mut heap, (stats.heap_bytes / 1024) as u64);
        heap.push_str(" KiB");
        self.push_line(heap);

        // PCI device inventory. q35/QEMU keeps everything on bus 0–1.
        let list = hal::pci::list_devices(1);
        let mut header = String::from("pci devices: ");
        push_dec(&mut header, list.len() as u64);
        self.push_line(header);
        if list.is_empty() {
            self.push_line(String::from("  (none found)"));
            return;
        }
        for dev in list.as_slice() {
            // "  00:03.0 8086:100e  Intel e1000 (82540EM) NIC"
            let mut line = String::from("  ");
            push_hex(&mut line, dev.bus as u64, 2);
            line.push(':');
            push_hex(&mut line, dev.device as u64, 2);
            line.push('.');
            push_dec(&mut line, dev.function as u64);
            line.push(' ');
            push_hex(&mut line, dev.vendor as u64, 4);
            line.push(':');
            push_hex(&mut line, dev.dev_id as u64, 4);
            line.push_str("  ");
            if dev.name.is_empty() {
                // No friendly name: fall back to the raw class/subclass bytes.
                line.push_str("class ");
                push_hex(&mut line, dev.class as u64, 2);
                line.push('.');
                push_hex(&mut line, dev.subclass as u64, 2);
            } else {
                line.push_str(dev.name);
            }
            self.push_line(line);
        }
    }

    /// `uptime` — whole seconds since boot, derived from the PIT tick counter.
    fn cmd_uptime(&mut self) {
        let secs = hal::pit::ticks() / hal::pit::TICK_HZ;
        let mut line = String::from("uptime: ");
        push_dec(&mut line, secs);
        line.push_str(" s");
        self.push_line(line);
    }

    /// `ls [path]` — list a directory (the CWD when no path is given). Directories
    /// are suffixed with `/`. Output is one entry per line, or `(empty)` for an
    /// empty directory.
    fn cmd_ls(&mut self, arg: &str) {
        let path = if arg.is_empty() { "." } else { arg };
        match self.fs.list(path) {
            Ok(entries) => {
                if entries.is_empty() {
                    self.push_line(String::from("(empty)"));
                    return;
                }
                for entry in entries {
                    let mut line = entry.name;
                    if entry.is_dir {
                        line.push('/');
                    }
                    self.push_line(line);
                }
            }
            Err(err) => self.push_fs_error("ls", path, err),
        }
    }

    /// `cat <file>` — print a file's contents, line by line. Non-UTF-8 bytes are
    /// rendered with the Unicode replacement character so the renderer never sees
    /// invalid text.
    fn cmd_cat(&mut self, arg: &str) {
        if arg.is_empty() {
            self.push_line(String::from("cat: missing file"));
            return;
        }
        match self.fs.read_file(arg) {
            // Clone the bytes into an owned buffer so we drop the borrow on
            // `self.fs` before pushing into `self.scrollback`.
            Ok(bytes) => {
                let owned = bytes.to_vec();
                let text: String = String::from_utf8_lossy(&owned).into_owned();
                // Drop a single trailing newline so a file ending in '\n' doesn't
                // print an extra blank line (matches a normal `cat`), then print
                // each remaining line on its own scrollback row.
                let body = text.strip_suffix('\n').unwrap_or(&text);
                for line in body.split('\n') {
                    self.push_line(String::from(line));
                }
            }
            Err(err) => self.push_fs_error("cat", arg, err),
        }
    }

    /// `mkdir <dir>` — create a directory. Reports the typed error on failure.
    fn cmd_mkdir(&mut self, arg: &str) {
        if arg.is_empty() {
            self.push_line(String::from("mkdir: missing directory name"));
            return;
        }
        match self.fs.mkdir(arg) {
            Ok(()) => audit_fs(crate::security::audit::Action::FsCreate, arg, "mkdir"),
            Err(err) => self.push_fs_error("mkdir", arg, err),
        }
    }

    /// `write <file> <text...>` — create/overwrite `<file>` with the rest of the
    /// line as its (newline-terminated) content.
    fn cmd_write(&mut self, arg: &str) {
        let (path, text) = match arg.split_once(char::is_whitespace) {
            Some((p, t)) => (p, t),
            None => (arg, ""),
        };
        if path.is_empty() {
            self.push_line(String::from("write: usage: write <file> <text>"));
            return;
        }
        // Store the text with a trailing newline so `cat` round-trips cleanly.
        let mut content = String::from(text);
        content.push('\n');
        match self.fs.write_file(path, content.as_bytes()) {
            Ok(()) => {
                // Summarise the size written without core::fmt (which faults here).
                let mut summary = String::new();
                push_dec(&mut summary, content.len() as u64);
                summary.push_str(" bytes");
                audit_fs(crate::security::audit::Action::FsWrite, path, &summary);
            }
            Err(err) => self.push_fs_error("write", path, err),
        }
    }

    /// `rm <path>` — remove a file or directory (recursively).
    fn cmd_rm(&mut self, arg: &str) {
        if arg.is_empty() {
            self.push_line(String::from("rm: missing path"));
            return;
        }
        match self.fs.remove(arg) {
            Ok(()) => audit_fs(crate::security::audit::Action::FsRemove, arg, "rm"),
            Err(err) => self.push_fs_error("rm", arg, err),
        }
    }

    /// `cd <dir>` — change the working directory (the root `/` with no argument).
    fn cmd_cd(&mut self, arg: &str) {
        let path = if arg.is_empty() { "/" } else { arg };
        if let Err(err) = self.fs.change_dir(path) {
            self.push_fs_error("cd", path, err);
        }
    }

    /// `pwd` — print the current working directory.
    fn cmd_pwd(&mut self) {
        let cwd = self.fs.cwd();
        self.push_line(cwd);
    }

    /// `audit` / `audit verify` — view the kernel-native audit log.
    ///
    /// * `audit` lists the most recent records (newest-first), one per line:
    ///   `#<seq> t<tick> <principal>/<action> <target> - <summary>`, and reports
    ///   the chain-verification status as a footer.
    /// * `audit verify` re-walks the tamper-evidence chain and prints `Ok` or the
    ///   `seq` where it broke.
    ///
    /// Read-only: it acquires the global log lock for the duration of the read and
    /// never hands out a mutable record (append-only is preserved).
    fn cmd_audit(&mut self, arg: &str) {
        use crate::security::audit;

        // Build the output under the lock, then print it (push_line borrows self
        // mutably, so we collect lines first to avoid overlapping borrows).
        let verify_only = arg.trim() == "verify";
        let mut lines: Vec<String> = Vec::new();

        audit::with_log(|log| {
            let verify = log.verify_chain();

            if verify_only {
                match verify {
                    Ok(()) => lines.push(String::from("audit: chain verified OK")),
                    Err(e) => {
                        let mut msg = String::from("audit: chain BROKEN at seq ");
                        push_dec(&mut msg, e.at_seq);
                        lines.push(msg);
                    }
                }
                return;
            }

            // Header: record count.
            let mut header = String::from("audit log: ");
            push_dec(&mut header, log.len() as u64);
            header.push_str(" records (newest first)");
            lines.push(header);

            // Up to the most-recent AUDIT_VIEW_LIMIT records, newest-first.
            for record in log.iter_rev().take(AUDIT_VIEW_LIMIT) {
                let mut line = String::from("#");
                push_dec(&mut line, record.seq);
                line.push_str(" t");
                push_dec(&mut line, record.tick);
                line.push(' ');
                line.push_str(principal_name(record.principal));
                line.push('/');
                line.push_str(action_name(record.action));
                line.push(' ');
                line.push_str(record.target.as_str());
                let summary = record.summary.as_str();
                if !summary.is_empty() {
                    line.push_str(" - ");
                    line.push_str(summary);
                }
                lines.push(line);
            }

            // Footer: chain status.
            match verify {
                Ok(()) => lines.push(String::from("chain: verified OK")),
                Err(e) => {
                    let mut msg = String::from("chain: BROKEN at seq ");
                    push_dec(&mut msg, e.at_seq);
                    lines.push(msg);
                }
            }
        });

        for line in lines {
            self.push_line(line);
        }
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

    /// Render the console text grid into an arbitrary window content rectangle
    /// `area`, with an explicit cursor visibility (so the WM can blink the caret
    /// off the PIT). This is the **windowed** render path used by the `Terminal`
    /// app: it draws *only* the console text (scrollback + input + cursor) into
    /// `area` through [`ui::draw_console_in`] — the surrounding glass chrome is
    /// drawn by the window manager via `ui::draw_window_chrome`, not here.
    ///
    /// Takes `&self` (it builds a small temporary borrowed `&[&str]` slice and
    /// draws from it) so it can be called from `App::render`. It does **not**
    /// touch the dirty flag; the WM owns damage bookkeeping and clears the flag
    /// via [`Shell::clear_dirty`] once the frame is composited.
    pub fn render_in(&self, fb: &hal::framebuffer::Framebuffer, area: Rect, cursor_visible: bool) {
        let lines: Vec<&str> = self.scrollback.iter().map(String::as_str).collect();
        ui::draw_console_in(
            fb,
            area,
            &lines,
            PROMPT,
            &self.input,
            cursor_visible,
            CursorStyle::Block,
        );
    }

    /// Clear the dirty flag after the WM has composited this shell's content.
    ///
    /// The windowed render path ([`render_in`](Self::render_in)) is `&self` and
    /// therefore cannot clear `dirty` itself; the WM calls this once it has
    /// repainted the window so the next idle tick won't redundantly re-composite.
    pub fn clear_dirty(&mut self) {
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

/// Maximum number of recent records the `audit` command lists, so a long log
/// never floods the console; `audit` shows the newest [`AUDIT_VIEW_LIMIT`].
const AUDIT_VIEW_LIMIT: usize = 16;

/// Emit a filesystem-mutation audit record for a shell-driven `fs` op.
///
/// Spec §9.3 resolution: for the seed we emit at the *shell* wrapper, but stamp
/// the principal as
/// [`Principal::FileSystem`](crate::security::audit::Principal::FileSystem) — the
/// filesystem is the actor that performed the mutation, so attributing the record
/// to it is the defensible choice (clean layering is preserved because `fs.rs`
/// stays unaware of `security`). When a non-shell caller (an agent/process)
/// appears, the emit moves into `fs.rs` with the principal passed *in* by the
/// caller, never assumed. Called only on a successful mutation.
///
/// Note: a successful fs shell command therefore intentionally emits **two**
/// records — a `Shell`/`Command` record from `execute` (which logs every command
/// uniformly) plus this `FileSystem`/`Fs*` record describing the mutation it
/// produced. They share the same boot and chain, distinguished by principal.
fn audit_fs(action: crate::security::audit::Action, target: &str, summary: &str) {
    crate::security::audit::append(
        crate::security::audit::Principal::FileSystem,
        action,
        target,
        summary,
    );
}

/// Short display name for a [`Principal`](crate::security::audit::Principal) in
/// the `audit` listing (no `core::fmt`).
fn principal_name(p: crate::security::audit::Principal) -> &'static str {
    use crate::security::audit::Principal;
    match p {
        Principal::Kernel => "kernel",
        Principal::Shell => "shell",
        Principal::FileSystem => "fs",
        Principal::WindowManager => "wm",
    }
}

/// Short display name for an [`Action`](crate::security::audit::Action) in the
/// `audit` listing (no `core::fmt`).
fn action_name(a: crate::security::audit::Action) -> &'static str {
    use crate::security::audit::Action;
    match a {
        Action::Boot => "boot",
        Action::Command => "cmd",
        Action::FsCreate => "create",
        Action::FsWrite => "write",
        Action::FsRemove => "remove",
        Action::AppSpawn => "spawn",
        Action::AppClose => "close",
        Action::SecurityEvent => "security",
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
        for name in [
            "help", "clear", "about", "mem", "cpuinfo", "devices", "echo", "uptime", "ls", "cat",
            "mkdir", "write", "rm", "cd", "pwd",
        ] {
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

    // --- Command history ------------------------------------------------------

    /// Submitting a command records it for Up/Down recall; Up recalls it.
    #[test]
    fn up_arrow_recalls_last_command() {
        let mut shell = Shell::new();
        type_line(&mut shell, "echo one");
        // Input is clear after submit; Up brings back the last command.
        assert_eq!(shell.input, "");
        shell.on_key(KeyEvent::UpArrowPressed);
        assert_eq!(shell.input, "echo one");
    }

    /// Up walks toward older entries; Down walks back toward newer ones, and
    /// stepping past the newest restores an empty line.
    #[test]
    fn up_down_walk_history_both_ways() {
        let mut shell = Shell::new();
        type_line(&mut shell, "first");
        type_line(&mut shell, "second");
        type_line(&mut shell, "third");

        // Up: newest → oldest.
        shell.on_key(KeyEvent::UpArrowPressed);
        assert_eq!(shell.input, "third");
        shell.on_key(KeyEvent::UpArrowPressed);
        assert_eq!(shell.input, "second");
        shell.on_key(KeyEvent::UpArrowPressed);
        assert_eq!(shell.input, "first");
        // Stops at the oldest entry.
        shell.on_key(KeyEvent::UpArrowPressed);
        assert_eq!(shell.input, "first");

        // Down: oldest → newest, then past the newest → empty.
        shell.on_key(KeyEvent::DownArrowPressed);
        assert_eq!(shell.input, "second");
        shell.on_key(KeyEvent::DownArrowPressed);
        assert_eq!(shell.input, "third");
        shell.on_key(KeyEvent::DownArrowPressed);
        assert_eq!(shell.input, "");
    }

    /// Down with no active recall is a no-op (stays at the live, empty input).
    #[test]
    fn down_arrow_without_recall_is_noop() {
        let mut shell = Shell::new();
        type_line(&mut shell, "x");
        shell.on_key(KeyEvent::DownArrowPressed);
        assert_eq!(shell.input, "");
    }

    /// Up arrow on an empty history does nothing.
    #[test]
    fn up_arrow_with_empty_history_is_noop() {
        let mut shell = Shell::new();
        shell.on_key(KeyEvent::UpArrowPressed);
        assert_eq!(shell.input, "");
    }

    /// Typing after a recall abandons it: the next Up restarts from the newest.
    #[test]
    fn typing_abandons_active_recall() {
        let mut shell = Shell::new();
        type_line(&mut shell, "alpha");
        type_line(&mut shell, "beta");
        shell.on_key(KeyEvent::UpArrowPressed); // "beta"
        shell.on_key(KeyEvent::Char('!')); // now "beta!", recall cleared
        assert_eq!(shell.input, "beta!");
        shell.on_key(KeyEvent::UpArrowPressed); // restarts from newest
        assert_eq!(shell.input, "beta");
    }

    /// Consecutive duplicate commands are stored once.
    #[test]
    fn duplicate_consecutive_commands_collapse() {
        let mut shell = Shell::new();
        type_line(&mut shell, "same");
        type_line(&mut shell, "same");
        assert_eq!(shell.history.len(), 1);
    }

    /// History never grows past its cap.
    #[test]
    fn history_is_capped() {
        let mut shell = Shell::new();
        for i in 0..(HISTORY_CAP + 20) {
            let mut s = String::from("cmd");
            push_dec(&mut s, i as u64);
            shell.record_history(&s);
        }
        assert_eq!(shell.history.len(), HISTORY_CAP);
        // The oldest entry was evicted.
        assert_eq!(shell.history[0], "cmd20");
    }

    // --- Filesystem commands --------------------------------------------------

    /// `ls` on the seeded root shows the welcome file and the home directory
    /// (directories suffixed with `/`).
    #[test]
    fn ls_shows_seeded_tree() {
        let mut shell = Shell::new();
        shell.execute("ls");
        let body = shell.scrollback.join("\n");
        assert!(body.contains("readme.txt"));
        assert!(body.contains("home/"));
    }

    /// `cat readme.txt` prints the seeded welcome message.
    #[test]
    fn cat_prints_readme() {
        let mut shell = Shell::new();
        shell.execute("cat /readme.txt");
        let body = shell.scrollback.join("\n");
        assert!(body.contains("Welcome to SentinelOS"));
    }

    /// `cat` of a missing file reports a typed error.
    #[test]
    fn cat_missing_file_errors() {
        let mut shell = Shell::new();
        shell.execute("cat nope.txt");
        let last = shell.scrollback.last().unwrap();
        assert!(last.contains("cat: nope.txt"));
        assert!(last.contains("no such file"));
    }

    /// `mkdir` then `ls` shows the new directory.
    #[test]
    fn mkdir_then_ls_shows_dir() {
        let mut shell = Shell::new();
        shell.execute("mkdir foo");
        shell.execute("ls");
        assert!(shell.scrollback.join("\n").contains("foo/"));
    }

    /// `write` then `cat` round-trips the text (one trailing newline, no extra
    /// blank line printed).
    #[test]
    fn write_then_cat_roundtrips() {
        let mut shell = Shell::new();
        shell.execute("write note.txt hello world");
        let before = shell.scrollback.len();
        shell.execute("cat note.txt");
        // Exactly one new scrollback line: "hello world".
        assert_eq!(shell.scrollback.len(), before + 1);
        assert_eq!(shell.scrollback.last().unwrap(), "hello world");
    }

    /// `cd` + `pwd` track the working directory; relative `ls` resolves against it.
    #[test]
    fn cd_pwd_and_relative_ls() {
        let mut shell = Shell::new();
        shell.execute("cd home");
        shell.execute("pwd");
        assert_eq!(shell.scrollback.last().unwrap(), "/home");
        // The seeded /home holds notes.txt; a bare `ls` lists it.
        shell.execute("ls");
        assert!(shell.scrollback.join("\n").contains("notes.txt"));
    }

    /// `rm` removes a file so a later `cat` fails.
    #[test]
    fn rm_removes_file() {
        let mut shell = Shell::new();
        shell.execute("write doomed.txt bye");
        shell.execute("rm doomed.txt");
        shell.execute("cat doomed.txt");
        assert!(shell.scrollback.last().unwrap().contains("no such file"));
    }

    /// Drive a full command line through `on_key` (typing + Enter), like the real
    /// idle loop, so history is recorded the same way it is at runtime.
    fn type_line(shell: &mut Shell, line: &str) {
        for c in line.chars() {
            shell.on_key(KeyEvent::Char(c));
        }
        shell.on_key(KeyEvent::EnterPressed);
    }
}
