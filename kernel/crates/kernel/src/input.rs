//! Keyboard scancode decoding (PS/2 scancode SET 1) + the lock-screen state
//! machine — the **safe** kernel side of the first interactive input.
//!
//! This module carries the crate's `#![forbid(unsafe_code)]`. The TCB
//! ([`hal::keyboard`]) drains raw scancode bytes from port `0x60` in the IRQ1
//! handler and pushes them into a lock-free ring; everything here — the `0xE0`
//! extended-prefix state machine, the make/break decoding, and the
//! `Locked → Unlocking → Desktop` transitions — is pure safe logic.
//!
//! # Scancode SET 1 (the only set we decode here)
//!
//! In SET 1 a key *press* (make) is a byte with bit 7 clear; the matching
//! *release* (break) is the same byte with bit 7 set (`+0x80`). "Extended" keys
//! (the arrow cluster, right-ctrl, etc.) are prefixed by a `0xE0` byte:
//!
//! - Right arrow **pressed**:  `0xE0` then `0x4D`.
//! - Right arrow **released**: `0xE0` then `0xCD` (`0x4D | 0x80`).
//!
//! We therefore track whether the previous byte was the `0xE0` prefix, so the
//! pair `0xE0,0x4D` is recognised as a single "right arrow pressed" event.

/// A decoded key event the kernel cares about.
///
/// The lock screen needs only the right arrow (plus Enter as a friendly
/// alternative); the upcoming shell needs full printable text plus the editing
/// keys. We therefore surface both: the original lock-screen variants are kept
/// verbatim so existing callers keep working, and printable keys arrive as a
/// single [`KeyEvent::Char`] already resolved through the US-QWERTY +
/// SHIFT mapping. Every scancode we do not map (most releases, modifier
/// make/break, unhandled keys) decodes to `None` and is ignored.
///
/// SHIFT make/break is consumed internally to maintain the decoder's
/// shift-pressed state and never surfaces as an event of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyEvent {
    /// The right-arrow key was pressed (`0xE0 0x4D`) — the unlock gesture.
    RightArrowPressed,
    /// The right-arrow key was released (`0xE0 0xCD`).
    RightArrowReleased,
    /// Enter / Return was pressed (`0x1C`) — also accepted as an unlock, and
    /// the shell's "submit line" key.
    EnterPressed,
    /// A printable character was typed, already resolved through US-QWERTY and
    /// the current SHIFT state (e.g. `a`/`A`, `2`/`@`, `/`/`?`, space).
    Char(char),
    /// Backspace was pressed (`0x0E`) — the shell erases the last character.
    Backspace,
    /// Tab was pressed (`0x0F`).
    Tab,
    /// Escape was pressed (`0x01`).
    Escape,
}

/// The `0xE0` extended-scancode prefix byte.
const EXT_PREFIX: u8 = 0xE0;
/// Make code for the right arrow (after the `0xE0` prefix).
const RIGHT_ARROW_MAKE: u8 = 0x4D;
/// Break code for the right arrow (after the `0xE0` prefix): make `| 0x80`.
const RIGHT_ARROW_BREAK: u8 = 0xCD;
/// Make code for Enter / Return (a non-extended key).
const ENTER_MAKE: u8 = 0x1C;
/// Make code for Backspace.
const BACKSPACE_MAKE: u8 = 0x0E;
/// Make code for Tab.
const TAB_MAKE: u8 = 0x0F;
/// Make code for Escape.
const ESCAPE_MAKE: u8 = 0x01;
/// Make code for the left SHIFT key.
const LSHIFT_MAKE: u8 = 0x2A;
/// Make code for the right SHIFT key.
const RSHIFT_MAKE: u8 = 0x36;
/// Break code for the left SHIFT key (`LSHIFT_MAKE | 0x80`).
const LSHIFT_BREAK: u8 = 0xAA;
/// Break code for the right SHIFT key (`RSHIFT_MAKE | 0x80`).
const RSHIFT_BREAK: u8 = 0xB6;
/// Bit 7 distinguishes a break (release) from a make (press) in SET 1.
const BREAK_BIT: u8 = 0x80;

/// US-QWERTY scancode → `(unshifted, shifted)` printable character, indexed by
/// the SET 1 *make* code. A `'\0'` pair means "no printable character at this
/// scancode" (we then return `None`). The table covers the main alpha block, the
/// number row, the bracket/semicolon/quote/backtick/comma/period/slash/backslash
/// punctuation, and space — everything a US-QWERTY shell needs to read typed
/// text. Editing keys (Enter, Backspace, Tab, Escape) and modifiers are handled
/// separately and are left as `'\0'` here.
///
/// The table is sized to the highest scancode we map (space, `0x39`); indexing it
/// with `scancode as usize` is therefore always in bounds for make codes `<=
/// 0x39` and we bounds-check anything larger before lookup.
const PRINTABLE: [(char, char); 0x3A] = build_printable_table();

/// Build the [`PRINTABLE`] lookup table at compile time. Kept as a `const fn` so
/// the whole table is baked into the binary (no runtime init, no allocator) while
/// staying readable as a list of `(scancode, unshifted, shifted)` rows.
const fn build_printable_table() -> [(char, char); 0x3A] {
    let mut table = [('\0', '\0'); 0x3A];
    // (scancode, unshifted, shifted)
    let rows: &[(u8, char, char)] = &[
        // Number row.
        (0x02, '1', '!'),
        (0x03, '2', '@'),
        (0x04, '3', '#'),
        (0x05, '4', '$'),
        (0x06, '5', '%'),
        (0x07, '6', '^'),
        (0x08, '7', '&'),
        (0x09, '8', '*'),
        (0x0A, '9', '('),
        (0x0B, '0', ')'),
        (0x0C, '-', '_'),
        (0x0D, '=', '+'),
        // Top alpha row.
        (0x10, 'q', 'Q'),
        (0x11, 'w', 'W'),
        (0x12, 'e', 'E'),
        (0x13, 'r', 'R'),
        (0x14, 't', 'T'),
        (0x15, 'y', 'Y'),
        (0x16, 'u', 'U'),
        (0x17, 'i', 'I'),
        (0x18, 'o', 'O'),
        (0x19, 'p', 'P'),
        (0x1A, '[', '{'),
        (0x1B, ']', '}'),
        // Home alpha row.
        (0x1E, 'a', 'A'),
        (0x1F, 's', 'S'),
        (0x20, 'd', 'D'),
        (0x21, 'f', 'F'),
        (0x22, 'g', 'G'),
        (0x23, 'h', 'H'),
        (0x24, 'j', 'J'),
        (0x25, 'k', 'K'),
        (0x26, 'l', 'L'),
        (0x27, ';', ':'),
        (0x28, '\'', '"'),
        (0x29, '`', '~'),
        (0x2B, '\\', '|'),
        // Bottom alpha row.
        (0x2C, 'z', 'Z'),
        (0x2D, 'x', 'X'),
        (0x2E, 'c', 'C'),
        (0x2F, 'v', 'V'),
        (0x30, 'b', 'B'),
        (0x31, 'n', 'N'),
        (0x32, 'm', 'M'),
        (0x33, ',', '<'),
        (0x34, '.', '>'),
        (0x35, '/', '?'),
        // Space.
        (0x39, ' ', ' '),
    ];
    let mut i = 0;
    while i < rows.len() {
        let (sc, lo, hi) = rows[i];
        table[sc as usize] = (lo, hi);
        i += 1;
    }
    table
}

/// The incremental decoder for PS/2 scancode SET 1.
///
/// Holds the small amount of state the protocol needs:
/// - `extended`: whether the previous byte was the `0xE0` extended prefix, so
///   the next byte is an extended make/break code (the arrow cluster).
/// - `shift`: whether either SHIFT key is currently held, tracked from the
///   `0x2A`/`0x36` makes and `0xAA`/`0xB6` breaks so printable keys can resolve
///   to their shifted form.
///
/// Feed it raw bytes (drained from [`hal::keyboard::poll_scancode`]) one at a
/// time via [`feed`](Self::feed); it returns `Some(KeyEvent)` for the keys we
/// recognise — printable keys as [`KeyEvent::Char`] — and `None` for prefixes,
/// SHIFT make/break (consumed into the shift state), unrecognised codes, or the
/// inert release half of a key.
#[derive(Clone, Copy, Debug, Default)]
pub struct ScancodeDecoder {
    /// `true` when the immediately-preceding byte was the `0xE0` prefix, so the
    /// next byte must be interpreted as an extended make/break code.
    extended: bool,
    /// `true` while either LEFT or RIGHT SHIFT is held (set on `0x2A`/`0x36`
    /// make, cleared on `0xAA`/`0xB6` break).
    shift: bool,
}

impl ScancodeDecoder {
    /// A fresh decoder with no prefix pending and SHIFT released.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            extended: false,
            shift: false,
        }
    }

    /// `true` while either SHIFT key is currently held. Exposed mainly for tests
    /// and any caller that wants the modifier state directly.
    #[must_use]
    pub const fn shift_held(&self) -> bool {
        self.shift
    }

    /// Feed one raw scancode byte; return a decoded [`KeyEvent`] if this byte
    /// completed one we recognise.
    ///
    /// Decoding order:
    /// 1. The `0xE0` prefix sets a latch and yields `None`; the *following* byte
    ///    is decoded in the extended namespace (and clears the latch).
    /// 2. SHIFT make/break (`0x2A`/`0x36`/`0xAA`/`0xB6`) updates the shift state
    ///    and yields `None` — SHIFT is a modifier, not an event.
    /// 3. The editing keys (Enter, Backspace, Tab, Escape) decode to their own
    ///    events on *make*; their releases are ignored.
    /// 4. Any remaining *make* code is looked up in the US-QWERTY [`PRINTABLE`]
    ///    table and, if present, returned as [`KeyEvent::Char`] resolved through
    ///    the current shift state.
    ///
    /// Anything else — release halves, unmapped makes — returns `None`.
    pub fn feed(&mut self, byte: u8) -> Option<KeyEvent> {
        if byte == EXT_PREFIX {
            // Begin a two-byte extended sequence; the real code is next.
            self.extended = true;
            return None;
        }

        if self.extended {
            // This byte is the second half of an extended sequence.
            self.extended = false;
            return match byte {
                RIGHT_ARROW_MAKE => Some(KeyEvent::RightArrowPressed),
                RIGHT_ARROW_BREAK => Some(KeyEvent::RightArrowReleased),
                _ => None, // other extended keys: ignored at this slice
            };
        }

        // SHIFT is a modifier: fold make/break into our shift state, emit nothing.
        match byte {
            LSHIFT_MAKE | RSHIFT_MAKE => {
                self.shift = true;
                return None;
            }
            LSHIFT_BREAK | RSHIFT_BREAK => {
                self.shift = false;
                return None;
            }
            _ => {}
        }

        // Releases of plain keys (bit 7 set) carry no event for the shell.
        if byte & BREAK_BIT != 0 {
            return None;
        }

        // Plain make codes. Named editing keys first, then printable lookup.
        match byte {
            ENTER_MAKE => Some(KeyEvent::EnterPressed),
            BACKSPACE_MAKE => Some(KeyEvent::Backspace),
            TAB_MAKE => Some(KeyEvent::Tab),
            ESCAPE_MAKE => Some(KeyEvent::Escape),
            _ => self.printable(byte),
        }
    }

    /// Resolve a plain make code to a printable [`KeyEvent::Char`] via the
    /// US-QWERTY table and the current shift state, or `None` if the scancode is
    /// out of range or has no printable mapping.
    fn printable(&self, make: u8) -> Option<KeyEvent> {
        let (lo, hi) = *PRINTABLE.get(make as usize)?;
        let ch = if self.shift { hi } else { lo };
        if ch == '\0' {
            None
        } else {
            Some(KeyEvent::Char(ch))
        }
    }
}

/// The lock-screen lifecycle: locked → a brief unlock animation → the desktop.
///
/// The kernel's idle loop owns one of these and advances it each tick. The
/// `Unlocking` state carries the tick at which the animation began so the loop
/// can derive the current animation frame from the monotonic [`hal::pit::TICKS`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockState {
    /// Showing the Cyber Dusk lock screen with the pulsing unlock hint.
    Locked,
    /// Playing the unlock animation; the field is the [`hal::pit::ticks`] value
    /// captured when the unlock gesture was accepted (the animation's t₀).
    Unlocking {
        /// Tick count at which the animation started (its frame-zero reference).
        start_tick: u64,
    },
    /// The unlock animation finished; the desktop is up and the clock ticks on.
    Desktop,
}

impl LockState {
    /// `true` while the right-arrow unlock gesture should be accepted (i.e. only
    /// in [`LockState::Locked`]). Once unlocking or on the desktop, further key
    /// presses are ignored by the lock logic.
    #[must_use]
    pub const fn accepts_unlock(self) -> bool {
        matches!(self, LockState::Locked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn right_arrow_press_is_two_byte_sequence() {
        let mut d = ScancodeDecoder::new();
        // The 0xE0 prefix alone yields nothing...
        assert_eq!(d.feed(0xE0), None);
        // ...and the 0x4D completes a "right arrow pressed".
        assert_eq!(d.feed(0x4D), Some(KeyEvent::RightArrowPressed));
    }

    #[test]
    fn right_arrow_release_is_decoded_separately() {
        let mut d = ScancodeDecoder::new();
        assert_eq!(d.feed(0xE0), None);
        assert_eq!(d.feed(0xCD), Some(KeyEvent::RightArrowReleased));
    }

    #[test]
    fn bare_0x4d_without_prefix_is_not_right_arrow() {
        // 0x4D without the 0xE0 prefix is the numpad '4' make — not our arrow.
        let mut d = ScancodeDecoder::new();
        assert_eq!(d.feed(0x4D), None);
    }

    #[test]
    fn enter_make_is_decoded() {
        let mut d = ScancodeDecoder::new();
        assert_eq!(d.feed(0x1C), Some(KeyEvent::EnterPressed));
    }

    #[test]
    fn lowercase_letter_decodes_to_char() {
        let mut d = ScancodeDecoder::new();
        // 'a' make (0x1E) with no shift held -> lowercase 'a'.
        assert_eq!(d.feed(0x1E), Some(KeyEvent::Char('a')));
        // Its break (0x9E) carries no event.
        assert_eq!(d.feed(0x9E), None);
    }

    #[test]
    fn shifted_letter_is_uppercase() {
        let mut d = ScancodeDecoder::new();
        // Left SHIFT make (0x2A) latches the modifier, emitting nothing.
        assert_eq!(d.feed(0x2A), None);
        assert!(d.shift_held());
        // 'a' make while shift held -> 'A'.
        assert_eq!(d.feed(0x1E), Some(KeyEvent::Char('A')));
        // SHIFT break (0xAA) releases the modifier.
        assert_eq!(d.feed(0xAA), None);
        assert!(!d.shift_held());
        // 'a' again is lowercase now.
        assert_eq!(d.feed(0x1E), Some(KeyEvent::Char('a')));
    }

    #[test]
    fn right_shift_make_break_tracked() {
        let mut d = ScancodeDecoder::new();
        // Right SHIFT make (0x36) and break (0xB6) behave like the left one.
        assert_eq!(d.feed(0x36), None);
        assert_eq!(d.feed(0x12), Some(KeyEvent::Char('E')));
        assert_eq!(d.feed(0xB6), None);
        assert_eq!(d.feed(0x12), Some(KeyEvent::Char('e')));
    }

    #[test]
    fn digit_decodes_unshifted() {
        let mut d = ScancodeDecoder::new();
        // '2' make (0x03) with no shift -> '2'.
        assert_eq!(d.feed(0x03), Some(KeyEvent::Char('2')));
    }

    #[test]
    fn shifted_symbol_decodes() {
        let mut d = ScancodeDecoder::new();
        assert_eq!(d.feed(0x2A), None); // SHIFT down
                                        // SHIFT + '2' (0x03) -> '@'.
        assert_eq!(d.feed(0x03), Some(KeyEvent::Char('@')));
        // SHIFT + '/' (0x35) -> '?'.
        assert_eq!(d.feed(0x35), Some(KeyEvent::Char('?')));
    }

    #[test]
    fn space_decodes_to_char() {
        let mut d = ScancodeDecoder::new();
        // Space make (0x39) -> ' ' (same shifted or not).
        assert_eq!(d.feed(0x39), Some(KeyEvent::Char(' ')));
        assert_eq!(d.feed(0x2A), None); // SHIFT down
        assert_eq!(d.feed(0x39), Some(KeyEvent::Char(' ')));
    }

    #[test]
    fn backspace_tab_escape_decode() {
        let mut d = ScancodeDecoder::new();
        assert_eq!(d.feed(0x0E), Some(KeyEvent::Backspace));
        assert_eq!(d.feed(0x0F), Some(KeyEvent::Tab));
        assert_eq!(d.feed(0x01), Some(KeyEvent::Escape));
    }

    #[test]
    fn enter_make_decodes_to_enter_event() {
        let mut d = ScancodeDecoder::new();
        // Enter remains its own event (also the shell's submit key).
        assert_eq!(d.feed(0x1C), Some(KeyEvent::EnterPressed));
    }

    #[test]
    fn prefix_latch_only_affects_next_byte() {
        let mut d = ScancodeDecoder::new();
        assert_eq!(d.feed(0xE0), None);
        assert_eq!(d.feed(0x4D), Some(KeyEvent::RightArrowPressed));
        // Latch cleared: a following bare 0x4D is no longer the arrow.
        assert_eq!(d.feed(0x4D), None);
    }

    #[test]
    fn lock_state_accepts_unlock_only_when_locked() {
        assert!(LockState::Locked.accepts_unlock());
        assert!(!LockState::Unlocking { start_tick: 0 }.accepts_unlock());
        assert!(!LockState::Desktop.accepts_unlock());
    }
}
