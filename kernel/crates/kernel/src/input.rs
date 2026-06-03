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

/// A decoded key event the kernel cares about at this slice.
///
/// We deliberately decode only what the lock screen needs (the right arrow) plus
/// a couple of friendly extras; every other scancode decodes to `None` and is
/// ignored. Releases are decoded but currently unused by the caller — they are
/// surfaced so a later slice can do key-repeat / held-key handling without
/// changing this API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyEvent {
    /// The right-arrow key was pressed (`0xE0 0x4D`) — the unlock gesture.
    RightArrowPressed,
    /// The right-arrow key was released (`0xE0 0xCD`).
    RightArrowReleased,
    /// Enter / Return was pressed (`0x1C`) — also accepted as an unlock.
    EnterPressed,
}

/// The `0xE0` extended-scancode prefix byte.
const EXT_PREFIX: u8 = 0xE0;
/// Make code for the right arrow (after the `0xE0` prefix).
const RIGHT_ARROW_MAKE: u8 = 0x4D;
/// Break code for the right arrow (after the `0xE0` prefix): make `| 0x80`.
const RIGHT_ARROW_BREAK: u8 = 0xCD;
/// Make code for Enter / Return (a non-extended key).
const ENTER_MAKE: u8 = 0x1C;
/// Bit 7 distinguishes a break (release) from a make (press) in SET 1.
const BREAK_BIT: u8 = 0x80;

/// The incremental decoder for PS/2 scancode SET 1.
///
/// Holds the single bit of state the protocol needs: whether the previous byte
/// was the `0xE0` extended prefix. Feed it raw bytes (drained from
/// [`hal::keyboard::poll_scancode`]) one at a time via [`feed`](Self::feed); it
/// returns `Some(KeyEvent)` for the keys we recognise and `None` for prefixes,
/// unrecognised codes, or the inert half of an event.
#[derive(Clone, Copy, Debug, Default)]
pub struct ScancodeDecoder {
    /// `true` when the immediately-preceding byte was the `0xE0` prefix, so the
    /// next byte must be interpreted as an extended make/break code.
    extended: bool,
}

impl ScancodeDecoder {
    /// A fresh decoder with no prefix pending.
    #[must_use]
    pub const fn new() -> Self {
        Self { extended: false }
    }

    /// Feed one raw scancode byte; return a decoded [`KeyEvent`] if this byte
    /// completed one we recognise.
    ///
    /// The `0xE0` prefix sets a latch and yields `None`; the *following* byte is
    /// then decoded in the extended namespace (and clears the latch). Non-extended
    /// bytes are decoded directly. Anything we do not map returns `None`.
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

        // A plain (non-extended) key. We only care about Enter as a friendly
        // alternative unlock; bit 7 set means a release, which we ignore here.
        if byte & BREAK_BIT == 0 && byte == ENTER_MAKE {
            return Some(KeyEvent::EnterPressed);
        }
        None
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
    fn unrelated_keys_are_ignored() {
        let mut d = ScancodeDecoder::new();
        // 'A' make (0x1E) and its break (0x9E) decode to nothing here.
        assert_eq!(d.feed(0x1E), None);
        assert_eq!(d.feed(0x9E), None);
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
