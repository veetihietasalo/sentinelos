//! 8253/8254 Programmable Interval Timer (PIT) — channel 0 — part of the TCB.
//!
//! The PIT is the legacy PC heartbeat: channel 0's output is wired to the
//! master PIC's IRQ0. We program it to fire at a fixed frequency so the kernel
//! gets a periodic tick (vector `0x20` once the PIC is remapped — see
//! [`crate::pic`]). Each tick increments a free-running counter the kernel reads
//! to drive the wall clock.
//!
//! This module does raw x86 port I/O (`out`) through a private primitive, each
//! call documented with a `// SAFETY:` block; see `kernel/docs/hal-tcb.md`
//! (§2f). The public surface is **safe**:
//!
//! - [`init`] — program channel 0 to ~100 Hz in rate-generator mode.
//! - [`TICKS`] / [`ticks`] — the monotonic tick counter, incremented by the
//!   kernel's IRQ0 handler ([`on_tick`]).
//! - [`on_tick`] — the body of the timer interrupt: bump [`TICKS`] and EOI. The
//!   kernel registers a one-line vector-32 handler that calls this, so all the
//!   privileged work (the EOI port write) stays in the TCB.
//! - [`TICK_HZ`] — the tick frequency, so the kernel can convert ticks ↔ seconds.

use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

// ── I/O ports ──────────────────────────────────────────────────────────────

/// PIT channel 0 data port (read/write the 16-bit reload/count value here).
const PIT_CHANNEL0_DATA: u16 = 0x40;
/// PIT mode/command register.
const PIT_COMMAND: u16 = 0x43;

/// Input clock to the PIT, in Hz (the classic 1.193182 MHz crystal).
const PIT_INPUT_HZ: u32 = 1_193_182;

/// Target tick frequency: ~100 Hz → a 10 ms tick. A round, well-behaved rate
/// that divides the wall clock cleanly and keeps interrupt overhead negligible.
pub const TICK_HZ: u64 = 100;

/// Mode/command byte (`0x34`): channel 0, access mode lobyte/hibyte, mode 2
/// (rate generator), binary counting.
///
/// Bit fields, high → low: `00` (select channel 0) · `11` (lo/hi byte access) ·
/// `010` (mode 2, rate generator) · `0` (binary, not BCD) ⇒ `0b0011_0100`.
const PIT_MODE_RATE_GEN: u8 = 0b0011_0100;

/// Monotonic tick counter, incremented once per PIT interrupt by [`on_tick`].
///
/// A plain `static AtomicU64` so it needs no `unsafe` and is read without
/// tearing. Wraps after ~5.8 billion years at 100 Hz, so overflow is a
/// non-issue. Read it with [`ticks`].
pub static TICKS: AtomicU64 = AtomicU64::new(0);

/// Write a byte to the given x86 I/O port.
///
/// # Safety
///
/// The caller must ensure `port` names a PIT register that is safe to write with
/// `value`. All call sites write only the channel-0 data port or the mode/
/// command register.
#[inline]
unsafe fn outb(port: u16, value: u8) {
    // SAFETY: `out dx, al` writes the byte in `al` to the I/O port in `dx`. The
    // contract that `port`/`value` are a valid, write-safe PIT register pair is
    // delegated to this function's `# Safety` section and upheld by every
    // caller, which only programs `0x40`/`0x43`. The instruction touches no
    // memory (`nomem`) and no stack (`nostack`).
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack));
    }
}

/// Program PIT channel 0 as a ~100 Hz rate generator (mode 2).
///
/// Must be called once, on the boot core, with interrupts disabled, **after**
/// [`crate::pic::init`]. After this the PIT pulses IRQ0 at [`TICK_HZ`]; the line
/// is still masked until [`crate::pic::unmask_irq`]`(0)` opens it. Idempotent on
/// QEMU's emulated PIT.
///
/// The reload value is `PIT_INPUT_HZ / TICK_HZ`, clamped into the 16-bit range
/// (a 0 divisor means 65536 on the 8254, the slowest rate — we never hit that
/// for 100 Hz, where the divisor is 11932).
pub fn init() {
    // Divisor = input clock / desired rate, clamped to the 16-bit reload range.
    // For 100 Hz this is 1_193_182 / 100 = 11_931 (≈100.006 Hz actual).
    let divisor = (PIT_INPUT_HZ / TICK_HZ as u32).clamp(1, 0xFFFF) as u16;
    let low = (divisor & 0xFF) as u8;
    let high = (divisor >> 8) as u8;

    // SAFETY: writes the mode/command register (`0x43`) then the channel-0 data
    // port (`0x40`) low byte and high byte — the documented 8254 programming
    // sequence for channel 0 in lo/hi access, rate-generator mode. These writes
    // only configure the PIT device (its mode and reload count); they cannot
    // alias or corrupt Rust memory. `init` runs once on the boot core with
    // interrupts disabled, so there is no concurrent PIT access. Each `outb`'s
    // safety contract (valid, write-safe PIT port) is satisfied per call.
    unsafe {
        outb(PIT_COMMAND, PIT_MODE_RATE_GEN);
        outb(PIT_CHANNEL0_DATA, low);
        outb(PIT_CHANNEL0_DATA, high);
    }
}

/// Current monotonic tick count (number of PIT interrupts since boot).
///
/// Divide by [`TICK_HZ`] to get elapsed whole seconds.
#[inline]
#[must_use]
pub fn ticks() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

/// The body of the PIT (IRQ0 / vector `0x20`) interrupt.
///
/// Increments [`TICKS`] and signals End-Of-Interrupt to the PIC so the next tick
/// can be delivered. The kernel registers a tiny safe `fn(&InterruptFrame)` for
/// vector 32 that calls this; keeping the EOI here means the privileged PIC
/// write stays inside the TCB while the kernel handler remains `unsafe`-free.
#[inline]
pub fn on_tick() {
    TICKS.fetch_add(1, Ordering::Relaxed);
    // The PIT is IRQ0 → master-PIC vector PIC1_OFFSET (0x20). EOI lets the PIC
    // deliver the next tick.
    crate::pic::end_of_interrupt(crate::pic::PIC1_OFFSET);
}
