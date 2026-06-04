//! PS/2 mouse (i8042 auxiliary device) on IRQ12 — part of the TCB.
//!
//! The legacy PS/2 mouse (emulated by QEMU's i8042 controller) raises IRQ12
//! whenever the pointer moves or a button changes. Like the keyboard on IRQ1, the
//! controller delivers its bytes through the **same** data port (`0x60`), and the
//! single hard rule of the 8042 is that the IRQ handler **must read the data port
//! on every interrupt**: the controller holds the byte in its output buffer and
//! will not raise another IRQ12 until that byte is drained.
//!
//! Unlike the keyboard, the mouse delivers a **3-byte packet** per event (flags,
//! dx, dy) — but the i8042 raises one IRQ12 per *byte*, so this module reassembles
//! the three bytes across three interrupts before publishing a single
//! [`MouseEvent`]. We keep the privileged port read + EOI in the TCB and push the
//! decoded `{ dx, dy, buttons }` triple into a lock-free SPSC ring the safe kernel
//! polls (mirroring [`crate::keyboard`]). No pointer *policy* (cursor position,
//! clamping, hit-testing) lives here — that is all safe kernel logic.
//!
//! This module does raw x86 port I/O (`in`/`out`) through two private primitives,
//! each documented with a `// SAFETY:` block; see `kernel/docs/hal-tcb.md` (§2h).
//! The public surface is **safe**:
//!
//! - [`init`] — enable the auxiliary device on the i8042, switch the config byte's
//!   port-2 interrupt-enable bit on, put the mouse into streaming mode, then unmask
//!   IRQ12 (and the IRQ2 cascade). Call after [`crate::pic::init`] with the
//!   vector-`0x2C` handler already registered.
//! - [`on_irq`] — the body of the IRQ12 interrupt: read one packet byte from the
//!   data port, reassemble the 3-byte packet, push a decoded [`MouseEvent`] when
//!   complete, and EOI **both** PICs (IRQ12 is a slave-PIC line).
//! - [`poll_event`] — drain one decoded [`MouseEvent`] from the ring (safe,
//!   lock-free); returns `None` when empty. The kernel polls this from its idle
//!   loop and does **all** cursor/window policy in `#![forbid(unsafe_code)]` code.
//!
//! # Concurrency model
//!
//! Identical in spirit to [`crate::keyboard`]: single-core at bring-up. [`on_irq`]
//! runs inside the IRQ12 interrupt gate (interrupts already masked), producing into
//! the ring; the kernel's idle loop consumes from it between `hlt`s. The ring is a
//! small SPSC buffer of plain atomics, so neither side needs `unsafe` and reads
//! never tear. The 3-byte packet reassembly state (`PHASE`, `PKT*`) is touched only
//! by [`on_irq`], so it too needs no lock.

use core::arch::asm;
use core::sync::atomic::{AtomicI16, AtomicU8, AtomicUsize, Ordering};

// ── I/O ports ──────────────────────────────────────────────────────────────

/// PS/2 controller data port. Mouse packet bytes are read here (shared with the
/// keyboard), and the data half of a command (config byte, mouse command) is
/// written here.
const PS2_DATA: u16 = 0x60;
/// PS/2 controller status (read) / command (write) port.
const PS2_STATUS_CMD: u16 = 0x64;

/// Status-register bit 0: output buffer full (data available to read at `0x60`).
const STATUS_OUT_FULL: u8 = 1 << 0;
/// Status-register bit 1: input buffer full (do **not** write a port until clear).
const STATUS_IN_FULL: u8 = 1 << 1;

/// Controller command: enable the second (auxiliary / mouse) PS/2 port.
const CMD_ENABLE_AUX: u8 = 0xA8;
/// Controller command: read the "command byte" (configuration) → output buffer.
const CMD_READ_CONFIG: u8 = 0x20;
/// Controller command: write the next data byte as the new command byte.
const CMD_WRITE_CONFIG: u8 = 0x60;
/// Controller command: the next byte written to `0x60` is forwarded to the mouse.
const CMD_WRITE_TO_AUX: u8 = 0xD4;

/// Config-byte bit 1: enable the IRQ for the second PS/2 port (the mouse's IRQ12).
/// Setting this is what makes the i8042 actually raise IRQ12 on a mouse event.
const CONFIG_PORT2_IRQ: u8 = 1 << 1;
/// Config-byte bit 5: second-port clock **disable**. We clear it so the mouse
/// port is clocked (enabling the aux port should already clear it, but we ensure).
const CONFIG_PORT2_CLOCK_DISABLE: u8 = 1 << 5;

/// Mouse command: set defaults (100 dpi, streaming off, 1:1 scaling).
const MOUSE_SET_DEFAULTS: u8 = 0xF6;
/// Mouse command: enable data reporting (streaming) — start sending packets.
const MOUSE_ENABLE_REPORTING: u8 = 0xF4;
/// The mouse acks each command with `0xFA`; we drain it (bounded) but do not
/// require it (QEMU always acks; bare-metal robustness comes from the bounded
/// waits, not from asserting the ack value).
const MOUSE_ACK: u8 = 0xFA;

/// IRQ line the PS/2 mouse is wired to (IRQ12 on the slave PIC).
pub const IRQ_MOUSE: u8 = 12;
/// IRQ line of the master→slave cascade (the slave PIC reaches the CPU through it).
const IRQ_CASCADE: u8 = 2;

/// Vector IRQ12 lands on after the PIC remap (`PIC2_OFFSET + (12 - 8)` = `0x2C`).
pub const VECTOR_MOUSE: u8 = crate::pic::PIC2_OFFSET + (IRQ_MOUSE - 8);

// ── Decoded event ────────────────────────────────────────────────────────────

/// One decoded PS/2 mouse event: a relative motion delta plus the button bitmap,
/// already extracted from the raw 3-byte packet (sign + overflow handled).
///
/// `dx`/`dy` are in mouse units (right is +x, **up** is +y in PS/2 convention; the
/// safe kernel flips dy to screen-down when it moves the cursor). `buttons` is the
/// low-3-bit button bitmap from the packet's first byte.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MouseEvent {
    /// Horizontal movement since the last packet (right positive), sign-extended
    /// and overflow-clamped from the raw packet.
    pub dx: i16,
    /// Vertical movement since the last packet (**up** positive, PS/2 convention),
    /// sign-extended and overflow-clamped from the raw packet.
    pub dy: i16,
    /// Button bitmap: bit 0 = left, bit 1 = right, bit 2 = middle.
    pub buttons: u8,
}

impl MouseEvent {
    /// `true` if the left button is currently held in this packet.
    #[must_use]
    pub const fn left(&self) -> bool {
        self.buttons & BTN_LEFT != 0
    }

    /// `true` if the right button is currently held in this packet.
    #[must_use]
    pub const fn right(&self) -> bool {
        self.buttons & BTN_RIGHT != 0
    }

    /// `true` if the middle button is currently held in this packet.
    #[must_use]
    pub const fn middle(&self) -> bool {
        self.buttons & BTN_MIDDLE != 0
    }
}

/// Packet byte-0 bit 0: left button down.
pub const BTN_LEFT: u8 = 1 << 0;
/// Packet byte-0 bit 1: right button down.
pub const BTN_RIGHT: u8 = 1 << 1;
/// Packet byte-0 bit 2: middle button down.
pub const BTN_MIDDLE: u8 = 1 << 2;

/// Packet byte-0 bit 3: always 1 on a valid first packet byte — used to resync if
/// the stream slips (we only accept a byte as packet-start when this bit is set).
const BYTE0_ALWAYS_ONE: u8 = 1 << 3;
/// Packet byte-0 bit 4: X-movement sign bit (1 = negative).
const BYTE0_X_SIGN: u8 = 1 << 4;
/// Packet byte-0 bit 5: Y-movement sign bit (1 = negative).
const BYTE0_Y_SIGN: u8 = 1 << 5;
/// Packet byte-0 bit 6: X-movement overflow (delta too large to represent).
const BYTE0_X_OVERFLOW: u8 = 1 << 6;
/// Packet byte-0 bit 7: Y-movement overflow.
const BYTE0_Y_OVERFLOW: u8 = 1 << 7;

// ── Lock-free decoded-event ring (SPSC) ──────────────────────────────────────

/// Capacity of the decoded-event ring (a power of two so the index wraps with a
/// mask). 32 events is far more than a single idle-loop interval accumulates at
/// human pointer speeds; an overrun drops the oldest unread event.
const RING_LEN: usize = 32;

/// The decoded `dx` of each ring slot.
static RING_DX: [AtomicI16; RING_LEN] = [const { AtomicI16::new(0) }; RING_LEN];
/// The decoded `dy` of each ring slot.
static RING_DY: [AtomicI16; RING_LEN] = [const { AtomicI16::new(0) }; RING_LEN];
/// The decoded button bitmap of each ring slot.
static RING_BTN: [AtomicU8; RING_LEN] = [const { AtomicU8::new(0) }; RING_LEN];

/// Producer index (next slot the IRQ handler will write). Monotonic; masked at use.
static HEAD: AtomicUsize = AtomicUsize::new(0);
/// Consumer index (next slot the kernel will read). Monotonic; masked at use.
static TAIL: AtomicUsize = AtomicUsize::new(0);

// ── 3-byte packet reassembly state (touched only by `on_irq`) ────────────────

/// Which byte of the current packet we expect next: 0 (flags), 1 (dx), 2 (dy).
static PHASE: AtomicUsize = AtomicUsize::new(0);
/// The packet's byte 0 (flags) captured while phases 1/2 arrive.
static PKT0: AtomicU8 = AtomicU8::new(0);
/// The packet's byte 1 (raw dx) captured while phase 2 arrives.
static PKT1: AtomicU8 = AtomicU8::new(0);

// ── Raw port primitives (the only `unsafe` in this module) ───────────────────

/// Read a byte from the given x86 I/O port.
///
/// # Safety
///
/// The caller must ensure `port` names a register that is safe to read. All call
/// sites read the PS/2 data port (`0x60`) or status port (`0x64`) — pure device
/// reads with no memory-safety-relevant side effect.
#[inline]
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: `in al, dx` reads one byte from the I/O port in `dx` into `al`. The
    // contract that `port` is a valid, read-safe register is delegated to this
    // function's `# Safety` section and upheld by every caller, which reads only
    // the PS/2 data port `0x60` or status port `0x64`. The instruction touches no
    // memory (`nomem`) and uses no stack (`nostack`).
    unsafe {
        asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack));
    }
    value
}

/// Write a byte to the given x86 I/O port.
///
/// # Safety
///
/// The caller must ensure `port` names a register that is safe to write with
/// `value`. All call sites write the PS/2 command port (`0x64`) and data port
/// (`0x60`) during [`init`] to program the i8042 / mouse — a device-only effect.
#[inline]
unsafe fn outb(port: u16, value: u8) {
    // SAFETY: `out dx, al` writes the byte in `al` to the I/O port in `dx`. The
    // contract that `port`/`value` are a valid, write-safe PS/2 register pair is
    // delegated to this function's `# Safety` section and upheld by every caller,
    // which programs only `0x60`/`0x64` with documented i8042/mouse command and
    // config values. The instruction touches no memory (`nomem`) and no stack
    // (`nostack`).
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack));
    }
}

/// Spin (bounded) until the controller's input buffer is empty, so it is safe to
/// write a command or data byte. The bound prevents a wedged controller from
/// hanging boot; on QEMU's i8042 it clears within a few reads.
fn wait_input_empty() {
    for _ in 0..100_000 {
        // SAFETY: reads the i8042 status register (`0x64`), a read-only status
        // port with no memory-safety-relevant side effect. `inb`'s contract holds.
        let status = unsafe { inb(PS2_STATUS_CMD) };
        if status & STATUS_IN_FULL == 0 {
            return;
        }
        core::hint::spin_loop();
    }
}

/// Spin (bounded) until the controller's output buffer is full, so a read of the
/// data port returns the byte we asked for (e.g. a mouse command ack).
fn wait_output_full() {
    for _ in 0..100_000 {
        // SAFETY: reads the i8042 status register (`0x64`); pure status read.
        let status = unsafe { inb(PS2_STATUS_CMD) };
        if status & STATUS_OUT_FULL != 0 {
            return;
        }
        core::hint::spin_loop();
    }
}

/// Send one byte to the **mouse** (auxiliary device) and drain its ack.
///
/// The i8042 routes a data-port write to the mouse only when prefixed with the
/// `0xD4` command, so each mouse command is: `outb(0x64, 0xD4)` then
/// `outb(0x60, cmd)`. The mouse replies with `0xFA` (ACK) on the data port, which
/// we read back to keep the output buffer clear before the next command (and so a
/// stray ack can't masquerade as the first packet byte once IRQ12 is unmasked).
fn write_to_mouse(cmd: u8) {
    // SAFETY: writes the documented "write to aux" command (`0xD4`) to the i8042
    // command port (`0x64`), then the mouse command byte to the data port (`0x60`),
    // each after waiting for the input buffer to clear; then reads the mouse's ack
    // byte from the data port once the output buffer is full. All three are
    // device-only i8042/mouse operations on constant ports with documented values;
    // they cannot alias or corrupt Rust memory. Runs in `init` on the boot core
    // with interrupts disabled, so there is no concurrent PS/2 access. `inb`/`outb`
    // contracts (valid PS/2 ports) hold.
    unsafe {
        wait_input_empty();
        outb(PS2_STATUS_CMD, CMD_WRITE_TO_AUX);
        wait_input_empty();
        outb(PS2_DATA, cmd);
        // Drain the ack so the output buffer is clear for the next command.
        wait_output_full();
        let ack = inb(PS2_DATA);
        let _ = ack == MOUSE_ACK; // observed, not asserted (QEMU always acks)
    }
}

// ── Ring producer / consumer (no `unsafe`) ───────────────────────────────────

/// Push one decoded event into the ring (producer side, only from [`on_irq`]).
///
/// If the ring is full the oldest unread event is dropped (the consumer index is
/// advanced past it), which is acceptable: at pointer speeds the idle loop drains
/// far faster than packets arrive, and dropping a stale delta is better than
/// blocking an interrupt handler. No `unsafe`: every slot is an independent atomic.
fn ring_push(ev: MouseEvent) {
    let head = HEAD.load(Ordering::Relaxed);
    let tail = TAIL.load(Ordering::Acquire);
    let next = head.wrapping_add(1);
    if next.wrapping_sub(tail) > RING_LEN {
        // Full: drop the oldest by advancing the consumer index past it.
        TAIL.store(tail.wrapping_add(1), Ordering::Release);
    }
    let slot = head & (RING_LEN - 1);
    RING_DX[slot].store(ev.dx, Ordering::Relaxed);
    RING_DY[slot].store(ev.dy, Ordering::Relaxed);
    RING_BTN[slot].store(ev.buttons, Ordering::Relaxed);
    // Publish the event: the Release pairs with the consumer's Acquire load of HEAD
    // so the three stored fields are visible before the index advance.
    HEAD.store(next, Ordering::Release);
}

/// Drain one decoded [`MouseEvent`] from the ring, or `None` if empty (consumer).
///
/// Safe, lock-free, and the **only** thing the kernel needs to read mouse input:
/// it does all cursor positioning, clamping, and hit-testing itself in safe code.
/// Called from the single consumer (the kernel idle loop).
#[must_use]
pub fn poll_event() -> Option<MouseEvent> {
    let tail = TAIL.load(Ordering::Relaxed);
    let head = HEAD.load(Ordering::Acquire);
    if tail == head {
        return None; // empty
    }
    let slot = tail & (RING_LEN - 1);
    let ev = MouseEvent {
        dx: RING_DX[slot].load(Ordering::Relaxed),
        dy: RING_DY[slot].load(Ordering::Relaxed),
        buttons: RING_BTN[slot].load(Ordering::Relaxed),
    };
    TAIL.store(tail.wrapping_add(1), Ordering::Release);
    Some(ev)
}

// ── Packet decoding (pure logic) ─────────────────────────────────────────────

/// Sign-extend a raw 8-bit movement byte using the packet's sign bit, clamping to
/// `0` when the corresponding overflow bit is set (an over-range delta is dropped
/// rather than wrapping into a wild jump).
///
/// PS/2 reports movement as a 9-bit two's-complement value split as `(sign_bit,
/// data_byte)`; when `negative` the value is `data - 256`.
fn decode_delta(data: u8, negative: bool, overflow: bool) -> i16 {
    if overflow {
        return 0;
    }
    if negative {
        i16::from(data) - 256
    } else {
        i16::from(data)
    }
}

/// Assemble a [`MouseEvent`] from the three raw packet bytes.
fn decode_packet(flags: u8, raw_dx: u8, raw_dy: u8) -> MouseEvent {
    let dx = decode_delta(
        raw_dx,
        flags & BYTE0_X_SIGN != 0,
        flags & BYTE0_X_OVERFLOW != 0,
    );
    let dy = decode_delta(
        raw_dy,
        flags & BYTE0_Y_SIGN != 0,
        flags & BYTE0_Y_OVERFLOW != 0,
    );
    let buttons = flags & (BTN_LEFT | BTN_RIGHT | BTN_MIDDLE);
    MouseEvent { dx, dy, buttons }
}

// ── IRQ body + init (the privileged surface) ─────────────────────────────────

/// The body of the PS/2 mouse (IRQ12 / vector `0x2C`) interrupt.
///
/// **Always** reads the next packet byte from the data port first — the i8042 will
/// not raise another IRQ12 until its output buffer is drained — then advances the
/// 3-byte reassembly state machine. On the third byte it decodes the packet and
/// pushes a [`MouseEvent`] into the ring for the kernel to consume; on the first
/// byte it resyncs if the "always 1" bit (bit 3) is clear (the stream slipped).
/// Finally it signals End-Of-Interrupt to **both** PICs (IRQ12 is a slave-PIC
/// line, so the slave *and* the master must be EOI'd via [`crate::pic`]).
///
/// The kernel registers a tiny safe `fn(&InterruptFrame)` for vector `0x2C` that
/// calls this; keeping the port read + EOI here means the privileged work stays
/// inside the TCB while the kernel handler remains `unsafe`-free.
#[inline]
pub fn on_irq() {
    // SAFETY: reads the PS/2 controller data port (`0x60`), the documented place a
    // mouse packet byte is delivered for IRQ12. Draining it is mandatory (the i8042
    // stops raising IRQ12 until read) and is a pure device read that cannot alias or
    // corrupt Rust memory. `inb`'s safety contract (valid, read-safe port) holds.
    let byte = unsafe { inb(PS2_DATA) };

    match PHASE.load(Ordering::Relaxed) {
        0 => {
            // First byte must have bit 3 set; if not, the stream slipped — stay in
            // phase 0 and wait for a valid packet head rather than mis-decoding.
            if byte & BYTE0_ALWAYS_ONE != 0 {
                PKT0.store(byte, Ordering::Relaxed);
                PHASE.store(1, Ordering::Relaxed);
            }
        }
        1 => {
            PKT1.store(byte, Ordering::Relaxed);
            PHASE.store(2, Ordering::Relaxed);
        }
        _ => {
            let flags = PKT0.load(Ordering::Relaxed);
            let raw_dx = PKT1.load(Ordering::Relaxed);
            let ev = decode_packet(flags, raw_dx, byte);
            ring_push(ev);
            PHASE.store(0, Ordering::Relaxed);
        }
    }

    // IRQ12 → slave-PIC vector 0x2C. EOI both the slave and the master (the slave
    // reaches the CPU through the master's cascade); `pic::end_of_interrupt`
    // handles the both-PIC EOI for slave-range vectors.
    crate::pic::end_of_interrupt(VECTOR_MOUSE);
}

/// Program the i8042 to deliver mouse interrupts, put the mouse into streaming
/// mode, then unmask IRQ12 (and the IRQ2 cascade).
///
/// Call once, on the boot core, **after** [`crate::pic::init`] (which remaps the
/// pair and masks every line) and after the kernel has registered the
/// vector-`0x2C` handler — so no packet can arrive before its handler exists.
///
/// Steps:
/// 1. Enable the auxiliary (mouse) port on the controller (command `0xA8`).
/// 2. Read the config byte (`0x20`), **set** the port-2 interrupt-enable bit and
///    **clear** the port-2 clock-disable bit, and write it back (`0x60`). Without
///    the interrupt-enable bit the i8042 never raises IRQ12.
/// 3. Tell the mouse to use defaults (`0xF6`) and enable data reporting (`0xF4`),
///    so it begins streaming 3-byte movement packets.
/// 4. Drain any stale byte, then unmask the IRQ2 cascade (so the slave PIC reaches
///    the CPU at all) and IRQ12 (so the mouse line is delivered).
pub fn init() {
    // 1) Enable the auxiliary device.
    // SAFETY: writes the documented "enable aux port" command (`0xA8`) to the i8042
    // command port (`0x64`) after waiting for the input buffer to clear. Device-only
    // i8042 operation on a constant port; cannot alias Rust memory. Runs once on the
    // boot core with interrupts disabled. `outb`'s contract holds.
    unsafe {
        wait_input_empty();
        outb(PS2_STATUS_CMD, CMD_ENABLE_AUX);
    }

    // 2) Read-modify-write the config byte to enable IRQ12 and clock the aux port.
    // SAFETY: writes the documented "read config byte" command (`0x20`), reads the
    // resulting config byte from the data port once the output buffer is full, then
    // writes the "write config byte" command (`0x60`) followed by the new config
    // byte — each after gating on the input/output buffer state. All are device-only
    // i8042 operations on constant ports with documented values; the new byte only
    // toggles which interrupts the controller raises and which ports are clocked.
    // Cannot corrupt Rust memory. `inb`/`outb` contracts hold.
    let config = unsafe {
        wait_input_empty();
        outb(PS2_STATUS_CMD, CMD_READ_CONFIG);
        wait_output_full();
        inb(PS2_DATA)
    };
    let new_config = (config | CONFIG_PORT2_IRQ) & !CONFIG_PORT2_CLOCK_DISABLE;
    // SAFETY: as above — write the "write config byte" command then the new byte,
    // each after waiting for the input buffer. Device-only i8042 programming.
    unsafe {
        wait_input_empty();
        outb(PS2_STATUS_CMD, CMD_WRITE_CONFIG);
        wait_input_empty();
        outb(PS2_DATA, new_config);
    }

    // 3) Put the mouse into a known state and start streaming. `write_to_mouse`
    //    sends each command via the `0xD4` prefix and drains the mouse's ack.
    write_to_mouse(MOUSE_SET_DEFAULTS);
    write_to_mouse(MOUSE_ENABLE_REPORTING);

    // 4) Drain any byte the controller may still be holding, so a stale byte does
    //    not desync the very first packet.
    // SAFETY: if the output buffer is full, read one byte from the data port to
    // clear it — a pure device read. `inb`'s contract holds.
    unsafe {
        if inb(PS2_STATUS_CMD) & STATUS_OUT_FULL != 0 {
            let _ = inb(PS2_DATA);
        }
    }

    // Start packet reassembly cleanly from phase 0.
    PHASE.store(0, Ordering::Relaxed);

    // Open the IRQ2 cascade (so the slave PIC's lines reach the CPU at all) and
    // IRQ12 (the mouse line) on the PIC.
    crate::pic::unmask_irq(IRQ_CASCADE);
    crate::pic::unmask_irq(IRQ_MOUSE);
}

// ── Unit tests (host) ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positive_motion_decodes() {
        // flags: always-one set, no signs, no overflow; dx=5, dy=3.
        let ev = decode_packet(BYTE0_ALWAYS_ONE, 5, 3);
        assert_eq!(ev.dx, 5);
        assert_eq!(ev.dy, 3);
        assert_eq!(ev.buttons, 0);
    }

    #[test]
    fn negative_x_sign_extends() {
        // X sign bit set, raw dx = 0xFE (254) → 254 - 256 = -2.
        let ev = decode_packet(BYTE0_ALWAYS_ONE | BYTE0_X_SIGN, 0xFE, 0);
        assert_eq!(ev.dx, -2);
        assert_eq!(ev.dy, 0);
    }

    #[test]
    fn negative_y_sign_extends() {
        let ev = decode_packet(BYTE0_ALWAYS_ONE | BYTE0_Y_SIGN, 0, 0xFB);
        assert_eq!(ev.dy, -5); // 251 - 256
    }

    #[test]
    fn overflow_clamps_to_zero() {
        let ev = decode_packet(
            BYTE0_ALWAYS_ONE | BYTE0_X_OVERFLOW | BYTE0_Y_OVERFLOW,
            0x7F,
            0x7F,
        );
        assert_eq!(ev.dx, 0);
        assert_eq!(ev.dy, 0);
    }

    #[test]
    fn buttons_extracted() {
        let ev = decode_packet(BYTE0_ALWAYS_ONE | BTN_LEFT | BTN_MIDDLE, 0, 0);
        assert!(ev.left());
        assert!(!ev.right());
        assert!(ev.middle());
        assert_eq!(ev.buttons, BTN_LEFT | BTN_MIDDLE);
    }

    #[test]
    fn vector_is_0x2c() {
        // IRQ12 is on the slave PIC at line 4 → PIC2_OFFSET (0x28) + 4 = 0x2C.
        assert_eq!(VECTOR_MOUSE, 0x2C);
    }
}
