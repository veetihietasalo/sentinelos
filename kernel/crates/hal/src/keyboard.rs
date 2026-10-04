//! PS/2 keyboard controller — IRQ1 scancode capture — part of the TCB.
//!
//! The legacy PS/2 keyboard (emulated by QEMU's i8042 controller) raises IRQ1
//! whenever a key is pressed or released. The single hard rule of the 8042 is
//! that the IRQ1 handler **must read the data port (`0x60`) on every interrupt**:
//! the controller holds the byte in its output buffer and will not raise another
//! IRQ1 until that byte is drained. If we EOI without reading, the keyboard
//! goes silent after the first keystroke.
//!
//! This module does raw x86 port I/O (`in`) through a private primitive,
//! documented with a `// SAFETY:` block; see `kernel/docs/hal-tcb.md` (§2g). The
//! public surface is **safe**:
//!
//! - [`init`] — unmask IRQ1 on the PIC (call after [`crate::pic::init`], with
//!   the line's vector-33 handler already registered).
//! - [`on_irq`] — the body of the IRQ1 interrupt: read the scancode byte, hand it
//!   to the lock-free queue, and EOI. The kernel registers a one-line vector-33
//!   handler that calls this, so the privileged port read + EOI stay in the TCB.
//! - [`poll_scancode`] — drain one raw scancode byte from the queue (safe,
//!   lock-free); returns `None` when empty. The kernel polls this from its idle
//!   loop and does **all** decoding in `#![forbid(unsafe_code)]` code.
//!
//! # Why a raw-byte queue (not a decoded key)
//!
//! Scancode *decoding* — tracking the `0xE0` extended prefix, mapping make/break
//! codes to keys — is pure logic with no privilege, so it belongs in the safe
//! `kernel` crate. The TCB's only job is to drain the hardware byte promptly and
//! make it available without tearing. We therefore expose the *raw* bytes through
//! a tiny lock-free ring and keep the state machine out of the TCB entirely.
//!
//! # Concurrency model
//!
//! Identical in spirit to [`crate::pit`]: single-core at bring-up. [`on_irq`]
//! runs inside the IRQ1 interrupt gate (interrupts already masked), producing
//! into the ring; the kernel's idle loop consumes from it between `hlt`s. The
//! ring is a small SPSC (single-producer / single-consumer) buffer built from
//! plain atomics, so neither side needs `unsafe` and reads never tear.

use core::arch::asm;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

// ── I/O ports ──────────────────────────────────────────────────────────────

/// PS/2 controller data port. The scancode byte for IRQ1 is read here, and the
/// data half of a command (e.g. the new command byte) is written here.
const PS2_DATA: u16 = 0x60;
/// PS/2 controller status (read) / command (write) port.
const PS2_STATUS_CMD: u16 = 0x64;

/// Status-register bit 0: output buffer full (data available to read at `0x60`).
const STATUS_OUT_FULL: u8 = 1 << 0;
/// Status-register bit 1: input buffer full (do **not** write a port until clear).
const STATUS_IN_FULL: u8 = 1 << 1;

/// Controller command: read the "command byte" (configuration) → output buffer.
const CMD_READ_CONFIG: u8 = 0x20;
/// Controller command: write the next data byte as the new command byte.
const CMD_WRITE_CONFIG: u8 = 0x60;

/// Config-byte bit 0: enable the IRQ for the first PS/2 port (the keyboard's
/// IRQ1). Setting this is what makes the i8042 actually raise IRQ1 on a keypress.
const CONFIG_PORT1_IRQ: u8 = 1 << 0;
/// Config-byte bit 4: first-port clock **disable**. We clear it to keep the
/// keyboard port enabled.
const CONFIG_PORT1_CLOCK_DISABLE: u8 = 1 << 4;

/// IRQ line the PS/2 keyboard is wired to (IRQ1 on the master PIC).
pub const IRQ_KEYBOARD: u8 = 1;

/// Vector IRQ1 lands on after the PIC remap (`PIC1_OFFSET + 1` = `0x21`).
pub const VECTOR_KEYBOARD: u8 = crate::pic::PIC1_OFFSET + IRQ_KEYBOARD;

// ── Lock-free raw-scancode ring (SPSC) ──────────────────────────────────────

/// Capacity of the raw-scancode ring. A power of two so the index wraps with a
/// mask. 32 bytes is far more than a single idle-loop interval can accumulate at
/// human typing rates; an overrun simply drops the oldest unread byte.
const RING_LEN: usize = 32;

/// The raw scancode bytes, one slot each. Each is an independent [`AtomicU8`] so
/// a producer store and a consumer load on different slots never tear and need no
/// `unsafe`. Slots are addressed modulo [`RING_LEN`] by the head/tail indices.
static RING: [AtomicU8; RING_LEN] = [const { AtomicU8::new(0) }; RING_LEN];

/// Producer index (next slot the IRQ handler will write). Monotonic; masked into
/// `0..RING_LEN` at use.
static HEAD: AtomicUsize = AtomicUsize::new(0);
/// Consumer index (next slot the kernel will read). Monotonic; masked at use.
static TAIL: AtomicUsize = AtomicUsize::new(0);

/// Read a byte from the given x86 I/O port.
///
/// # Safety
///
/// The caller must ensure `port` names a register that is safe to read. The only
/// call site reads the PS/2 data port (`0x60`), draining the controller's output
/// buffer — a pure device read with no memory-safety-relevant side effect.
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
/// `value`. The only call sites write the PS/2 command port (`0x64`) and data
/// port (`0x60`) during [`init`] to program the i8042 configuration byte — a
/// device-only effect.
#[inline]
unsafe fn outb(port: u16, value: u8) {
    // SAFETY: `out dx, al` writes the byte in `al` to the I/O port in `dx`. The
    // contract that `port`/`value` are a valid, write-safe PS/2 register pair is
    // delegated to this function's `# Safety` section and upheld by every caller,
    // which programs only `0x60`/`0x64` with documented i8042 command/config
    // values. The instruction touches no memory (`nomem`) and no stack
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
        // port with no side effects relevant to memory safety. `inb`'s contract
        // (valid, read-safe port) holds.
        let status = unsafe { inb(PS2_STATUS_CMD) };
        if status & STATUS_IN_FULL == 0 {
            return;
        }
        core::hint::spin_loop();
    }
}

/// Spin (bounded) until the controller's output buffer is full, so a read of the
/// data port returns the byte we asked for (e.g. the config byte). Bounded for
/// the same robustness reason as [`wait_input_empty`].
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

/// Push one raw scancode byte into the ring (producer side).
///
/// Called only from [`on_irq`] (the IRQ1 handler), so there is exactly one
/// producer. If the ring is full the oldest unread byte is dropped (the consumer
/// advances), which is acceptable: at human typing rates the idle loop drains far
/// faster than keys arrive, and dropping a stale byte is better than blocking an
/// interrupt handler. No `unsafe`: every slot is an independent atomic.
fn ring_push(byte: u8) {
    let head = HEAD.load(Ordering::Relaxed);
    let tail = TAIL.load(Ordering::Acquire);
    let next = head.wrapping_add(1);
    if next.wrapping_sub(tail) > RING_LEN {
        // Full: drop the oldest by advancing the consumer index past it.
        TAIL.store(tail.wrapping_add(1), Ordering::Release);
    }
    RING[head & (RING_LEN - 1)].store(byte, Ordering::Relaxed);
    // Publish the byte: the Release pairs with the consumer's Acquire load of HEAD
    // so the stored byte is visible before the index advance.
    HEAD.store(next, Ordering::Release);
}

/// Drain one raw scancode byte from the ring, or `None` if empty (consumer side).
///
/// Safe, lock-free, and the **only** thing the kernel needs to read keyboard
/// input: it does all scancode decoding itself in safe code. Called from the
/// single consumer (the kernel idle loop).
#[must_use]
pub fn poll_scancode() -> Option<u8> {
    let tail = TAIL.load(Ordering::Relaxed);
    let head = HEAD.load(Ordering::Acquire);
    if tail == head {
        return None; // empty
    }
    let byte = RING[tail & (RING_LEN - 1)].load(Ordering::Relaxed);
    TAIL.store(tail.wrapping_add(1), Ordering::Release);
    Some(byte)
}

/// The body of the PS/2 keyboard (IRQ1 / vector `0x21`) interrupt.
///
/// **Always** reads the scancode byte from the data port first — the i8042 will
/// not raise another IRQ1 until its output buffer is drained — then enqueues the
/// byte for the kernel to decode and signals End-Of-Interrupt to the PIC. The
/// kernel registers a tiny safe `fn(&InterruptFrame)` for vector 33 that calls
/// this; keeping the port read + EOI here means the privileged work stays inside
/// the TCB while the kernel handler remains `unsafe`-free.
#[inline]
pub fn on_irq() {
    // SAFETY: reads the PS/2 controller data port (`0x60`), the documented place a
    // keyboard scancode is delivered for IRQ1. Draining it is mandatory (the i8042
    // stops raising IRQ1 until read) and is a pure device read that cannot alias or
    // corrupt Rust memory. `inb`'s safety contract (valid, read-safe port) holds.
    let scancode = unsafe { inb(PS2_DATA) };
    ring_push(scancode);
    // IRQ1 → master-PIC vector PIC1_OFFSET + 1 (0x21). EOI lets the PIC deliver
    // the next keystroke.
    crate::ioapic::device_eoi(VECTOR_KEYBOARD);
}

/// Discard a byte left in the i8042 output buffer, if any; returns whether one
/// was discarded.
///
/// Called once when device IRQs move from the 8259 to the IOAPIC (SMP 3b-ii):
/// IRQ1/IRQ12 are edge-triggered, so an edge raised while the old route was
/// masked and the new one not yet open is lost — and the i8042 raises no
/// further edge until its buffer is drained. Draining it here (the same policy
/// as `init`'s stale-byte drain) re-arms delivery at the cost of at most one
/// boot-time byte.
pub fn drain_stale_output() -> bool {
    // SAFETY: (K6) reads the i8042 status port (`0x64`) and, if its output
    // buffer is full, the data port (`0x60`) — pure device reads, exactly
    // `init`'s drain. Cannot alias Rust memory. `inb`'s contract holds.
    unsafe {
        if inb(PS2_STATUS_CMD) & STATUS_OUT_FULL != 0 {
            let _ = inb(PS2_DATA);
            return true;
        }
    }
    false
}

/// Program the i8042 controller to deliver keyboard interrupts, then unmask IRQ1.
///
/// Call once, on the boot core, **after** [`crate::pic::init`] (which remaps the
/// pair and masks every line) and after the kernel has registered the vector-33
/// handler — so no keystroke can arrive before its handler exists.
///
/// We cannot rely on the firmware having left the i8042 with keyboard interrupts
/// enabled, so we program the controller's configuration byte explicitly: read it
/// (command `0x20`), **set** the first-port interrupt-enable bit and **clear** the
/// first-port clock-disable bit, and write it back (command `0x60`). Without the
/// interrupt-enable bit the i8042 never raises IRQ1 and the keyboard appears dead.
/// Finally we drain any byte already sitting in the output buffer (so a stale byte
/// can't wedge delivery) and open IRQ1 on the PIC.
pub fn init() {
    // Read the current configuration byte: command 0x20, then read the data port.
    // SAFETY: writes the documented "read config byte" command (`0x20`) to the
    // i8042 command port (`0x64`) after waiting for the input buffer to clear,
    // then reads the resulting config byte from the data port (`0x60`) once the
    // output buffer is full. Both are device-only i8042 operations that cannot
    // alias or corrupt Rust memory; `inb`/`outb` contracts (valid PS/2 ports)
    // hold. Runs once on the boot core with interrupts disabled.
    let config = unsafe {
        wait_input_empty();
        outb(PS2_STATUS_CMD, CMD_READ_CONFIG);
        wait_output_full();
        inb(PS2_DATA)
    };

    // Enable IRQ1 (port-1 interrupt) and ensure the keyboard clock is enabled.
    let new_config = (config | CONFIG_PORT1_IRQ) & !CONFIG_PORT1_CLOCK_DISABLE;

    // Write the new configuration byte: command 0x60, then the byte on the data
    // port.
    // SAFETY: writes the documented "write config byte" command (`0x60`) to the
    // command port, then the new config byte to the data port, each after waiting
    // for the input buffer to clear. Device-only i8042 programming; the value only
    // toggles which interrupts the controller raises and which ports are clocked.
    // Cannot corrupt Rust memory. `outb`'s contract holds.
    unsafe {
        wait_input_empty();
        outb(PS2_STATUS_CMD, CMD_WRITE_CONFIG);
        wait_input_empty();
        outb(PS2_DATA, new_config);
    }

    // Drain any byte the controller may already be holding, so a stale byte does
    // not stop it from raising the next IRQ1.
    // SAFETY: if the output buffer is full, read one byte from the data port
    // (`0x60`) to clear it — a pure device read. `inb`'s contract holds.
    unsafe {
        if inb(PS2_STATUS_CMD) & STATUS_OUT_FULL != 0 {
            let _ = inb(PS2_DATA);
        }
    }

    // Open IRQ1 on the PIC so keyboard interrupts now reach the CPU.
    crate::pic::unmask_irq(IRQ_KEYBOARD);
}
