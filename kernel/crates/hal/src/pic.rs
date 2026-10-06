//! 8259A Programmable Interrupt Controller (PIC) pair — part of the TCB.
//!
//! A PC exposes two cascaded 8259A PICs (a *master* at I/O ports `0x20/0x21`
//! and a *slave* at `0xA0/0xA1`). At power-on they deliver hardware IRQs 0–15 on
//! CPU vectors `0x08`–`0x0F` and `0x70`–`0x77` — and the first range
//! **collides** with the CPU's own exception vectors (0–31). Before we enable
//! maskable interrupts we therefore **remap** the two PICs so their 16 IRQ lines
//! land on vectors `0x20`–`0x2F` (32–47), clear of every CPU exception.
//!
//! This module is the only PIC owner in the TCB. Like [`crate::serial`] it does
//! raw x86 port I/O (`in`/`out`) through two private primitives, each documented
//! with a `# Safety` rustdoc section; see `kernel/docs/hal-tcb.md` (§2e) for the
//! registry. The public surface is **safe**:
//!
//! - [`init`] — remap the pair to `0x20`–`0x2F` and mask every line.
//! - [`unmask_irq`] — open a single IRQ line (e.g. IRQ0 for the PIT timer).
//! - [`mask_irq`] — close a single IRQ line.
//! - [`end_of_interrupt`] — signal EOI for a serviced vector (call from an IRQ
//!   handler before it returns), so the PIC will deliver further interrupts.
//!
//! # Concurrency model
//!
//! Identical to the serial driver: single-core at bring-up. [`init`] runs once
//! with interrupts disabled; [`end_of_interrupt`] runs inside an interrupt
//! handler (interrupts already masked by the interrupt gate). No SMP lock is
//! needed (that is a later concern).

use core::arch::asm;

// ── I/O ports ──────────────────────────────────────────────────────────────

/// Master PIC command port.
const PIC1_COMMAND: u16 = 0x20;
/// Master PIC data port (interrupt mask register when not mid-ICW sequence).
const PIC1_DATA: u16 = 0x21;
/// Slave PIC command port.
const PIC2_COMMAND: u16 = 0xA0;
/// Slave PIC data port.
const PIC2_DATA: u16 = 0xA1;

/// Vector the master PIC's IRQ0 is remapped to (IRQ0..7 → `0x20`..`0x27`).
pub const PIC1_OFFSET: u8 = 0x20;
/// Vector the slave PIC's IRQ8 is remapped to (IRQ8..15 → `0x28`..`0x2F`).
pub const PIC2_OFFSET: u8 = 0x28;

// ── 8259A command words ──────────────────────────────────────────────────────

/// ICW1: begin initialisation, expect ICW4 (cascade mode, edge-triggered).
const ICW1_INIT: u8 = 0x11; // 0x10 (INIT) | 0x01 (ICW4 will follow)
/// ICW4: 8086/88 mode (the only mode a modern PC uses).
const ICW4_8086: u8 = 0x01;
/// OCW2: non-specific End-Of-Interrupt command.
const PIC_EOI: u8 = 0x20;

/// Number of IRQ lines on the master before the cascade (the slave is wired to
/// the master's IRQ2).
const CASCADE_IRQ: u8 = 2;

/// Write a byte to the given x86 I/O port.
///
/// # Safety
///
/// Writing to an arbitrary I/O port can reconfigure hardware and is therefore
/// `unsafe`. The caller must ensure `port` names a PIC register that is safe to
/// write with `value`. All call sites in this module write only the two 8259A
/// command/data ports of the master and slave PICs.
#[inline]
unsafe fn outb(port: u16, value: u8) {
    // SAFETY: `out dx, al` writes the byte in `al` to the I/O port in `dx`. The
    // contract that `port`/`value` are a valid, write-safe PIC register pair is
    // delegated to this function's `# Safety` section and upheld by every
    // caller, which only programs the four PIC ports above. The instruction
    // touches no memory (`nomem`) and no stack (`nostack`).
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack));
    }
}

/// Read a byte from the given x86 I/O port.
///
/// # Safety
///
/// The caller must ensure `port` names a PIC register that is safe to read. All
/// call sites read only the master/slave PIC data ports (the interrupt mask
/// register), which is a pure device read.
#[inline]
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: `in al, dx` reads one byte from the I/O port in `dx` into `al`.
    // The contract that `port` is a valid, read-safe PIC register is delegated
    // to this function's `# Safety` section and upheld by every caller, which
    // only reads the master/slave data ports. The instruction touches no memory
    // (`nomem`) and uses no stack (`nostack`).
    unsafe {
        asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack));
    }
    value
}

/// Write to an I/O port and then waste a few cycles, so a slow PIC has settled
/// before the next command byte. Writing to the unused port `0x80` is the
/// canonical "I/O delay" idiom on PC hardware (it is harmless on QEMU and real
/// PCs alike).
///
/// # Safety
///
/// Same contract as [`outb`]: `port`/`value` must be a write-safe PIC register
/// pair. The extra write targets the conventional POST/diagnostic port `0x80`,
/// which has no functional side effect.
#[inline]
unsafe fn outb_wait(port: u16, value: u8) {
    // SAFETY: delegated to `outb` (PIC register write, upheld by callers), then
    // a single throwaway write to `0x80` — the standard I/O-delay port — whose
    // only effect is to consume bus cycles. Neither write touches Rust memory.
    unsafe {
        outb(port, value);
        outb(0x80, 0);
    }
}

/// Remap the master/slave 8259A pair to vectors `0x20`–`0x2F` and mask every
/// IRQ line.
///
/// Must be called **once**, on the boot core, with maskable interrupts disabled,
/// before `sti`. After it returns every hardware IRQ is masked; open the lines
/// you want with [`unmask_irq`]. Idempotent on QEMU's emulated 8259A.
///
/// Sequence (the standard 8259A ICW1..ICW4 programming for a cascaded pair):
/// 1. ICW1 — start init on both PICs.
/// 2. ICW2 — set each PIC's vector offset (`0x20` master, `0x28` slave).
/// 3. ICW3 — tell the master a slave is on IRQ2, and the slave its cascade id.
/// 4. ICW4 — select 8086 mode.
/// 5. Mask all lines (write `0xFF` to both data ports).
pub fn init() {
    // SAFETY: every `outb`/`outb_wait` below targets a documented 8259A
    // command/data port of the master (`0x20`/`0x21`) or slave (`0xA0`/`0xA1`)
    // PIC, with the standard ICW1..ICW4 values for a cascaded pair in 8086 mode.
    // The sequence only reprograms the two PIC devices (where their IRQ lines
    // vector and which lines are masked); it cannot alias or corrupt
    // Rust-managed memory. `init` runs once on the boot core with interrupts
    // disabled, so there is no concurrent PIC access. Each `outb`'s safety
    // contract (valid, write-safe PIC port) is therefore satisfied per call.
    unsafe {
        // ICW1: begin the initialisation sequence on both PICs.
        outb_wait(PIC1_COMMAND, ICW1_INIT);
        outb_wait(PIC2_COMMAND, ICW1_INIT);

        // ICW2: vector offset for each PIC.
        outb_wait(PIC1_DATA, PIC1_OFFSET);
        outb_wait(PIC2_DATA, PIC2_OFFSET);

        // ICW3: wire the cascade. Master: bitmask of the IRQ line the slave sits
        // on (IRQ2 → bit 2 → 0x04). Slave: its cascade identity (2).
        outb_wait(PIC1_DATA, 1 << CASCADE_IRQ);
        outb_wait(PIC2_DATA, CASCADE_IRQ);

        // ICW4: 8086/88 mode.
        outb_wait(PIC1_DATA, ICW4_8086);
        outb_wait(PIC2_DATA, ICW4_8086);

        // Mask every line on both PICs; callers open the ones they need.
        outb(PIC1_DATA, 0xFF);
        outb(PIC2_DATA, 0xFF);
    }
}

/// Unmask (enable) a single IRQ line, `0..=15`.
///
/// IRQ 0–7 live on the master, 8–15 on the slave. Clearing a bit in the
/// Interrupt Mask Register lets that line through. Out-of-range `irq` (`>= 16`)
/// is a no-op.
pub fn unmask_irq(irq: u8) {
    if irq >= 16 {
        return;
    }
    let (port, line) = if irq < 8 {
        (PIC1_DATA, irq)
    } else {
        (PIC2_DATA, irq - 8)
    };
    // SAFETY: reads then writes the master/slave PIC data port (the Interrupt
    // Mask Register), a documented 8259A register. We clear exactly one mask bit
    // (`line < 8`) and write the result back, which only enables delivery of one
    // IRQ line — a device-only effect that cannot corrupt Rust memory. `inb`/
    // `outb`'s contracts (valid, read/write-safe PIC port) hold.
    unsafe {
        let mask = inb(port);
        outb(port, mask & !(1 << line));
    }
}

/// Mask (disable) a single IRQ line, `0..=15`. Out-of-range `irq` is a no-op.
pub fn mask_irq(irq: u8) {
    if irq >= 16 {
        return;
    }
    let (port, line) = if irq < 8 {
        (PIC1_DATA, irq)
    } else {
        (PIC2_DATA, irq - 8)
    };
    // SAFETY: as in `unmask_irq`, but setting one mask bit. Reads then writes the
    // PIC Interrupt Mask Register; device-only effect, cannot corrupt memory.
    unsafe {
        let mask = inb(port);
        outb(port, mask | (1 << line));
    }
}

/// Mask **every** line on both PICs (IMR = `0xFF` on master and slave) — the
/// 8259 is retired once device IRQs are routed through the IOAPIC (SMP 3b-ii;
/// ACPI requires it when the MADT's `PCAT_COMPAT` flag is set).
pub fn mask_all() {
    // SAFETY: (P4) writes `0xFF` to the master and slave data ports (the IMRs),
    // exactly the final writes of `init` (P3). Device-only effect: no line can
    // raise an interrupt; cannot corrupt Rust memory. `outb`'s contract holds.
    unsafe {
        outb(PIC1_DATA, 0xFF);
        outb(PIC2_DATA, 0xFF);
    }
}

/// Read both Interrupt Mask Registers back: `(master, slave)`. Boot-proof
/// evidence that the 8259 is fully masked.
#[must_use]
pub fn masks() -> (u8, u8) {
    // SAFETY: (P1) reads the master and slave data ports (IMRs) — pure device
    // reads with no side effect. `inb`'s contract holds.
    unsafe { (inb(PIC1_DATA), inb(PIC2_DATA)) }
}

/// Signal End-Of-Interrupt for the vector currently being serviced.
///
/// Call this from an IRQ handler **before it returns**, passing the *vector*
/// number the handler ran for (e.g. `0x20` for the PIT/IRQ0). Without an EOI the
/// PIC will not deliver any further interrupt of equal or lower priority.
///
/// For a slave-PIC line (vectors `0x28`–`0x2F`) we must EOI **both** the slave
/// and the master, since the slave reaches the CPU through the master's
/// cascade. Vectors outside the remapped PIC range are ignored.
pub fn end_of_interrupt(vector: u8) {
    // Only PIC-remapped vectors (0x20..=0x2F) carry an EOI obligation.
    if !(PIC1_OFFSET..PIC1_OFFSET + 16).contains(&vector) {
        return;
    }
    let from_slave = vector >= PIC2_OFFSET;
    // SAFETY: writes the non-specific EOI command (OCW2 = 0x20) to the master
    // command port, and additionally to the slave command port when the serviced
    // vector belongs to a slave line. Both are documented 8259A command ports;
    // an EOI only tells the PIC the interrupt has been handled (device-only
    // effect) and cannot corrupt Rust memory. `outb`'s contract holds.
    unsafe {
        if from_slave {
            outb(PIC2_COMMAND, PIC_EOI);
        }
        outb(PIC1_COMMAND, PIC_EOI);
    }
}
