//! CPU exception handlers + hardware-IRQ wiring — the safe kernel side of
//! sub-projects #2 and #2a.
//!
//! This module registers handler functions for the four most-critical CPU
//! exception vectors plus the PIT timer IRQ, and calls [`hal::interrupts::init`]
//! to arm the GDT, TSS, and IDT. Everything here is **safe** Rust; the raw ISR
//! stubs, descriptor-table loads, PIC/PIT port I/O, and the `int3`/`sti`
//! instructions live in `hal` (the TCB).
//!
//! # Vectors handled
//!
//! | Vector | Mnemonic | Policy |
//! |--------|----------|--------|
//! | 3      | #BP Breakpoint     | Print RIP, then **return** (execution resumes after `int3`). |
//! | 8      | #DF Double Fault   | Print + [`hal::cpu::halt_loop`]. |
//! | 13     | #GP General Protection | Print error code + RIP + [`hal::cpu::halt_loop`]. |
//! | 14     | #PF Page Fault     | Decode error-code bits + CR2 faulting address, print, [`hal::cpu::halt_loop`]. |
//! | 32     | IRQ0 PIT timer     | Bump the tick counter + EOI, then **return** (resumes). |
//! | 33     | IRQ1 PS/2 keyboard | Drain the scancode byte into the ring + EOI, then **return** (resumes). |
//! | 44     | IRQ12 PS/2 mouse   | Drain a packet byte, reassemble the 3-byte packet into the ring + dual EOI, then **return** (resumes). |
//! | 255    | LAPIC spurious     | No-op **return** (a spurious interrupt owes no EOI); prevents a boot-halt once the LAPIC is software-enabled. |
//!
//! Vectors without a registered handler fall through to `hal`'s `default_handler`,
//! which already reports and halts — no action needed here.

use hal::interrupts::{Handler, InterruptFrame};

// ── Vector numbers ────────────────────────────────────────────────────────────

/// Vector 3: Breakpoint (`int3`).
const VECTOR_BREAKPOINT: u8 = 3;
/// Vector 8: Double Fault.
const VECTOR_DOUBLE_FAULT: u8 = 8;
/// Vector 13: General Protection Fault.
const VECTOR_GENERAL_PROTECTION: u8 = 13;
/// Vector 14: Page Fault.
const VECTOR_PAGE_FAULT: u8 = 14;
/// Vector 32 (`0x20`): IRQ0 — the PIT timer, after the PIC remap.
const VECTOR_TIMER: u8 = hal::pic::PIC1_OFFSET;
/// IRQ line the PIT is wired to (IRQ0).
const IRQ_TIMER: u8 = 0;
/// Vector 33 (`0x21`): IRQ1 — the PS/2 keyboard, after the PIC remap.
const VECTOR_KEYBOARD: u8 = hal::keyboard::VECTOR_KEYBOARD;
/// Vector 44 (`0x2C`): IRQ12 — the PS/2 mouse (slave PIC), after the PIC remap.
const VECTOR_MOUSE: u8 = hal::mouse::VECTOR_MOUSE;
/// Vector 255 (`0xFF`): the LAPIC spurious-interrupt vector (matches the SVR the
/// `hal::apic` x2APIC bring-up programs). A spurious interrupt is delivered when a
/// raised interrupt is de-asserted before the CPU acknowledges it; the correct
/// response is to **return without an EOI** (see [`handle_spurious`]).
const VECTOR_SPURIOUS: u8 = 0xFF;

// ── Handlers ─────────────────────────────────────────────────────────────────

/// Vector 3 — Breakpoint (`int3`).
///
/// Prints the faulting RIP and **returns**, allowing execution to resume at the
/// instruction following `int3`. This is the only non-fatal exception handler at
/// this slice; it is safe to return because the CPU pushed a resumable exception
/// frame and the ISR stub will `iretq` after we return.
fn handle_breakpoint(frame: &InterruptFrame) {
    // Copy the RIP out of the packed struct into a local first, to avoid a
    // reference into a potentially-unaligned field. Use the fmt-arg-free hex
    // printer: the exception path must not depend on `core::fmt`'s integer
    // argument machinery (see `hal::serial::print_labeled_hex`).
    let rip = frame.rip;
    hal::serial::print_labeled_hex("EXCEPTION: BREAKPOINT at rip=", rip);
    // Return normally: the stub will `iretq` back to the instruction after `int3`.
}

/// Vector 8 — Double Fault.
///
/// The double-fault handler runs on the dedicated IST stack (armed by
/// `hal::gdt::init`), so it remains reachable even when the regular kernel stack
/// is corrupt. It reports and halts; recovery is not possible at this slice.
fn handle_double_fault(frame: &InterruptFrame) {
    let rip = frame.rip;
    hal::serial::print_labeled_hex("EXCEPTION: DOUBLE FAULT at rip=", rip);
    hal::cpu::halt_loop()
}

/// Vector 13 — General Protection Fault.
fn handle_general_protection(frame: &InterruptFrame) {
    let error_code = frame.error_code;
    let rip = frame.rip;
    hal::serial::print_line("EXCEPTION: #GP (general protection)");
    hal::serial::print_labeled_hex("  error_code = ", error_code);
    hal::serial::print_labeled_hex("  rip        = ", rip);
    hal::cpu::halt_loop()
}

/// Decode the page-fault error-code bits into a short human-readable string.
///
/// Returns a `&'static str` chosen from the relevant bit-combination so the
/// fault path never allocates or formats dynamically, keeping the reporting path
/// panic-safe.
///
/// Bit layout (Intel/AMD64 manual):
/// - Bit 0 (`P`)    — 0 = non-present page, 1 = protection violation
/// - Bit 1 (`W`)    — 0 = read, 1 = write
/// - Bit 2 (`U`)    — 0 = supervisor, 1 = user
/// - Bit 3 (`RSVD`) — 1 = reserved-bit set in a page-table entry
/// - Bit 4 (`I/D`)  — 1 = instruction fetch
///
/// Only the low five bits are significant; higher bits (shadow-stack, SGX, etc.)
/// introduced in later Intel/AMD extensions are masked off and noted in the
/// returned string.
fn decode_pf_error(ec: u64) -> &'static str {
    // Mask to the five defined bits so the match is exhaustive over them. Higher
    // bits are silently ignored here; their presence is flagged in the returned
    // string only via the `has_extra` note appended at the call site if desired.
    // For simplicity we just decode the five canonical bits.
    let present = (ec & (1 << 0)) != 0;
    let write = (ec & (1 << 1)) != 0;
    let user = (ec & (1 << 2)) != 0;
    let rsvd = (ec & (1 << 3)) != 0;
    let fetch = (ec & (1 << 4)) != 0;

    if rsvd {
        // Reserved-bit violation trumps all other bits.
        return "reserved-bit set in page table entry";
    }

    if fetch {
        // Instruction-fetch fault; write bit is not meaningful here.
        return match (present, user) {
            (false, false) => "supervisor instr-fetch on non-present page",
            (false, true) => "user instr-fetch on non-present page",
            (true, false) => "supervisor instr-fetch protection violation",
            (true, true) => "user instr-fetch protection violation",
        };
    }

    // Data access fault (read or write).
    match (present, write, user) {
        (false, false, false) => "supervisor read on non-present page",
        (false, false, true) => "user read on non-present page",
        (true, false, false) => "supervisor read protection violation",
        (true, false, true) => "user read protection violation",
        (false, true, false) => "supervisor write on non-present page",
        (false, true, true) => "user write on non-present page",
        (true, true, false) => "supervisor write protection violation",
        (true, true, true) => "user write protection violation",
    }
}

/// Vector 14 — Page Fault.
///
/// Reads `CR2` (the faulting linear address the CPU latched on the fault),
/// decodes the error code, and prints a human-readable fault summary. Halts via
/// [`hal::cpu::halt_loop`] — no recovery at this slice.
///
/// `CR2` is read first thing, before any other memory access could clobber it.
fn handle_page_fault(frame: &InterruptFrame) {
    // Read CR2 immediately: it holds the faulting linear address and is only
    // valid until the next page fault overwrites it.
    let fault_addr = hal::cpu::read_cr2();
    let error_code = frame.error_code;
    let rip = frame.rip;
    let description = decode_pf_error(error_code);
    // Report via the fmt-arg-free path: an exception reporter must never depend
    // on `core::fmt`'s integer-argument machinery (which faults on this target).
    hal::serial::print_line("EXCEPTION: PAGE FAULT");
    hal::serial::print_labeled_hex("  error_code             = ", error_code);
    hal::serial::print_labeled_hex("  rip                    = ", rip);
    hal::serial::print_labeled_hex("  faulting address (CR2) = ", fault_addr);
    // `description` is a fixed `&'static str`; print it on its own labelled line.
    hal::serial::print_line("  fault type:");
    hal::serial::print_line(description);
    hal::cpu::halt_loop()
}

/// Vector 32 (IRQ0) — the PIT timer tick.
///
/// Delegates to [`hal::pit::on_tick`], which bumps the monotonic tick counter
/// and signals End-Of-Interrupt to the PIC. Returns normally so the interrupted
/// code resumes — this is a resumable handler like the breakpoint one. All the
/// privileged work (the PIC EOI port write) stays inside `hal`.
fn handle_timer(_frame: &InterruptFrame) {
    hal::pit::on_tick();
}

/// Vector 33 (IRQ1) — the PS/2 keyboard.
///
/// Delegates to [`hal::keyboard::on_irq`], which **must** read the scancode byte
/// from port `0x60` on every interrupt (the i8042 will not raise another IRQ1
/// until its output buffer is drained), enqueues the raw byte into a lock-free
/// ring for the kernel to decode, and signals End-Of-Interrupt to the PIC.
/// Returns normally so the interrupted code resumes. All the privileged work (the
/// port read + PIC EOI port write) stays inside `hal`; decoding happens in safe
/// code (`crate::input`) from the idle loop.
fn handle_keyboard(_frame: &InterruptFrame) {
    hal::keyboard::on_irq();
}

/// Vector 44 (IRQ12) — the PS/2 mouse (i8042 auxiliary device).
///
/// Delegates to [`hal::mouse::on_irq`], which **must** read the next packet byte
/// from port `0x60` on every interrupt (the i8042 will not raise another IRQ12
/// until its output buffer is drained), reassembles the 3-byte movement packet,
/// pushes a decoded `MouseEvent` into a lock-free ring for the kernel to consume,
/// and signals End-Of-Interrupt to **both** PICs (IRQ12 is a slave-PIC line).
/// Returns normally so the interrupted code resumes. All the privileged work (the
/// port read + dual PIC EOI) stays inside `hal`; cursor/window policy happens in
/// safe code (`crate::wm`) from the idle loop.
fn handle_mouse(_frame: &InterruptFrame) {
    hal::mouse::on_irq();
}

/// The NIC receive interrupt (vector = `PIC1_OFFSET + NIC IRQ line`).
///
/// Delegates to [`hal::e1000::on_irq`], which acks the device's interrupt-cause
/// register (read-to-clear) and signals End-Of-Interrupt to the PIC. The actual
/// received frames are drained by the idle loop via the safe
/// [`hal::e1000::poll_frame`]; the handler stays tiny (ack + EOI), keeping the
/// privileged MMIO/EOI work inside the TCB. Returns normally so the interrupted
/// code resumes.
fn handle_nic(_frame: &InterruptFrame) {
    hal::e1000::on_irq();
}

/// Vector 255 (`0xFF`) — the LAPIC spurious-interrupt vector.
///
/// Once `hal::apic` software-enables the Local APIC (x2APIC virtual-wire), a
/// spurious LAPIC interrupt can be delivered on this vector. Per the Intel SDM a
/// spurious interrupt requires **no** End-Of-Interrupt and the handler must simply
/// **return** (it does not set the LAPIC ISR). Without this handler the vector
/// would fall through to `hal`'s `default_handler`, which halts the core — a
/// latent boot-halt on real hardware. Returning normally makes it a no-op.
fn handle_spurious(_frame: &InterruptFrame) {
    // Intentionally empty: no EOI, just resume.
}

// ── Public initialisation ─────────────────────────────────────────────────────

/// Register CPU exception handlers and arm the GDT + TSS + IDT.
///
/// Must be called as the **very first statement** of [`crate::kmain`], before any
/// other kernel code, so that faults encountered during initialisation are caught
/// and reported rather than cascading into a triple fault.
///
/// Order:
/// 1. Register each exception handler via [`hal::interrupts::set_handler`].
/// 2. Call [`hal::interrupts::init`] to load the GDT + TSS + IDT.
///
/// Registering handlers before loading the IDT is safe: the stubs are not live
/// until `hal::interrupts::init` returns, so there is no window where a handler
/// could be called before it is registered.
pub fn init() {
    hal::interrupts::set_handler(VECTOR_BREAKPOINT, handle_breakpoint as Handler);
    hal::interrupts::set_handler(VECTOR_DOUBLE_FAULT, handle_double_fault as Handler);
    hal::interrupts::set_handler(
        VECTOR_GENERAL_PROTECTION,
        handle_general_protection as Handler,
    );
    hal::interrupts::set_handler(VECTOR_PAGE_FAULT, handle_page_fault as Handler);

    // Load GDT + TSS + IDT — from this point forward CPU exceptions are caught.
    hal::interrupts::init();
}

/// Run a one-shot runtime self-test of the live IDT by executing `int3`.
///
/// `int3` raises a breakpoint exception (vector 3), which the CPU vectors
/// through the just-loaded IDT to our [`handle_breakpoint`] handler. That
/// handler prints and **returns**, so the `int3` resumes normally — proving the
/// whole path (IDT gate → ISR stub → trampoline → registered handler → `iretq`)
/// is live. Call this **after** [`init`] but it does not require interrupts to
/// be enabled (`int3` is a software exception, not a maskable IRQ).
///
/// Emits a confirmation line over serial so the boot test can assert the IDT is
/// armed. Safe: `hal::cpu::breakpoint()` is a safe wrapper over the `int3`
/// instruction, and the breakpoint handler is resumable.
pub fn self_test() {
    hal::println!("[selftest] executing int3 to probe the live IDT ...");
    hal::cpu::breakpoint();
    hal::println!("[selftest] int3 -> #BP handler ran; IDT live");
}

/// Bring up the hardware-IRQ foundation: register the vector-32 (PIT),
/// vector-33 (PS/2 keyboard), and vector-44 (PS/2 mouse) handlers, remap the PIC
/// pair, program the PIT to ~100 Hz, and unmask IRQ0 + IRQ1 + IRQ12 (and the IRQ2
/// cascade the mouse's slave-PIC line needs).
///
/// Does **not** enable interrupts — the caller (`kmain`) must `sti` only after
/// every handler is registered. Order matters: remap the PIC (so the IRQs land on
/// vectors 32/33, clear of the CPU exceptions) before programming the PIT, and
/// register each handler **before** unmasking its line so no interrupt can arrive
/// before its handler exists.
pub fn init_timer() {
    // Register the vector-32 (timer), vector-33 (keyboard), and vector-44 (mouse)
    // handlers first, before any line is unmasked.
    hal::interrupts::set_handler(VECTOR_TIMER, handle_timer as Handler);
    hal::interrupts::set_handler(VECTOR_KEYBOARD, handle_keyboard as Handler);
    hal::interrupts::set_handler(VECTOR_MOUSE, handle_mouse as Handler);
    // Register the LAPIC spurious-interrupt handler (vector 0xFF) now, so it is
    // live before `kmain` software-enables the Local APIC (x2APIC): a spurious
    // LAPIC interrupt must return without an EOI rather than halt the core.
    hal::interrupts::set_handler(VECTOR_SPURIOUS, handle_spurious as Handler);

    // Remap the 8259A pair to vectors 32–47 (every line masked), then program
    // PIT channel 0 to ~100 Hz, then open IRQ0 (timer) and IRQ1 (keyboard).
    hal::pic::init();
    hal::pit::init();
    hal::pic::unmask_irq(IRQ_TIMER);
    hal::keyboard::init();
    // Bring up the PS/2 mouse: enable the i8042 aux device, start streaming, and
    // unmask IRQ12 + the IRQ2 cascade (so the slave PIC's lines reach the CPU).
    hal::mouse::init();
}

/// Register the NIC receive-interrupt handler and unmask its PIC line.
///
/// Call **after** the NIC has been initialised (`net::init` → `hal::e1000::init`),
/// which reads the NIC's IRQ line from PCI config space, and **before** `sti`.
/// The vector is `PIC1_OFFSET + irq`. If the NIC was not brought up
/// (`hal::e1000::irq()` returns the `0xFF` "none" sentinel) this is a no-op, so
/// a missing NIC never opens a stray PIC line.
///
/// Registering the handler before unmasking the line guarantees no NIC interrupt
/// can arrive before its handler exists.
pub fn init_nic_irq() {
    let irq = hal::e1000::irq();
    if irq == 0xFF || irq >= 16 {
        return; // NIC absent or an out-of-range (non-legacy) line — skip.
    }
    let vector = hal::e1000::vector_for(irq);
    hal::interrupts::set_handler(vector, handle_nic as Handler);
    hal::pic::unmask_irq(irq);
}

// ── Unit tests (host) ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::decode_pf_error;

    #[test]
    fn pf_non_present_read_supervisor() {
        assert_eq!(
            decode_pf_error(0b000_00),
            "supervisor read on non-present page"
        );
    }

    #[test]
    fn pf_non_present_write_user() {
        assert_eq!(decode_pf_error(0b0_0110), "user write on non-present page");
    }

    #[test]
    fn pf_protection_violation_write_supervisor() {
        assert_eq!(
            decode_pf_error(0b0_0011),
            "supervisor write protection violation"
        );
    }

    #[test]
    fn pf_instruction_fetch_present() {
        // P=1, W=0, U=0, RSVD=0, I/D=1
        assert_eq!(
            decode_pf_error(0b1_0001),
            "supervisor instr-fetch protection violation"
        );
    }

    #[test]
    fn pf_reserved_bit() {
        // RSVD=1 overrides all other bits
        assert_eq!(
            decode_pf_error(0b0_1000),
            "reserved-bit set in page table entry"
        );
    }
}
