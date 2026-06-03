//! CPU exception handlers — the safe kernel side of sub-project #2a.
//!
//! This module registers handler functions for the four most-critical CPU
//! exception vectors and calls [`hal::interrupts::init`] to arm the GDT, TSS,
//! and IDT. Everything here is **safe** Rust; the raw ISR stubs and descriptor
//! table loads live in `hal` (the TCB).
//!
//! # Vectors handled
//!
//! | Vector | Mnemonic | Policy |
//! |--------|----------|--------|
//! | 3      | #BP Breakpoint     | Print RIP, then **return** (execution resumes after `int3`). |
//! | 8      | #DF Double Fault   | Print + [`hal::cpu::halt_loop`]. |
//! | 13     | #GP General Protection | Print error code + RIP + [`hal::cpu::halt_loop`]. |
//! | 14     | #PF Page Fault     | Decode error-code bits, print, [`hal::cpu::halt_loop`]. |
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

// ── Handlers ─────────────────────────────────────────────────────────────────

/// Vector 3 — Breakpoint (`int3`).
///
/// Prints the faulting RIP and **returns**, allowing execution to resume at the
/// instruction following `int3`. This is the only non-fatal exception handler at
/// this slice; it is safe to return because the CPU pushed a resumable exception
/// frame and the ISR stub will `iretq` after we return.
fn handle_breakpoint(frame: &InterruptFrame) {
    // Copy the RIP out of the packed struct into a local before passing to
    // format machinery, to avoid a reference into a potentially-unaligned field.
    let rip = frame.rip;
    hal::println!("EXCEPTION: BREAKPOINT at rip={:#018x}", rip);
    // Return normally: the stub will `iretq` back to the instruction after `int3`.
}

/// Vector 8 — Double Fault.
///
/// The double-fault handler runs on the dedicated IST stack (armed by
/// `hal::gdt::init`), so it remains reachable even when the regular kernel stack
/// is corrupt. It reports and halts; recovery is not possible at this slice.
fn handle_double_fault(frame: &InterruptFrame) {
    let rip = frame.rip;
    hal::println!("EXCEPTION: DOUBLE FAULT at rip={:#018x}", rip);
    hal::cpu::halt_loop()
}

/// Vector 13 — General Protection Fault.
fn handle_general_protection(frame: &InterruptFrame) {
    let error_code = frame.error_code;
    let rip = frame.rip;
    hal::println!(
        "EXCEPTION: #GP error_code={:#x} rip={:#018x}",
        error_code,
        rip
    );
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
/// Decodes the CPU's error code and prints a human-readable fault summary.
/// Halts via [`hal::cpu::halt_loop`] — no recovery at this slice.
///
/// Note: CR2 (the faulting linear address) is not yet printed here because the
/// HAL has not yet exposed a safe `hal::cpu::read_cr2()` wrapper.
// TODO(#2a-polish): also print CR2 (faulting address) once hal::cpu::read_cr2() is exposed
fn handle_page_fault(frame: &InterruptFrame) {
    let error_code = frame.error_code;
    let rip = frame.rip;
    let description = decode_pf_error(error_code);
    hal::println!(
        "EXCEPTION: PAGE FAULT  error_code={:#x}  rip={:#018x}",
        error_code,
        rip
    );
    hal::println!("  fault type: {}", description);
    hal::cpu::halt_loop()
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
        assert_eq!(decode_pf_error(0b0_1000), "reserved-bit set in page table entry");
    }
}
