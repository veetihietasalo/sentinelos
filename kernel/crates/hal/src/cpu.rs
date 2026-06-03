//! CPU primitives — safe wrappers over privileged `x86_64` instructions.
//!
//! This module is part of the TCB. Each public function is a **safe** wrapper
//! around exactly one `unsafe` inline-assembly block, and every such block
//! carries a `// SAFETY:` justification. See `kernel/docs/hal-tcb.md` for the
//! registry of every `unsafe` operation in the HAL.

use core::arch::asm;

/// Disable maskable hardware interrupts on the current CPU (`cli`).
///
/// After this call returns, the CPU will not service maskable external
/// interrupts until interrupts are re-enabled (e.g. via `sti`, not yet exposed)
/// or the flags register is otherwise restored. Non-maskable interrupts (NMI)
/// and exceptions are unaffected.
///
/// This is a safe wrapper: clearing the interrupt flag cannot, on its own,
/// violate Rust's memory-safety invariants. It is exposed so that higher-level
/// safe code can establish short critical sections without `unsafe`.
#[inline]
pub fn disable_interrupts() {
    // SAFETY: `cli` clears the interrupt-enable flag (IF) in RFLAGS. It touches
    // no memory and reads/writes no general-purpose registers, so `nomem` and
    // `nostack` hold. It *does* modify RFLAGS.IF, so `preserves_flags` is NOT
    // set. Disabling interrupts cannot create undefined behaviour: it only
    // affects interrupt delivery timing, never memory validity or aliasing.
    unsafe {
        asm!("cli", options(nomem, nostack));
    }
}

/// Enable maskable hardware interrupts on the current CPU (`sti`).
///
/// After this call the CPU will (subject to the interrupt-shadow of `sti`)
/// service maskable external interrupts again. This is the inverse of
/// [`disable_interrupts`] and is used to re-open an interrupt window after a
/// critical section.
///
/// This is a safe wrapper: setting the interrupt flag cannot, on its own,
/// violate Rust's memory-safety invariants. Whether an interrupt *handler* is
/// safe to run is the responsibility of whoever installed the IDT (out of scope
/// for sub-project #1, where no interrupt handlers are installed).
#[inline]
pub fn enable_interrupts() {
    // SAFETY: `sti` sets the interrupt-enable flag (IF) in RFLAGS. It touches no
    // memory and no general-purpose registers, so `nomem`/`nostack` hold; it
    // modifies RFLAGS.IF so `preserves_flags` is NOT set. Enabling interrupt
    // delivery is not itself UB. (At bring-up no IDT/handlers exist, so this is
    // provided for completeness and symmetry; callers are responsible for IDT
    // state before relying on handler execution.)
    unsafe {
        asm!("sti", options(nomem, nostack));
    }
}

/// Halt the CPU until the next interrupt (`hlt`) — executed exactly once.
///
/// If interrupts are disabled this parks the core until an NMI or reset.
/// Prefer [`halt_loop`] for the "stop forever" use-case; this single-step
/// variant exists so callers can build their own idle loops.
#[inline]
pub fn halt() {
    // SAFETY: `hlt` places the CPU in a halted state until the next interrupt,
    // NMI, or reset. It accesses no memory and no registers (`nomem`/`nostack`)
    // and leaves RFLAGS untouched (`preserves_flags`). Halting cannot violate
    // memory safety; at worst, with interrupts masked, the core simply idles.
    unsafe {
        asm!("hlt", options(nomem, nostack, preserves_flags));
    }
}

/// Halt the CPU forever in a `hlt` loop and never return.
///
/// This is the canonical "we are done / nothing left to do" terminator for the
/// kernel: the boot path and the panic handler both end here. The loop re-issues
/// `hlt` after any wake (e.g. a spurious interrupt) so the core never spins hot
/// and never falls through.
///
/// The function is diverging (`-> !`); it is a safe wrapper because halting the
/// CPU has no effect on Rust's memory model.
#[inline]
pub fn halt_loop() -> ! {
    loop {
        // SAFETY: identical to [`halt`] — `hlt` idles the CPU until the next
        // interrupt/NMI/reset, accessing no memory or registers and preserving
        // RFLAGS. Re-halting on every wake keeps the core parked without UB.
        unsafe {
            asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
}
