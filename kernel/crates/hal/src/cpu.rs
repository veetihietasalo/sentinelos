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

/// Raise a breakpoint exception (`int3`, vector 3) on the current CPU.
///
/// `int3` is a one-byte software interrupt that traps to the IDT's vector-3
/// gate. It is the canonical way to *probe* a live IDT: if the breakpoint
/// handler runs and returns, the whole interrupt path is proven working. The
/// kernel uses this as a one-shot IDT self-test at boot.
///
/// This is a safe wrapper: triggering a breakpoint cannot, on its own, violate
/// Rust's memory-safety invariants. It is only meaningful once an IDT with a
/// resumable vector-3 handler is loaded; with no handler the `hal` default
/// reporter runs and halts (so it never silently corrupts state).
#[inline]
pub fn breakpoint() {
    // SAFETY: `int3` raises the breakpoint exception, vectoring through the IDT's
    // gate for vector 3. It accesses no program memory (`nomem`) and does not use
    // the stack from Rust's point of view beyond the CPU's own interrupt-frame
    // push, which the ISR stub balances (`nostack` is therefore appropriate for
    // the inline-asm boundary). Whether execution resumes depends on the
    // installed handler, but the instruction itself cannot create UB or corrupt
    // memory; at worst, with no handler, `hal`'s default reporter halts the core.
    unsafe {
        asm!("int3", options(nomem, nostack));
    }
}

/// Read `CR2`, the faulting linear address recorded on a page fault (`#PF`).
///
/// On a page fault (vector 14) the CPU latches the address whose translation
/// failed into the `CR2` control register. A `#PF` handler reads it to report
/// *which* address faulted. The value is only meaningful immediately inside a
/// page-fault handler, before any later memory access overwrites it.
///
/// This is a safe wrapper: reading `CR2` is a pure register read with no memory
/// effect and cannot, on its own, violate Rust's memory-safety invariants.
#[inline]
#[must_use]
pub fn read_cr2() -> u64 {
    let value: u64;
    // SAFETY: `mov {}, cr2` copies the 64-bit CR2 control register into a
    // general-purpose register. CR2 is readable at CPL 0 (the kernel always runs
    // ring 0 here); the read accesses no program memory (`nomem`), uses no stack
    // (`nostack`), and does not modify RFLAGS (`preserves_flags`). Reading a
    // control register cannot create undefined behaviour or affect memory
    // validity/aliasing — it only observes the last faulting linear address.
    unsafe {
        asm!("mov {}, cr2", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
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
