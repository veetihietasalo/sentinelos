//! Safe interrupt registration API — the bridge from the `unsafe` ISR stubs to
//! safe handler code in the `kernel` crate.
//!
//! # Why this module exists
//!
//! The raw ISR stubs and the IDT live in [`crate::idt`] (unsafe, TCB). The
//! handler *logic* — printing a fault report, deciding to halt — wants to live
//! in the `kernel` crate, which carries `#![forbid(unsafe_code)]`. If the stubs
//! called `kernel` directly we would need a `hal → kernel` dependency, creating
//! a cycle (`kernel → hal → kernel`).
//!
//! Instead, `hal` owns a **static table of handler function pointers**, one per
//! vector. The `kernel` crate registers a plain safe `fn(&InterruptFrame)` for
//! each vector it cares about via [`set_handler`]; the trampoline in
//! [`crate::idt`] looks the pointer up and calls through it. No `hal → kernel`
//! edge is needed, and the dependency direction stays one-way (`kernel → hal`).
//!
//! # Public contract (consumed by the `kernel` crate)
//!
//! - [`init`] — load the GDT+TSS+IDT (call once, on the boot path).
//! - [`set_handler`] — register a handler `fn(&InterruptFrame)` for a vector.
//! - [`InterruptFrame`] — the `#[repr(C)]` view the trampoline builds and hands
//!   to a handler (vector, error code, saved registers, `rip`/`cs`/`rflags`/…).
//! - [`Handler`] — the handler function-pointer type alias.
//!
//! All items here are **safe**; the only `unsafe` is confined to [`crate::idt`]
//! and [`crate::gdt`].

use core::sync::atomic::{AtomicPtr, Ordering};

/// Number of IDT vectors (and handler-table slots).
pub const VECTOR_COUNT: usize = 256;

/// The general-purpose register snapshot captured by the ISR stub at the moment
/// of the fault, in the order the stub pushes them.
///
/// `#[repr(C)]` so the field order is the wire format the assembly stub builds;
/// the trampoline overlays an `&InterruptFrame` directly onto the stub's stack
/// frame, so this layout must match the push order in [`crate::idt`]'s stubs
/// exactly. Do not reorder without updating the stubs.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SavedRegisters {
    /// `r15` at fault time.
    pub r15: u64,
    /// `r14` at fault time.
    pub r14: u64,
    /// `r13` at fault time.
    pub r13: u64,
    /// `r12` at fault time.
    pub r12: u64,
    /// `r11` at fault time.
    pub r11: u64,
    /// `r10` at fault time.
    pub r10: u64,
    /// `r9` at fault time.
    pub r9: u64,
    /// `r8` at fault time.
    pub r8: u64,
    /// `rbp` at fault time.
    pub rbp: u64,
    /// `rdi` at fault time.
    pub rdi: u64,
    /// `rsi` at fault time.
    pub rsi: u64,
    /// `rdx` at fault time.
    pub rdx: u64,
    /// `rcx` at fault time.
    pub rcx: u64,
    /// `rbx` at fault time.
    pub rbx: u64,
    /// `rax` at fault time.
    pub rax: u64,
}

/// The complete view of an interrupt/exception as assembled by the ISR stub and
/// passed to a handler.
///
/// `#[repr(C)]` and field order are load-bearing: the trampoline in
/// [`crate::idt`] forms an `&InterruptFrame` pointing straight at the stub's
/// stack. From the lowest address upward the stub lays out: the saved GP
/// registers, then the vector number, then the error code, then the
/// CPU-pushed interrupt frame (`rip`, `cs`, `rflags`, `rsp`, `ss`).
///
/// For vectors that the CPU does not push an error code for, the stub pushes a
/// synthetic `0`, so [`error_code`](Self::error_code) is always well-defined.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct InterruptFrame {
    /// General-purpose registers saved by the stub (pushed first, lowest addr).
    pub registers: SavedRegisters,
    /// The interrupt/exception vector number (0–255).
    pub vector: u64,
    /// The CPU error code, or a synthetic `0` for vectors that push none.
    pub error_code: u64,
    /// Instruction pointer at the point of the fault (where `iretq` returns to).
    pub rip: u64,
    /// Code segment selector at fault time.
    pub cs: u64,
    /// Flags register at fault time.
    pub rflags: u64,
    /// Stack pointer at fault time.
    pub rsp: u64,
    /// Stack segment selector at fault time.
    pub ss: u64,
}

/// The type of a registered interrupt handler.
///
/// A handler receives an immutable view of the fault and runs in **safe** Rust.
/// At this slice handlers are expected to report and then halt (they may diverge
/// by calling [`crate::cpu::halt_loop`]); resumable handlers are additive later.
pub type Handler = fn(&InterruptFrame);

/// One slot per vector, each an atomically-swappable handler pointer.
///
/// We store the `fn` pointer as a type-erased `*mut ()` inside an [`AtomicPtr`]
/// so the table is a plain `static` (no `unsafe`, no interior-mutability crate)
/// and so the trampoline reads it without tearing. A null pointer means
/// "no handler registered" → the default behaviour applies.
static HANDLERS: [AtomicPtr<()>; VECTOR_COUNT] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; VECTOR_COUNT];

/// Register `handler` as the handler for `vector`.
///
/// Overwrites any previously-registered handler for that vector. Safe to call
/// from the `kernel` crate; typically called once per vector during early init,
/// after [`init`]. Thread-safe by construction (atomic store), though at this
/// slice the kernel is single-core and registration happens before any fault.
pub fn set_handler(vector: u8, handler: Handler) {
    // A `fn` pointer is a single non-null code address; cast it to `*mut ()` for
    // type-erased storage. This is a provenance-preserving fn→ptr cast, not a
    // data pointer dereference, so no `unsafe` is involved.
    let raw = handler as *mut ();
    HANDLERS[vector as usize].store(raw, Ordering::Release);
}

/// Look up the handler registered for `vector`, if any.
///
/// Returns `None` when no handler is registered (the slot is null), in which
/// case the caller applies the default behaviour.
pub(crate) fn handler_for(vector: u8) -> Option<Handler> {
    let raw = HANDLERS[vector as usize].load(Ordering::Acquire);
    if raw.is_null() {
        None
    } else {
        // SAFETY: `raw` is non-null and was produced *only* by [`set_handler`]
        // casting a valid `Handler` (`fn(&InterruptFrame)`) to `*mut ()`. We cast
        // it straight back to the identical fn-pointer type, recovering the exact
        // pointer that was stored. No data is dereferenced here; this is the
        // inverse of a sound fn→ptr→fn round-trip. `transmute` is the only way to
        // turn a data pointer back into a fn pointer in stable Rust.
        let handler: Handler = unsafe { core::mem::transmute::<*mut (), Handler>(raw) };
        Some(handler)
    }
}

/// Initialise the interrupt subsystem: load the GDT+TSS, then the IDT.
///
/// This is the single entry point the `kernel` crate calls (once, on the boot
/// path, with interrupts disabled). After it returns, CPU exceptions are routed
/// through the ISR stubs to any handlers registered via [`set_handler`], or to
/// the built-in default reporter if none is registered.
///
/// Order matters: the GDT (and its kernel-code selector) must be live before the
/// IDT, whose gate descriptors reference that selector, and before `ltr` arms
/// the IST stack the double-fault gate depends on.
pub fn init() {
    crate::gdt::init();
    crate::idt::init();
}
