//! HAL — Hardware Abstraction Layer (the SentinelOS TCB).
//!
//! This is the **only** crate in `crates/` permitted to use `unsafe`; it is the
//! entire Trusted Computing Base for kernel bring-up (sub-project #1). Every
//! capability that needs a privileged instruction or raw device access is
//! confined here and re-exported behind a **safe** API, so that the `kernel`
//! crate can carry `#![forbid(unsafe_code)]`.
//!
//! `hal` is a pure library of safe primitives: it deliberately does **not**
//! define `_start` or a `#[panic_handler]`. The boot entry point and panic
//! handler live in the `kernel` crate, which keeps the dependency edge
//! one-directional (`kernel` → `hal`) and avoids a cycle.
//!
//! # Modules
//!
//! - [`serial`] — a 16550 UART driver on COM1 (`0x3F8`) with a global console
//!   and the [`print!`] / [`println!`] macros.
//! - [`cpu`] — safe wrappers over `hlt`, `cli`, and `sti`.
//! - [`gdt`] — the 64-bit GDT + TSS with an IST double-fault stack (`lgdt`/`ltr`).
//! - [`idt`] — the 256-entry IDT and the raw ISR entry stubs (`lidt`).
//! - [`interrupts`] — the **safe** registration API ([`interrupts::init`],
//!   [`interrupts::set_handler`], [`interrupts::InterruptFrame`]) the `kernel`
//!   crate uses to hook exception handlers without a `hal → kernel` cycle.
//!
//! # `unsafe` discipline
//!
//! Every `unsafe` block in this crate carries a `// SAFETY:` comment, and every
//! distinct `unsafe` operation is registered in `kernel/docs/hal-tcb.md` with
//! its justification and verification status. The crate denies any *implicit*
//! unsafety lints so that new unsafe code is always a deliberate, documented act.
//!
//! # Stable API contract (consumed by the `kernel` crate)
//!
//! - [`println!`] / [`print!`]
//! - [`serial::init`]
//! - [`cpu::halt_loop`]
//! - [`cpu::disable_interrupts`]
//! - [`interrupts::init`] — load GDT+TSS+IDT (call once at boot).
//! - [`interrupts::set_handler`] — register a `fn(&InterruptFrame)` for a vector.
//! - [`interrupts::InterruptFrame`] — the `#[repr(C)]` fault view passed to a
//!   handler (vector, error code, saved registers, `rip`/`cs`/`rflags`/…).
//! - [`interrupts::Handler`] — the handler function-pointer type.

#![no_std]
// `unsafe` is permitted in this crate (and only this crate), but it must always
// be explicit and documented. These lints make undocumented or accidental
// unsafety a hard error rather than a silent allowance.
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
#![warn(clippy::undocumented_unsafe_blocks)]

pub mod cpu;
pub mod gdt;
pub mod idt;
pub mod interrupts;
pub mod serial;
