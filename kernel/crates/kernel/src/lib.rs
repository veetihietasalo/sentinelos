//! SentinelOS kernel — the safe kernel logic (`kmain`).
//!
//! This crate is the kernel proper, written entirely in **safe** Rust;
//! `#![forbid(unsafe_code)]` enforces that at compile time. All hardware access is
//! delegated to the [`hal`] crate.
//!
//! The Limine entry shim (`_start`), the protocol marker, and the panic handler
//! live in the thin `boot` binary crate — the only place where `#[no_mangle]` /
//! `#[link_section]` (which Rust classifies as `unsafe_code`) are permitted.
//! Together, `hal` plus `boot`'s tiny entry form the Trusted Computing Base.
//!
//! Boot flow:  Limine → `boot::_start` → `hal::serial::init()` → [`kmain`] → halt.

#![no_std]
#![forbid(unsafe_code)]

pub mod interrupts;

/// Kernel entry point — called by `boot::_start` after serial initialisation.
///
/// All privileged setup (serial port I/O, CPU control) is performed by `hal`
/// before this runs. Never returns: it ends in [`hal::cpu::halt_loop`], enforced
/// statically by the `-> !` return type.
pub fn kmain() -> ! {
    // ARM the GDT + TSS + IDT **first**, so any fault during the banner or beyond
    // is caught and reported rather than causing a triple fault → silent reset.
    interrupts::init();

    hal::println!("┌─────────────────────────────────────┐");
    hal::println!("│  SentinelOS — boot bring-up OK       │");
    // Use concat! to bake the version into a literal at compile time, avoiding
    // any runtime format-argument machinery (and the GOT-relative vtable calls
    // it generates) that would fault on a bare-metal target without an IDT.
    hal::println!(concat!(
        "│  version ",
        env!("CARGO_PKG_VERSION"),
        "  (stable Rust, no_std)   │"
    ));
    hal::println!("│  serial console: COM1                │");
    hal::println!("└─────────────────────────────────────┘");
    hal::println!("[sentinelos] boot-bringup-ok; entering idle");

    hal::cpu::halt_loop()
}
