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

/// Kernel version string, baked in at compile time.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Kernel entry point — called by `boot::_start` after serial initialisation.
///
/// All privileged setup (serial port I/O, CPU control) is performed by `hal`
/// before this runs. Never returns: it ends in [`hal::cpu::halt_loop`], enforced
/// statically by the `-> !` return type.
pub fn kmain() -> ! {
    hal::println!("┌─────────────────────────────────────┐");
    hal::println!("│  SentinelOS — boot bring-up OK       │");
    hal::println!("│  version {}  (stable Rust, no_std)   │", VERSION);
    hal::println!("│  serial console: COM1                │");
    hal::println!("└─────────────────────────────────────┘");

    hal::cpu::halt_loop()
}
