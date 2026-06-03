//! SentinelOS boot binary — the thin entry shim (part of the Trusted Computing Base).
//!
//! This is the *only* crate (besides `hal`) where the linker-facing attributes
//! `#[no_mangle]` and `#[link_section]` — which Rust classifies as `unsafe_code` —
//! are permitted. It is kept deliberately tiny: declare the Limine marker, define
//! `_start`, initialise serial via `hal`, then hand control to the safe
//! `kernel::kmain`. All real logic lives in the `kernel` crate (`forbid(unsafe_code)`).

#![no_std]
#![no_main]

use core::panic::PanicInfo;

/// Limine base-revision marker.
///
/// Limine scans the loaded image for this magic structure to learn which boot
/// protocol revision the kernel expects. `#[used]` keeps it from being stripped.
#[used]
static BASE_REVISION: limine::BaseRevision = limine::BaseRevision::new();

/// Kernel entry point. Limine jumps here after loading the image (it has already
/// set up a stack). We initialise the serial console, then enter the safe kernel.
#[no_mangle]
extern "C" fn _start() -> ! {
    hal::serial::init();
    kernel::kmain()
}

/// Panic handler: report over serial, then halt forever (last resort).
#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    hal::println!();
    hal::println!("!!! KERNEL PANIC !!!");
    if let Some(location) = info.location() {
        hal::println!(
            "  at {}:{}:{}",
            location.file(),
            location.line(),
            location.column()
        );
    }
    hal::println!("  {}", info.message());

    hal::cpu::halt_loop()
}
