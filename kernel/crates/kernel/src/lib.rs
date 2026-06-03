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

// The kernel can heap-allocate (`Box`, `Vec`, `String`) once `memory::init` has
// installed the global allocator. Pulling in `alloc` here is what makes those
// types available to the safe kernel logic.
extern crate alloc;

pub mod interrupts;
pub mod memory;

/// Kernel entry point — called by `boot::_start` after serial initialisation.
///
/// All privileged setup (serial port I/O, CPU control) is performed by `hal`
/// before this runs. Never returns: it ends in [`hal::cpu::halt_loop`], enforced
/// statically by the `-> !` return type.
pub fn kmain() -> ! {
    // ARM the GDT + TSS + IDT **first**, so any fault during the banner or beyond
    // is caught and reported rather than causing a triple fault → silent reset.
    interrupts::init();

    // Bring up memory management: physical frame allocator + paging + kernel heap
    // + global allocator. After this the kernel can heap-allocate. Done before the
    // banner/draw so the heap is ready for everything that follows.
    memory::init_and_prove();

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

    // First *real* pixels: paint the "Cyber Dusk" boot screen onto the Limine
    // framebuffer. This runs AFTER the serial banner + end-marker above, so the
    // boot test sees `boot-bringup-ok` immediately and is never delayed by the
    // (slow, per-pixel) software rendering. If no framebuffer was provided, we
    // simply skip it and stay headless.
    if let Some(fb) = hal::framebuffer::get() {
        ui::draw_boot_screen(&fb);
    }

    hal::cpu::halt_loop()
}
