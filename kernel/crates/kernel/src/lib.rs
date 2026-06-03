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

    // One-shot runtime self-test of the live IDT: `int3` → #BP handler → resume.
    // Runs with interrupts still disabled (int3 is a software exception), so it
    // is independent of the hardware-IRQ wiring set up further below.
    interrupts::self_test();

    // Bring up the hardware-interrupt foundation: remap the 8259 PIC pair to
    // vectors 32–47, register the vector-32 timer handler, program the PIT to
    // ~100 Hz, and unmask IRQ0. Interrupts stay DISABLED until `sti` below — we
    // only enable them once every handler is registered.
    interrupts::init_timer();

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
    let framebuffer = hal::framebuffer::get();
    if let Some(fb) = framebuffer.as_ref() {
        ui::draw_boot_screen(fb);
    }

    // Now that every handler is registered, open the interrupt window. From here
    // the PIT fires IRQ0 (vector 32) at ~100 Hz; `hlt` in the idle loop wakes on
    // each tick. (Safe wrapper over `sti`; the IDT + handlers are all live.)
    hal::cpu::enable_interrupts();

    idle_loop(framebuffer.as_ref())
}

/// The kernel idle loop: park on `hlt` and tick the on-screen clock.
///
/// `hlt` halts the core until the next interrupt — the PIT timer wakes us ~100
/// times a second. Each wake we read the monotonic tick counter; when it crosses
/// a new whole second we derive `HH:MM:SS` (counting up from the boot screen's
/// 21:04:00) and redraw **only** the clock region (cheap), leaving the rest of
/// the Cyber Dusk screen untouched. Diverging (`-> !`): the kernel never returns.
fn idle_loop(fb: Option<&hal::framebuffer::Framebuffer>) -> ! {
    let tick_hz = hal::pit::TICK_HZ;
    // Seconds elapsed at the previous redraw; start at "none drawn yet" so the
    // first whole second triggers a draw.
    let mut last_secs: u64 = u64::MAX;

    loop {
        // Sleep until the next interrupt (the PIT tick, at minimum).
        hal::cpu::halt();

        let secs = hal::pit::ticks() / tick_hz;
        if secs == last_secs {
            continue; // still within the same wall-clock second
        }
        last_secs = secs;

        if let Some(fb) = fb {
            let (h, m, s) = wall_clock(secs);
            ui::draw_clock(fb, h, m, s);
        }
    }
}

/// Derive `HH:MM:SS` from whole seconds elapsed since boot, counting up from the
/// boot screen's start time (21:04:00) and wrapping at 24 h.
fn wall_clock(elapsed_secs: u64) -> (u8, u8, u8) {
    const DAY: u64 = 24 * 60 * 60;
    let start = (ui::CLOCK_START_H as u64 * 3600)
        + (ui::CLOCK_START_M as u64 * 60)
        + ui::CLOCK_START_S as u64;
    let t = (start + elapsed_secs) % DAY;
    let h = (t / 3600) as u8;
    let m = ((t % 3600) / 60) as u8;
    let s = (t % 60) as u8;
    (h, m, s)
}
