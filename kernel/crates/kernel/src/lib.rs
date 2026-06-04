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

pub mod input;
pub mod interrupts;
pub mod memory;
pub mod shell;

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

    // Bring up memory management: physical frame allocator + paging + kernel heap
    // + global allocator. After this the kernel can heap-allocate. Done before the
    // banner/draw so the heap is ready for everything that follows.
    memory::init_and_prove();

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

/// The kernel idle loop: park on `hlt`, service keyboard input, and run the
/// lock-screen state machine to its desktop.
///
/// `hlt` halts the core until the next interrupt — the PIT wakes us ~100×/s, and
/// any keystroke (IRQ1) wakes us too. On each wake we:
///
/// 1. **Drain & decode keyboard input.** Pull every raw scancode byte the IRQ1
///    handler queued ([`hal::keyboard::poll_scancode`]) and feed it through the
///    safe [`input::ScancodeDecoder`]. While [`Locked`](input::LockState::Locked),
///    a right-arrow (or Enter) press starts the unlock.
/// 2. **Drive the state machine.**
///    - `Locked`: redraw the per-second clock and re-draw the gently pulsing
///      "press → to unlock" hint (driven by the tick counter).
///    - `Unlocking`: step the unlock animation by the elapsed ticks; when it
///      completes, paint the desktop **with the console panel**, initialise the
///      shell, and enter `Desktop`.
///    - `Desktop`: keep the top-bar clock ticking once per second, and drain
///      keyboard events into the [`shell::Shell`] — printable keys echo into the
///      console, Enter runs the command. The console is redrawn only when its
///      content changed or the cursor-blink phase flipped, so idle ticks stay
///      cheap.
///
/// Diverging (`-> !`): the kernel never returns.
fn idle_loop(fb: Option<&hal::framebuffer::Framebuffer>) -> ! {
    use input::{KeyEvent, LockState, ScancodeDecoder};
    use shell::Shell;

    let tick_hz = hal::pit::TICK_HZ;
    // Seconds elapsed at the previous clock redraw; "none drawn yet" so the first
    // whole second forces a draw.
    let mut last_secs: u64 = u64::MAX;
    // Last hint-pulse phase we drew, so we only repaint the hint when its
    // brightness step actually changes (keeps the locked screen cheap).
    let mut last_hint_phase: u64 = u64::MAX;
    // Last animation progress byte we drew, so we don't redraw an identical frame.
    let mut last_anim_p: i32 = -1;

    let mut decoder = ScancodeDecoder::new();
    let mut state = LockState::Locked;

    // The interactive shell — created (on the heap) the moment we reach the
    // desktop, so its banner appears under the freshly-drawn console panel. While
    // locked / unlocking it stays `None` and costs nothing.
    let mut shell: Option<Shell> = None;

    loop {
        // Sleep until the next interrupt (a PIT tick or a keystroke).
        hal::cpu::halt();

        // 1) Service all pending keyboard bytes through the safe decoder. While
        //    locked, the right-arrow (or Enter) starts the unlock; on the desktop
        //    every decoded event is fed to the shell.
        while let Some(scancode) = hal::keyboard::poll_scancode() {
            if let Some(event) = decoder.feed(scancode) {
                if state.accepts_unlock() {
                    let is_unlock =
                        matches!(event, KeyEvent::RightArrowPressed | KeyEvent::EnterPressed);
                    if is_unlock {
                        // Log via the fmt-arg-free helper (core::fmt int args fault
                        // on this target — see hal::serial::print_labeled_*).
                        hal::serial::print_line("[input] right-arrow -> unlocking");
                        state = LockState::Unlocking {
                            start_tick: hal::pit::ticks(),
                        };
                        // Force the first animation frame to draw on this pass.
                        last_anim_p = -1;
                    }
                } else if let (LockState::Desktop, Some(sh)) = (state, shell.as_mut()) {
                    // On the desktop: type into the shell. Printable keys echo,
                    // Enter runs the command; the redraw below paints the result.
                    sh.on_key(event);
                }
            }
        }

        let now = hal::pit::ticks();

        // 2) Advance whichever state we are in.
        match state {
            LockState::Locked => {
                // Per-second clock.
                let secs = now / tick_hz;
                if secs != last_secs {
                    last_secs = secs;
                    if let Some(fb) = fb {
                        let (h, m, s) = wall_clock(secs);
                        ui::draw_clock(fb, h, m, s);
                    }
                }
                // Pulse the hint. Quantise the phase to a handful of steps per
                // pulse so we redraw only when the brightness visibly changes.
                let phase = now % ui::HINT_PULSE_PERIOD_TICKS;
                let step = phase / (ui::HINT_PULSE_PERIOD_TICKS / 16).max(1);
                if step != last_hint_phase {
                    last_hint_phase = step;
                    if let Some(fb) = fb {
                        ui::draw_unlock_hint(fb, now);
                    }
                }
            }

            LockState::Unlocking { start_tick } => {
                let elapsed = now.saturating_sub(start_tick);
                if elapsed >= ui::UNLOCK_ANIM_TICKS {
                    // Animation done → arrive at the desktop. Paint the desktop
                    // chrome, then bring up the shell and draw its console panel
                    // on top, so unlock lands on a usable terminal.
                    let mut sh = Shell::new();
                    if let Some(fb) = fb {
                        ui::draw_desktop(fb);
                        // First console paint, with the caret shown.
                        sh.render(fb);
                    }
                    shell = Some(sh);
                    hal::serial::print_line("[input] unlock complete -> desktop");
                    hal::serial::print_line("[shell] ready");
                    state = LockState::Desktop;
                    last_secs = u64::MAX; // force the desktop clock to redraw
                } else {
                    // Map elapsed ticks → progress byte 0..=255 and draw the frame
                    // (only when the byte changes, so identical frames are skipped).
                    let p = (elapsed * 255 / ui::UNLOCK_ANIM_TICKS.max(1)).min(255) as i32;
                    if p != last_anim_p {
                        last_anim_p = p;
                        if let Some(fb) = fb {
                            ui::draw_unlock_frame(fb, p as u8);
                        }
                    }
                }
            }

            LockState::Desktop => {
                // Keep the top-bar clock ticking once per second.
                let secs = now / tick_hz;
                if secs != last_secs {
                    last_secs = secs;
                    if let Some(fb) = fb {
                        let (h, m, s) = wall_clock(secs);
                        ui::draw_desktop_clock(fb, h, m, s);
                    }
                }

                // Redraw the console only when its content actually changed (a
                // keystroke or command output). `draw_console` repaints the whole
                // glass panel — an expensive per-pixel pass under software
                // rendering — so triggering it on a timer (e.g. a blinking caret)
                // would repaint several times a second and visibly flicker. The
                // caret is therefore drawn solid, and a redraw happens only on a
                // content change.
                if let (Some(fb), Some(sh)) = (fb, shell.as_mut()) {
                    if sh.is_dirty() {
                        sh.render(fb);
                    }
                }
            }
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
