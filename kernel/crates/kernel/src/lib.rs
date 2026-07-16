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

pub mod app;
pub mod fs;
pub mod input;
pub mod interrupts;
pub mod memory;
pub mod ml;
pub mod net;
pub mod sched;
pub mod shell;
pub mod wm;

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

    // Bring up the cooperative kernel-thread scheduler (PR-A of
    // docs/specs/2026-07-15-scheduler-design.md): adopt this very call stack
    // (kmain) as the permanent idle task. Needs the heap (just brought up
    // above) for its `Box`/`BTreeMap`/`VecDeque` state; the actual boot proof
    // (spawning + interleaving real tasks) runs later, alongside the other
    // subsystem proofs — see `sched::prove_cooperative()` further down.
    sched::init();

    // Enable hardware W^X + user/kernel isolation (NX / SMEP / SMAP / UMIP) on
    // this CPU, gated on what it advertises via cpuid. Safe at this point: no
    // kernel page is user-accessible and no ring-3 code runs yet, so these add
    // faults only for accesses that never occur today. Done after paging/heap so
    // cpuid detection can allocate nothing and the write is on a live address
    // space. See docs/specs/2026-07-14-cpu-security-features-design.md.
    let sec = hal::cpu_security::enable();
    hal::println!(
        "[cpu-sec] enabled:{}{}{}{}",
        if sec.nx { " nx" } else { "" },
        if sec.smep { " smep" } else { "" },
        if sec.smap { " smap" } else { "" },
        if sec.umip { " umip" } else { "" },
    );

    // Enable AVX (YMM) vector state so the AI/ML compute path can use the AVX2
    // int8 GEMM kernel (gated on cpuid + this enablement). A no-op on a CPU without
    // xsave+avx, in which case the ml dispatch stays on the scalar reference. Must
    // run before `ml::prove()` below (and any other AVX use). See the SIMD design
    // doc + hal-tcb.md.
    if hal::simd::enable() {
        // Report each vector tier's boot self-test result (fmt-free — integer/format
        // `println!` faults on this target; see `memory.rs`). `ok` means the tier's
        // hand-written `asm!` kernel matched the scalar reference bit-for-bit on this
        // core and is live; `no` means absent or self-test-failed → it falls back.
        let yn = |ready: bool| if ready { "ok" } else { "no" };
        hal::serial::write_str("[simd] vector state enabled; int8 GEMM self-test: avx2=");
        hal::serial::write_str(yn(hal::simd::avx2_ready()));
        hal::serial::write_str(" avx512f=");
        hal::serial::write_str(yn(hal::simd::avx512_ready()));
        hal::serial::write_str(" avx512-vnni=");
        hal::serial::write_str(yn(hal::simd::avx512vnni_ready()));
        hal::serial::write_str("\n");
    } else {
        hal::println!("[simd] AVX not advertised; ML compute stays on the scalar tier");
    }

    // Bring up the hardware-interrupt foundation: remap the 8259 PIC pair to
    // vectors 32–47, register the vector-32 timer handler, program the PIT to
    // ~100 Hz, and unmask IRQ0. Interrupts stay DISABLED until `sti` below — we
    // only enable them once every handler is registered.
    interrupts::init_timer();

    // Enable the BSP's Local APIC in x2APIC mode (virtual-wire: the 8259 PIC still
    // delivers through LINT0=ExtINT) — the first step toward SMP. Then briefly open
    // the interrupt window to PROVE the PIT timer still ticks across the switch: a
    // broken virtual wire would stall here and fail the boot test, rather than
    // silently stopping the clock. See docs/specs/2026-07-14-smp-x2apic-design.md.
    match hal::apic::enable_bsp() {
        Some(apic_id) => {
            let start = hal::pit::ticks();
            hal::cpu::enable_interrupts();
            while hal::pit::ticks() < start + 3 {
                hal::cpu::halt();
            }
            hal::cpu::disable_interrupts();
            // Build the line with the fmt-free serial helpers: `println!("{}", n)`
            // faults on this target for INTEGER args (the GOT-relative vtable calls
            // `core::fmt` emits need `.got`/`.rela` the linker script discards; see
            // memory.rs / hal-tcb.md §5e). String-literal `println!` is fine, but
            // the dynamic apic id / cpu count / tick count must go through write_dec.
            hal::serial::write_str("[smp] x2APIC enabled; BSP apic id=");
            hal::serial::write_dec(apic_id as u64);
            hal::serial::write_str("; ");
            hal::serial::write_dec(hal::apic::logical_cpu_count() as u64);
            hal::serial::write_str(" logical CPU(s); timer live (");
            hal::serial::write_dec(hal::pit::ticks());
            hal::serial::write_str(" ticks)\n");
        }
        None => hal::println!("[smp] x2APIC not advertised; staying on legacy xAPIC/PIC"),
    }

    // Bring up the AI/ML COMPUTE path: turn the C1 cpuid detection (AMX / AVX-512)
    // into an actual quantized-inference primitive. Reports the detected hardware
    // tier vs. the active (implemented) tier and runs a real int8 GEMM as an
    // end-to-end proof. Pure safe Rust; the SIMD/AMX kernels are later phases.
    // See docs/specs/2026-07-14-aiml-inference-compute-design.md.
    ml::prove();
    // ...then run a real batched quantized 2-layer MLP forward pass over that same
    // path, proving end-to-end *inference* (quantize → GEMM → dequant → ReLU →
    // requant → GEMM) works in the booted kernel, not just a bare matrix multiply.
    ml::infer_prove();
    // ...and prove vector GEMM stays correct with interrupts ENABLED — the old
    // interrupts-off precondition is lifted now that handlers are vector-free
    // (CI-enforced) and isr_common per-IRQ-saves vector state. Runs GEMMs in a loop
    // with the PIT firing, then restores the interrupts-off boot state.
    ml::prove_interrupts_on();
    // ...then run the second inference workload: one full pre-norm quantized
    // transformer block (layernorm → multi-head attention → residual →
    // layernorm → FFN → residual), proving the int8 GEMM tiers in the
    // attention shapes too, plus the two new libm-free primitives softmax and
    // layernorm need. See docs/specs/2026-07-16-inference-workload2-design.md.
    ml::infer_block_prove();

    // Bring up NETWORKING: find + init the e1000 NIC (heap is ready), read its
    // MAC, set up RX/TX rings, then start the minimal ARP/IPv4/ICMP stack and
    // fire an ARP request + ICMP echo at the gateway as a TX proof. Degrades
    // gracefully — if no NIC is present this logs and continues, never breaking
    // the boot path. Done with interrupts still DISABLED.
    net::init();
    // Register the NIC's receive-interrupt handler and unmask its PIC line (a
    // no-op if no NIC came up). Must run before `sti`, after `net::init`.
    interrupts::init_nic_irq();

    // Bring up STORAGE: probe the legacy ATA disk and prove the on-disk
    // filesystem persists across reboots. This loads the filesystem image from
    // disk (or seeds + saves a fresh one), then writes a marker file so a second
    // boot on the same image can demonstrate the file survived. Degrades
    // gracefully — with no disk it logs and uses the in-memory seeded tree.
    fs::prove_persistence();

    // PR-A cooperative-scheduler boot proof (scheduler design doc, "Boot
    // proofs — PR-A"): spawn two kernel threads that print and voluntarily
    // yield in a fixed, small loop, and (as the idle task) yield until both
    // exit and the ready queue drains. Runs here, alongside the other
    // subsystem proofs, and BEFORE the closing banner/end-marker below (like
    // every other proof in `kmain`) so the boot test's log-polling loop — which
    // stops as soon as it sees the end-marker — cannot race ahead of it and
    // tear the VM down before it prints. `task_prologue` unconditionally opens
    // the interrupt window on the FIRST spawned task's first run — from that
    // point on, interrupts stay live for the remainder of `kmain` (nothing
    // turns them back off), and the timer (now wired to `sched::on_tick`,
    // PR-B) is already programmed + unmasked by this point, so this proof's
    // handful of print+yield rounds run under a genuinely live timer. Each
    // task's turn is a few instructions (print, then immediately
    // `yield_now()`), far shorter than one `TIME_SLICE_TICKS` quantum, so no
    // task is ever continuously `current` long enough to be preempted here —
    // the deterministic interleave holds regardless.
    sched::prove_cooperative();

    // PR-B **preemptive**-scheduler boot proof (scheduler design doc, "Boot
    // proofs — PR-B", the payoff): spawn a compute ("gemm") task that loops a
    // fixed int8 GEMM and a "spin" task that loops a counter — **neither ever
    // calls `yield_now`** — so only the timer can switch either of them away.
    // Runs after `prove_cooperative` has fully drained (so `ready`/`tasks`
    // start clean) and before the closing banner, same rationale as above.
    sched::prove_preemptive();

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
    // A no-op if the cooperative-scheduler proof above already opened it via
    // `task_prologue` (idempotent — `sti` when IF is already set changes nothing).
    hal::cpu::enable_interrupts();

    idle_loop(framebuffer.as_ref())
}

/// The kernel idle loop: park on `hlt`, service keyboard + mouse input, and run
/// the lock-screen state machine to its desktop.
///
/// `hlt` halts the core until the next interrupt — the PIT wakes us ~100×/s, and
/// any keystroke (IRQ1) or mouse packet (IRQ12) wakes us too. On each wake we:
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
///      console, Enter runs the command, and the Up/Down arrows recall command
///      history. The console is redrawn only when its content changed or the
///      cursor-blink phase flipped, so idle ticks stay cheap.
///
/// Diverging (`-> !`): the kernel never returns.
fn idle_loop(fb: Option<&hal::framebuffer::Framebuffer>) -> ! {
    use input::{KeyEvent, LockState, ScancodeDecoder};
    use wm::{WindowManager, WmAction};

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

    // The window manager — created (on the heap) the moment we reach the desktop,
    // seeded with one Terminal window so unlock still lands on a usable terminal.
    // While locked / unlocking it stays `None` and costs nothing.
    let mut wm: Option<WindowManager> = None;

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
                } else if let (LockState::Desktop, Some(manager)) = (state, wm.as_mut()) {
                    // On the desktop: route the event through the window manager.
                    // Tab cycles focus, Escape toggles the launcher, and any other
                    // key goes to the launcher (if open) or the focused app. Paint
                    // the result immediately so typing/cycling feels responsive.
                    if manager.on_key(event) == WmAction::Redraw {
                        if let Some(fb) = fb {
                            manager.composite(fb);
                        }
                    }
                }
            }
        }

        // 1b) Service all pending MOUSE packets the IRQ12 handler queued. Only the
        //     desktop cares about the pointer: each decoded packet moves the cursor
        //     (the WM clamps + damages it) and a left-click hit-tests for
        //     click-to-focus. We composite once after draining the batch so a burst
        //     of motion packets coalesces into a single repaint. The privileged
        //     port read lives in `hal::mouse`; everything here is safe policy.
        if let (LockState::Desktop, Some(manager)) = (state, wm.as_mut()) {
            let mut moved = false;
            while let Some(ev) = hal::mouse::poll_event() {
                if manager.on_mouse(ev.dx, ev.dy, ev.buttons) == WmAction::Redraw {
                    moved = true;
                }
            }
            if moved {
                if let Some(fb) = fb {
                    manager.composite(fb);
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
                    // chrome, then bring up the window manager seeded with one
                    // Terminal window and composite it on top, so unlock lands on
                    // a usable terminal (preserving today's UX).
                    let (sw, sh_px) = fb.map_or((0, 0), |f| (f.width(), f.height()));
                    let mut manager = WindowManager::new(sw, sh_px);
                    manager.spawn(app::AppKind::Terminal);
                    if let Some(fb) = fb {
                        ui::draw_desktop(fb);
                        // First composite: paints the seeded Terminal window.
                        manager.composite(fb);
                    }
                    wm = Some(manager);
                    hal::serial::print_line("[input] unlock complete -> desktop");
                    hal::serial::print_line("[wm] desktop ready");
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

                // Drive the apps' periodic ticks (the System panel self-refreshes
                // once a second; the Terminal blinks its caret), then composite —
                // but only the damaged windows, and only when something is dirty,
                // so idle ticks stay cheap (no full-screen repaint per frame).
                if let Some(manager) = wm.as_mut() {
                    let ticked = manager.tick(now) == WmAction::Redraw;
                    if let Some(fb) = fb {
                        if ticked || !manager.is_clean() {
                            manager.composite(fb);
                        }
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
