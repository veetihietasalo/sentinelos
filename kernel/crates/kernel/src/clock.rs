//! Core-independent monotonic clock (SMP phase 3b-i; component-model spec §14
//! PR-1b; retires `hal-tcb.md` invariant 4.15's precondition).
//!
//! # Why
//!
//! The PIT wall clock (`hal::pit::ticks`) advances only when the **BSP**
//! services IRQ0. A BSP spinning with `IF = 0` while waiting on work on another
//! core therefore froze the very clock that work was timing itself against: a
//! mutual wait, seen once as a silent hang (invariant 4.15). Capability expiry
//! and reply timeouts (component PR-2) must never hang off a counter one core
//! can stall.
//!
//! # What
//!
//! [`mono_ticks`] is a monotonic tick count at [`TICK_HZ`] that advances
//! whenever **any** core's scheduler tick lands:
//!
//! - every core keeps a per-core count of its own ticks, **aligned** to the
//!   global clock on its first tick (`base = mono` then), so cores that started
//!   their timers at different times agree to within a tick or two;
//! - the global clock is the `max` over cores of `base + local`, maintained with
//!   `fetch_max`, so it never goes backwards and advances by at most one per
//!   tick ([`advance`], proven in `proofs`);
//! - a stalled core (IF = 0, or halted) simply stops contributing; the others
//!   carry the clock. Only when *no* core ticks does it stop — which is the
//!   single-core situation the PIT already had.
//!
//! The PIT stays the wall clock for uptime display and the LAPIC calibration
//! reference. `hal::pit::ticks` and `mono_ticks` run at the same nominal rate;
//! they differ by start offset only.
//!
//! # Feeding it
//!
//! [`on_tick`] is called from the tick ISRs in `kernel::interrupts`: the
//! per-core LAPIC timer (vector 0xF1) on every core once phase 3 is live, or
//! the PIT path on the BSP alone before that. Zero `hal` delta: two atomics.
//!
//! # Proof
//!
//! [`prove_mono`] prints, for `cargo xtask test` to assert:
//!
//! ```text
//! [clock] mono: source=lapic cores=4 ticking=4 lag-max=110 pit-frozen=yes bsp-stalled-advance=yes rate=20/20 rate-ok=yes ok
//! ```
//!
//! `pit-frozen=yes bsp-stalled-advance=yes` is the payoff: with the BSP's
//! interrupts **disabled**, the PIT did not move and the monotonic clock did —
//! the application processors carried it. `lag-max` is the largest distance any
//! core's own aligned count has fallen behind the clock; in practice that is
//! the **BSP**, which loses a tick for every period it spends with `IF = 0`
//! during the boot proofs (a periodic LAPIC interrupt held pending collapses to
//! one). A core that stalls simply stops contributing and stays behind; the
//! clock does not — which is the whole point. It is reported, not asserted.

use core::sync::atomic::{AtomicU64, Ordering};
use hal::smp::MAX_CPUS;

/// Nominal rate of [`mono_ticks`]: the scheduler tick rate.
pub const TICK_HZ: u64 = crate::interrupts::SCHED_TICK_HZ;

/// One core's contribution: `base` (the global clock at its first tick) plus
/// `local` (its own ticks since). Only that core writes either.
struct CoreClock {
    base: AtomicU64,
    local: AtomicU64,
}

impl CoreClock {
    const fn new() -> Self {
        Self {
            base: AtomicU64::new(0),
            local: AtomicU64::new(0),
        }
    }
}

static CORES: [CoreClock; MAX_CPUS] = [const { CoreClock::new() }; MAX_CPUS];
static MONO: AtomicU64 = AtomicU64::new(0);

/// The pure step: the clock after one tick on a core whose aligned count is
/// now `core_value = base + local`. `max`, so never backwards; and because
/// every core's value was `<= mono` before its own increment, at most `+1`.
/// Production performs exactly this step atomically (`AtomicU64::fetch_max` in
/// [`on_tick`]); the host tests and the Kani harness exercise the pure model.
#[cfg_attr(not(any(test, kani)), allow(dead_code))]
pub(crate) fn advance(mono: u64, core_value: u64) -> u64 {
    mono.max(core_value)
}

/// Record one scheduler tick on dense cpu `cpu`. ISR context on that core.
pub fn on_tick(cpu: usize) {
    let Some(core) = CORES.get(cpu) else {
        return;
    };
    let local = core.local.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
    if local == 1 {
        // First tick on this core: align to the global clock so cores that
        // started at different times agree to within a tick.
        core.base
            .store(MONO.load(Ordering::Acquire), Ordering::Relaxed);
    }
    let value = core.base.load(Ordering::Relaxed).wrapping_add(local);
    MONO.fetch_max(value, Ordering::AcqRel);
}

/// The monotonic tick count. Any context, any core; a single atomic load.
#[must_use]
pub fn mono_ticks() -> u64 {
    MONO.load(Ordering::Acquire)
}

/// Dense cpu `cpu`'s aligned count (`base + local`), or `None` if it has never
/// ticked.
#[must_use]
pub fn core_value(cpu: usize) -> Option<u64> {
    let core = CORES.get(cpu)?;
    let local = core.local.load(Ordering::Relaxed);
    if local == 0 {
        return None;
    }
    Some(core.base.load(Ordering::Relaxed).wrapping_add(local))
}

/// How many cores have ticked at least once, and the largest lag of any such
/// core's aligned count behind the global clock, in ticks (see the module docs
/// on `lag-max`: mostly the BSP's lost `IF = 0` ticks).
#[must_use]
pub fn ticking_and_lag() -> (usize, u64) {
    let mono = mono_ticks();
    let mut ticking = 0;
    let mut lag = 0;
    for cpu in 0..MAX_CPUS {
        if let Some(v) = core_value(cpu) {
            ticking += 1;
            lag = lag.max(mono.saturating_sub(v));
        }
    }
    (ticking, lag)
}

/// Whether `delta_mono` ticks of this clock and `delta_pit` PIT ticks over the
/// same window agree on the rate: within 25 % or 3 ticks, whichever is looser.
/// Pure; Kani proves it total.
pub(crate) fn rates_agree(delta_mono: u64, delta_pit: u64) -> bool {
    let tolerance = (delta_pit / 4).max(3);
    delta_mono.abs_diff(delta_pit) <= tolerance
}

/// Upper bound on spin iterations while waiting for the clock to advance with
/// interrupts off — generous (seconds under TCG) so a broken clock fails the
/// proof instead of hanging the boot.
const STALL_SPIN_CAP: u64 = 200_000_000;
/// Ticks the clock must advance while the BSP is stalled.
const STALL_ADVANCE_TICKS: u64 = 3;
/// Window, in PIT ticks, for the rate comparison.
const RATE_WINDOW_TICKS: u64 = 20;

/// Boot proof (SMP 3b-i). Runs on the BSP after the APs are online and ticking.
///
/// 1. Interrupts **off** on the BSP: record the PIT and the monotonic clock,
///    spin until the monotonic clock has advanced [`STALL_ADVANCE_TICKS`] (or
///    the cap), then check the PIT did **not** move (`pit-frozen`) while the
///    clock did (`bsp-stalled-advance`). Only another core can have done that.
/// 2. Interrupts on: over [`RATE_WINDOW_TICKS`] PIT ticks the clock must
///    advance at the same rate (`rate-ok`).
///
/// Prints one `fmt`-free line; restores the interrupt state it found. With no
/// second ticking core the stall step cannot pass and the line says so.
pub fn prove_mono() {
    use hal::serial::{write_dec, write_str};

    let were_enabled = hal::cpu::interrupts_enabled();

    // ── 1. stalled BSP ──
    hal::cpu::disable_interrupts();
    let pit0 = hal::pit::ticks();
    let m0 = mono_ticks();
    let mut spins: u64 = 0;
    while mono_ticks().wrapping_sub(m0) < STALL_ADVANCE_TICKS && spins < STALL_SPIN_CAP {
        core::hint::spin_loop();
        spins += 1;
    }
    let advanced = mono_ticks().wrapping_sub(m0);
    let pit_frozen = hal::pit::ticks() == pit0;
    let stalled_advance = advanced >= STALL_ADVANCE_TICKS;

    // ── 2. rate against the PIT, interrupts on ──
    hal::cpu::enable_interrupts();
    let pit_start = hal::pit::ticks();
    let mono_start = mono_ticks();
    while hal::pit::ticks().wrapping_sub(pit_start) < RATE_WINDOW_TICKS {
        core::hint::spin_loop();
    }
    let delta_pit = hal::pit::ticks().wrapping_sub(pit_start);
    let delta_mono = mono_ticks().wrapping_sub(mono_start);
    let rate_ok = rates_agree(delta_mono, delta_pit);
    if !were_enabled {
        hal::cpu::disable_interrupts();
    }

    let (ticking, lag) = ticking_and_lag();
    let ok = pit_frozen && stalled_advance && rate_ok && ticking >= 2;

    write_str("[clock] mono: source=");
    write_str(if crate::interrupts::lapic_tick_active() {
        "lapic"
    } else {
        "pit"
    });
    write_str(" cores=");
    write_dec(crate::smp::cpu_count() as u64);
    write_str(" ticking=");
    write_dec(ticking as u64);
    write_str(" lag-max=");
    write_dec(lag);
    write_str(" pit-frozen=");
    write_str(if pit_frozen { "yes" } else { "no" });
    write_str(" bsp-stalled-advance=");
    if stalled_advance {
        write_str("yes");
    } else {
        write_str("no(");
        write_dec(advanced);
        write_str(")");
    }
    write_str(" rate=");
    write_dec(delta_mono);
    write_str("/");
    write_dec(delta_pit);
    write_str(" rate-ok=");
    write_str(if rate_ok { "yes" } else { "no" });
    write_str(if ok { " ok\n" } else { " FAIL\n" });
}

#[cfg(test)]
mod tests {
    use super::{advance, rates_agree};

    #[test]
    fn advance_is_max() {
        assert_eq!(advance(10, 7), 10);
        assert_eq!(advance(10, 11), 11);
        assert_eq!(advance(0, 0), 0);
    }

    #[test]
    fn rates_agree_within_tolerance() {
        assert!(rates_agree(20, 20));
        assert!(rates_agree(16, 20));
        assert!(rates_agree(25, 20));
        assert!(!rates_agree(14, 20));
        assert!(!rates_agree(26, 20));
        // Small windows get the 3-tick floor.
        assert!(rates_agree(0, 3));
        assert!(rates_agree(3, 0));
        assert!(!rates_agree(4, 0));
    }

    /// A pure model of `on_tick` over several cores, mirroring the atomics
    /// one-for-one: cores that start late align to the clock and the clock is
    /// the max of the aligned counts.
    #[test]
    fn late_starter_aligns_and_carries_the_clock() {
        let mut base = [0u64; 3];
        let mut local = [0u64; 3];
        let mut mono = 0u64;
        let mut tick = |cpu: usize, mono: &mut u64| {
            local[cpu] += 1;
            if local[cpu] == 1 {
                base[cpu] = *mono;
            }
            *mono = advance(*mono, base[cpu] + local[cpu]);
        };
        for _ in 0..50 {
            tick(0, &mut mono);
        }
        assert_eq!(mono, 50);
        // Core 1 starts 50 ticks late: its first tick lands at 51, not 1.
        tick(1, &mut mono);
        assert_eq!(mono, 51);
        // Core 0 stalls; core 1 alone carries the clock forward.
        for _ in 0..10 {
            tick(1, &mut mono);
        }
        assert_eq!(mono, 61);
        // Core 0 resumes 11 behind; its ticks do not move the clock until it
        // catches up, and never move it backwards.
        for expect in [61, 61, 61] {
            tick(0, &mut mono);
            assert_eq!(mono, expect);
        }
    }
}

/// Kani proof harnesses. Compiled only under `cargo kani`.
#[cfg(kani)]
mod proofs {
    use super::{advance, rates_agree};

    /// Over a bounded, symbolic sequence of ticks on three cores, the model of
    /// [`super::on_tick`] never moves the clock backwards, advances it by at
    /// most one per tick, and keeps it equal to the max of every core's aligned
    /// count — so a stalled core can never hold the clock back.
    #[kani::proof]
    fn mono_never_regresses_and_steps_by_at_most_one() {
        const CORES: usize = 3;
        const STEPS: usize = 8;
        let mut base = [0u64; CORES];
        let mut local = [0u64; CORES];
        let mut mono: u64 = 0;
        for _ in 0..STEPS {
            let cpu: usize = kani::any();
            kani::assume(cpu < CORES);
            let before = mono;
            local[cpu] += 1;
            if local[cpu] == 1 {
                base[cpu] = mono;
            }
            mono = advance(mono, base[cpu] + local[cpu]);
            assert!(mono >= before);
            assert!(mono - before <= 1);
            // The ticking core is never behind after its own tick.
            assert!(mono == base[cpu] + local[cpu] || mono > base[cpu] + local[cpu]);
            // The clock is the max over cores that have ticked.
            for c in 0..CORES {
                if local[c] > 0 {
                    assert!(base[c] + local[c] <= mono);
                }
            }
        }
    }

    /// `rates_agree` is total: no overflow or panic for any pair of deltas.
    #[kani::proof]
    fn rates_agree_is_total() {
        let a: u64 = kani::any();
        let b: u64 = kani::any();
        let _ = rates_agree(a, b);
    }
}
