//! Per-CPU state and the application-processor bring-up driver — **safe** kernel.
//!
//! SMP phase 2 (`docs/specs/2026-07-16-smp-ap-bringup-design.md`, PR-1). The
//! bootloader has already started and parked every application processor (AP);
//! `hal::smp` releases one into its sealed privileged entry sequence and then into
//! [`ap_main`] here. This module owns everything that is *not* privileged:
//!
//! - the fixed per-CPU array ([`PerCpu`], indexed by a **dense cpu index**, BSP =
//!   0) and its accessors — zero TCB, pure atomics;
//! - the bring-up **plan** (which bootloader entry becomes which cpu index, capped
//!   at [`MAX_CPUS`]) — a pure function with host tests;
//! - the serial bring-up **driver** ([`bring_up_aps`]): start one AP, wait for it
//!   to publish `online` (bounded by a PIT timeout, so a dead AP is logged and
//!   skipped, never hung on), report, next;
//! - the AP's own first Rust code ([`ap_main`]): record what the HAL handed it,
//!   run the int8 GEMM boot proof **on its own core**, publish `online`, and park.
//!
//! **Per-CPU state stays out of the TCB.** `this_cpu_index` maps the core's
//! `cpuid` APIC ID to its dense index with a plain scan — no `%gs`-relative
//! access, no `swapgs`, no nightly `#[thread_local]`. Phase 2 has no hot per-CPU
//! path, so the lookup cost is irrelevant; revisit only if syscall entry ever
//! needs a single-instruction `current`.
//!
//! **Who prints.** Only the BSP writes to the serial console. `hal::serial`'s
//! console guard masks interrupts on the *calling* core — it is not a multi-core
//! lock — so an AP printing concurrently could interleave bytes. APs therefore
//! publish results into their [`PerCpu`] slot and the BSP reports them after
//! `online`, which also makes the boot-proof output deterministic in order.
//!
//! PR-2 (per-CPU scheduler) will move the run-queue / `current` / preempt state
//! into [`PerCpu`] and replace the park loop in [`ap_main`] with each AP's idle
//! task.

use alloc::vec::Vec;
use core::hint::spin_loop;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, AtomicUsize, Ordering};

use hal::apic::{LapicInfo, LapicMode};
pub use hal::smp::MAX_CPUS;
use hal::smp::{ApInfo, CpuDesc, StartError};

use crate::ml;

/// How long the BSP waits for one AP to publish `online` before logging it as
/// failed and moving on: 100 PIT ticks = 1 s at 100 Hz. Generous on purpose —
/// under TCG on a contended CI host an AP thread can be descheduled for far
/// longer than the ~ms its entry sequence needs; the cost is paid only by a
/// genuinely dead AP.
const AP_ONLINE_TIMEOUT_TICKS: u64 = 100;

/// One logical CPU's kernel-side record. All fields are atomics, so the array of
/// these is a plain `static` (no lock, no `unsafe`); the writer of every
/// AP-published field is that AP itself, and the BSP reads them only after
/// observing `online` with `Acquire`.
pub struct PerCpu {
    /// Local APIC ID per the bootloader's enumeration (set by the BSP's plan).
    lapic_id: AtomicU32,
    /// Set (`Release`) by the CPU itself once it is running kernel code; every
    /// other AP-written field below is published by this store.
    online: AtomicBool,
    /// How the core's LAPIC is reached: `0` = none, `1` = xAPIC (MMIO, QEMU
    /// TCG), `2` = x2APIC (MSRs). Set from `apic::enable_bsp` / `enable_ap`.
    lapic_mode: AtomicU8,
    /// `hal::simd::enable` succeeded on this core (vector state on, save contract
    /// verified). `false` ⇒ this core runs scalar tiers only.
    simd: AtomicBool,
    /// The identity int8 GEMM boot proof passed **on this core**.
    gemm_ok: AtomicBool,
    /// The core's own `cpuid` APIC ID equals the bootloader's `lapic_id` for the
    /// slot it was handed — i.e. the AP that arrived is the one we started.
    lapic_match: AtomicBool,
}

impl PerCpu {
    const fn new() -> Self {
        Self {
            lapic_id: AtomicU32::new(0),
            online: AtomicBool::new(false),
            lapic_mode: AtomicU8::new(0),
            simd: AtomicBool::new(false),
            gemm_ok: AtomicBool::new(false),
            lapic_match: AtomicBool::new(false),
        }
    }

    /// Local APIC ID of this CPU.
    #[must_use]
    pub fn lapic_id(&self) -> u32 {
        self.lapic_id.load(Ordering::Acquire)
    }

    /// Whether this CPU is running kernel code.
    #[must_use]
    pub fn is_online(&self) -> bool {
        self.online.load(Ordering::Acquire)
    }

    /// How this CPU's LAPIC is reached, or `None` if it has no access path.
    #[must_use]
    pub fn lapic_mode(&self) -> Option<LapicMode> {
        match self.lapic_mode.load(Ordering::Relaxed) {
            1 => Some(LapicMode::XApic),
            2 => Some(LapicMode::X2Apic),
            _ => None,
        }
    }

    fn set_lapic_mode(&self, mode: Option<LapicMode>) {
        let code = match mode {
            None => 0,
            Some(LapicMode::XApic) => 1,
            Some(LapicMode::X2Apic) => 2,
        };
        self.lapic_mode.store(code, Ordering::Relaxed);
    }

    /// Whether vector state is enabled (and verified) on this CPU.
    #[must_use]
    pub fn simd_enabled(&self) -> bool {
        self.simd.load(Ordering::Relaxed)
    }

    /// Whether the GEMM boot proof passed on this CPU.
    #[must_use]
    pub fn gemm_ok(&self) -> bool {
        self.gemm_ok.load(Ordering::Relaxed)
    }

    /// Whether the CPU's own `cpuid` APIC ID matched its slot's `lapic_id`.
    #[must_use]
    pub fn lapic_matches(&self) -> bool {
        self.lapic_match.load(Ordering::Relaxed)
    }

    /// A CPU counts as **verified** when it is online, arrived on the core we
    /// expected, and passed the GEMM proof on that core.
    #[must_use]
    pub fn verified(&self) -> bool {
        self.is_online() && self.lapic_matches() && self.gemm_ok()
    }
}

/// The fixed per-CPU array (no heap): slot `i` is dense cpu index `i`.
static CPUS: [PerCpu; MAX_CPUS] = [const { PerCpu::new() }; MAX_CPUS];

/// Number of CPUs tracked (`0` until [`bring_up_aps`] has enumerated; then `>= 1`).
static CPU_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Number of CPUs tracked: BSP + every AP given a slot (online or not).
#[must_use]
pub fn cpu_count() -> usize {
    CPU_COUNT.load(Ordering::Acquire)
}

/// The tracked CPUs, by dense index (`[0]` is the BSP). Empty before enumeration.
#[must_use]
pub fn cpus() -> &'static [PerCpu] {
    &CPUS[..cpu_count()]
}

/// The CPU record at dense index `index`, if tracked.
#[must_use]
pub fn by_index(index: u32) -> Option<&'static PerCpu> {
    cpus().get(index as usize)
}

/// The local APIC ID of the CPU at dense index `cpu`, if tracked — the IPI
/// destination `kernel::sched::spawn_on` uses to wake that core.
#[must_use]
pub fn lapic_id_of(cpu: u32) -> Option<u32> {
    by_index(cpu).map(PerCpu::lapic_id)
}

/// The dense index of the **calling** core, by matching its `cpuid` APIC ID
/// against the tracked slots; `None` before enumeration or for an unknown core.
#[must_use]
pub fn this_cpu_index() -> Option<u32> {
    let count = cpu_count();
    let mut ids = [0u32; MAX_CPUS];
    for (slot, cpu) in CPUS[..count].iter().enumerate() {
        ids[slot] = cpu.lapic_id();
    }
    dense_index(&ids[..count], hal::apic::cpuid_apic_id())
}

/// Position of `lapic_id` in `lapic_ids` (the dense index), or `None`.
///
/// Pure; the first match wins. Host-tested and Kani-proved below.
#[must_use]
pub(crate) fn dense_index(lapic_ids: &[u32], lapic_id: u32) -> Option<u32> {
    lapic_ids
        .iter()
        .position(|&id| id == lapic_id)
        .map(|pos| pos as u32)
}

/// The bring-up plan derived from the bootloader's CPU list: a pure function of
/// its input so the index assignment is host-testable.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct BringUpPlan {
    /// Dense table: `[0]` = BSP, then APs in bootloader order. Only `..count` valid.
    pub lapic_ids: [u32; MAX_CPUS],
    /// CPUs given a slot (`1..=MAX_CPUS`).
    pub count: usize,
    /// `(bootloader index, dense cpu index)` for every AP to start, in order.
    pub aps: Vec<(usize, u32)>,
    /// APs beyond [`MAX_CPUS`] that get no slot (logged, never started).
    pub skipped: usize,
    /// The bootloader list contained the BSP (it always should).
    pub bsp_listed: bool,
}

/// Assign dense indices: the BSP is `0` (falling back to `bsp_lapic_fallback` —
/// the running core's `cpuid` ID — if the list somehow lacks a BSP entry); each
/// non-BSP entry takes the next index in bootloader order until [`MAX_CPUS`] is
/// reached, after which the rest are counted as `skipped`.
pub(crate) fn plan(descs: &[CpuDesc], bsp_lapic_fallback: u32) -> BringUpPlan {
    let mut lapic_ids = [0u32; MAX_CPUS];
    let bsp = descs.iter().find(|d| d.is_bsp);
    lapic_ids[0] = bsp.map_or(bsp_lapic_fallback, |d| d.lapic_id);
    let mut count = 1;
    let mut aps = Vec::new();
    let mut skipped = 0;
    for (bootloader_index, desc) in descs.iter().enumerate() {
        if desc.is_bsp {
            continue;
        }
        if count < MAX_CPUS {
            lapic_ids[count] = desc.lapic_id;
            aps.push((bootloader_index, count as u32));
            count += 1;
        } else {
            skipped += 1;
        }
    }
    BringUpPlan {
        lapic_ids,
        count,
        aps,
        skipped,
        bsp_listed: bsp.is_some(),
    }
}

// ── the BSP-side driver ───────────────────────────────────────────────────────

/// Enumerate the bootloader's CPUs, bring every application processor online
/// (serially, each bounded by [`AP_ONLINE_TIMEOUT_TICKS`]), and report.
///
/// Call once on the BSP from `kmain`, after `interrupts::init`, `memory::init`,
/// `simd::enable`, `init_timer` and `apic::enable_bsp` — the APs load the IDT the
/// BSP built, the wait loop needs PIT ticks, and the BSP's own record mirrors its
/// x2APIC state. Interrupts are enabled only for the duration of each wait and
/// restored to their prior state afterwards.
///
/// Serial output (all from the BSP):
///
/// ```text
/// [smp] cpu1 online: apic-id=1 lapic-match=yes lapic=xapic simd=yes gemm=ok
/// [smp] cpu2 FAILED to start (timeout 100 ticks): apic-id=2
/// [smp] online=4/4 bsp-apic-id=0 aps-ok=3 aps-failed=0 skipped=0
/// ```
///
/// `aps-ok` counts APs that are [`PerCpu::verified`]; `online=A/B` is CPUs online
/// over CPUs tracked (BSP included). Asserted by `cargo xtask test` under `-smp 4`.
pub fn bring_up_aps() {
    let descs: Vec<CpuDesc> = hal::smp::cpus().collect();
    let bsp_cpuid_apic = hal::apic::cpuid_apic_id();

    // The BSP's own record: it is trivially online; mirror its LAPIC mode and
    // vector state, and run the same GEMM proof it will demand of every AP.
    CPUS[0].set_lapic_mode(if hal::apic::id().is_some() {
        Some(LapicMode::X2Apic)
    } else {
        None
    });
    CPUS[0]
        .simd
        .store(hal::cpu::osxsave_enabled(), Ordering::Relaxed);
    CPUS[0]
        .gemm_ok
        .store(ml::gemm_proof_ok(), Ordering::Relaxed);
    CPUS[0].lapic_match.store(true, Ordering::Relaxed);

    if descs.is_empty() {
        CPUS[0].lapic_id.store(bsp_cpuid_apic, Ordering::Release);
        CPUS[0].online.store(true, Ordering::Release);
        CPU_COUNT.store(1, Ordering::Release);
        hal::serial::write_str("[smp] no MP response from the bootloader; single-core (apic-id=");
        hal::serial::write_dec(u64::from(bsp_cpuid_apic));
        hal::serial::write_str(")\n");
        hal::serial::write_str("[smp] online=1/1 bsp-apic-id=");
        hal::serial::write_dec(u64::from(bsp_cpuid_apic));
        hal::serial::write_str(" aps-ok=0 aps-failed=0 skipped=0\n");
        return;
    }

    let plan = plan(&descs, bsp_cpuid_apic);
    for (slot, &lapic) in plan.lapic_ids[..plan.count].iter().enumerate() {
        CPUS[slot].lapic_id.store(lapic, Ordering::Release);
    }
    CPUS[0]
        .lapic_match
        .store(plan.lapic_ids[0] == bsp_cpuid_apic, Ordering::Relaxed);
    CPUS[0].online.store(true, Ordering::Release);
    CPU_COUNT.store(plan.count, Ordering::Release);
    if !plan.bsp_listed {
        hal::serial::write_str(
            "[smp] warning: bootloader CPU list has no BSP entry; using cpuid apic-id\n",
        );
    }

    hal::smp::set_ap_main(ap_main);

    let mut aps_ok: u64 = 0;
    let mut aps_failed: u64 = 0;
    for &(bootloader_index, cpu_index) in &plan.aps {
        let cpu = &CPUS[cpu_index as usize];
        hal::serial::write_str("[smp] cpu");
        hal::serial::write_dec(u64::from(cpu_index));
        match hal::smp::start_cpu(bootloader_index, cpu_index) {
            Ok(()) => {}
            Err(err) => {
                aps_failed += 1;
                hal::serial::write_str(" NOT started (");
                hal::serial::write_str(start_error_label(err));
                hal::serial::write_str("): apic-id=");
                hal::serial::write_dec(u64::from(cpu.lapic_id()));
                hal::serial::write_str("\n");
                continue;
            }
        }
        if wait_online(cpu) {
            if cpu.verified() {
                aps_ok += 1;
            } else {
                aps_failed += 1;
            }
            hal::serial::write_str(" online: apic-id=");
            hal::serial::write_dec(u64::from(cpu.lapic_id()));
            hal::serial::write_str(" lapic-match=");
            hal::serial::write_str(yes_no(cpu.lapic_matches()));
            hal::serial::write_str(" lapic=");
            hal::serial::write_str(match cpu.lapic_mode() {
                Some(LapicMode::X2Apic) => "x2apic",
                Some(LapicMode::XApic) => "xapic",
                None => "none",
            });
            hal::serial::write_str(" simd=");
            hal::serial::write_str(yes_no(cpu.simd_enabled()));
            hal::serial::write_str(" gemm=");
            hal::serial::write_str(if cpu.gemm_ok() { "ok" } else { "FAIL" });
            hal::serial::write_str("\n");
        } else {
            aps_failed += 1;
            hal::serial::write_str(" FAILED to start (timeout ");
            hal::serial::write_dec(AP_ONLINE_TIMEOUT_TICKS);
            hal::serial::write_str(" ticks): apic-id=");
            hal::serial::write_dec(u64::from(cpu.lapic_id()));
            hal::serial::write_str("\n");
        }
    }

    let online = cpus().iter().filter(|c| c.is_online()).count();
    hal::serial::write_str("[smp] online=");
    hal::serial::write_dec(online as u64);
    hal::serial::write_str("/");
    hal::serial::write_dec(plan.count as u64);
    hal::serial::write_str(" bsp-apic-id=");
    hal::serial::write_dec(u64::from(plan.lapic_ids[0]));
    hal::serial::write_str(" aps-ok=");
    hal::serial::write_dec(aps_ok);
    hal::serial::write_str(" aps-failed=");
    hal::serial::write_dec(aps_failed);
    hal::serial::write_str(" skipped=");
    hal::serial::write_dec(plan.skipped as u64);
    hal::serial::write_str("\n");
}

/// Spin (interrupts enabled so the PIT ticks) until `cpu` publishes `online` or
/// [`AP_ONLINE_TIMEOUT_TICKS`] elapse; restores the prior interrupt state.
fn wait_online(cpu: &PerCpu) -> bool {
    let were_enabled = hal::cpu::interrupts_enabled();
    hal::cpu::enable_interrupts();
    let deadline = hal::pit::ticks().saturating_add(AP_ONLINE_TIMEOUT_TICKS);
    while !cpu.is_online() && hal::pit::ticks() < deadline {
        spin_loop();
    }
    if !were_enabled {
        hal::cpu::disable_interrupts();
    }
    cpu.is_online()
}

fn yes_no(flag: bool) -> &'static str {
    if flag {
        "yes"
    } else {
        "no"
    }
}

fn start_error_label(err: StartError) -> &'static str {
    match err {
        StartError::NoResponse => "no MP response",
        StartError::BadIndex => "bad bootloader index",
        StartError::IsBsp => "entry is the BSP",
        StartError::BadCpuIndex => "bad cpu index",
        StartError::NoApMain => "no AP main registered",
    }
}

// ── the AP side ───────────────────────────────────────────────────────────────

/// First safe-Rust code on an application processor, entered from
/// `hal::smp::ap_entry` after its privileged sequence (per-AP GDT/TSS, shared
/// IDT, `simd::enable`, `apic::enable_ap`) with interrupts still masked.
///
/// Records the HAL's report, proves the int8 GEMM **on this core** (through the
/// vector tiers only if this core's vector state is on — otherwise only if the
/// active tier is already scalar), adopts itself as this core's scheduler idle
/// task (`sched::init_ap`), publishes `online` (which releases every field
/// written above to the BSP), and enters the per-CPU idle loop
/// (`sched::ap_idle_loop`: reap, `sti; hlt`). The AP receives only reschedule
/// IPIs (LINT0 masked, no IOAPIC, no LAPIC timer yet), so it sleeps until the
/// BSP places a task on it.
///
/// **Invariant:** the AP's first `sti` is inside `ap_idle_loop`, and this
/// function is reachable only through `hal::smp::ap_entry`, which ran
/// `simd::enable` (setting `CR4.OSXSAVE`) before calling here — so the per-IRQ
/// vector save can never execute on a core without vector state (and
/// `isr_common` checks the live bit regardless).
fn ap_main(info: ApInfo) -> ! {
    let Some(cpu) = by_index(info.cpu_index) else {
        // Unknown slot: the BSP never handed out this index. Nothing to report
        // into; park (the BSP will time out and log the AP as failed).
        hal::cpu::halt_loop();
    };
    let own_apic = hal::apic::cpuid_apic_id();
    cpu.lapic_match.store(
        cpu.lapic_id() == info.lapic_id && own_apic == info.lapic_id,
        Ordering::Relaxed,
    );
    cpu.set_lapic_mode(info.lapic.map(|l: LapicInfo| l.mode));
    cpu.simd.store(info.simd_enabled, Ordering::Relaxed);
    let can_run_active_tier = info.simd_enabled || matches!(ml::active_tier(), ml::Tier::Scalar);
    cpu.gemm_ok.store(
        can_run_active_tier && ml::gemm_proof_ok(),
        Ordering::Relaxed,
    );

    // Adopt this control flow as the core's idle task BEFORE publishing
    // `online`: `online` is what tells `sched::spawn_on` this core can take
    // work, and work arrives as a reschedule IPI that expects a run queue with
    // an idle to switch away from.
    if crate::sched::init_ap(info.cpu_index).is_none() {
        hal::cpu::halt_loop();
    }
    cpu.online.store(true, Ordering::Release);

    // The per-CPU idle: reap what exited here, then `sti; hlt` until the next
    // IPI (there is no timer on an AP yet — phase 3). The first `sti` on this
    // core happens inside that loop.
    crate::sched::ap_idle_loop()
}

// ── host tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{dense_index, plan, MAX_CPUS};
    use alloc::vec;
    use hal::smp::CpuDesc;

    fn desc(lapic_id: u32, is_bsp: bool) -> CpuDesc {
        CpuDesc {
            lapic_id,
            acpi_id: lapic_id + 100,
            is_bsp,
        }
    }

    #[test]
    fn dense_index_finds_first_match() {
        assert_eq!(dense_index(&[], 0), None);
        assert_eq!(dense_index(&[7], 7), Some(0));
        assert_eq!(dense_index(&[7], 8), None);
        assert_eq!(dense_index(&[0, 2, 4, 6], 4), Some(2));
        assert_eq!(dense_index(&[0, 2, 4, 6], 5), None);
        // Duplicates (never produced by firmware) resolve to the first slot.
        assert_eq!(dense_index(&[3, 3], 3), Some(0));
    }

    #[test]
    fn plan_puts_bsp_first_and_aps_in_bootloader_order() {
        // QEMU `-smp 4`: BSP is apic 0 and listed first.
        let descs = [
            desc(0, true),
            desc(1, false),
            desc(2, false),
            desc(3, false),
        ];
        let p = plan(&descs, 99);
        assert_eq!(p.count, 4);
        assert_eq!(&p.lapic_ids[..4], &[0, 1, 2, 3]);
        assert_eq!(p.aps, vec![(1, 1), (2, 2), (3, 3)]);
        assert_eq!(p.skipped, 0);
        assert!(p.bsp_listed);
    }

    #[test]
    fn plan_handles_bsp_not_first_and_sparse_apic_ids() {
        // Firmware may list the BSP anywhere and APIC IDs may be sparse.
        let descs = [desc(4, false), desc(6, true), desc(12, false)];
        let p = plan(&descs, 99);
        assert_eq!(p.count, 3);
        assert_eq!(&p.lapic_ids[..3], &[6, 4, 12]);
        // Bootloader indices 0 and 2 become dense indices 1 and 2.
        assert_eq!(p.aps, vec![(0, 1), (2, 2)]);
        assert!(p.bsp_listed);
    }

    #[test]
    fn plan_falls_back_to_cpuid_when_bsp_missing() {
        let descs = [desc(1, false), desc(2, false)];
        let p = plan(&descs, 0);
        assert!(!p.bsp_listed);
        assert_eq!(&p.lapic_ids[..3], &[0, 1, 2]);
        assert_eq!(p.aps, vec![(0, 1), (1, 2)]);
    }

    #[test]
    fn plan_caps_at_max_cpus_and_counts_skipped() {
        let mut descs = vec![desc(0, true)];
        for id in 1..(MAX_CPUS as u32 + 5) {
            descs.push(desc(id, false));
        }
        let p = plan(&descs, 0);
        assert_eq!(p.count, MAX_CPUS);
        assert_eq!(p.aps.len(), MAX_CPUS - 1);
        assert_eq!(p.skipped, 5);
        // Every dense index is unique and in range, and maps to the right APIC ID.
        for &(bl, ci) in &p.aps {
            assert!((1..MAX_CPUS as u32).contains(&ci));
            assert_eq!(p.lapic_ids[ci as usize], descs[bl].lapic_id);
        }
    }

    #[test]
    fn plan_single_cpu_has_no_aps() {
        let p = plan(&[desc(0, true)], 0);
        assert_eq!(p.count, 1);
        assert!(p.aps.is_empty());
        assert_eq!(p.skipped, 0);
    }
}

/// Kani proof harnesses — compiled only under `cargo kani` (`cfg(kani)`).
///
/// Tractability: one bounded linear scan over at most [`MAX_CPUS`] `u32`s, no
/// multiplication, no allocation. Measured locally before promotion (see
/// `.github/workflows/verify.yml`'s note on adding kernel harnesses).
#[cfg(kani)]
mod proofs {
    use super::{dense_index, MAX_CPUS};

    /// `dense_index` is **total** over any table of `count <= MAX_CPUS` ids and
    /// returns exactly the first matching position: `Some(i)` ⇒ `i < count`,
    /// `ids[i] == target`, and no earlier slot matches; `None` ⇒ no slot matches.
    #[kani::proof]
    #[kani::unwind(33)]
    fn dense_index_is_first_match_or_none() {
        let ids: [u32; MAX_CPUS] = kani::any();
        let count: usize = kani::any();
        kani::assume(count <= MAX_CPUS);
        let target: u32 = kani::any();
        match dense_index(&ids[..count], target) {
            Some(i) => {
                let i = i as usize;
                assert!(i < count);
                assert_eq!(ids[i], target);
                let mut j = 0;
                while j < i {
                    assert_ne!(ids[j], target);
                    j += 1;
                }
            }
            None => {
                let mut j = 0;
                while j < count {
                    assert_ne!(ids[j], target);
                    j += 1;
                }
            }
        }
    }
}
