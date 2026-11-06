//! SMP application-processor (AP) bring-up over the **Limine MP protocol** — TCB.
//!
//! Every logical CPU the firmware reports (via the ACPI MADT) is already running
//! when the kernel starts: Limine, honouring our [`MpRequest`], performs the
//! INIT–SIPI–SIPI sequence and the 16→32→64-bit mode walk for each AP *before*
//! jumping to `_start`, then parks every AP in 64-bit long mode — same page
//! tables (kernel + HHDM) as the BSP, interrupts masked, on its own 64 KiB stack
//! in bootloader-reclaimable memory — spinning on that CPU's `goto_address` slot.
//! Writing a function pointer to the slot releases the AP into that function
//! with `rdi = &Cpu`.
//!
//! # Why the bootloader's trampoline, not our own
//!
//! The SMP AP-bring-up design doc (`docs/specs/2026-07-16-smp-ap-bringup-design.md`)
//! sketched a hand-written 16-bit real-mode trampoline, AP bootstrap page tables,
//! a low-memory reservation, ICR MSR writes and a MADT parser: six new TCB rows and
//! the largest `asm` blob since the ISR stubs, none of it Miri- or Kani-checkable.
//! Its open question #1 asked whether the bootloader's guarantees let us drop part
//! of that. They let us drop **all** of it: we already trust Limine for the BSP's
//! own mode switch, page tables, HHDM and memory map — its AP path is the same
//! code, exercised by every Limine kernel, and it works under QEMU TCG (xAPIC
//! INIT-SIPI-SIPI), so AP bring-up is proven on every `make test`, not only on KVM.
//! The residual TCB here is three small rows: reading the response, releasing an
//! AP into [`ap_entry`], and `ap_entry`'s fixed privileged sequence (it reuses the
//! audited `gdt`/`idt`/`simd`/`apic` primitives; nothing here is a new
//! instruction). The hand-rolled trampoline remains the fallback if SentinelOS
//! ever ships its own boot stage.
//!
//! # Contract with the safe kernel
//!
//! - [`cpus`] / [`bsp_lapic_id`] expose the enumerated CPU list as plain data.
//! - Early in boot (right after `apic::enable_bsp`, before the first `sti`) the
//!   kernel may call [`park_cpu`] once per AP, passing the dense per-CPU index it
//!   assigned: the AP leaves Limine's spin loop at once, runs its setup, and
//!   sleeps in `sti; hlt` (see [`park_cpu`] for why spinning hangs VirtualBox).
//! - The kernel registers its AP main with [`set_ap_main`], then calls
//!   [`start_cpu`] once per AP (serially) with the same index and a wake vector
//!   it has a handler for. The AP arrives in the kernel's `ApMain` with an
//!   [`ApInfo`] after [`ap_entry`] has, in a **fixed order**: loaded this AP's
//!   private GDT/TSS (with its own double-fault IST stack), loaded the shared
//!   IDT, enabled its own vector state (`simd::enable`), enabled its LAPIC
//!   (`apic::enable_ap`), and waited for its release flag.
//! - **Invariant:** there is exactly one AP entry (`ap_entry`). Its only `sti` is
//!   in the release wait, *after* `simd::enable`, so `CR4.OSXSAVE` is always set
//!   on an AP before its first interrupt — and `isr_common` independently gates
//!   on the live bit anyway. The wait clears IF on every wake, so `ApMain` is
//!   entered with interrupts masked and the *kernel* decides when to `sti` there.
//!   Before release only the wake IPI and LAPIC spurious (0xFF) can reach the AP:
//!   its LINT0 is masked, its timer unarmed, and the IOAPIC routes to the BSP.
//!
//! All `unsafe` is registered in `kernel/docs/hal-tcb.md` (§2k).

use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use limine::mp::Cpu;
use limine::request::MpRequest;

/// Upper bound on logical CPUs the kernel tracks (BSP included).
///
/// Sizes the safe kernel's per-CPU array and this crate's per-AP descriptor
/// tables (`gdt::MAX_APS = MAX_CPUS - 1`). Firmware may report more; the kernel
/// then brings up the first `MAX_CPUS - 1` APs and logs the rest as skipped.
pub const MAX_CPUS: usize = 32;

/// Limine MP request: asks the bootloader to start every AP and park it for us.
///
/// Flags are empty on purpose — we do **not** ask Limine to enable x2APIC. The
/// BSP's LAPIC is switched by [`crate::apic::enable_bsp`] (the phase-1 proof the
/// KVM CI job asserts) and each AP's by [`crate::apic::enable_ap`], so the mode
/// switch stays a kernel-owned, registered TCB step.
#[used]
static MP_REQUEST: MpRequest = MpRequest::new();

/// One enumerated logical CPU, as plain data (a copy of the bootloader's entry).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuDesc {
    /// Local APIC ID (per the ACPI MADT) — the identity `cpuid` also reports.
    pub lapic_id: u32,
    /// ACPI processor ID (per the MADT) — informational.
    pub acpi_id: u32,
    /// Whether this entry is the bootstrap processor (already running `kmain`).
    pub is_bsp: bool,
}

/// What an AP hands the kernel's [`ApMain`] once [`ap_entry`] has run.
#[derive(Clone, Copy, Debug)]
pub struct ApInfo {
    /// The dense per-CPU index the kernel passed to [`start_cpu`] (BSP = 0, so
    /// this is `>= 1`).
    pub cpu_index: u32,
    /// This AP's local APIC ID, per the bootloader's enumeration.
    pub lapic_id: u32,
    /// Whether [`crate::simd::enable`] succeeded on this core (vector state on and
    /// its save contract verified). `false` ⇒ this core must stay on scalar tiers.
    pub simd_enabled: bool,
    /// How [`crate::apic::enable_ap`] reached this core's LAPIC (x2APIC MSRs, or
    /// the shared xAPIC MMIO page under QEMU TCG) and the ID it read back;
    /// `None` only if no LAPIC access path exists at all.
    pub lapic: Option<crate::apic::LapicInfo>,
}

/// The kernel-side AP main: never returns (the AP parks or schedules forever).
pub type ApMain = fn(ApInfo) -> !;

/// The registered [`ApMain`], type-erased (same scheme as
/// `interrupts::HANDLERS`). Null until [`set_ap_main`]; [`start_cpu`] refuses to
/// release an AP while it is null, so `ap_entry` never observes null in practice
/// and parks defensively if it somehow did.
static AP_MAIN: AtomicPtr<()> = AtomicPtr::new(null_mut());

/// Per-AP "sent into [`ap_entry`]" flags, indexed by dense cpu index (slot 0, the
/// BSP, is never set). Makes the `goto_address` write happen at most once per AP,
/// whether [`park_cpu`] or [`start_cpu`] gets there first.
static PARKED: [AtomicBool; MAX_CPUS] = [const { AtomicBool::new(false) }; MAX_CPUS];

/// Per-AP release flags, indexed by dense cpu index. [`ap_entry`] waits on its
/// own flag after its setup and before it reads [`AP_MAIN`]; [`start_cpu`] sets it.
static RELEASED: [AtomicBool; MAX_CPUS] = [const { AtomicBool::new(false) }; MAX_CPUS];

/// Why [`start_cpu`] declined to release an AP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartError {
    /// The bootloader provided no MP response (single CPU, or protocol not
    /// honoured) — there are no APs to start.
    NoResponse,
    /// `limine_index` is not a valid index into the enumerated CPU list.
    BadIndex,
    /// The entry at `limine_index` is the bootstrap processor.
    IsBsp,
    /// `cpu_index` is `0` (reserved for the BSP) or `>= MAX_CPUS`.
    BadCpuIndex,
    /// [`set_ap_main`] has not been called yet.
    NoApMain,
    /// The AP was already parked by [`park_cpu`] under a different `cpu_index`.
    IndexMismatch,
}

/// Iterate the bootloader's CPU list (BSP included), in its order.
///
/// Empty if Limine provided no MP response. Each item is a scalar copy; nothing
/// borrowed from the bootloader escapes.
pub fn cpus() -> impl Iterator<Item = CpuDesc> {
    // SAFETY: `get_response()` returns `Some(&MpResponse)` only when Limine
    // populated our `#[used]` `MP_REQUEST` before `_start` (same pattern as
    // `mm::bootinfo`, B1). `cpus()` reconstructs a slice over the
    // bootloader-filled `Cpu` array, which lives in bootloader-reclaimable memory
    // the frame allocator never hands out (it seeds from `USABLE` regions only),
    // so it stays valid for the whole run. We only copy scalars out of each entry.
    let (bsp, entries): (u32, &[&Cpu]) = match MP_REQUEST.get_response() {
        Some(response) => (response.bsp_lapic_id(), response.cpus()),
        None => (0, &[]),
    };
    entries.iter().map(move |cpu| CpuDesc {
        lapic_id: cpu.lapic_id,
        acpi_id: cpu.id,
        is_bsp: cpu.lapic_id == bsp,
    })
}

/// The bootstrap processor's local APIC ID per the bootloader, or `None` without
/// an MP response.
#[must_use]
pub fn bsp_lapic_id() -> Option<u32> {
    // SAFETY: as in `cpus` — a shared borrow of the bootloader-filled response for
    // the duration of one scalar read.
    MP_REQUEST.get_response().map(|r| r.bsp_lapic_id())
}

/// Register the kernel's AP main. Must precede every [`start_cpu`].
///
/// A `fn` pointer is stored type-erased via a plain (safe) fn→ptr cast and an
/// atomic store; [`ap_entry`] casts it back (see there). Idempotent.
pub fn set_ap_main(main: ApMain) {
    AP_MAIN.store(main as *mut (), Ordering::Release);
}

/// Release the AP at `limine_index` (into the [`cpus`] order) into [`ap_entry`],
/// tagging it with the kernel's dense `cpu_index` (`1..MAX_CPUS`).
///
/// Returns immediately; the caller observes the AP's arrival through whatever
/// state its `ApMain` publishes (the kernel's per-CPU `online` flag) and should
/// bring APs up **serially** — start one, wait for it (with a timeout), then the
/// next — so a dead AP is logged and skipped rather than hanging the machine.
pub fn start_cpu(limine_index: usize, cpu_index: u32, wake_vector: u8) -> Result<(), StartError> {
    if AP_MAIN.load(Ordering::Acquire).is_null() {
        return Err(StartError::NoApMain);
    }
    let cpu = enter_ap_entry(limine_index, cpu_index)?;
    // Let the AP past its park wait, then wake it. The flag store is ordered
    // before the IPI, and the AP checks the flag with IF = 0 before each
    // `sti; hlt` — so an IPI that lands before the AP halts stays pending in its
    // IRR and wakes the `hlt` at once (the `sti` shadow). `send_ipi` returns
    // false without a LAPIC access path; the AP then polls instead of halting.
    RELEASED[cpu_index as usize].store(true, Ordering::Release);
    let _sent = crate::apic::send_ipi(cpu.lapic_id, wake_vector);
    Ok(())
}

/// Send the AP at `limine_index` into [`ap_entry`] **now**, tagged with
/// `cpu_index`, without releasing it to the kernel: it runs its setup, then
/// sleeps in `sti; hlt` until [`start_cpu`] wakes it.
///
/// Why: Limine parks APs in a `pause` loop on `goto_address`. Under VirtualBox
/// on Hyper-V (NEM) a vCPU in that loop never exits to the VMM, and VirtualBox
/// runs device timers on its last vCPU's thread — so with 2+ vCPUs the PIT never
/// fires and the BSP hangs at its first timer wait. Halted APs exit; spinning
/// ones don't. Call once per AP right after [`crate::apic::enable_bsp`] (the AP
/// reaches the LAPIC through the page it mapped) and before the first `sti`.
/// Optional: [`start_cpu`] alone still works, as before.
pub fn park_cpu(limine_index: usize, cpu_index: u32) -> Result<(), StartError> {
    enter_ap_entry(limine_index, cpu_index).map(|_| ())
}

/// The shared half of [`park_cpu`] / [`start_cpu`]: validate, then write the
/// AP's `extra` and `goto_address` exactly once. A repeat call for an AP
/// already sent in must name the same `cpu_index`.
fn enter_ap_entry(limine_index: usize, cpu_index: u32) -> Result<&'static Cpu, StartError> {
    if cpu_index == 0 || cpu_index as usize >= MAX_CPUS {
        return Err(StartError::BadCpuIndex);
    }
    // SAFETY: same response borrow as `cpus` (B1-pattern); the `&Cpu` we index
    // out of it points into the bootloader-owned, never-reclaimed CPU array and
    // is valid for the whole run.
    let response = MP_REQUEST.get_response().ok_or(StartError::NoResponse)?;
    let cpu: &'static Cpu = response
        .cpus()
        .get(limine_index)
        .ok_or(StartError::BadIndex)?;
    if cpu.lapic_id == response.bsp_lapic_id() {
        return Err(StartError::IsBsp);
    }
    if PARKED[cpu_index as usize].swap(true, Ordering::AcqRel) {
        // Already sent in by an earlier call: only the index must agree.
        return if cpu.extra.load(Ordering::Acquire) == u64::from(cpu_index) {
            Ok(cpu)
        } else {
            Err(StartError::IndexMismatch)
        };
    }
    // Hand the AP its dense index through the protocol's free-for-use slot. The
    // `goto_address` store below is `SeqCst`, and the protocol guarantees the AP
    // observes every write that precedes it — so the AP's `extra` read is ordered
    // after this store.
    cpu.extra.store(u64::from(cpu_index), Ordering::SeqCst);
    // Release the AP. `GotoAddress::write` is a safe API over an atomic pointer
    // store; the target must be an `unsafe extern "C" fn(&Cpu) -> !`, which
    // `ap_entry` is. The soundness obligation (that `ap_entry` is a valid AP entry
    // for the state Limine parks an AP in) is discharged at `ap_entry`.
    cpu.goto_address.write(ap_entry);
    Ok(cpu)
}

/// The single AP entry point: the fixed, ordered privileged sequence every
/// application processor runs before the safe kernel sees it.
///
/// Arrives from Limine's parking loop with: 64-bit long mode, the kernel's page
/// tables (kernel image + HHDM mapped), interrupts masked, `rdi = cpu`, and a
/// 64 KiB bootloader-provided stack (in reclaimable memory we never reclaim — so,
/// like the BSP's Limine stack `kmain` runs on, it is ours for the whole run).
/// Limine leaves the IDT undefined and a Limine GDT loaded, hence steps 1–2.
///
/// # Safety
///
/// Never call this from Rust. It is invoked only by the hardware, on an AP,
/// exactly once, via the `goto_address` store in [`start_cpu`], with `cpu`
/// pointing at that AP's bootloader-owned `Cpu` entry (valid for the whole run).
unsafe extern "C" fn ap_entry(cpu: &Cpu) -> ! {
    // Ordered after the BSP's `goto_address` store by the protocol (see `start_cpu`).
    let cpu_index = cpu.extra.load(Ordering::Acquire) as u32;
    let lapic_id = cpu.lapic_id;

    // (1) Private GDT + TSS + double-fault IST stack for this core. `start_cpu`
    // guarantees `1 <= cpu_index < MAX_CPUS`, so the slot is in range; if the
    // tables somehow cannot be installed, park rather than run without a TSS.
    let Some(slot) = (cpu_index as usize).checked_sub(1) else {
        crate::cpu::halt_loop();
    };
    if !crate::gdt::init_ap(slot) {
        crate::cpu::halt_loop();
    }
    // (2) The shared, already-built IDT (the BSP's `interrupts::init` ran long
    // before any AP was released).
    crate::idt::load();
    // (3) This core's vector state: `CR4.OSXSAVE` + `XCR0` + the save-contract
    // check + tier self-tests. Must precede any interrupt on this core (the
    // kernel `sti`s only after we return control to it) and any GEMM on it.
    let simd_enabled = crate::simd::enable();
    // (4) This core's LAPIC: software-enabled (so reschedule IPIs reach it) with
    // LINT0 masked — only the BSP fronts the PIC. x2APIC where advertised, else
    // through the MMIO page the BSP mapped in `enable_bsp`.
    let lapic = crate::apic::enable_ap();

    // (5) Wait for `start_cpu`. This is the sequence's only `sti`, and it comes
    // after (3), so OSXSAVE is still set before this core's first interrupt.
    // Each pass checks the flag with IF = 0, then `sti; hlt` as one asm block, so
    // the wake IPI cannot slip in between; IF is cleared again on every wake, so
    // the kernel's `ApMain` still starts with interrupts masked. With no LAPIC
    // access path no IPI can reach us, so poll instead.
    let Some(released) = RELEASED.get(cpu_index as usize) else {
        crate::cpu::halt_loop();
    };
    while !released.load(Ordering::Acquire) {
        if lapic.is_some() {
            crate::cpu::enable_interrupts_and_halt();
            crate::cpu::disable_interrupts();
        } else {
            core::hint::spin_loop();
        }
    }

    // (6) Hand off to the safe kernel. `start_cpu` refused to release us while
    // `AP_MAIN` was null, so it is set; park defensively if not.
    let raw = AP_MAIN.load(Ordering::Acquire);
    if raw.is_null() {
        crate::cpu::halt_loop();
    }
    // SAFETY: `raw` is non-null and was produced *only* by `set_ap_main` casting a
    // valid `ApMain` (`fn(ApInfo) -> !`) to `*mut ()`; we cast it straight back to
    // the identical fn-pointer type — the inverse of a sound fn→ptr→fn round-trip
    // (the same scheme, and argument, as `interrupts::handler_for`, X1). No data
    // is dereferenced; `transmute` is the only stable way to recover a fn pointer.
    let main: ApMain = unsafe { core::mem::transmute::<*mut (), ApMain>(raw) };
    main(ApInfo {
        cpu_index,
        lapic_id,
        simd_enabled,
        lapic,
    })
}
