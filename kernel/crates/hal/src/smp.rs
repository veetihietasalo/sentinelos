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
//! - The kernel registers its AP main with [`set_ap_main`], then calls
//!   [`start_cpu`] once per AP (serially), passing the dense per-CPU index it
//!   assigned. The AP arrives in the kernel's `ApMain` with an [`ApInfo`] after
//!   [`ap_entry`] has, in a **fixed, branch-free order**: loaded this AP's private
//!   GDT/TSS (with its own double-fault IST stack), loaded the shared IDT, enabled
//!   its own vector state (`simd::enable`), and enabled its LAPIC (`apic::enable_ap`).
//!   Interrupts stay masked throughout; the *kernel* decides when to `sti`.
//! - **Invariant:** there is exactly one AP entry (`ap_entry`) and its sequence
//!   contains no `sti`, so `CR4.OSXSAVE` is always set on an AP before its first
//!   interrupt — and `isr_common` independently gates on the live bit anyway.
//!
//! All `unsafe` is registered in `kernel/docs/hal-tcb.md` (§2k).

use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, Ordering};

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
    /// This core's x2APIC ID if [`crate::apic::enable_ap`] switched it into x2APIC
    /// mode; `None` where x2APIC is not advertised (QEMU TCG).
    pub x2apic_id: Option<u32>,
}

/// The kernel-side AP main: never returns (the AP parks or schedules forever).
pub type ApMain = fn(ApInfo) -> !;

/// The registered [`ApMain`], type-erased (same scheme as
/// `interrupts::HANDLERS`). Null until [`set_ap_main`]; [`start_cpu`] refuses to
/// release an AP while it is null, so `ap_entry` never observes null in practice
/// and parks defensively if it somehow did.
static AP_MAIN: AtomicPtr<()> = AtomicPtr::new(null_mut());

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
pub fn start_cpu(limine_index: usize, cpu_index: u32) -> Result<(), StartError> {
    if cpu_index == 0 || cpu_index as usize >= MAX_CPUS {
        return Err(StartError::BadCpuIndex);
    }
    if AP_MAIN.load(Ordering::Acquire).is_null() {
        return Err(StartError::NoApMain);
    }
    // SAFETY: same response borrow as `cpus` (B1-pattern); the `&Cpu` we index
    // out of it points into the bootloader-owned, never-reclaimed CPU array and
    // is valid for the whole run.
    let response = MP_REQUEST.get_response().ok_or(StartError::NoResponse)?;
    let cpu: &Cpu = response
        .cpus()
        .get(limine_index)
        .ok_or(StartError::BadIndex)?;
    if cpu.lapic_id == response.bsp_lapic_id() {
        return Err(StartError::IsBsp);
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
    Ok(())
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
    // (4) This core's LAPIC into x2APIC mode (LINT0 masked — only the BSP fronts
    // the PIC); a no-op `None` where x2APIC is not advertised.
    let x2apic_id = crate::apic::enable_ap();

    // (5) Hand off to the safe kernel. `start_cpu` refused to release us while
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
        x2apic_id,
    })
}
