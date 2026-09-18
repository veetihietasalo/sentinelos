//! Local APIC in **x2APIC** mode — part of the TCB, the first step toward SMP.
//!
//! Each logical CPU has a Local APIC (LAPIC). The legacy 8259 PIC ([`crate::pic`])
//! delivers IRQs to a single core; SMP needs the LAPIC (per-core) plus an IOAPIC
//! (external-IRQ routing) and inter-processor interrupts. This module takes the
//! first, non-disruptive step: enable the BSP's LAPIC in x2APIC mode.
//!
//! **Virtual wire.** Enabling the LAPIC makes it the interrupt gateway, so the
//! 8259 PIC's line must be routed through it or the PIT timer stops. We program
//! LVT LINT0 as `ExtINT` (the 8259 passes through, the CPU's INTA cycle fetches
//! the vector from the PIC exactly as before) and LINT1 as `NMI`. The existing
//! PIT handler — which EOIs the *PIC* — stays correct, because ExtINT delivery
//! does not touch the LAPIC's ISR. So this switch preserves the current timer /
//! keyboard / mouse / NIC IRQ path unchanged; migrating those to the IOAPIC is a
//! later, designed phase (see `docs/specs/2026-07-14-smp-x2apic-design.md`).
//!
//! **Application processors** (SMP phase 2, `hal::smp`) each enable their own
//! LAPIC via [`enable_ap`] — identical, except LINT0 is *masked* so only the BSP
//! fronts the PIC. [`cpuid_apic_id`] identifies the calling core in any LAPIC
//! mode (x2APIC or the TCG-only xAPIC), which is how the safe kernel finds its
//! per-CPU slot without a privileged read.
//!
//! **Two register-access paths.** Where the CPU advertises x2APIC (KVM, real
//! hardware) every register is an MSR at `0x800 + (offset >> 4)`. Where it does
//! not (QEMU TCG) the same registers are 32-bit MMIO words at the LAPIC's
//! physical base (`IA32_APIC_BASE[..12]`, normally `0xFEE0_0000`), which
//! [`enable_bsp`] maps once, uncached, through the audited `mm::map_mmio`. Both
//! paths program the same virtual-wire configuration and support the same two
//! SMP operations the per-CPU scheduler needs — [`send_ipi`] (a fixed-delivery
//! inter-processor interrupt, so a core idling in `hlt` learns it has work) and
//! [`eoi`] — so multi-core scheduling is exercised on every TCG boot test, not
//! only under KVM.
//!
//! The `unsafe` here is the `MSR` access (via [`crate::cpu`]'s `read_msr` /
//! `write_msr`) and the bounded volatile MMIO access to the mapped LAPIC page,
//! documented below and registered in `kernel/docs/hal-tcb.md`.

use crate::cpu;
use crate::cpuid;
use crate::mm::{PhysAddr, VirtAddr};
use core::sync::atomic::{AtomicU64, Ordering};

/// `IA32_APIC_BASE` MSR — the LAPIC enable/mode word.
const IA32_APIC_BASE: u32 = 0x1B;
/// `IA32_APIC_BASE.EN` (bit 11) — LAPIC global (hardware) enable.
const APIC_BASE_EN: u64 = 1 << 11;
/// `IA32_APIC_BASE.EXTD` (bit 10) — x2APIC mode enable (MSR register access).
const APIC_BASE_EXTD: u64 = 1 << 10;

/// Physical-address mask of `IA32_APIC_BASE`: bits 12..=51 hold the LAPIC MMIO
/// page (bits 0..11 are flags; bits above MAXPHYADDR are reserved).
const APIC_BASE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

// LAPIC register offsets (xAPIC MMIO byte offsets). In x2APIC mode the same
// register is MSR `0x800 + (offset >> 4)` — see `reg_read`/`reg_write`.
/// Local APIC ID register.
const REG_ID: u32 = 0x020;
/// End-Of-Interrupt register (write-only).
const REG_EOI: u32 = 0x0B0;
/// Spurious Interrupt Vector Register.
const REG_SVR: u32 = 0x0F0;
/// Interrupt Command Register, low dword (xAPIC) / whole 64-bit ICR (x2APIC).
const REG_ICR_LOW: u32 = 0x300;
/// Interrupt Command Register, high dword (xAPIC only: destination in 31:24).
const REG_ICR_HIGH: u32 = 0x310;
/// LVT LINT0 (local interrupt 0 — the 8259 PIC's line in virtual-wire mode).
const REG_LVT_LINT0: u32 = 0x350;
/// LVT LINT1 (local interrupt 1 — NMI in virtual-wire mode).
const REG_LVT_LINT1: u32 = 0x360;
/// Base MSR of the x2APIC register block.
const X2APIC_MSR_BASE: u32 = 0x800;
/// Size of the xAPIC MMIO register page.
const XAPIC_MMIO_LEN: usize = 0x1000;

/// xAPIC ICR low-dword bit 12 — delivery status (`1` = send pending).
const ICR_DELIVERY_PENDING: u32 = 1 << 12;
/// Upper bound on polling an xAPIC ICR send to completion (a few µs in practice).
const ICR_SEND_SPIN_LIMIT: u32 = 1_000_000;

/// `SVR` bit 8 — APIC software enable (unmasks the LVT entries).
const SVR_SOFTWARE_ENABLE: u64 = 1 << 8;
/// Spurious-interrupt vector delivered when the APIC has nothing better (0xFF).
const SPURIOUS_VECTOR: u64 = 0xFF;
/// LVT delivery mode `ExtINT` (0b111 in bits 10:8) — externally-provided vector.
const LVT_DELIVERY_EXTINT: u64 = 0b111 << 8;
/// LVT delivery mode `NMI` (0b100 in bits 10:8).
const LVT_DELIVERY_NMI: u64 = 0b100 << 8;
/// LVT bit 16 — mask: the local interrupt line is ignored.
const LVT_MASKED: u64 = 1 << 16;

/// cpuid leaf 1 ECX bit 21 — the CPU advertises x2APIC.
const CPUID_ECX_X2APIC: u32 = 1 << 21;

/// Virtual address of the mapped xAPIC MMIO page, or `0` until [`enable_bsp`]
/// maps it (never mapped where x2APIC is in use). Written once by the BSP
/// before any AP is released; every core then reads it — the LAPIC sits at the
/// same physical address on every core, so one mapping serves all of them.
static XAPIC_MMIO_BASE: AtomicU64 = AtomicU64::new(0);

/// How this CPU's LAPIC registers are reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LapicMode {
    /// MSR-based access (`IA32_APIC_BASE.EXTD` set).
    X2Apic,
    /// Memory-mapped access through the page [`enable_bsp`] mapped.
    XApic,
}

/// What [`enable_bsp`] / [`enable_ap`] report about the calling core's LAPIC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LapicInfo {
    /// The access path in use on this core.
    pub mode: LapicMode,
    /// This core's local APIC ID as read back from the LAPIC itself.
    pub id: u32,
}

impl LapicMode {
    /// Short label for boot output.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            LapicMode::X2Apic => "x2APIC",
            LapicMode::XApic => "xAPIC (MMIO)",
        }
    }
}

/// The access mode currently usable on the calling core, or `None` if neither
/// x2APIC mode is active nor an MMIO mapping exists yet.
fn access_mode() -> Option<LapicMode> {
    // SAFETY: IA32_APIC_BASE (MSR 0x1B) is implemented on every long-mode CPU, so
    // this read cannot `#GP`; it is a pure, side-effect-free register read.
    let base = unsafe { cpu::read_msr(IA32_APIC_BASE) };
    if base & APIC_BASE_EXTD != 0 {
        Some(LapicMode::X2Apic)
    } else if XAPIC_MMIO_BASE.load(Ordering::Acquire) != 0 {
        Some(LapicMode::XApic)
    } else {
        None
    }
}

/// Read a LAPIC register (`reg` = xAPIC byte offset) on the calling core.
///
/// # Safety
///
/// `mode` must be the access mode currently valid on this core (from
/// [`access_mode`]) and `reg` a defined, readable register offset below
/// `XAPIC_MMIO_LEN`. In x2APIC mode the corresponding MSR must exist (it does
/// for every register named in this module once `EXTD` is set).
unsafe fn reg_read(mode: LapicMode, reg: u32) -> u64 {
    match mode {
        // SAFETY: EXTD is set (that is what `X2Apic` means), so MSR
        // 0x800 + reg/16 is architecturally accessible; a read-only register
        // access with no side effect.
        LapicMode::X2Apic => unsafe { cpu::read_msr(X2APIC_MSR_BASE + (reg >> 4)) },
        LapicMode::XApic => {
            let base = XAPIC_MMIO_BASE.load(Ordering::Acquire);
            // SAFETY: `base` is the non-zero virtual address of the one 4 KiB
            // LAPIC page `enable_bsp` mapped uncached (PCD+PWT) via `mm::map_mmio`
            // and never unmaps; `reg < XAPIC_MMIO_LEN` and is 16-byte aligned
            // (every register offset in this module is), so the 4-byte volatile
            // read is in bounds and aligned. Volatile because it is a device
            // register, not memory the compiler may cache or elide.
            unsafe { core::ptr::read_volatile((base + u64::from(reg)) as *const u32) as u64 }
        }
    }
}

/// Write a LAPIC register (`reg` = xAPIC byte offset) on the calling core.
///
/// # Safety
///
/// As [`reg_read`], for a writable register. In xAPIC mode only the low 32 bits
/// of `value` are written (every xAPIC register is 32 bits wide).
unsafe fn reg_write(mode: LapicMode, reg: u32, value: u64) {
    match mode {
        // SAFETY: as in `reg_read` — EXTD is set, the MSR exists; writing a LAPIC
        // register reconfigures interrupt routing/state only and cannot alias
        // Rust memory.
        LapicMode::X2Apic => unsafe { cpu::write_msr(X2APIC_MSR_BASE + (reg >> 4), value) },
        LapicMode::XApic => {
            let base = XAPIC_MMIO_BASE.load(Ordering::Acquire);
            // SAFETY: same bounds/alignment/mapping argument as `reg_read`; the
            // volatile write reaches the device (uncached mapping) and touches no
            // Rust-managed memory.
            unsafe { core::ptr::write_volatile((base + u64::from(reg)) as *mut u32, value as u32) }
        }
    }
}

/// The LAPIC ID as the LAPIC itself reports it, in either mode (x2APIC: the full
/// 32-bit ID register; xAPIC: bits 31:24 of the ID register).
fn lapic_id_in(mode: LapicMode) -> u32 {
    // SAFETY: `mode` is the live access mode and `REG_ID` is a readable register.
    let raw = unsafe { reg_read(mode, REG_ID) };
    match mode {
        LapicMode::X2Apic => raw as u32,
        LapicMode::XApic => (raw as u32) >> 24,
    }
}

/// Whether a leaf-1 ECX value advertises x2APIC (bit 21).
///
/// Pure bit test, split out from [`has_x2apic`] so it is host-unit-testable and
/// Kani-provable (the `cpuid::raw` read it wraps is privileged inline asm and thus
/// neither).
#[must_use]
const fn ecx_has_x2apic(ecx: u32) -> bool {
    ecx & CPUID_ECX_X2APIC != 0
}

/// Max-addressable logical processors per package from leaf-1 EBX bits 23:16,
/// clamped to at least 1.
///
/// Pure, split out from [`logical_cpu_count`] for the same testability reason.
#[must_use]
const fn ebx_logical_cpu_count(ebx: u32) -> u32 {
    let count = (ebx >> 16) & 0xFF;
    // `Ord::max` is not `const`, so clamp to ≥1 manually.
    if count == 0 {
        1
    } else {
        count
    }
}

/// Whether the CPU advertises x2APIC (cpuid leaf 1 ECX bit 21).
#[must_use]
fn has_x2apic() -> bool {
    ecx_has_x2apic(cpuid::raw(1, 0).ecx)
}

/// Maximum-addressable logical processors per package (cpuid leaf 1 EBX 23:16).
///
/// This is an *upper bound*, **not** the number of online CPUs (that is the ACPI
/// MADT's job, a later phase). It is also topology-dependent: QEMU's default
/// `-smp N` is N single-core packages, so this field often reads **1** even with
/// N vCPUs — the per-package max, not the machine total. Good enough as a coarse
/// bring-up figure; the real online-AP list arrives with MADT parsing in phase 3.
#[must_use]
pub fn logical_cpu_count() -> u32 {
    ebx_logical_cpu_count(cpuid::raw(1, 0).ebx)
}

/// The current core's x2APIC ID, or `None` if the LAPIC is not in x2APIC mode.
///
/// Reads `IA32_APIC_BASE` first and checks the `EXTD` bit: MSR `0x802` exists only
/// in x2APIC mode (reading it in xAPIC mode `#GP`s), so this **self-guards** and
/// never faults regardless of call order — a safe wrapper must not depend on the
/// caller having entered x2APIC mode. Returns `Some` only after [`enable_bsp`] (or
/// firmware) has entered x2APIC mode.
#[must_use]
pub fn id() -> Option<u32> {
    // SAFETY: IA32_APIC_BASE (MSR 0x1B) is implemented on every long-mode CPU, so
    // this read cannot `#GP`; it is a pure, side-effect-free register read.
    let base = unsafe { cpu::read_msr(IA32_APIC_BASE) };
    if base & APIC_BASE_EXTD == 0 {
        return None;
    }
    // SAFETY: EXTD is confirmed set above, so the LAPIC is in x2APIC mode and MSR
    // 0x802 (x2APIC ID) is architecturally accessible; a read-only register access
    // with no side effect — cannot corrupt memory.
    Some(lapic_id_in(LapicMode::X2Apic))
}

/// Enable the BSP's Local APIC — **x2APIC** where advertised, otherwise **xAPIC
/// via a fresh uncached MMIO mapping** — in **virtual-wire** configuration.
///
/// Returns the mode chosen and the BSP's LAPIC ID, or `None` if the LAPIC is
/// unreachable in both ways (no x2APIC *and* `mm::map_mmio` failed — e.g. called
/// before `mm::init`), in which case the caller stays on the bare legacy PIC
/// path. Call once on the BSP at boot, after the PIC/PIT are programmed (so
/// LINT0=ExtINT front-ends an already-configured PIC) and after `mm::init`.
///
/// The xAPIC path re-asserts the very configuration firmware already left the
/// BSP in (SeaBIOS boots in virtual-wire mode), so it is idempotent there; what
/// it adds is the **mapping**, which is what later lets this core send IPIs
/// ([`send_ipi`]) and lets application processors software-enable themselves
/// ([`enable_ap`]) under TCG, where x2APIC does not exist.
#[must_use]
pub fn enable_bsp() -> Option<LapicInfo> {
    let mode = if has_x2apic() {
        // SAFETY: this is a fixed, architectural LAPIC bring-up sequence on MSRs
        // that exist on any x2APIC-capable CPU (checked above), touching no Rust
        // memory: enter x2APIC mode via IA32_APIC_BASE. The APIC mode machine
        // forbids the (EN=0,EXTD=0) → (EN=1,EXTD=1) jump in a single write, so if
        // the LAPIC is software-disabled we first set EN alone (enter xAPIC — a
        // valid intermediate state), then set EXTD. We only OR bits in (never
        // clear the base address). In practice EN is already set after
        // reset/Limine, so the first write is usually skipped; handling EN=0
        // makes the sequence robust instead of asserting an unverified
        // precondition. After EXTD is set the 0x800-range registers are
        // accessible.
        unsafe {
            let base = cpu::read_msr(IA32_APIC_BASE);
            if base & APIC_BASE_EN == 0 {
                // Software-disabled LAPIC: enable xAPIC first, because a direct
                // disabled → x2APIC transition is illegal (`#GP`).
                cpu::write_msr(IA32_APIC_BASE, base | APIC_BASE_EN);
            }
            cpu::write_msr(IA32_APIC_BASE, base | APIC_BASE_EN | APIC_BASE_EXTD);
        }
        LapicMode::X2Apic
    } else {
        map_xapic_mmio()?;
        LapicMode::XApic
    };
    // SAFETY: `mode` is now the live access mode on this core. The three writes
    // are the virtual-wire configuration: SVR = software-enable | spurious vector
    // 0xFF (unmask the LVT); LVT LINT0 = ExtINT — the 8259 PIC's INTR passes
    // through unchanged, so the existing PIT/keyboard/mouse/NIC handlers (which
    // EOI the PIC) keep working; ExtINT delivery never sets the LAPIC ISR, so no
    // LAPIC EOI is owed; LINT1 = NMI. These only reconfigure interrupt *routing*,
    // which cannot alias or corrupt Rust-managed memory. The `kmain` caller
    // verifies delivery survived by waiting for PIT ticks.
    unsafe {
        reg_write(mode, REG_SVR, SVR_SOFTWARE_ENABLE | SPURIOUS_VECTOR);
        reg_write(mode, REG_LVT_LINT0, LVT_DELIVERY_EXTINT);
        reg_write(mode, REG_LVT_LINT1, LVT_DELIVERY_NMI);
    }
    Some(LapicInfo {
        mode,
        id: lapic_id_in(mode),
    })
}

/// Map the xAPIC MMIO page (once) and publish its virtual address.
///
/// The LAPIC's physical base comes from `IA32_APIC_BASE`; it is the same on
/// every core (each core sees its *own* LAPIC there), so one mapping serves the
/// BSP and every AP. Requires `mm::init` (the HHDM offset + frame allocator).
fn map_xapic_mmio() -> Option<()> {
    if XAPIC_MMIO_BASE.load(Ordering::Acquire) != 0 {
        return Some(());
    }
    // SAFETY: IA32_APIC_BASE is implemented on every long-mode CPU; a pure read.
    let base = unsafe { cpu::read_msr(IA32_APIC_BASE) };
    if base & APIC_BASE_EN == 0 {
        // Hardware-disabled LAPIC: the MMIO page would be inert. (Cannot happen
        // on a machine whose APs the bootloader just started via INIT-SIPI.)
        return None;
    }
    let phys = PhysAddr::new(base & APIC_BASE_ADDR_MASK);
    let virt: VirtAddr = crate::mm::map_mmio(phys, XAPIC_MMIO_LEN).ok()?;
    XAPIC_MMIO_BASE.store(virt.as_u64(), Ordering::Release);
    Some(())
}

/// Enable the **calling application processor's** Local APIC — x2APIC where
/// advertised, else through the MMIO page [`enable_bsp`] mapped.
///
/// The AP counterpart of [`enable_bsp`], with one deliberate difference: **LVT
/// LINT0 is masked**, not `ExtINT`. In virtual-wire mode exactly one LAPIC may
/// front the 8259 PIC's INTR line; the BSP already does. A second `ExtINT` sink
/// would make every PIC IRQ (PIT, keyboard, mouse, NIC) deliver on two cores at
/// once — double-counted ticks, drained-twice scancodes. Until the IOAPIC phase
/// routes device IRQs explicitly, APs receive **only IPIs**: the software-enable
/// here (SVR bit 8) is what lets a fixed-delivery IPI ([`send_ipi`]) reach this
/// core at all — a software-disabled LAPIC drops them — so it is the
/// precondition for the per-CPU scheduler's wake-ups. LINT1 = NMI as on the BSP.
///
/// Returns the mode and this core's LAPIC ID, or `None` (doing nothing) when
/// neither access path exists — only possible if [`enable_bsp`] itself found no
/// LAPIC, in which case no AP is ever started. Called once per AP by
/// `hal::smp::ap_entry`, interrupts masked.
#[must_use]
pub fn enable_ap() -> Option<LapicInfo> {
    let mode = if has_x2apic() {
        // SAFETY: the same fixed, architectural mode-switch sequence as
        // `enable_bsp` (AP1), on MSRs that exist on any x2APIC-capable CPU
        // (checked above), executed on *this* core's LAPIC (MSR-mapped LAPIC
        // registers are per-core by construction). The EN=0 → EN=1 → EN|EXTD
        // ordering avoids the illegal disabled→x2APIC jump; only bits are OR-ed
        // into `IA32_APIC_BASE`. Touches no Rust memory.
        unsafe {
            let base = cpu::read_msr(IA32_APIC_BASE);
            if base & APIC_BASE_EN == 0 {
                cpu::write_msr(IA32_APIC_BASE, base | APIC_BASE_EN);
            }
            cpu::write_msr(IA32_APIC_BASE, base | APIC_BASE_EN | APIC_BASE_EXTD);
        }
        LapicMode::X2Apic
    } else if XAPIC_MMIO_BASE.load(Ordering::Acquire) != 0 {
        LapicMode::XApic
    } else {
        return None;
    };
    // SAFETY: `mode` is the live access mode on this core. SVR software-enables
    // the LVT with spurious vector 0xFF; LINT0 is *masked* so this core does not
    // become a second ExtINT sink for the PIC (see the doc above); LINT1 = NMI.
    // Routing only — cannot alias or corrupt Rust memory. In xAPIC mode the
    // writes go through the shared uncached mapping to *this* core's LAPIC (the
    // physical page is per-core).
    unsafe {
        reg_write(mode, REG_SVR, SVR_SOFTWARE_ENABLE | SPURIOUS_VECTOR);
        reg_write(mode, REG_LVT_LINT0, LVT_MASKED);
        reg_write(mode, REG_LVT_LINT1, LVT_DELIVERY_NMI);
    }
    Some(LapicInfo {
        mode,
        id: lapic_id_in(mode),
    })
}

/// Send a **fixed-delivery, edge-triggered, physical-destination** IPI carrying
/// `vector` to the core whose LAPIC ID is `dest_lapic_id`.
///
/// This is how one core tells another it has work: `kernel::sched` places a task
/// on a remote per-CPU run queue and then sends the reschedule vector, waking
/// that core out of its `sti; hlt` idle. Returns `false` (sending nothing) if
/// this core has no usable LAPIC access path. The delivery itself is
/// asynchronous; in xAPIC mode this waits (bounded) for the ICR's send-pending
/// bit to clear so back-to-back sends never overwrite an in-flight command
/// (x2APIC has no such bit — its ICR write is atomic).
#[must_use]
pub fn send_ipi(dest_lapic_id: u32, vector: u8) -> bool {
    let Some(mode) = access_mode() else {
        return false;
    };
    let low = u64::from(vector); // delivery=fixed(000), dest mode=physical, edge
    match mode {
        LapicMode::X2Apic => {
            // SAFETY: EXTD is set; the x2APIC ICR (MSR 0x830) is one 64-bit write
            // with the destination in bits 63:32 and the fixed command below —
            // reserved bits zero. Sending an interrupt to another core cannot
            // alias Rust memory; what the receiving core does is decided by its
            // IDT (the kernel registered a handler for this vector before any AP
            // was released).
            unsafe { reg_write(mode, REG_ICR_LOW, (u64::from(dest_lapic_id) << 32) | low) }
        }
        LapicMode::XApic => {
            // SAFETY: the xAPIC ICR is two 32-bit MMIO words: destination in
            // ICR_HIGH[31:24], then the command word in ICR_LOW (the write to the
            // low word triggers the send). Both offsets are in the mapped page.
            // Polling bit 12 afterwards is a read-only wait; bounded so a
            // misbehaving APIC cannot hang the sender.
            unsafe {
                reg_write(mode, REG_ICR_HIGH, u64::from(dest_lapic_id & 0xFF) << 24);
                reg_write(mode, REG_ICR_LOW, low);
                let mut spins = 0u32;
                while reg_read(mode, REG_ICR_LOW) as u32 & ICR_DELIVERY_PENDING != 0
                    && spins < ICR_SEND_SPIN_LIMIT
                {
                    core::hint::spin_loop();
                    spins += 1;
                }
            }
        }
    }
    true
}

/// Signal end-of-interrupt to the **calling core's** LAPIC.
///
/// Required at the end of every handler for an interrupt the LAPIC itself
/// delivered — IPIs and (later) LAPIC-timer ticks — so the LAPIC clears the
/// in-service bit and can deliver the next one. **Not** for PIC-routed IRQs
/// (those are `ExtINT`, never in the LAPIC's ISR, and EOI the PIC instead) nor
/// for the spurious vector. A no-op if this core has no LAPIC access path.
pub fn eoi() {
    if let Some(mode) = access_mode() {
        // SAFETY: `mode` is live; EOI is a write-only register whose value is
        // ignored (0 by convention). Acknowledging an interrupt cannot alias Rust
        // memory.
        unsafe { reg_write(mode, REG_EOI, 0) }
    }
}

/// The **calling core's** APIC ID as reported by `cpuid`, valid in any LAPIC mode.
///
/// [`id`] reads the x2APIC ID register, which exists only once the core is in
/// x2APIC mode — so it cannot identify a core under QEMU TCG (no x2APIC) or an AP
/// before its LAPIC is enabled. `cpuid` reports the same identity without any
/// privileged access or mode dependency: leaf `0xB` `EDX` is the full 32-bit
/// x2APIC ID wherever leaf `0xB` exists (every CPU this project targets); on an
/// older CPU whose max basic leaf is below `0xB`, leaf 1 `EBX[31:24]` gives the
/// 8-bit initial APIC ID. Either equals the LAPIC ID the ACPI MADT (and hence the
/// bootloader's MP response) lists for this core, so the safe kernel uses it to
/// find its own per-CPU slot. Pure `cpuid` reads (§8, Q1) — **no** new privileged
/// op; the field decode is split into a pure `const fn` for host tests / Kani.
#[must_use]
pub fn cpuid_apic_id() -> u32 {
    if cpuid::raw(0, 0).eax >= 0xB {
        cpuid::raw(0xB, 0).edx
    } else {
        initial_apic_id_from_ebx(cpuid::raw(1, 0).ebx)
    }
}

/// The 8-bit initial APIC ID from leaf-1 `EBX` bits 31:24 (pure decode).
#[must_use]
const fn initial_apic_id_from_ebx(ebx: u32) -> u32 {
    ebx >> 24
}

// ── Unit tests (host) ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{ebx_logical_cpu_count, ecx_has_x2apic, initial_apic_id_from_ebx};

    #[test]
    fn initial_apic_id_is_ebx_31_24() {
        assert_eq!(initial_apic_id_from_ebx(0), 0);
        assert_eq!(initial_apic_id_from_ebx(0x0100_0000), 1);
        assert_eq!(initial_apic_id_from_ebx(0xFF00_0000), 255);
        // Only bits 31:24 are the APIC ID — the logical-count byte (23:16), the
        // CLFLUSH size (15:8), and the brand index (7:0) must not leak in.
        assert_eq!(initial_apic_id_from_ebx(0x03FF_FFFF), 3);
        assert_eq!(initial_apic_id_from_ebx(0x00FF_FFFF), 0);
    }

    #[test]
    fn x2apic_bit_detected() {
        assert!(!ecx_has_x2apic(0));
        assert!(ecx_has_x2apic(1 << 21));
        assert!(!ecx_has_x2apic(!(1 << 21)));
        assert!(ecx_has_x2apic(0xFFFF_FFFF));
        // Off-by-one guards: the adjacent bits (SSE4.2 = 20, MOVBE = 22) must not
        // read as x2APIC.
        assert!(!ecx_has_x2apic(1 << 20));
        assert!(!ecx_has_x2apic(1 << 22));
    }

    #[test]
    fn logical_cpu_count_reads_ebx_23_16_and_clamps() {
        assert_eq!(ebx_logical_cpu_count(0), 1); // clamp: never 0
        assert_eq!(ebx_logical_cpu_count(1 << 16), 1);
        assert_eq!(ebx_logical_cpu_count(4 << 16), 4);
        assert_eq!(ebx_logical_cpu_count(0xFF << 16), 255);
        // Only bits 23:16 are decoded — the surrounding bytes are ignored.
        assert_eq!(ebx_logical_cpu_count(0xABCD_EF12), 0xCD);
        // Bits outside 23:16 do not leak into the field (still clamps to 1).
        assert_eq!(ebx_logical_cpu_count(0xFF00_FFFF), 1);
    }
}

/// Kani proof harnesses — exhaustive (all-input) proofs of the pure cpuid-field
/// decode logic. Compiled only under `cargo kani` (the `kani` cfg); the normal
/// stable build (and `cargo test`) excludes this module. Run `cargo kani -p hal`.
#[cfg(kani)]
mod proofs {
    use super::{ebx_logical_cpu_count, ecx_has_x2apic, initial_apic_id_from_ebx};

    /// `initial_apic_id_from_ebx` is **total** and always fits 8 bits, for any EBX.
    #[kani::proof]
    fn initial_apic_id_is_total_and_8_bit() {
        let ebx: u32 = kani::any();
        let id = initial_apic_id_from_ebx(ebx);
        assert!(id <= 0xFF);
        assert_eq!(id, (ebx >> 24) & 0xFF);
    }

    /// `ecx_has_x2apic` is **total** (never panics for any 32-bit ECX) and is
    /// exactly the bit-21 test over all inputs.
    #[kani::proof]
    fn ecx_has_x2apic_is_total() {
        let ecx: u32 = kani::any();
        assert_eq!(ecx_has_x2apic(ecx), ecx & (1 << 21) != 0);
    }

    /// `ebx_logical_cpu_count` is **total** and always clamped to `1..=255`
    /// (never 0), for any 32-bit EBX.
    #[kani::proof]
    fn ebx_logical_cpu_count_is_total_and_clamped() {
        let ebx: u32 = kani::any();
        let n = ebx_logical_cpu_count(ebx);
        assert!((1..=255).contains(&n));
    }
}
