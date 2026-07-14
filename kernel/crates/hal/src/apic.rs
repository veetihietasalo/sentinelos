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
//! The only `unsafe` here is the `MSR` access (via [`crate::cpu`]'s `read_msr` /
//! `write_msr`), documented below and registered in `kernel/docs/hal-tcb.md`.

use crate::cpu;
use crate::cpuid;

/// `IA32_APIC_BASE` MSR — the LAPIC enable/mode word.
const IA32_APIC_BASE: u32 = 0x1B;
/// `IA32_APIC_BASE.EN` (bit 11) — LAPIC global (hardware) enable.
const APIC_BASE_EN: u64 = 1 << 11;
/// `IA32_APIC_BASE.EXTD` (bit 10) — x2APIC mode enable (MSR register access).
const APIC_BASE_EXTD: u64 = 1 << 10;

// x2APIC register MSRs (the xAPIC MMIO offset >> 4, based at 0x800).
/// x2APIC ID register (read-only).
const X2APIC_ID: u32 = 0x802;
/// Spurious Interrupt Vector Register.
const X2APIC_SVR: u32 = 0x80F;
/// LVT LINT0 (local interrupt 0 — the 8259 PIC's line in virtual-wire mode).
const X2APIC_LVT_LINT0: u32 = 0x835;
/// LVT LINT1 (local interrupt 1 — NMI in virtual-wire mode).
const X2APIC_LVT_LINT1: u32 = 0x836;

/// `SVR` bit 8 — APIC software enable (unmasks the LVT entries).
const SVR_SOFTWARE_ENABLE: u64 = 1 << 8;
/// Spurious-interrupt vector delivered when the APIC has nothing better (0xFF).
const SPURIOUS_VECTOR: u64 = 0xFF;
/// LVT delivery mode `ExtINT` (0b111 in bits 10:8) — externally-provided vector.
const LVT_DELIVERY_EXTINT: u64 = 0b111 << 8;
/// LVT delivery mode `NMI` (0b100 in bits 10:8).
const LVT_DELIVERY_NMI: u64 = 0b100 << 8;

/// Whether the CPU advertises x2APIC (cpuid leaf 1 ECX bit 21).
#[must_use]
fn has_x2apic() -> bool {
    cpuid::raw(1, 0).ecx & (1 << 21) != 0
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
    let count = (cpuid::raw(1, 0).ebx >> 16) & 0xFF;
    count.max(1)
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
    Some((unsafe { cpu::read_msr(X2APIC_ID) }) as u32)
}

/// Enable the BSP's Local APIC in x2APIC mode, in **virtual-wire** configuration.
///
/// Returns the BSP's x2APIC ID, or `None` if the CPU does not advertise x2APIC
/// (in which case the caller stays on the legacy xAPIC/PIC path). Idempotent-ish:
/// re-running re-asserts the same bits. Call once on the BSP at boot, after the
/// PIC/PIT are programmed (so LINT0=ExtINT front-ends an already-configured PIC).
#[must_use]
pub fn enable_bsp() -> Option<u32> {
    if !has_x2apic() {
        return None;
    }
    // SAFETY: this is a fixed, architectural LAPIC bring-up sequence on MSRs that
    // exist on any x2APIC-capable CPU (checked above), touching no Rust memory:
    //   1. Enter x2APIC mode via IA32_APIC_BASE. The APIC mode machine forbids the
    //      (EN=0,EXTD=0) → (EN=1,EXTD=1) jump in a single write, so if the LAPIC is
    //      software-disabled we first set EN alone (enter xAPIC — a valid
    //      intermediate state), then set EXTD. We only OR bits in (never clear the
    //      base address). In practice EN is already set after reset/Limine, so the
    //      first write is usually skipped; handling EN=0 makes the sequence robust
    //      instead of asserting an unverified precondition. After EXTD is set the
    //      0x800-range registers below are accessible.
    //   2. SVR = software-enable | spurious vector 0xFF — unmask the LVT.
    //   3. LVT LINT0 = ExtINT — the 8259 PIC's INTR passes through unchanged, so
    //      the existing PIT/keyboard/mouse/NIC handlers (which EOI the PIC) keep
    //      working; ExtINT delivery never sets the LAPIC ISR, so no LAPIC EOI is
    //      owed. LINT1 = NMI. These only reconfigure interrupt *routing*, which
    //      cannot alias or corrupt Rust-managed memory.
    // The `kmain` caller verifies delivery survived by waiting for PIT ticks.
    unsafe {
        let base = cpu::read_msr(IA32_APIC_BASE);
        if base & APIC_BASE_EN == 0 {
            // Software-disabled LAPIC: enable xAPIC first, because a direct
            // disabled → x2APIC transition is illegal (`#GP`).
            cpu::write_msr(IA32_APIC_BASE, base | APIC_BASE_EN);
        }
        cpu::write_msr(IA32_APIC_BASE, base | APIC_BASE_EN | APIC_BASE_EXTD);
        cpu::write_msr(X2APIC_SVR, SVR_SOFTWARE_ENABLE | SPURIOUS_VECTOR);
        cpu::write_msr(X2APIC_LVT_LINT0, LVT_DELIVERY_EXTINT);
        cpu::write_msr(X2APIC_LVT_LINT1, LVT_DELIVERY_NMI);
    }
    // `id()` self-guards on EXTD (just set), so this is `Some(the BSP id)`.
    id()
}
