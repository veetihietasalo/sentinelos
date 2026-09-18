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
/// LVT bit 16 — mask: the local interrupt line is ignored.
const LVT_MASKED: u64 = 1 << 16;

/// cpuid leaf 1 ECX bit 21 — the CPU advertises x2APIC.
const CPUID_ECX_X2APIC: u32 = 1 << 21;

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

/// Enable the **calling application processor's** Local APIC in x2APIC mode.
///
/// The AP counterpart of [`enable_bsp`], with one deliberate difference: **LVT
/// LINT0 is masked**, not `ExtINT`. In virtual-wire mode exactly one LAPIC may
/// front the 8259 PIC's INTR line; the BSP already does. A second `ExtINT` sink
/// would make every PIC IRQ (PIT, keyboard, mouse, NIC) deliver on two cores at
/// once — double-counted ticks, drained-twice scancodes. Until the IOAPIC phase
/// routes device IRQs explicitly, APs receive no external interrupts at all; the
/// LAPIC is enabled so that the core has an x2APIC ID, a spurious vector, NMI
/// routing, and is ready to be an IPI / LAPIC-timer target later. LINT1 = NMI as
/// on the BSP.
///
/// Returns this core's x2APIC ID, or `None` (doing nothing) if the CPU does not
/// advertise x2APIC — the AP then stays in its reset-default xAPIC state, which
/// is fine for this phase (it takes no interrupts either way). Called once per AP
/// by `hal::smp::ap_entry`, interrupts masked.
#[must_use]
pub fn enable_ap() -> Option<u32> {
    if !has_x2apic() {
        return None;
    }
    // SAFETY: the same fixed, architectural LAPIC bring-up sequence as `enable_bsp`
    // (AP1), on MSRs that exist on any x2APIC-capable CPU (checked above), touching
    // no Rust memory — executed on *this* core's LAPIC (MSR-mapped LAPIC registers
    // are per-core by construction). The EN=0 → EN=1 → EN|EXTD ordering avoids the
    // illegal disabled→x2APIC jump; only bits are OR-ed into `IA32_APIC_BASE`. SVR
    // software-enables the LVT with spurious vector 0xFF; LINT0 is *masked* so this
    // core does not become a second ExtINT sink for the PIC (see the doc above);
    // LINT1 = NMI. These reconfigure interrupt routing only — they cannot alias or
    // corrupt Rust-managed memory.
    unsafe {
        let base = cpu::read_msr(IA32_APIC_BASE);
        if base & APIC_BASE_EN == 0 {
            cpu::write_msr(IA32_APIC_BASE, base | APIC_BASE_EN);
        }
        cpu::write_msr(IA32_APIC_BASE, base | APIC_BASE_EN | APIC_BASE_EXTD);
        cpu::write_msr(X2APIC_SVR, SVR_SOFTWARE_ENABLE | SPURIOUS_VECTOR);
        cpu::write_msr(X2APIC_LVT_LINT0, LVT_MASKED);
        cpu::write_msr(X2APIC_LVT_LINT1, LVT_DELIVERY_NMI);
    }
    id()
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
