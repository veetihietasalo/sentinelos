//! Enabling CPU security features — hardware W^X + user/kernel isolation.
//!
//! Companion to [`crate::cpuid`], which *detects* these features; this module
//! *enforces* the ones the processor advertises by flipping the relevant
//! `IA32_EFER` / `CR4` bits once at boot:
//!
//! - **NX** (`EFER.NXE`) — makes the page-table No-eXecute bit (PTE bit 63)
//!   effective, so data/stack pages marked non-executable actually fault on an
//!   instruction fetch (W^X). Limine already sets NXE, so this is an idempotent
//!   confirmation.
//! - **SMEP** (`CR4.SMEP`) — ring 0 cannot *execute* a user-accessible page.
//! - **SMAP** (`CR4.SMAP`) — ring 0 cannot *read/write* a user-accessible page
//!   unless `RFLAGS.AC` is set (`stac`/`clac`).
//! - **UMIP** (`CR4.UMIP`) — ring 3 cannot run `sgdt/sidt/sldt/smsw/str`.
//!
//! # Why this is a **safe** public API
//!
//! [`enable`] only ever *sets* bits the CPU reports via `cpuid` (never a
//! reserved/unsupported bit, which would `#GP`), and it preserves all other
//! `CR4`/`EFER` bits. Per the design doc
//! (`docs/specs/2026-07-14-cpu-security-features-design.md`) the kernel maps no
//! user-accessible page and runs no ring-3 code, so SMEP/SMAP/UMIP add faults
//! only for accesses that never occur today. Turning protections on cannot
//! corrupt memory or create UB — at worst a (currently impossible) illegal
//! access would fault. So the `unsafe` privileged writes stay inside this module
//! and the `#![forbid(unsafe_code)]` kernel calls a plain safe function.
//!
//! The privileged writes ([`crate::cpu::write_cr4`] / [`crate::cpu::write_msr`])
//! are registered in `kernel/docs/hal-tcb.md`.

use crate::cpu;
use crate::cpuid::{self, CpuidResult};

/// `IA32_EFER` model-specific register — the long-mode / NX enable word.
const IA32_EFER: u32 = 0xC000_0080;
/// `EFER.NXE` (bit 11): make the PTE No-eXecute bit effective.
const EFER_NXE: u64 = 1 << 11;

/// `CR4.UMIP` (bit 11): User-Mode Instruction Prevention.
const CR4_UMIP: u64 = 1 << 11;
/// `CR4.SMEP` (bit 20): Supervisor-Mode Execution Prevention.
const CR4_SMEP: u64 = 1 << 20;
/// `CR4.SMAP` (bit 21): Supervisor-Mode Access Prevention.
const CR4_SMAP: u64 = 1 << 21;

/// Which protections [`enable`] actually turned on (a feature the CPU does not
/// advertise is skipped and reads back `false`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Enabled {
    /// `EFER.NXE` — No-eXecute page permission (W^X).
    pub nx: bool,
    /// `CR4.SMEP` — supervisor can't execute user pages.
    pub smep: bool,
    /// `CR4.SMAP` — supervisor can't access user pages without `stac`/`clac`.
    pub smap: bool,
    /// `CR4.UMIP` — user-mode instruction prevention.
    pub umip: bool,
}

impl Enabled {
    /// Whether no protection was enabled (e.g. a minimal CPU that advertises none).
    #[must_use]
    pub fn is_empty(self) -> bool {
        !(self.nx || self.smep || self.smap || self.umip)
    }
}

/// Enable every W^X / isolation feature the CPU advertises, once, on this core.
///
/// Detection-gated: each bit is set only if the corresponding `cpuid` flag is
/// present, so we never write an unsupported bit (which would `#GP`). Idempotent
/// — safe to call again (e.g. per-AP once SMP lands). Returns what was enabled.
#[must_use]
pub fn enable() -> Enabled {
    // Re-derive support directly from CPUID leaves (rather than the string-named
    // feature table) so this policy does not depend on those display names.
    let max_std = cpuid::max_standard_leaf();
    let leaf7 = if max_std >= 7 {
        cpuid::raw(7, 0)
    } else {
        CpuidResult::default()
    };
    let max_ext = cpuid::max_extended_leaf();
    let ext1_edx = if max_ext >= 0x8000_0001 {
        cpuid::raw(0x8000_0001, 0).edx
    } else {
        0
    };

    let has_nx = ext1_edx & (1 << 20) != 0; // 0x8000_0001 EDX[20]
    let has_smep = leaf7.ebx & (1 << 7) != 0; // leaf 7 EBX[7]
    let has_smap = leaf7.ebx & (1 << 20) != 0; // leaf 7 EBX[20]
    let has_umip = leaf7.ecx & (1 << 2) != 0; // leaf 7 ECX[2]

    let mut enabled = Enabled::default();

    // NX first, via IA32_EFER. Idempotent (Limine sets NXE; our page flags rely
    // on it already).
    if has_nx {
        // SAFETY: IA32_EFER is implemented on every long-mode CPU (we are in long
        // mode), so the rdmsr/wrmsr cannot #GP. We read the current value and only
        // OR in NXE, preserving LME/LMA/SCE; enabling NX honors PTE bit 63, which
        // the kernel's page flags already set — it can only make an errant
        // instruction fetch fault, never corrupt memory.
        unsafe {
            let efer = cpu::read_msr(IA32_EFER);
            cpu::write_msr(IA32_EFER, efer | EFER_NXE);
        }
        enabled.nx = true;
    }

    // CR4 protections: read-modify-write, setting only advertised bits.
    let mut cr4 = cpu::read_cr4();
    if has_smep {
        cr4 |= CR4_SMEP;
        enabled.smep = true;
    }
    if has_smap {
        cr4 |= CR4_SMAP;
        enabled.smap = true;
    }
    if has_umip {
        cr4 |= CR4_UMIP;
        enabled.umip = true;
    }
    if enabled.smep || enabled.smap || enabled.umip {
        // SAFETY: `cr4` is the live CR4 with only CPU-advertised feature bits
        // OR-ed in (every other bit, incl. PAE/PGE, preserved). SMEP/SMAP fault
        // only on ring-0 use of user-accessible pages and UMIP only on ring-3
        // instructions; the kernel maps no user page and runs no ring-3 code
        // (see the design doc), so no currently-valid access changes behaviour —
        // this cannot create UB.
        unsafe {
            cpu::write_cr4(cr4);
        }
    }

    enabled
}
