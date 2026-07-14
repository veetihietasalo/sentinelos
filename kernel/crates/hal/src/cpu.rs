//! CPU primitives — safe wrappers over privileged `x86_64` instructions.
//!
//! This module is part of the TCB. Each public function is a **safe** wrapper
//! around exactly one `unsafe` inline-assembly block, and every such block
//! carries a `// SAFETY:` justification. See `kernel/docs/hal-tcb.md` for the
//! registry of every `unsafe` operation in the HAL.

use core::arch::asm;

/// Disable maskable hardware interrupts on the current CPU (`cli`).
///
/// After this call returns, the CPU will not service maskable external
/// interrupts until interrupts are re-enabled (e.g. via `sti`, not yet exposed)
/// or the flags register is otherwise restored. Non-maskable interrupts (NMI)
/// and exceptions are unaffected.
///
/// This is a safe wrapper: clearing the interrupt flag cannot, on its own,
/// violate Rust's memory-safety invariants. It is exposed so that higher-level
/// safe code can establish short critical sections without `unsafe`.
#[inline]
pub fn disable_interrupts() {
    // SAFETY: `cli` clears the interrupt-enable flag (IF) in RFLAGS. It touches
    // no memory and reads/writes no general-purpose registers, so `nomem` and
    // `nostack` hold. It *does* modify RFLAGS.IF, so `preserves_flags` is NOT
    // set. Disabling interrupts cannot create undefined behaviour: it only
    // affects interrupt delivery timing, never memory validity or aliasing.
    unsafe {
        asm!("cli", options(nomem, nostack));
    }
}

/// Enable maskable hardware interrupts on the current CPU (`sti`).
///
/// After this call the CPU will (subject to the interrupt-shadow of `sti`)
/// service maskable external interrupts again. This is the inverse of
/// [`disable_interrupts`] and is used to re-open an interrupt window after a
/// critical section.
///
/// This is a safe wrapper: setting the interrupt flag cannot, on its own,
/// violate Rust's memory-safety invariants. Whether an interrupt *handler* is
/// safe to run is the responsibility of whoever installed the IDT (out of scope
/// for sub-project #1, where no interrupt handlers are installed).
#[inline]
pub fn enable_interrupts() {
    // SAFETY: `sti` sets the interrupt-enable flag (IF) in RFLAGS. It touches no
    // memory and no general-purpose registers, so `nomem`/`nostack` hold; it
    // modifies RFLAGS.IF so `preserves_flags` is NOT set. Enabling interrupt
    // delivery is not itself UB. (At bring-up no IDT/handlers exist, so this is
    // provided for completeness and symmetry; callers are responsible for IDT
    // state before relying on handler execution.)
    unsafe {
        asm!("sti", options(nomem, nostack));
    }
}

/// Raise a breakpoint exception (`int3`, vector 3) on the current CPU.
///
/// `int3` is a one-byte software interrupt that traps to the IDT's vector-3
/// gate. It is the canonical way to *probe* a live IDT: if the breakpoint
/// handler runs and returns, the whole interrupt path is proven working. The
/// kernel uses this as a one-shot IDT self-test at boot.
///
/// This is a safe wrapper: triggering a breakpoint cannot, on its own, violate
/// Rust's memory-safety invariants. It is only meaningful once an IDT with a
/// resumable vector-3 handler is loaded; with no handler the `hal` default
/// reporter runs and halts (so it never silently corrupts state).
#[inline]
pub fn breakpoint() {
    // SAFETY: `int3` raises the breakpoint exception, vectoring through the IDT's
    // gate for vector 3. It accesses no program memory (`nomem`) and does not use
    // the stack from Rust's point of view beyond the CPU's own interrupt-frame
    // push, which the ISR stub balances (`nostack` is therefore appropriate for
    // the inline-asm boundary). Whether execution resumes depends on the
    // installed handler, but the instruction itself cannot create UB or corrupt
    // memory; at worst, with no handler, `hal`'s default reporter halts the core.
    unsafe {
        asm!("int3", options(nomem, nostack));
    }
}

/// Read `CR2`, the faulting linear address recorded on a page fault (`#PF`).
///
/// On a page fault (vector 14) the CPU latches the address whose translation
/// failed into the `CR2` control register. A `#PF` handler reads it to report
/// *which* address faulted. The value is only meaningful immediately inside a
/// page-fault handler, before any later memory access overwrites it.
///
/// This is a safe wrapper: reading `CR2` is a pure register read with no memory
/// effect and cannot, on its own, violate Rust's memory-safety invariants.
#[inline]
#[must_use]
pub fn read_cr2() -> u64 {
    let value: u64;
    // SAFETY: `mov {}, cr2` copies the 64-bit CR2 control register into a
    // general-purpose register. CR2 is readable at CPL 0 (the kernel always runs
    // ring 0 here); the read accesses no program memory (`nomem`), uses no stack
    // (`nostack`), and does not modify RFLAGS (`preserves_flags`). Reading a
    // control register cannot create undefined behaviour or affect memory
    // validity/aliasing — it only observes the last faulting linear address.
    unsafe {
        asm!("mov {}, cr2", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
}

/// Read the `CR4` control register (the feature-enable flags: SMEP, SMAP, UMIP,
/// PAE, PGE, …).
///
/// A pure register read with no memory effect; exposed **safe** so higher-level
/// safe code (and the `cpuinfo`-style reporting) can inspect which hardware
/// protections are active without `unsafe`.
#[inline]
#[must_use]
pub fn read_cr4() -> u64 {
    let value: u64;
    // SAFETY: `mov {}, cr4` copies the 64-bit CR4 control register into a GP
    // register. CR4 is readable at CPL 0 (the kernel always runs ring 0); the
    // read accesses no program memory (`nomem`), uses no stack (`nostack`), and
    // leaves RFLAGS untouched (`preserves_flags`). Observing a control register
    // cannot create UB or affect memory validity/aliasing.
    unsafe {
        asm!("mov {}, cr4", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
}

/// Write the `CR4` control register.
///
/// # Safety
///
/// The written value must keep the system sound: it must preserve every bit the
/// active configuration depends on (e.g. `PAE`, `PGE`) and must only *set*
/// feature bits the CPU actually implements — writing a reserved or unsupported
/// bit raises `#GP`. Enabling paging-relevant protections (SMEP/SMAP) is only
/// safe if no kernel-executed/accessed page is user-accessible. This primitive
/// is `pub(crate)` and is driven by two callers, each read-modify-writing to set
/// only detected, audited-safe bits: [`crate::cpu_security::enable`] (SMEP/SMAP/
/// UMIP) and [`crate::simd::enable`] (`OSXSAVE`, to bring up AVX vector state).
#[inline]
pub(crate) unsafe fn write_cr4(value: u64) {
    // SAFETY: the caller (`cpu_security::enable` or `simd::enable`) guarantees
    // `value` is the
    // current CR4 with only supported, memory-safety-preserving feature bits
    // OR-ed in. `mov cr4, {}` is a privileged move legal at CPL 0. We omit
    // `nomem` deliberately — a CR4 write can change paging-related semantics, so
    // it acts as a conservative compiler barrier around memory accesses; it uses
    // no stack (`nostack`) and does not modify RFLAGS (`preserves_flags`).
    unsafe {
        asm!("mov cr4, {}", in(reg) value, options(nostack, preserves_flags));
    }
}

/// Read a model-specific register via `rdmsr`, returning `edx:eax` as one `u64`.
///
/// # Safety
///
/// `msr` must name an MSR the CPU implements; `rdmsr` on an unimplemented MSR
/// raises `#GP`. `pub(crate)`; callers pass only known-present MSRs: `IA32_EFER`
/// (every long-mode CPU), and — from [`crate::apic`] — `IA32_APIC_BASE` plus the
/// x2APIC register MSRs (`0x800..=0x8FF`), which are only read after
/// [`crate::apic::enable_bsp`] has switched the LAPIC into x2APIC mode (reading
/// them in xAPIC mode `#GP`s, so the mode switch is a precondition).
#[inline]
#[must_use]
pub(crate) unsafe fn read_msr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: the caller guarantees `msr` is implemented, so `rdmsr` cannot
    // `#GP`. It reads the MSR selected by `ecx` into `edx:eax`, touching no
    // program memory (`nomem`), no stack (`nostack`), and no RFLAGS
    // (`preserves_flags`). A pure MSR read cannot create UB.
    unsafe {
        asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi,
             options(nomem, nostack, preserves_flags));
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// Write a model-specific register via `wrmsr` (`value` split across `edx:eax`).
///
/// # Safety
///
/// `msr` must name a writable, implemented MSR and `value` must be
/// architecturally valid for it — otherwise `wrmsr` raises `#GP` (or worse,
/// reconfigures the CPU). `pub(crate)`; driven by [`crate::cpu_security::enable`]
/// writing a validated `IA32_EFER`, and by [`crate::apic::enable_bsp`] writing
/// `IA32_APIC_BASE` (EN|EXTD) and the x2APIC LVT/SVR MSRs (`0x800..=0x8FF`) as a
/// fixed architectural LAPIC bring-up sequence — each MSR checked present via
/// `cpuid` before the write.
#[inline]
pub(crate) unsafe fn write_msr(msr: u32, value: u64) {
    let lo = value as u32;
    let hi = (value >> 32) as u32;
    // SAFETY: the caller guarantees `msr` is a writable implemented MSR and
    // `value` is valid for it (IA32_EFER with NXE OR-ed into its current value,
    // or — from apic::enable_bsp — IA32_APIC_BASE with EN|EXTD or an x2APIC
    // LVT/SVR register, each present on the checked-x2APIC-capable CPU). `wrmsr`
    // writes `edx:eax` to the MSR named by `ecx`. We omit
    // `nomem` (an EFER write changes NX paging semantics, so it acts as a
    // conservative barrier); it uses no stack and preserves RFLAGS.
    unsafe {
        asm!("wrmsr", in("ecx") msr, in("eax") lo, in("edx") hi,
             options(nostack, preserves_flags));
    }
}

/// Read an extended control register (`xgetbv`), returning `edx:eax` as one `u64`.
///
/// Used to read `XCR0` (the enabled XSAVE state-component mask) when bringing up
/// AVX vector state.
///
/// # Safety
///
/// `xgetbv` `#UD`s unless `CR4.OSXSAVE` is already set, and `#GP`s for a reserved
/// `xcr` index. `pub(crate)`; the sole caller ([`crate::simd`]) reads only `XCR0`
/// (index 0) and only after it has set `CR4.OSXSAVE` (or confirmed it set).
#[inline]
#[must_use]
pub(crate) unsafe fn xgetbv(xcr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: the caller guarantees `CR4.OSXSAVE` is set and `xcr` is a valid index
    // (0 = XCR0), so `xgetbv` neither `#UD`s nor `#GP`s. It reads the XCR selected
    // by `ecx` into `edx:eax`, touching no memory (`nomem`), no stack (`nostack`),
    // and no RFLAGS (`preserves_flags`). A pure control-register read cannot create
    // UB.
    unsafe {
        asm!("xgetbv", in("ecx") xcr, out("eax") lo, out("edx") hi,
             options(nomem, nostack, preserves_flags));
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// Write an extended control register (`xsetbv`), `value` split across `edx:eax`.
///
/// Used to enable AVX (`YMM`) state in `XCR0` so `avx`/`avx2` instructions do not
/// `#UD`.
///
/// # Safety
///
/// `xsetbv` `#UD`s unless `CR4.OSXSAVE` is set, and `#GP`s if `value` sets a
/// state-component bit the CPU does not support or an invalid combination (e.g.
/// AVX without SSE). `pub(crate)`; the sole caller ([`crate::simd::enable`]) sets
/// `CR4.OSXSAVE` first and writes only `XCR0` with the x87|SSE|AVX bits, each
/// confirmed supported via `cpuid` — so the write is always architecturally valid.
#[inline]
pub(crate) unsafe fn xsetbv(xcr: u32, value: u64) {
    let lo = value as u32;
    let hi = (value >> 32) as u32;
    // SAFETY: the caller guarantees `CR4.OSXSAVE` is set and `value` is a valid
    // XCR0 mask for this CPU (x87|SSE|AVX, all cpuid-confirmed), so `xsetbv`
    // neither `#UD`s nor `#GP`s. Enabling AVX state only makes YMM saveable and
    // AVX instructions legal; it changes no Rust-visible memory. We omit `nomem`
    // as a conservative barrier around the state change; no stack, preserves flags.
    unsafe {
        asm!("xsetbv", in("ecx") xcr, in("eax") lo, in("edx") hi,
             options(nostack, preserves_flags));
    }
}

/// Halt the CPU until the next interrupt (`hlt`) — executed exactly once.
///
/// If interrupts are disabled this parks the core until an NMI or reset.
/// Prefer [`halt_loop`] for the "stop forever" use-case; this single-step
/// variant exists so callers can build their own idle loops.
#[inline]
pub fn halt() {
    // SAFETY: `hlt` places the CPU in a halted state until the next interrupt,
    // NMI, or reset. It accesses no memory and no registers (`nomem`/`nostack`)
    // and leaves RFLAGS untouched (`preserves_flags`). Halting cannot violate
    // memory safety; at worst, with interrupts masked, the core simply idles.
    unsafe {
        asm!("hlt", options(nomem, nostack, preserves_flags));
    }
}

/// Halt the CPU forever in a `hlt` loop and never return.
///
/// This is the canonical "we are done / nothing left to do" terminator for the
/// kernel: the boot path and the panic handler both end here. The loop re-issues
/// `hlt` after any wake (e.g. a spurious interrupt) so the core never spins hot
/// and never falls through.
///
/// The function is diverging (`-> !`); it is a safe wrapper because halting the
/// CPU has no effect on Rust's memory model.
#[inline]
pub fn halt_loop() -> ! {
    loop {
        // SAFETY: identical to [`halt`] — `hlt` idles the CPU until the next
        // interrupt/NMI/reset, accessing no memory or registers and preserving
        // RFLAGS. Re-halting on every wake keeps the core parked without UB.
        unsafe {
            asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
}
