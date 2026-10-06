//! ACPI table access — the RSDP address from Limine and a bounded,
//! copy-out reader of firmware-table bytes (SMP phase 3b-ii) — part of the TCB.
//!
//! `hal` deliberately does **no** ACPI parsing: the RSDP → RSDT/XSDT → MADT walk
//! and every byte decode live in the safe kernel (`kernel::acpi`, Kani +
//! mutation-fuzz). This module provides exactly two primitives:
//!
//! - [`rsdp_phys`] — the physical address of the RSDP, from Limine's
//!   `RsdpRequest` (base revision 3: the response carries a physical address).
//! - [`read_phys`] — copy `buf.len()` bytes at a physical address into a
//!   caller-owned buffer. The range is refused if it overlaps memory the kernel
//!   owns (`mm::overlaps_kernel_owned`) or exceeds [`MAX_READ`]; otherwise it is
//!   mapped read-only through `mm::map_firmware_ro` and copied with volatile byte
//!   loads. The kernel therefore never holds a reference into firmware memory,
//!   and no length read from firmware sizes anything here beyond the caller's
//!   own fixed buffer.
//!
//! Registry: `kernel/docs/hal-tcb.md` §2l (AC1–AC2).

use crate::mm::{self, PhysAddr};
use limine::request::RsdpRequest;

/// Limine RSDP request (`#[used]` so the linker keeps it for Limine to find).
#[used]
static RSDP_REQUEST: RsdpRequest = RsdpRequest::new();

/// Largest single [`read_phys`] request, in bytes. Bounds the virtual window and
/// page-table frames one call can consume; the kernel's MADT buffer is 8 KiB.
pub const MAX_READ: usize = 16 * 1024;

/// Physical address of the ACPI RSDP, or `None` if Limine provided none.
///
/// Under base revision 3 (the `boot` crate's `BaseRevision::new()`), Limine
/// reports the RSDP as a **physical** address. A response at or above the HHDM
/// offset would be a revision-0 virtual address; it is converted back so the
/// caller always gets a physical address.
#[must_use]
pub fn rsdp_phys() -> Option<u64> {
    // `get_response()` is `Some` only after Limine populated our `#[used]`
    // request before `_start`; we copy the plain address out of the borrow.
    let addr = RSDP_REQUEST.get_response()?.address() as u64;
    if addr == 0 {
        return None;
    }
    match mm::hhdm_offset() {
        Some(hhdm) if addr >= hhdm => Some(addr - hhdm),
        _ => Some(addr),
    }
}

/// Copy the `buf.len()` bytes at physical address `phys` into `buf`.
///
/// Returns `false` (and leaves `buf` unspecified-but-initialised) if `buf` is
/// empty or longer than [`MAX_READ`], if the range overflows or overlaps
/// kernel-owned memory, or if it cannot be mapped (memory management not up,
/// out of page-table frames). Each successful call maps the span afresh in the
/// MMIO window and never unmaps it — boot-time only, a handful of calls.
#[must_use]
pub fn read_phys(phys: u64, buf: &mut [u8]) -> bool {
    let len = buf.len();
    if len == 0 || len > MAX_READ {
        return false;
    }
    if mm::overlaps_kernel_owned(phys, len as u64) {
        return false;
    }
    let Ok(virt) = mm::map_firmware_ro(PhysAddr::new(phys), len) else {
        return false;
    };
    let src = virt.as_u64() as *const u8;
    for (i, dst) in buf.iter_mut().enumerate() {
        // SAFETY: (AC2) `map_firmware_ro` just mapped every page covering
        // `[phys, phys + len)` present + read-only at `virt` (in-page offset
        // preserved), so `src + i` for `i < len` is a mapped, readable byte. The
        // range overlaps no kernel-owned RAM (checked above), so no Rust code
        // holds a reference to or writes these bytes; the read is volatile so it
        // is a plain device/firmware load the compiler cannot elide or widen into
        // a reference. `u8` has no alignment or validity requirement.
        *dst = unsafe { core::ptr::read_volatile(src.add(i)) };
    }
    true
}
