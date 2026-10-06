//! Limine boot-info requests for memory management: the **memory map** and the
//! **higher-half direct map (HHDM) offset**.
//!
//! This module owns two `#[used] static` Limine requests, declared with the same
//! pattern as [`crate::framebuffer`]'s `FRAMEBUFFER_REQUEST`: Limine scans the
//! loaded image for these tagged structures (matched by magic `id`) and fills in
//! a response before jumping to `_start`. `#[used]` keeps the linker from
//! stripping them; the `BaseRevision` marker that gates the whole protocol lives
//! in the `boot` crate.
//!
//! The only `unsafe` here is reading the two responses (raw pointers the
//! bootloader filled in). Both reads are confined to the safe accessors below,
//! each carrying a `// SAFETY:` justification; see `kernel/docs/hal-tcb.md`
//! (§5a) for the registry.

use limine::memory_map::EntryType;
use limine::request::{HhdmRequest, MemoryMapRequest};

use super::addr::PhysAddr;

/// Limine memory-map request: asks the bootloader for the firmware memory map so
/// the frame allocator knows which physical RAM is usable.
#[used]
static MEMORY_MAP_REQUEST: MemoryMapRequest = MemoryMapRequest::new();

/// Limine HHDM request: asks for the offset of the higher-half direct map, i.e.
/// the constant `virt = phys + offset` mapping the bootloader installed over all
/// physical RAM. We use it to read/write page tables (which we only have as
/// physical addresses) without installing our own mappings first.
#[used]
static HHDM_REQUEST: HhdmRequest = HhdmRequest::new();

/// A usable physical-RAM region: a frame-aligned base and a length in bytes.
///
/// Produced by [`usable_regions`] from the Limine memory map; consumed by the
/// frame allocator to seed its free list. Only [`EntryType::USABLE`] regions are
/// reported — reserved, ACPI, bad-memory, framebuffer, and the
/// bootloader/executable regions are excluded, so the allocator can never hand
/// out a frame that is still in use by firmware or the loaded kernel image.
#[derive(Clone, Copy, Debug)]
pub struct UsableRegion {
    /// Physical base address of the region (frame-aligned by Limine).
    pub base: PhysAddr,
    /// Length of the region in bytes (a whole number of frames in practice).
    pub length: u64,
}

/// The higher-half direct-map (HHDM) offset, or `None` if Limine did not honour
/// the request.
///
/// Adding this offset to any physical address yields a virtual address that maps
/// it, as long as the bootloader's page tables are still active (they are — we
/// build *on top* of them). This is how `mm` dereferences page-table frames it
/// only knows by physical address.
#[must_use]
pub fn hhdm_offset() -> Option<u64> {
    // SAFETY: `get_response()` returns `Some(&HhdmResponse)` only when Limine
    // populated the response slot of our `#[used]` `HHDM_REQUEST` before jumping
    // to `_start` (it writes the pointer atomically). We never mutate the
    // request, so the shared borrow is sound; we copy out the plain `u64` offset
    // and drop the borrow within this expression.
    let response = HHDM_REQUEST.get_response()?;
    Some(response.offset())
}

/// Iterate the **usable** physical-RAM regions reported by the firmware.
///
/// Returns an iterator over [`UsableRegion`] for every [`EntryType::USABLE`]
/// memory-map entry, or an empty iterator if Limine provided no memory map. The
/// frame allocator consumes this to build its free list; no other region type is
/// ever surfaced, so the allocator cannot reclaim memory the firmware, the
/// framebuffer, or the loaded kernel still needs.
pub fn usable_regions() -> impl Iterator<Item = UsableRegion> {
    // SAFETY: `get_response()` returns `Some(&MemoryMapResponse)` only after
    // Limine populated our `#[used]` `MEMORY_MAP_REQUEST` before `_start`. The
    // `entries()` accessor (called below, inside `limine`) reconstructs a slice
    // from the bootloader-filled entry array; the borrow stays within this
    // function and the iterator copies each entry's `base`/`length` (plain
    // scalars) out. We never mutate the request. If there is no response we hand
    // back an empty iterator (never UB).
    let entries: &[&limine::memory_map::Entry] = match MEMORY_MAP_REQUEST.get_response() {
        Some(response) => response.entries(),
        None => &[],
    };

    entries.iter().filter_map(|entry| {
        if entry.entry_type == EntryType::USABLE {
            Some(UsableRegion {
                base: PhysAddr::new(entry.base),
                length: entry.length,
            })
        } else {
            None
        }
    })
}

/// Whether any byte of the physical range `[phys, phys + len)` lies in memory
/// the kernel owns or may own: `USABLE` (frame allocator), `BOOTLOADER_RECLAIMABLE`
/// (live Limine structures, the boot stack), `EXECUTABLE_AND_MODULES` (the kernel
/// image) or `FRAMEBUFFER`. Firmware-described physical addresses (ACPI tables,
/// an IOAPIC register window) are only ever mapped by `hal` after this returns
/// `false`, so a lying firmware table can never make `hal` read memory a Rust
/// writer may be using, or write device registers over kernel RAM.
///
/// Fails closed: without a memory map, or on an overflowing range, it reports
/// an overlap.
#[must_use]
pub fn overlaps_kernel_owned(phys: u64, len: u64) -> bool {
    let Some(end) = phys.checked_add(len) else {
        return true;
    };
    // SAFETY: same contract as `usable_regions` — `get_response()` is `Some`
    // only after Limine populated our `#[used]` request before `_start`; the
    // borrowed entry slice is read-only and copied out per entry.
    let Some(response) = MEMORY_MAP_REQUEST.get_response() else {
        return true;
    };
    response.entries().iter().any(|e| {
        let owned = e.entry_type == EntryType::USABLE
            || e.entry_type == EntryType::BOOTLOADER_RECLAIMABLE
            || e.entry_type == EntryType::EXECUTABLE_AND_MODULES
            || e.entry_type == EntryType::FRAMEBUFFER;
        let e_end = e.base.saturating_add(e.length);
        owned && phys < e_end && e.base < end
    })
}
