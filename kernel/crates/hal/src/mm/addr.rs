//! Physical / virtual address newtypes and page-table layout constants.
//!
//! These are plain value types over `u64`; they carry **no** `unsafe` and exist
//! to keep the rest of `mm` from confusing a physical frame address with a
//! virtual one. All x86-64 4-level (48-bit) paging geometry constants live here.

/// Size of a standard page / physical frame, in bytes (4 KiB).
pub const PAGE_SIZE: u64 = 4096;

/// Number of entries in each page table level (PML4/PDPT/PD/PT): 512.
pub(crate) const ENTRY_COUNT: usize = 512;

/// A **physical** address.
///
/// On x86-64 with 4-level paging, physical addresses are at most 52 bits; the
/// frame allocator only ever hands out frame-aligned values, but the type
/// itself imposes no alignment — use [`PhysAddr::frame_floor`] /
/// [`PhysAddr::frame_ceil`] when alignment matters.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct PhysAddr(u64);

impl PhysAddr {
    /// Wrap a raw physical address.
    #[inline]
    #[must_use]
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }

    /// The raw `u64` value.
    #[inline]
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Round **down** to the start of the containing 4 KiB frame.
    #[inline]
    #[must_use]
    pub const fn frame_floor(self) -> Self {
        Self(self.0 & !(PAGE_SIZE - 1))
    }

    /// Round **up** to the next 4 KiB frame boundary (no-op if already aligned).
    #[inline]
    #[must_use]
    pub const fn frame_ceil(self) -> Self {
        Self((self.0 + PAGE_SIZE - 1) & !(PAGE_SIZE - 1))
    }
}

/// A **virtual** (linear) address.
///
/// Used for the higher-half kernel heap window and for indexing the active page
/// tables. The decomposition into 9-bit table indices is provided by
/// [`VirtAddr::table_indices`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct VirtAddr(u64);

impl VirtAddr {
    /// Wrap a raw virtual address.
    #[inline]
    #[must_use]
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }

    /// The raw `u64` value.
    #[inline]
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// The `(PML4, PDPT, PD, PT)` 9-bit indices for this address.
    ///
    /// Each index is in `0..512`. Bits 0..12 are the page offset and are not
    /// part of any index. (Bits 48..64 must be a canonical sign-extension of
    /// bit 47, which is true of every higher-half address we ever map.)
    #[inline]
    #[must_use]
    pub(crate) const fn table_indices(self) -> [usize; 4] {
        let a = self.0;
        [
            ((a >> 39) & 0x1FF) as usize, // PML4
            ((a >> 30) & 0x1FF) as usize, // PDPT
            ((a >> 21) & 0x1FF) as usize, // PD
            ((a >> 12) & 0x1FF) as usize, // PT
        ]
    }
}
