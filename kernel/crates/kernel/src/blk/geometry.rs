//! Allocation-group geometry and extent arithmetic (spec §4, §7.4).
//!
//! The image is divided into allocation groups, each described by one bitmap
//! block. A bitmap block is a metadata block, so its 64-byte header leaves
//! `4096 - 64 = 4032` bytes of payload: **[`GROUP_BLOCKS`] = 32 256 blocks per
//! group** (≈126 MiB), not the 32 768 the spec's first draft assumed. The one
//! group-index block likewise holds `(4096 - 64) / 48` pointers: **at most
//! [`MAX_GROUPS`] = 84 groups** (≈10.3 GiB), not 85. Larger devices are
//! refused with [`GeometryError::TooLarge`]; a second index level is a format
//! version bump (§14.6).
//!
//! Everything here is pure `u32`/`u64` arithmetic with no panic path; the Kani
//! harnesses in `proofs` prove the group mapping round-trips and the extent
//! arithmetic never overflows (A19).

use super::layout::{HEADER_LEN, POINTER_LEN};
use super::{BlockNo, BLOCK_SIZE};

/// Blocks per allocation group: one bit per block in a bitmap block's payload.
pub const GROUP_BLOCKS: u32 = ((BLOCK_SIZE - HEADER_LEN) * 8) as u32;
/// Groups the one-level index can name: one [`POINTER_LEN`]-byte pointer each
/// in an index block's payload.
pub const MAX_GROUPS: u32 = ((BLOCK_SIZE - HEADER_LEN) / POINTER_LEN) as u32;
/// Largest filesystem the v2 format describes.
pub const MAX_BLOCKS: u64 = MAX_GROUPS as u64 * GROUP_BLOCKS as u64;
/// Smallest filesystem `format` accepts: two superblock slots, the group-0
/// bitmap and the index, the metadata reserve, and room to work.
pub const MIN_BLOCKS: u64 = 128;
/// Longest extent: 32 blocks (128 KiB), one hash per block (amendment A3).
pub const MAX_EXTENT: u32 = 32;

/// Why a block count is not a filesystem geometry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GeometryError {
    /// Fewer than [`MIN_BLOCKS`] blocks.
    TooSmall,
    /// More than [`MAX_BLOCKS`] blocks (more than [`MAX_GROUPS`] groups).
    TooLarge,
}

impl GeometryError {
    /// Fixed label for `fmt`-free console output.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            GeometryError::TooSmall => "too-small",
            GeometryError::TooLarge => "too-large",
        }
    }
}

/// The group layout of a filesystem of `total` blocks.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Geometry {
    total: u32,
    groups: u32,
}

impl Geometry {
    /// Geometry for `total_blocks` blocks.
    ///
    /// # Errors
    ///
    /// [`GeometryError::TooSmall`] below [`MIN_BLOCKS`],
    /// [`GeometryError::TooLarge`] above [`MAX_BLOCKS`].
    pub fn new(total_blocks: u64) -> Result<Geometry, GeometryError> {
        if total_blocks < MIN_BLOCKS {
            return Err(GeometryError::TooSmall);
        }
        if total_blocks > MAX_BLOCKS {
            return Err(GeometryError::TooLarge);
        }
        // `total_blocks <= MAX_BLOCKS < 2^32`, so this conversion is exact.
        let total = u32::try_from(total_blocks).map_err(|_| GeometryError::TooLarge)?;
        let groups = total.div_ceil(GROUP_BLOCKS);
        Ok(Geometry { total, groups })
    }

    /// Total blocks.
    #[must_use]
    pub const fn total(&self) -> u32 {
        self.total
    }

    /// Number of allocation groups (`1..=MAX_GROUPS`).
    #[must_use]
    pub const fn groups(&self) -> u32 {
        self.groups
    }

    /// First block of group `g`.
    #[must_use]
    pub fn group_first(&self, g: u32) -> Option<u32> {
        if g < self.groups {
            g.checked_mul(GROUP_BLOCKS)
        } else {
            None
        }
    }

    /// Blocks in group `g` (the last group may be partial).
    #[must_use]
    pub fn group_len(&self, g: u32) -> Option<u32> {
        let first = self.group_first(g)?;
        Some((self.total - first).min(GROUP_BLOCKS))
    }

    /// `(group, bit)` of block `b`, if it is inside the filesystem.
    #[must_use]
    pub fn locate(&self, b: BlockNo) -> Option<(u32, u32)> {
        if b.0 < self.total {
            Some((b.0 / GROUP_BLOCKS, b.0 % GROUP_BLOCKS))
        } else {
            None
        }
    }

    /// The block at `bit` of group `g`, if that bit maps to a real block.
    #[must_use]
    pub fn block_at(&self, g: u32, bit: u32) -> Option<BlockNo> {
        if bit >= self.group_len(g)? {
            return None;
        }
        Some(BlockNo(self.group_first(g)? + bit))
    }
}

/// Why an extent is invalid.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ExtentError {
    /// Length 0 or above [`MAX_EXTENT`].
    Length,
    /// The run would wrap past the end of the 32-bit block space.
    Overflow,
}

/// A contiguous run of `1..=MAX_EXTENT` blocks.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Extent {
    start: BlockNo,
    len: u32,
}

impl Extent {
    /// The run `[start, start + len)`.
    ///
    /// # Errors
    ///
    /// [`ExtentError::Length`] for `len == 0` or `len > MAX_EXTENT`;
    /// [`ExtentError::Overflow`] if the run passes `u32::MAX`.
    pub fn new(start: BlockNo, len: u32) -> Result<Extent, ExtentError> {
        if len == 0 || len > MAX_EXTENT {
            return Err(ExtentError::Length);
        }
        if start.get() + u64::from(len) > u64::from(u32::MAX) + 1 {
            return Err(ExtentError::Overflow);
        }
        Ok(Extent { start, len })
    }

    /// First block.
    #[must_use]
    pub const fn start(&self) -> BlockNo {
        self.start
    }

    /// Number of blocks.
    #[must_use]
    pub const fn len(&self) -> u32 {
        self.len
    }

    /// Always `false`: an extent holds at least one block. Provided so `len`
    /// reads naturally next to it.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// One past the last block, as a `u64` (cannot wrap).
    #[must_use]
    pub const fn end(&self) -> u64 {
        self.start.get() + self.len as u64
    }

    /// Whether the run lies inside a filesystem of `total` blocks.
    #[must_use]
    pub const fn fits(&self, total: u32) -> bool {
        self.end() <= total as u64
    }

    /// The `i`-th block of the run.
    #[must_use]
    pub fn nth(&self, i: u32) -> Option<BlockNo> {
        if i < self.len {
            Some(BlockNo(self.start.0 + i))
        } else {
            None
        }
    }

    /// Position of `b` in the run.
    #[must_use]
    pub fn index_of(&self, b: BlockNo) -> Option<u32> {
        if b.0 >= self.start.0 && b.get() < self.end() {
            Some(b.0 - self.start.0)
        } else {
            None
        }
    }

    /// Whether `b` is in the run.
    #[must_use]
    pub fn contains(&self, b: BlockNo) -> bool {
        self.index_of(b).is_some()
    }

    /// Whether the two runs share a block.
    #[must_use]
    pub fn overlaps(&self, other: &Extent) -> bool {
        self.start.get() < other.end() && other.start.get() < self.end()
    }

    /// Split into `[start, start + k)` and `[start + k, end)`; `None` unless
    /// `0 < k < len`.
    #[must_use]
    pub fn split_at(&self, k: u32) -> Option<(Extent, Extent)> {
        if k == 0 || k >= self.len {
            return None;
        }
        Some((
            Extent {
                start: self.start,
                len: k,
            },
            Extent {
                start: BlockNo(self.start.0 + k),
                len: self.len - k,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_follow_from_the_block_and_header_sizes() {
        assert_eq!(GROUP_BLOCKS, 32_256);
        assert_eq!(MAX_GROUPS, 84);
        assert_eq!(MAX_BLOCKS, 2_709_504);
        // The index payload holds exactly MAX_GROUPS pointers.
        assert!(HEADER_LEN + MAX_GROUPS as usize * POINTER_LEN <= BLOCK_SIZE);
        assert!(HEADER_LEN + (MAX_GROUPS as usize + 1) * POINTER_LEN > BLOCK_SIZE);
    }

    #[test]
    fn geometry_of_the_dev_window_and_the_bounds() {
        // 16 MiB image, window from LBA 2048: 3840 blocks, one partial group.
        let g = Geometry::new(3840).unwrap();
        assert_eq!((g.total(), g.groups()), (3840, 1));
        assert_eq!(g.group_len(0), Some(3840));
        assert_eq!(g.group_len(1), None);
        assert_eq!(Geometry::new(MIN_BLOCKS - 1), Err(GeometryError::TooSmall));
        assert_eq!(Geometry::new(MAX_BLOCKS + 1), Err(GeometryError::TooLarge));
        let max = Geometry::new(MAX_BLOCKS).unwrap();
        assert_eq!(max.groups(), MAX_GROUPS);
        assert_eq!(max.group_len(MAX_GROUPS - 1), Some(GROUP_BLOCKS));
        let two = Geometry::new(u64::from(GROUP_BLOCKS) + 1).unwrap();
        assert_eq!(two.groups(), 2);
        assert_eq!(two.group_len(1), Some(1));
        assert_eq!(two.locate(BlockNo(GROUP_BLOCKS)), Some((1, 0)));
        assert_eq!(two.block_at(1, 0), Some(BlockNo(GROUP_BLOCKS)));
        assert_eq!(two.block_at(1, 1), None);
        assert_eq!(two.locate(BlockNo(GROUP_BLOCKS + 1)), None);
    }

    #[test]
    fn extent_bounds_and_queries() {
        assert_eq!(Extent::new(BlockNo(5), 0), Err(ExtentError::Length));
        assert_eq!(Extent::new(BlockNo(5), 33), Err(ExtentError::Length));
        assert_eq!(
            Extent::new(BlockNo(u32::MAX), 2),
            Err(ExtentError::Overflow)
        );
        let last = Extent::new(BlockNo(u32::MAX), 1).unwrap();
        assert_eq!(last.end(), 1u64 << 32);
        let e = Extent::new(BlockNo(10), 4).unwrap();
        assert_eq!((e.start(), e.len(), e.end()), (BlockNo(10), 4, 14));
        assert!(!e.is_empty());
        assert_eq!(e.nth(3), Some(BlockNo(13)));
        assert_eq!(e.nth(4), None);
        assert_eq!(e.index_of(BlockNo(12)), Some(2));
        assert!(!e.contains(BlockNo(14)));
        assert!(e.fits(14) && !e.fits(13));
        let (a, b) = e.split_at(1).unwrap();
        assert_eq!((a.len(), b.start(), b.len()), (1, BlockNo(11), 3));
        assert!(e.split_at(0).is_none() && e.split_at(4).is_none());
        assert!(e.overlaps(&Extent::new(BlockNo(13), 2).unwrap()));
        assert!(!e.overlaps(&Extent::new(BlockNo(14), 2).unwrap()));
    }
}

/// Kani proof harnesses (A19). Compiled only under `cargo kani`.
#[cfg(kani)]
mod proofs {
    use super::*;

    /// Extent arithmetic is total and self-consistent for every start, length
    /// and probe: construction never wraps, `nth`/`index_of`/`contains` agree,
    /// a split covers exactly the original run, and overlap is symmetric.
    #[kani::proof]
    fn extent_arithmetic_is_total_and_consistent() {
        let start: u32 = kani::any();
        let len: u32 = kani::any();
        let i: u32 = kani::any();
        let k: u32 = kani::any();
        let b: u32 = kani::any();
        let Ok(e) = Extent::new(BlockNo(start), len) else {
            return;
        };
        assert!(len >= 1 && len <= MAX_EXTENT);
        assert!(e.end() == u64::from(start) + u64::from(len));
        assert!(e.end() <= u64::from(u32::MAX) + 1);
        match e.nth(i) {
            Some(n) => {
                assert!(i < len);
                assert!(e.index_of(n) == Some(i));
                assert!(e.contains(n));
            }
            None => assert!(i >= len),
        }
        if let Some(j) = e.index_of(BlockNo(b)) {
            assert!(e.nth(j) == Some(BlockNo(b)));
        } else {
            assert!(!e.contains(BlockNo(b)));
        }
        if let Some((x, y)) = e.split_at(k) {
            assert!(x.start() == e.start() && x.end() == y.start().get());
            assert!(y.end() == e.end() && x.len() + y.len() == e.len());
            assert!(!x.overlaps(&y));
        }
        let o_start: u32 = kani::any();
        let o_len: u32 = kani::any();
        if let Ok(o) = Extent::new(BlockNo(o_start), o_len) {
            assert!(e.overlaps(&o) == o.overlaps(&e));
        }
    }

    /// The block ↔ (group, bit) mapping round-trips for every geometry, every
    /// group is non-empty and at most [`GROUP_BLOCKS`] long, and the groups
    /// exactly cover the filesystem.
    #[kani::proof]
    fn group_math_round_trips() {
        let total: u64 = kani::any();
        let Ok(geo) = Geometry::new(total) else {
            return;
        };
        assert!(geo.groups() >= 1 && geo.groups() <= MAX_GROUPS);
        let b: u32 = kani::any();
        match geo.locate(BlockNo(b)) {
            Some((g, bit)) => {
                assert!(u64::from(b) < total);
                assert!(g < geo.groups() && bit < GROUP_BLOCKS);
                assert!(geo.block_at(g, bit) == Some(BlockNo(b)));
            }
            None => assert!(u64::from(b) >= total),
        }
        let g: u32 = kani::any();
        if let Some(len) = geo.group_len(g) {
            assert!(len >= 1 && len <= GROUP_BLOCKS);
            if g + 1 == geo.groups() {
                assert!(u64::from(g) * u64::from(GROUP_BLOCKS) + u64::from(len) == total);
            } else {
                assert!(len == GROUP_BLOCKS);
            }
        } else {
            assert!(g >= geo.groups());
        }
    }
}
