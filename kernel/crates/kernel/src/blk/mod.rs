//! `kernel::blk` — the SentinelFS block layer (spec
//! `docs/specs/2026-09-18-sentinelfs-design.md` §6, FS-1a in §11).
//!
//! Everything below `kernel::sfs` and above `hal::ata`, all safe Rust:
//!
//! - [`BlockDevice`] — 4 KiB blocks, multi-block transfers and an explicit
//!   [`BlockDevice::flush`], shaped for DMA now (amendment A11) so the format
//!   never changes when NVMe / virtio-blk arrive. Two implementations:
//!   [`ata::AtaDevice`] (8 ATA sectors per block over `hal::ata`'s existing safe
//!   API, inside a block *window* of the disk) and [`mem::MemDevice`] (the host
//!   model with the §8 crash model: crash at a write index, torn sectors on the
//!   superblock slots, and the unflushed-subset durability model, A16).
//! - [`layout`] — the 64-byte metadata header, [`layout::Pointer`], and the two
//!   hash rules (metadata: the whole block with the hash field zeroed, A1;
//!   data: the whole block).
//! - [`cache::Cache`] — the one 64-block slab ([`cache::CACHE_BLOCKS`]) with at
//!   most [`cache::DIRTY_MAX`] dirty entries. A block's hash is checked *before*
//!   it enters the slab, and a resident verified entry is immutable: there is
//!   no `&mut` path to it, so hash-then-parse has no TOCTOU window.
//! - [`bitmap`] / [`geometry`] — bit operations and allocation-group / extent
//!   arithmetic, both pure and Kani-proven over shrunken sizes (A19).
//! - [`allocator::Allocator`] — per-group bitmaps under a one-level group index,
//!   copy-on-write like every other metadata block, with the per-group metadata
//!   reserve (§5.8) and "freed blocks become allocatable only after the commit
//!   that frees them" (§7.4).
//!
//! Nothing here touches a device except [`ata`]; nothing here runs in IRQ
//! context; no loop is driven by an on-disk count without being bounded by
//! the block size; no structure grows after construction.

#![deny(missing_docs)]

pub mod allocator;
pub mod ata;
pub mod bitmap;
pub mod cache;
pub mod geometry;
pub mod layout;
pub mod mem;

use alloc::boxed::Box;
use alloc::vec;

/// Bytes per block: the unit of allocation, hashing and caching (§4).
pub const BLOCK_SIZE: usize = 4096;
/// Bytes per device sector (the ATA atomic-write unit, §8).
pub const SECTOR_SIZE: usize = 512;
/// Sectors per block.
pub const SECTORS_PER_BLOCK: usize = BLOCK_SIZE / SECTOR_SIZE;

/// One 4 KiB block. Kernel paths keep blocks on the heap ([`Blocks`]), never
/// on a task's stack (16 KiB by default).
pub type Block = [u8; BLOCK_SIZE];

/// A block number relative to the start of the device (or device window).
/// `u32` addresses 16 TiB of 4 KiB blocks (§4); the v2 format stops far below
/// that ([`geometry::MAX_BLOCKS`]).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct BlockNo(pub u32);

impl BlockNo {
    /// The block number as a `u64`, for range arithmetic that must not wrap.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0 as u64
    }
}

/// Why a block-device operation failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BlkError {
    /// The request reaches past the end of the device (or its window), or past
    /// what the transport can address.
    OutOfRange,
    /// The transfer buffer was empty or not a whole number of blocks.
    BadBuffer,
    /// No device answered.
    NoDevice,
    /// The device reported an error or did not complete in time.
    Io,
    /// The (modelled) device lost power: every operation fails until the host
    /// test power-cycles it ([`mem::MemDevice::power_cycle`]).
    PowerLost,
}

impl BlkError {
    /// Fixed label for `fmt`-free console output.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            BlkError::OutOfRange => "out-of-range",
            BlkError::BadBuffer => "bad-buffer",
            BlkError::NoDevice => "no-device",
            BlkError::Io => "io",
            BlkError::PowerLost => "power-lost",
        }
    }
}

/// A block device, shaped for DMA (spec §6, amendment A11).
///
/// Transfers are whole blocks and may span many blocks in one call. The
/// durability contract is the one of §8: between two [`flush`](Self::flush)
/// calls the device may persist **any subset** of the writes issued, in any
/// order; a single 512-byte sector write is atomic; `flush` makes every
/// earlier write durable before it returns. Reads always observe the latest
/// write, flushed or not.
pub trait BlockDevice {
    /// Number of addressable blocks.
    fn blocks(&self) -> u64;

    /// Read `out.len()` consecutive blocks starting at `start`.
    ///
    /// # Errors
    ///
    /// [`BlkError::BadBuffer`] for an empty `out`, [`BlkError::OutOfRange`]
    /// past the end, otherwise whatever the transport reports.
    fn read_blocks(&mut self, start: BlockNo, out: &mut [Block]) -> Result<(), BlkError>;

    /// Write `data.len()` consecutive blocks starting at `start`. Not durable
    /// until the next [`flush`](Self::flush) returns `Ok`.
    ///
    /// # Errors
    ///
    /// As [`read_blocks`](Self::read_blocks).
    fn write_blocks(&mut self, start: BlockNo, data: &[Block]) -> Result<(), BlkError>;

    /// Make every earlier write durable.
    ///
    /// # Errors
    ///
    /// Whatever the transport reports; on error nothing is known about the
    /// durability of the writes since the last successful flush.
    fn flush(&mut self) -> Result<(), BlkError>;
}

/// Check a transfer of `len` blocks at `start` against a device of `blocks`
/// blocks. Shared by every [`BlockDevice`] implementation so they agree on the
/// edge cases (empty transfers, overflow, the exact end).
///
/// # Errors
///
/// [`BlkError::BadBuffer`] when `len == 0`; [`BlkError::OutOfRange`] when the
/// last block would be at or past `blocks`.
pub fn check_range(start: BlockNo, len: usize, blocks: u64) -> Result<(), BlkError> {
    if len == 0 {
        return Err(BlkError::BadBuffer);
    }
    let end = start
        .get()
        .checked_add(len as u64)
        .ok_or(BlkError::OutOfRange)?;
    if end > blocks {
        return Err(BlkError::OutOfRange);
    }
    Ok(())
}

/// A fixed number of blocks in one heap allocation, used as `[Block]`.
///
/// Why not `Box<[Block]>` built with `vec![[0u8; 4096]; n]`: in a debug build
/// that clones a by-value 4 KiB array through several stack frames, which
/// overflowed a 16 KiB kernel-task stack into its guard page (a double fault
/// at `Vec::<[u8; 4096]>::extend_with`, found at boot). This is a byte buffer
/// allocated zeroed (no large temporary anywhere) and viewed as blocks through
/// `as_chunks`.
pub struct Blocks(Box<[u8]>);

impl Blocks {
    /// `n` zero-filled blocks.
    #[must_use]
    pub fn zeroed(n: usize) -> Blocks {
        Blocks(vec![0u8; n.saturating_mul(BLOCK_SIZE)].into_boxed_slice())
    }
}

impl core::ops::Deref for Blocks {
    type Target = [Block];

    fn deref(&self) -> &[Block] {
        self.0.as_chunks::<BLOCK_SIZE>().0
    }
}

impl core::ops::DerefMut for Blocks {
    fn deref_mut(&mut self) -> &mut [Block] {
        self.0.as_chunks_mut::<BLOCK_SIZE>().0
    }
}

/// `n` zero-filled blocks in one heap allocation, without a 4 KiB stack
/// temporary anywhere (kernel task stacks are 16 KiB; see [`Blocks`]).
#[must_use]
pub fn zeroed_blocks(n: usize) -> Blocks {
    Blocks::zeroed(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_range_edges() {
        assert_eq!(check_range(BlockNo(0), 0, 10), Err(BlkError::BadBuffer));
        assert_eq!(check_range(BlockNo(0), 10, 10), Ok(()));
        assert_eq!(check_range(BlockNo(9), 1, 10), Ok(()));
        assert_eq!(check_range(BlockNo(9), 2, 10), Err(BlkError::OutOfRange));
        assert_eq!(check_range(BlockNo(10), 1, 10), Err(BlkError::OutOfRange));
        assert_eq!(
            check_range(BlockNo(u32::MAX), usize::MAX, u64::MAX),
            Err(BlkError::OutOfRange)
        );
    }

    #[test]
    fn zeroed_helper_is_zero_and_sized() {
        let bs = zeroed_blocks(3);
        assert_eq!(bs.len(), 3);
        assert!(bs.iter().all(|b| b.iter().all(|&x| x == 0)));
    }
}
