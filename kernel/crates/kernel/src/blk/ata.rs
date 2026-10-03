//! `AtaDevice` — [`BlockDevice`] over `hal::ata`'s existing safe PIO API
//! (spec §6; **zero `hal` delta**).
//!
//! One 4 KiB block is 8 ATA sectors. A device is a **window** of the disk,
//! `[base_lba, base_lba + 8 · blocks)`: until FS-2 deletes the old serialiser,
//! `kernel::fs` owns the start of the IDE disk (its `"SNTLFS01"` sector 0 and
//! ≤ 64 KiB of payload), so SentinelFS lives past it — block 0 of the window
//! is sector [`SFS_BASE_LBA`] of the disk (spec §11, "coexistence").
//!
//! # What `flush` means on ATA today (FS-1a)
//!
//! `hal::ata::write_sectors` ends **every** command with `FLUSH CACHE` and
//! waits for it (hal-tcb row A2), and `hal` has no separate flush entry point.
//! So every [`write_blocks`](BlockDevice::write_blocks) here is already as
//! durable as `hal` can make it when it returns `Ok`, and
//! [`flush`](BlockDevice::flush) has nothing left to do: it returns `Ok(())`
//! without touching the device. The §8 protocol still issues it at the right
//! points, so nothing changes above this file when FS-1b splits `hal::ata` into
//! an unflushed `write_sectors` plus a public `flush()` — at which point this
//! becomes the real barrier. One known weakness carries over unchanged and is
//! FS-1b's to fix (amendment A2): `hal` issues `FLUSH CACHE` without first
//! waiting for the data phase's BSY to clear.
//!
//! # Serialising the channel
//!
//! `hal::ata` requires that no two command sequences interleave on the primary
//! channel ("the single-threaded caller guarantees" it). There are now two
//! callers — the `sfs-commit` task and `kernel::fs` — so every `hal::ata` call
//! from the kernel goes through [`with_channel`], which holds a kernel-side
//! channel lock for exactly one command. A holder preempted mid-command is
//! waited for by **yielding**, never by spinning: on the BSP, where both callers
//! run, the yield hands the core straight back to the holder.

use super::{check_range, BlkError, Block, BlockDevice, BlockNo, SECTORS_PER_BLOCK};
use hal::ata::AtaError;
use hal::sync::SpinMutex;

/// First disk sector of the SentinelFS window: 1 MiB in, clear of the old
/// `kernel::fs` image (sector 0 plus at most 128 payload sectors).
pub const SFS_BASE_LBA: u32 = 2048;

/// Blocks per ATA command: `hal::ata` moves at most 256 sectors per command.
const BLOCKS_PER_COMMAND: usize = 256 / SECTORS_PER_BLOCK;

/// The primary IDE channel, held for one `hal::ata` command at a time.
static CHANNEL: SpinMutex<()> = SpinMutex::new(());

/// Run one `hal::ata` command sequence with the primary channel held.
///
/// Waits for a holder by yielding to the scheduler (the holder is on this core
/// in every current configuration, so it runs next), never by spinning with
/// the lock contended. Never call this with the `Sfs` lock held.
pub fn with_channel<R>(op: impl FnOnce() -> R) -> R {
    loop {
        if let Some(_held) = CHANNEL.try_lock() {
            return op();
        }
        crate::sched::yield_now();
    }
}

fn map_err(e: AtaError) -> BlkError {
    match e {
        AtaError::NoDevice => BlkError::NoDevice,
        AtaError::BadBuffer => BlkError::BadBuffer,
        AtaError::OutOfRange => BlkError::OutOfRange,
        AtaError::DeviceError | AtaError::Timeout => BlkError::Io,
    }
}

/// A window of the primary-master ATA disk, as 4 KiB blocks.
#[derive(Debug)]
pub struct AtaDevice {
    base_lba: u32,
    blocks: u64,
}

impl AtaDevice {
    /// Probe the primary master (`IDENTIFY`) and open the window that starts
    /// at sector `base_lba` and runs to the end of the disk, in whole blocks.
    ///
    /// Port I/O: call only from the `sfs-commit` task, the one thread that
    /// touches the device.
    ///
    /// # Errors
    ///
    /// [`BlkError::NoDevice`] without a disk; [`BlkError::OutOfRange`] if the
    /// disk ends at or before `base_lba`; [`BlkError::Io`] on a controller
    /// error.
    pub fn open(base_lba: u32) -> Result<AtaDevice, BlkError> {
        let info = with_channel(hal::ata::identify).map_err(map_err)?;
        let sectors = u64::from(info.sectors);
        let base = u64::from(base_lba);
        if sectors <= base {
            return Err(BlkError::OutOfRange);
        }
        Ok(AtaDevice {
            base_lba,
            blocks: (sectors - base) / SECTORS_PER_BLOCK as u64,
        })
    }

    /// First disk sector of the window.
    #[must_use]
    pub const fn base_lba(&self) -> u32 {
        self.base_lba
    }

    /// Disk sector of block `b` of the window, if it fits LBA28's `u32`.
    fn lba_of(&self, b: u64) -> Result<u32, BlkError> {
        let lba = b
            .checked_mul(SECTORS_PER_BLOCK as u64)
            .and_then(|s| s.checked_add(u64::from(self.base_lba)))
            .ok_or(BlkError::OutOfRange)?;
        u32::try_from(lba).map_err(|_| BlkError::OutOfRange)
    }
}

impl BlockDevice for AtaDevice {
    fn blocks(&self) -> u64 {
        self.blocks
    }

    fn read_blocks(&mut self, start: BlockNo, out: &mut [Block]) -> Result<(), BlkError> {
        check_range(start, out.len(), self.blocks)?;
        let mut at = start.get();
        for chunk in out.chunks_mut(BLOCKS_PER_COMMAND) {
            let lba = self.lba_of(at)?;
            let sectors = (chunk.len() * SECTORS_PER_BLOCK) as u16;
            let bytes = chunk.as_flattened_mut();
            with_channel(|| hal::ata::read_sectors(lba, sectors, bytes)).map_err(map_err)?;
            at += chunk.len() as u64;
        }
        Ok(())
    }

    fn write_blocks(&mut self, start: BlockNo, data: &[Block]) -> Result<(), BlkError> {
        check_range(start, data.len(), self.blocks)?;
        let mut at = start.get();
        for chunk in data.chunks(BLOCKS_PER_COMMAND) {
            let lba = self.lba_of(at)?;
            let sectors = (chunk.len() * SECTORS_PER_BLOCK) as u16;
            let bytes = chunk.as_flattened();
            // `hal::ata::write_sectors` ends with FLUSH CACHE (module docs).
            with_channel(|| hal::ata::write_sectors(lba, sectors, bytes)).map_err(map_err)?;
            at += chunk.len() as u64;
        }
        Ok(())
    }

    /// Nothing to do on today's `hal::ata`: every write above was already
    /// flushed by `hal` before it returned. See the module docs.
    fn flush(&mut self) -> Result<(), BlkError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_geometry_and_lba_math() {
        // The dev image: 16 MiB = 32768 sectors, window from 2048.
        let d = AtaDevice {
            base_lba: SFS_BASE_LBA,
            blocks: (32_768 - u64::from(SFS_BASE_LBA)) / 8,
        };
        assert_eq!(d.blocks(), 3840);
        assert_eq!(d.lba_of(0), Ok(2048));
        assert_eq!(d.lba_of(3839), Ok(2048 + 3839 * 8));
        assert_eq!(d.lba_of(u64::MAX), Err(BlkError::OutOfRange));
        assert_eq!(BLOCKS_PER_COMMAND, 32);
    }

    #[test]
    fn requests_outside_the_window_never_reach_the_port() {
        // Range checks run before any `hal::ata` call (which would fault on
        // the host), so these return without I/O.
        let mut d = AtaDevice {
            base_lba: SFS_BASE_LBA,
            blocks: 4,
        };
        let mut out = crate::blk::zeroed_blocks(2);
        assert_eq!(
            d.read_blocks(BlockNo(3), &mut out),
            Err(BlkError::OutOfRange)
        );
        assert_eq!(d.write_blocks(BlockNo(4), &out), Err(BlkError::OutOfRange));
        assert_eq!(d.read_blocks(BlockNo(0), &mut []), Err(BlkError::BadBuffer));
        assert_eq!(d.flush(), Ok(()));
    }

    #[test]
    fn ata_errors_map_onto_block_errors() {
        assert_eq!(map_err(AtaError::NoDevice), BlkError::NoDevice);
        assert_eq!(map_err(AtaError::Timeout), BlkError::Io);
        assert_eq!(map_err(AtaError::DeviceError), BlkError::Io);
        assert_eq!(map_err(AtaError::BadBuffer), BlkError::BadBuffer);
        assert_eq!(map_err(AtaError::OutOfRange), BlkError::OutOfRange);
    }
}
