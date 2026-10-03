//! `MemDevice` — a [`BlockDevice`] in memory with the §8 durability model, for
//! host tests (spec §6, §8, amendment A16).
//!
//! The model is exactly the one the commit protocol is designed against:
//!
//! - Between two [`flush`](BlockDevice::flush) calls the device may persist
//!   **any subset** of the writes issued, **in any order**.
//! - A single 512-byte sector write is atomic; a 4 KiB block write is not.
//!   Torn (sector-granular) persistence is modelled for the two superblock
//!   slots, blocks 0 and 1 — every other block is protected by the hash in its
//!   parent pointer, so a torn copy of it can only ever be *detected*.
//! - `flush` makes every earlier write durable.
//!
//! Reads always see the latest write. A crash is armed with a [`CrashPlan`]:
//! when the device is asked for write number `at_write` (counting individual
//! blocks from the moment the plan is armed), that write is in flight, power
//! is lost, and every later operation fails with [`BlkError::PowerLost`].
//! [`MemDevice::power_cycle`] then resolves the unflushed writes — a subset,
//! in a shuffled order, with torn slot writes — using a seeded PRNG, and the
//! device comes back with whatever survived. The same seed always yields the
//! same image.
//!
//! An *untracked* device ([`MemDevice::untracked`]) keeps no undo log: writes
//! are immediately durable and nothing is allocated per write. The heap
//! footprint tests use it so the device's own bookkeeping never mixes with the
//! filesystem's.

use super::{check_range, BlkError, Block, BlockDevice, BlockNo, Blocks, BLOCK_SIZE, SECTOR_SIZE};
use alloc::vec;
use alloc::vec::Vec;

/// SplitMix64 — a tiny, well-mixed, seedable PRNG (Steele, Lea, Flood 2014).
/// Deterministic across platforms; not for anything secret.
#[derive(Clone, Debug)]
pub struct SplitMix64(u64);

impl SplitMix64 {
    /// A generator seeded with `seed`.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// The next 64 pseudo-random bits.
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A fair coin.
    pub fn coin(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }

    /// Uniform-ish in `[0, n)` (`0` for `n == 0`). The modulo bias is
    /// irrelevant at the sizes the tests use.
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next_u64() % n
        }
    }
}

/// Which unflushed writes survive a crash.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Persist {
    /// None of them (the durable image is exactly the last flush).
    Nothing,
    /// All of them, in issue order (the in-flight write included, whole).
    Everything,
    /// A PRNG-chosen subset in a PRNG-chosen order; slot writes may be torn.
    Subset,
}

/// When and how the device loses power.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CrashPlan {
    /// Index (from arming, counting single blocks) of the write that is in
    /// flight when power is lost.
    pub at_write: u64,
    /// Seed for [`Persist::Subset`] (and for [`MemDevice::power_cycle`]).
    pub seed: u64,
    /// Which unflushed writes survive.
    pub persist: Persist,
}

/// One unflushed block write: enough to undo it or replay it (one block each).
struct Pending {
    block: usize,
    old: Blocks,
    new: Blocks,
}

/// An in-memory block device with the §8 crash model.
pub struct MemDevice {
    image: Vec<u8>,
    blocks: u64,
    tracked: bool,
    pending: Vec<Pending>,
    writes: u64,
    flushes: u64,
    armed_at: u64,
    plan: Option<CrashPlan>,
    crashed: bool,
}

impl MemDevice {
    /// A zero-filled, tracked device of `blocks` blocks.
    #[must_use]
    pub fn new(blocks: u64) -> MemDevice {
        let len = usize::try_from(blocks)
            .unwrap_or(0)
            .saturating_mul(BLOCK_SIZE);
        MemDevice::with_image(vec![0u8; len], true)
    }

    /// A zero-filled device that keeps no undo log (writes are immediately
    /// durable; crash plans are ignored). Allocates nothing per operation.
    #[must_use]
    pub fn untracked(blocks: u64) -> MemDevice {
        let len = usize::try_from(blocks)
            .unwrap_or(0)
            .saturating_mul(BLOCK_SIZE);
        MemDevice::with_image(vec![0u8; len], false)
    }

    /// A tracked device over an existing image (a whole number of blocks; any
    /// trailing partial block is ignored).
    #[must_use]
    pub fn from_image(image: Vec<u8>) -> MemDevice {
        MemDevice::with_image(image, true)
    }

    fn with_image(image: Vec<u8>, tracked: bool) -> MemDevice {
        let blocks = (image.len() / BLOCK_SIZE) as u64;
        MemDevice {
            image,
            blocks,
            tracked,
            pending: Vec::new(),
            writes: 0,
            flushes: 0,
            armed_at: 0,
            plan: None,
            crashed: false,
        }
    }

    /// The current image (what a read would return).
    #[must_use]
    pub fn image(&self) -> &[u8] {
        &self.image
    }

    /// Mutable access to the image, for fault injection (bit flips, foreign
    /// data). Bypasses the durability model.
    pub fn image_mut(&mut self) -> &mut [u8] {
        &mut self.image
    }

    /// Consume the device, returning its current image.
    #[must_use]
    pub fn into_image(self) -> Vec<u8> {
        self.image
    }

    /// Block writes issued so far (each block of a multi-block write counts).
    #[must_use]
    pub const fn writes(&self) -> u64 {
        self.writes
    }

    /// Successful flushes so far.
    #[must_use]
    pub const fn flushes(&self) -> u64 {
        self.flushes
    }

    /// Unflushed block writes.
    #[must_use]
    pub fn unflushed(&self) -> usize {
        self.pending.len()
    }

    /// Whether power has been lost (and not yet restored).
    #[must_use]
    pub const fn crashed(&self) -> bool {
        self.crashed
    }

    /// Arm a crash; `plan.at_write` counts block writes from now.
    pub fn arm_crash(&mut self, plan: CrashPlan) {
        self.armed_at = self.writes;
        self.plan = Some(plan);
    }

    /// Power the device off and on: resolve every unflushed write under the
    /// armed plan's persistence rule (or `Subset` with `seed` if none was
    /// armed), then come back up with an empty write cache.
    pub fn power_cycle(&mut self, seed: u64) {
        let (persist, seed) = match self.plan {
            Some(p) => (p.persist, p.seed),
            None => (Persist::Subset, seed),
        };
        self.resolve(persist, seed);
        self.pending.clear();
        self.plan = None;
        self.crashed = false;
    }

    /// Rewind the image to the last flush, then re-apply the survivors.
    fn resolve(&mut self, persist: Persist, seed: u64) {
        for p in self.pending.iter().rev() {
            if let (Some(dst), Some(old)) = (block_mut(&mut self.image, p.block), p.old.first()) {
                dst.copy_from_slice(old);
            }
        }
        let n = self.pending.len();
        let mut order: Vec<usize> = (0..n).collect();
        let mut rng = SplitMix64::new(seed);
        if persist == Persist::Subset {
            // Fisher–Yates: "in any order".
            for i in (1..n).rev() {
                let j = rng.below(i as u64 + 1) as usize;
                order.swap(i, j);
            }
        }
        for &i in &order {
            let Some(p) = self.pending.get(i) else {
                continue;
            };
            let (Some(dst), Some(new)) = (block_mut(&mut self.image, p.block), p.new.first())
            else {
                continue;
            };
            match persist {
                Persist::Nothing => {}
                Persist::Everything => dst.copy_from_slice(new),
                Persist::Subset => {
                    if !rng.coin() {
                        continue;
                    }
                    if p.block < 2 {
                        // A superblock slot: each sector independently.
                        for (d, n) in dst
                            .chunks_exact_mut(SECTOR_SIZE)
                            .zip(new.chunks_exact(SECTOR_SIZE))
                        {
                            if rng.coin() {
                                d.copy_from_slice(n);
                            }
                        }
                    } else {
                        dst.copy_from_slice(new);
                    }
                }
            }
        }
    }

    /// Record and apply one block write, or lose power on it.
    fn write_one(&mut self, block: usize, data: &Block) -> Result<(), BlkError> {
        let index = self.writes - self.armed_at;
        self.writes += 1;
        let in_flight = self.tracked && self.plan.is_some_and(|p| p.at_write == index);
        let dst = block_mut(&mut self.image, block).ok_or(BlkError::OutOfRange)?;
        if self.tracked {
            let old = copy_block(dst);
            let new = copy_block(data);
            self.pending.push(Pending { block, old, new });
        }
        dst.copy_from_slice(data);
        if in_flight {
            self.crashed = true;
            return Err(BlkError::PowerLost);
        }
        Ok(())
    }
}

/// A heap copy of one block's bytes.
fn copy_block(src: &[u8]) -> Blocks {
    let mut b = Blocks::zeroed(1);
    if let (Some(dst), Some(s)) = (b.first_mut(), src.get(..BLOCK_SIZE)) {
        dst.copy_from_slice(s);
    }
    b
}

fn block_mut(image: &mut [u8], block: usize) -> Option<&mut [u8]> {
    let start = block.checked_mul(BLOCK_SIZE)?;
    image.get_mut(start..start.checked_add(BLOCK_SIZE)?)
}

impl BlockDevice for MemDevice {
    fn blocks(&self) -> u64 {
        self.blocks
    }

    fn read_blocks(&mut self, start: BlockNo, out: &mut [Block]) -> Result<(), BlkError> {
        if self.crashed {
            return Err(BlkError::PowerLost);
        }
        check_range(start, out.len(), self.blocks)?;
        for (i, dst) in out.iter_mut().enumerate() {
            let b = start.0 as usize + i;
            let at = b * BLOCK_SIZE;
            let src = self
                .image
                .get(at..at + BLOCK_SIZE)
                .ok_or(BlkError::OutOfRange)?;
            dst.copy_from_slice(src);
        }
        Ok(())
    }

    fn write_blocks(&mut self, start: BlockNo, data: &[Block]) -> Result<(), BlkError> {
        if self.crashed {
            return Err(BlkError::PowerLost);
        }
        check_range(start, data.len(), self.blocks)?;
        for (i, src) in data.iter().enumerate() {
            self.write_one(start.0 as usize + i, src)?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), BlkError> {
        if self.crashed {
            return Err(BlkError::PowerLost);
        }
        self.pending.clear();
        self.flushes += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blk::zeroed_blocks;

    fn filled(v: u8) -> Blocks {
        let mut b = zeroed_blocks(1);
        b[0].fill(v);
        b
    }

    fn block_of(dev: &mut MemDevice, b: u32) -> Blocks {
        let mut out = zeroed_blocks(1);
        dev.read_blocks(BlockNo(b), &mut out).unwrap();
        out
    }

    #[test]
    fn reads_see_writes_and_ranges_are_checked() {
        let mut d = MemDevice::new(4);
        assert_eq!(d.blocks(), 4);
        d.write_blocks(BlockNo(1), &filled(7)).unwrap();
        assert!(block_of(&mut d, 1)[0].iter().all(|&x| x == 7));
        let mut two = zeroed_blocks(2);
        assert_eq!(
            d.read_blocks(BlockNo(3), &mut two),
            Err(BlkError::OutOfRange)
        );
        assert_eq!(d.write_blocks(BlockNo(0), &[]), Err(BlkError::BadBuffer));
        assert_eq!(d.writes(), 1);
        assert_eq!(d.unflushed(), 1);
        d.flush().unwrap();
        assert_eq!(d.unflushed(), 0);
    }

    #[test]
    fn crash_keeps_flushed_writes_and_drops_unflushed_ones_under_nothing() {
        let mut d = MemDevice::new(8);
        d.write_blocks(BlockNo(2), &filled(1)).unwrap();
        d.flush().unwrap();
        d.arm_crash(CrashPlan {
            at_write: 1,
            seed: 0,
            persist: Persist::Nothing,
        });
        d.write_blocks(BlockNo(3), &filled(2)).unwrap();
        assert_eq!(
            d.write_blocks(BlockNo(4), &filled(3)),
            Err(BlkError::PowerLost)
        );
        assert!(d.crashed());
        assert_eq!(d.flush(), Err(BlkError::PowerLost));
        let mut out = zeroed_blocks(1);
        assert_eq!(
            d.read_blocks(BlockNo(2), &mut out),
            Err(BlkError::PowerLost)
        );
        d.power_cycle(0);
        assert!(block_of(&mut d, 2)[0].iter().all(|&x| x == 1));
        assert!(block_of(&mut d, 3)[0].iter().all(|&x| x == 0));
        assert!(block_of(&mut d, 4)[0].iter().all(|&x| x == 0));
    }

    #[test]
    fn everything_persists_the_in_flight_write_too() {
        let mut d = MemDevice::new(8);
        d.arm_crash(CrashPlan {
            at_write: 0,
            seed: 0,
            persist: Persist::Everything,
        });
        assert_eq!(
            d.write_blocks(BlockNo(5), &filled(9)),
            Err(BlkError::PowerLost)
        );
        d.power_cycle(0);
        assert!(block_of(&mut d, 5)[0].iter().all(|&x| x == 9));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn subset_is_deterministic_per_seed_and_tears_only_slots() {
        let run = |seed: u64| {
            let mut d = MemDevice::new(8);
            d.arm_crash(CrashPlan {
                at_write: 99,
                seed,
                persist: Persist::Subset,
            });
            for b in 0..6u32 {
                d.write_blocks(BlockNo(b), &filled(0xA0 | b as u8)).unwrap();
            }
            d.power_cycle(0);
            d.into_image()
        };
        let mut torn_seen = false;
        let mut variety = alloc::collections::BTreeSet::new();
        for seed in 0..64 {
            let img = run(seed);
            assert_eq!(img, run(seed), "same seed, same image");
            for b in 0..6usize {
                let blk = &img[b * BLOCK_SIZE..(b + 1) * BLOCK_SIZE];
                let new = 0xA0 | b as u8;
                let sectors: Vec<bool> = blk
                    .chunks_exact(SECTOR_SIZE)
                    .map(|s| {
                        assert!(s.iter().all(|&x| x == 0) || s.iter().all(|&x| x == new));
                        s[0] == new
                    })
                    .collect();
                let mixed = sectors.iter().any(|&x| x) && sectors.iter().any(|&x| !x);
                if b >= 2 {
                    assert!(!mixed, "only slots 0/1 tear");
                } else if mixed {
                    torn_seen = true;
                }
            }
            variety.insert(img);
        }
        assert!(torn_seen, "64 seeds should tear a slot at least once");
        assert!(variety.len() > 8, "subsets vary with the seed");
    }

    #[test]
    fn untracked_device_keeps_no_log() {
        let mut d = MemDevice::untracked(4);
        d.arm_crash(CrashPlan {
            at_write: 0,
            seed: 0,
            persist: Persist::Nothing,
        });
        d.write_blocks(BlockNo(1), &filled(4)).unwrap();
        assert_eq!(d.unflushed(), 0);
        assert!(!d.crashed());
    }

    #[test]
    fn prng_is_stable() {
        let mut r = SplitMix64::new(0);
        // Reference values of SplitMix64 seeded with 0.
        assert_eq!(r.next_u64(), 0xE220_A839_7B1D_CDAF);
        assert_eq!(r.next_u64(), 0x6E78_9E6A_A1B9_65F4);
        assert_eq!(SplitMix64::new(5).below(0), 0);
    }
}
