//! Host tests for SentinelFS FS-1a (spec §11): format and mount, slot
//! alternation, the §8 crash model (write index × unflushed subset × torn
//! slots), the adversarial mount corpus, deterministic replay, the fixed heap
//! footprint, and the "never format over a disk that carries the magic" rule.
//!
//! [`mount_image`] is the fuzz-shaped whole-image target: any bytes in, a
//! classified [`Outcome`] out, never a panic. The corpus below feeds it
//! deterministic cases; the FS-2 fuzz lane can feed it unchanged.

use super::service::{mount_or_format, StartError};
use super::superblock::{self, SlotError, Superblock, MAGIC};
use super::volume::{
    format, write_commit, CommitError, Damage, FormatError, FormatParams, MountError, Stage,
    Volume, Workspace,
};
use crate::blk::allocator::{AllocClass, AllocError};
use crate::blk::geometry::{GeometryError, MAX_BLOCKS};
use crate::blk::layout::{seal_metadata, Pointer, HEADER_LEN};
use crate::blk::mem::{CrashPlan, MemDevice, Persist, SplitMix64};
use crate::blk::{
    zeroed_blocks, BlkError, Block, BlockDevice, BlockNo, Blocks, BLOCK_SIZE, SECTOR_SIZE,
};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

/// The dev image's SentinelFS window: 16 MiB from LBA 2048.
const DEV_WINDOW: u64 = 3840;
/// A small filesystem for tests that copy whole images many times.
const SMALL: u64 = 256;

fn params() -> FormatParams {
    FormatParams::from_seed(b"sfs-host-tests", 7)
}

fn formatted(blocks: u64) -> MemDevice {
    let mut d = MemDevice::new(blocks);
    format(&mut d, &mut Workspace::new(), &params()).unwrap();
    d
}

fn mount(d: &mut MemDevice) -> Result<Box<Volume>, MountError> {
    Volume::mount(d, &mut Workspace::new())
}

/// What a whole-image mount came to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Outcome {
    Mounted { gen: u64, slot: u8, free: u64 },
    Unformatted,
    Corrupt(Damage),
    TooLarge,
    Io,
}

/// The fuzz-shaped whole-image mount target.
pub(crate) fn mount_image(img: &[u8]) -> Outcome {
    let mut dev = MemDevice::from_image(img.to_vec());
    match Volume::mount(&mut dev, &mut Workspace::new()) {
        Ok(v) => {
            let i = v.info();
            Outcome::Mounted {
                gen: i.gen,
                slot: i.slot,
                free: i.free,
            }
        }
        Err(MountError::Unformatted) => Outcome::Unformatted,
        Err(MountError::Corrupt(d)) => Outcome::Corrupt(d),
        Err(MountError::TooLarge) => Outcome::TooLarge,
        Err(MountError::Io(_)) => Outcome::Io,
    }
}

fn block(img: &[u8], b: usize) -> &[u8] {
    &img[b * BLOCK_SIZE..(b + 1) * BLOCK_SIZE]
}

fn block_mut(img: &mut [u8], b: usize) -> &mut Block {
    let s = &mut img[b * BLOCK_SIZE..(b + 1) * BLOCK_SIZE];
    s.try_into().unwrap()
}

/// A device wrapper that records the order of writes and flushes.
struct Recorder<D> {
    inner: D,
    log: Vec<Op>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Op {
    Write(u32),
    Flush,
}

impl<D: BlockDevice> BlockDevice for Recorder<D> {
    fn blocks(&self) -> u64 {
        self.inner.blocks()
    }
    fn read_blocks(&mut self, start: BlockNo, out: &mut [Block]) -> Result<(), BlkError> {
        self.inner.read_blocks(start, out)
    }
    fn write_blocks(&mut self, start: BlockNo, data: &[Block]) -> Result<(), BlkError> {
        for i in 0..data.len() as u32 {
            self.log.push(Op::Write(start.0 + i));
        }
        self.inner.write_blocks(start, data)
    }
    fn flush(&mut self) -> Result<(), BlkError> {
        self.log.push(Op::Flush);
        self.inner.flush()
    }
}

/// A device that claims to be huge but stores only what was written.
struct Sparse {
    blocks: u64,
    map: BTreeMap<u32, Blocks>,
}

impl BlockDevice for Sparse {
    fn blocks(&self) -> u64 {
        self.blocks
    }
    fn read_blocks(&mut self, start: BlockNo, out: &mut [Block]) -> Result<(), BlkError> {
        crate::blk::check_range(start, out.len(), self.blocks)?;
        for (i, o) in out.iter_mut().enumerate() {
            match self.map.get(&(start.0 + i as u32)) {
                Some(b) => o.copy_from_slice(&b[0]),
                None => o.fill(0),
            }
        }
        Ok(())
    }
    fn write_blocks(&mut self, start: BlockNo, data: &[Block]) -> Result<(), BlkError> {
        crate::blk::check_range(start, data.len(), self.blocks)?;
        for (i, d) in data.iter().enumerate() {
            let mut b = zeroed_blocks(1);
            b[0].copy_from_slice(d);
            self.map.insert(start.0 + i as u32, b);
        }
        Ok(())
    }
    fn flush(&mut self) -> Result<(), BlkError> {
        Ok(())
    }
}

// ── format & mount ─────────────────────────────────────────────────────────

#[test]
fn fresh_window_is_unformatted_then_formats_and_mounts_at_gen_1_slot_1() {
    let mut d = MemDevice::new(DEV_WINDOW);
    assert!(matches!(mount(&mut d), Err(MountError::Unformatted)));
    let f = format(&mut d, &mut Workspace::new(), &params()).unwrap();
    assert_eq!((f.groups, f.total, f.free), (1, 3840, 3836));
    // zero both slots (2) + bitmap + index + superblock; three flushes.
    assert_eq!((d.writes(), d.flushes()), (5, 3));
    let v = mount(&mut d).unwrap();
    let i = v.info();
    assert_eq!(
        (i.gen, i.slot, i.groups, i.free, i.total),
        (1, 1, 1, 3836, 3840)
    );
    assert_eq!(i.reserve, 64);
    assert_eq!(i.sb_hash, f.sb_hash);
    // The superblock's hash is the one stored in its own header.
    assert_eq!(&block(d.image(), 1)[..32], &f.sb_hash[..]);
}

#[test]
fn format_refuses_unusable_sizes() {
    let mut small = MemDevice::new(127);
    assert_eq!(
        format(&mut small, &mut Workspace::new(), &params()),
        Err(FormatError::Geometry(GeometryError::TooSmall))
    );
    let mut huge = Sparse {
        blocks: MAX_BLOCKS + 1,
        map: BTreeMap::new(),
    };
    assert_eq!(
        format(&mut huge, &mut Workspace::new(), &params()),
        Err(FormatError::Geometry(GeometryError::TooLarge))
    );
}

#[test]
fn a_superblock_beyond_the_v2_geometry_mounts_as_too_large() {
    let mut huge = Sparse {
        blocks: MAX_BLOCKS + 1,
        map: BTreeMap::new(),
    };
    let sb = Superblock {
        total_blocks: MAX_BLOCKS + 1,
        gen: 1,
        uuid: [1; 16],
        root: Pointer::NULL,
        blobs: Pointer::NULL,
        roots: Pointer::NULL,
        free: Pointer {
            block: BlockNo(3),
            hash: [2; 32],
            gen: 1,
        },
        next_obj: 1,
        committed_at: 0,
        dirent_key: [0; 16],
        kdf: [0; 32],
        reserve_per_group: 64,
    };
    let mut b = zeroed_blocks(1);
    superblock::encode(&sb, &mut b[0]);
    huge.write_blocks(BlockNo(1), &b).unwrap();
    assert!(matches!(
        Volume::mount(&mut huge, &mut Workspace::new()),
        Err(MountError::TooLarge)
    ));
}

#[test]
#[cfg_attr(miri, ignore)]
fn mount_or_format_formats_only_an_unformatted_disk() {
    // Unformatted: formatted, then mounted.
    let mut d = MemDevice::new(DEV_WINDOW);
    let (v, f) = mount_or_format(&mut d, &mut Workspace::new(), params).unwrap();
    assert!(f.is_some());
    assert_eq!(v.info().gen, 1);
    // Already formatted: mounted, not formatted again.
    let (v, f) = mount_or_format(&mut d, &mut Workspace::new(), params).unwrap();
    assert!(f.is_none());
    assert_eq!(v.info().gen, 1);
    // Corrupt (both slots carry the magic, neither verifies): refused, and
    // the disk is not touched.
    let mut img = d.into_image();
    block_mut(&mut img, 1)[100] ^= 1;
    let head: Vec<u8> = block(&img, 1)[..72].to_vec();
    block_mut(&mut img, 0)[..72].copy_from_slice(&head);
    let before = img.clone();
    let mut d = MemDevice::from_image(img);
    let called = core::cell::Cell::new(false);
    let r = mount_or_format(&mut d, &mut Workspace::new(), || {
        called.set(true);
        params()
    });
    assert!(matches!(
        r,
        Err(StartError::Mount(MountError::Corrupt(Damage::Slots { .. })))
    ));
    assert!(!called.get(), "format was never even considered");
    assert_eq!(d.writes(), 0);
    assert_eq!(d.into_image(), before);
}

// ── commits ────────────────────────────────────────────────────────────────

#[test]
#[cfg_attr(miri, ignore)]
fn empty_commits_alternate_slots_across_remounts() {
    let mut d = formatted(DEV_WINDOW);
    let mut ws = Workspace::new();
    let mut v = mount(&mut d).unwrap();
    let mut last_hash = v.info().sb_hash;
    for k in 0..6u64 {
        let c = v.commit(&mut d, &mut ws, 100 + k).unwrap();
        let gen = 2 + k;
        assert_eq!((c.gen, c.slot), (gen, (gen % 2) as u8));
        assert_eq!(
            (c.blocks, c.flushes),
            (1, 2),
            "an empty commit writes only the superblock"
        );
        assert_ne!(c.sb_hash, last_hash);
        last_hash = c.sb_hash;
        // A fresh mount (a reboot) sees exactly this commit.
        v = mount(&mut d).unwrap();
        let i = v.info();
        assert_eq!(
            (i.gen, i.slot, i.sb_hash, i.free),
            (gen, c.slot, c.sb_hash, 3836)
        );
        assert_eq!(v.superblock().committed_at, 100 + k);
    }
}

#[test]
#[cfg_attr(miri, ignore)]
fn commit_io_order_is_dirty_flush_superblock_flush() {
    let mut d = Recorder {
        inner: formatted(DEV_WINDOW),
        log: Vec::new(),
    };
    let mut ws = Workspace::new();
    let mut v = Volume::mount(&mut d, &mut ws).unwrap();
    let a = v.alloc(AllocClass::Normal, None).unwrap();
    d.log.clear();
    let c = v.commit(&mut d, &mut ws, 1).unwrap();
    assert_eq!(c.blocks, 3, "bitmap copy + new index + superblock");
    // Bitmap copy at 4 (first fit), caller's block 5, index at 6; superblock
    // gen 2 into slot 0 (slot 1 holds gen 1).
    assert_eq!(a, BlockNo(5));
    assert_eq!(
        d.log,
        [
            Op::Write(4),
            Op::Write(6),
            Op::Flush,
            Op::Write(0),
            Op::Flush
        ]
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn allocations_and_frees_persist_and_freed_blocks_return_after_their_commit() {
    let mut d = formatted(DEV_WINDOW);
    let mut ws = Workspace::new();
    let mut v = mount(&mut d).unwrap();
    let got: Vec<BlockNo> = (0..10)
        .map(|_| v.alloc(AllocClass::Normal, None).unwrap())
        .collect();
    let run = v.alloc_run(32, AllocClass::Normal, None).unwrap();
    v.commit(&mut d, &mut ws, 1).unwrap();
    let mut v = mount(&mut d).unwrap();
    assert_eq!(v.info().free, 3836 - 10 - 32);
    // Allocated on disk: freeing them is accepted…
    for b in got
        .iter()
        .copied()
        .chain((0..run.len()).filter_map(|i| run.nth(i)))
    {
        v.free(b).unwrap();
    }
    // …and nothing freed is handed out again before the commit.
    let fresh: Vec<BlockNo> = (0..200)
        .map(|_| v.alloc(AllocClass::Normal, None).unwrap())
        .collect();
    assert!(fresh.iter().all(|b| !got.contains(b) && !run.contains(*b)));
    // Blocks allocated in a transaction may be freed in it too.
    for b in &fresh {
        v.free(*b).unwrap();
    }
    v.commit(&mut d, &mut ws, 2).unwrap();
    let mut v = mount(&mut d).unwrap();
    assert_eq!(v.info().free, 3836, "everything is free again");
    // The freed blocks are allocatable now: first fit reaches them.
    let again: Vec<BlockNo> = (0..60)
        .map(|_| v.alloc(AllocClass::Normal, None).unwrap())
        .collect();
    assert!(got.iter().all(|b| again.contains(b)));
}

#[test]
#[cfg_attr(miri, ignore)]
fn a_failed_commit_leaves_the_volume_read_only_and_the_disk_on_the_old_generation() {
    let mut d = formatted(DEV_WINDOW);
    let mut ws = Workspace::new();
    let mut v = mount(&mut d).unwrap();
    v.alloc(AllocClass::Normal, None).unwrap();
    d.arm_crash(CrashPlan {
        at_write: 1,
        seed: 0,
        persist: Persist::Nothing,
    });
    assert_eq!(
        v.commit(&mut d, &mut ws, 1),
        Err(CommitError::Io(BlkError::PowerLost))
    );
    assert!(v.is_read_only());
    assert_eq!(v.alloc(AllocClass::Normal, None), Err(AllocError::Sealed));
    assert_eq!(v.begin_commit(2), Err(CommitError::ReadOnly));
    d.power_cycle(0);
    let v = mount(&mut d).unwrap();
    assert_eq!((v.info().gen, v.info().free), (1, 3836));
}

#[test]
fn commit_phases_refuse_misuse() {
    let mut d = formatted(SMALL);
    let mut v = mount(&mut d).unwrap();
    let mut buf = zeroed_blocks(1);
    assert_eq!(v.fetch(Stage::Superblock, &mut buf[0]), None);
    assert_eq!(v.finish_commit(Ok(())), Err(CommitError::Internal));
    let plan = v.begin_commit(5).unwrap();
    assert_eq!((plan.dirty, plan.slot, plan.gen), (0, 0, 2));
    assert_eq!(v.begin_commit(5), Err(CommitError::Busy));
    assert_eq!(v.alloc(AllocClass::Normal, None), Err(AllocError::Sealed));
    assert_eq!(v.fetch(Stage::Dirty(0), &mut buf[0]), None);
    assert_eq!(v.fetch(Stage::Superblock, &mut buf[0]), Some(BlockNo(0)));
    let io = write_commit(&mut d, &mut buf[0], &plan, |s, out| v.fetch(s, out));
    assert_eq!(v.finish_commit(io).unwrap().gen, 2);
}

#[test]
fn an_evicted_bitmap_is_a_miss_that_a_verified_read_resolves() {
    let mut d = formatted(DEV_WINDOW);
    let mut ws = Workspace::new();
    let mut v = mount(&mut d).unwrap();
    let p = v.allocator().group_pointer(0).unwrap();
    assert!(v.drop_clean(p.block));
    assert_eq!(v.alloc(AllocClass::Normal, None), Err(AllocError::Miss(p)));
    assert!(!v.is_dirty(), "a miss changes nothing");
    v.load(&mut d, &mut ws, &p).unwrap();
    assert!(!v.is_read_only());
    assert_eq!(v.alloc(AllocClass::Normal, None), Ok(BlockNo(5)));
}

/// A two-group image whose next transaction can be made to miss at seal time.
fn two_groups() -> MemDevice {
    formatted(u64::from(crate::blk::geometry::GROUP_BLOCKS) + 200)
}

/// Mount `d`, open a transaction confined to group 1 and evict group 0's
/// committed bitmap: the seal then misses on it (the index lives in group 0).
fn missing_group0(d: &mut MemDevice) -> (Box<Volume>, Pointer) {
    let mut v = mount(d).unwrap();
    v.alloc(AllocClass::Normal, Some(1)).unwrap();
    let p0 = v.allocator().group_pointer(0).unwrap();
    assert!(v.drop_clean(p0.block));
    (v, p0)
}

/// FS-1a review: a miss that cannot be resolved — the read failed, the block
/// no longer matches its pointer — leaves the volume read-only, so the commit
/// task stops instead of re-reading the bad block every commit interval. The
/// committed generation on disk is untouched.
#[test]
#[cfg_attr(miri, ignore)]
fn an_unresolvable_miss_leaves_the_volume_read_only() {
    let mut d = two_groups();
    let mut flipped = zeroed_blocks(1);

    for case in 0..2 {
        let (mut v, p0) = missing_group0(&mut d);
        // The service's shape: the seal misses, the task reads (no lock held)
        // and hands the result back.
        assert_eq!(v.begin_commit(3), Err(CommitError::Miss(p0)));
        let (read, want) = if case == 0 {
            (Err(BlkError::Io), CommitError::Io(BlkError::Io))
        } else {
            d.read_blocks(p0.block, &mut flipped).unwrap();
            flipped[0][HEADER_LEN] ^= 1;
            (Ok(&flipped[0]), CommitError::Corrupt)
        };
        assert_eq!(v.resolve_miss(&p0, read), Err(want));
        assert!(v.is_read_only());
        assert_eq!(v.begin_commit(4), Err(CommitError::ReadOnly), "no retry");
        assert_eq!(v.alloc(AllocClass::Normal, None), Err(AllocError::Sealed));
    }

    // The synchronous form, with the block on disk itself gone bad.
    let (mut v, p0) = missing_group0(&mut d);
    let at = p0.block.0 as usize * BLOCK_SIZE + HEADER_LEN;
    d.image_mut()[at] ^= 1;
    let mut ws = Workspace::new();
    assert_eq!(v.commit(&mut d, &mut ws, 5), Err(CommitError::Corrupt));
    assert!(v.is_read_only());
    assert_eq!(v.commit(&mut d, &mut ws, 6), Err(CommitError::ReadOnly));
    // Nothing was written: with the byte restored, generation 1 mounts.
    d.image_mut()[at] ^= 1;
    assert_eq!(mount(&mut d).unwrap().info().gen, 1);
}

/// A seal that keeps missing cannot loop a caller forever: after
/// `MAX_SEAL_RETRIES` misses the volume gives up, read-only.
#[test]
#[cfg_attr(miri, ignore)]
fn a_seal_that_keeps_missing_gives_up_read_only() {
    use super::volume::MAX_SEAL_RETRIES;
    let mut d = two_groups();
    let (mut v, p0) = missing_group0(&mut d);
    for _ in 0..MAX_SEAL_RETRIES {
        assert_eq!(v.begin_commit(1), Err(CommitError::Miss(p0)));
        assert!(!v.is_read_only());
    }
    assert_eq!(v.begin_commit(1), Err(CommitError::Internal));
    assert!(v.is_read_only());
}

/// A transaction confined to group 1 still needs group 0 at seal time (the
/// index lives there): with group 0's committed bitmap evicted, the seal
/// reports the miss before changing anything, and the commit completes once
/// the block is read.
#[test]
#[cfg_attr(miri, ignore)]
fn a_miss_during_seal_changes_nothing_and_the_commit_completes_after_the_read() {
    let blocks = u64::from(crate::blk::geometry::GROUP_BLOCKS) + 200;
    let mut d = formatted(blocks);
    let mut ws = Workspace::new();
    let mut v = mount(&mut d).unwrap();
    assert_eq!(v.info().groups, 2);
    let b = v.alloc(AllocClass::Normal, Some(1)).unwrap();
    assert_eq!(v.allocator().geometry().locate(b).unwrap().0, 1);
    let p0 = v.allocator().group_pointer(0).unwrap();
    assert!(v.drop_clean(p0.block));
    assert_eq!(v.begin_commit(9), Err(CommitError::Miss(p0)));
    assert!(!v.allocator().is_sealed());
    assert_eq!(v.allocator().pending_frees(), 1, "only group 1's old copy");
    let c = v.commit(&mut d, &mut ws, 9).unwrap();
    assert_eq!(
        (c.gen, c.blocks),
        (2, 4),
        "both bitmaps, the index, the superblock"
    );
    let v = mount(&mut d).unwrap();
    // Group 0: 4 metadata blocks; group 1 (200 blocks): its bitmap + `b`.
    assert_eq!(v.info().free, blocks - 4 - 2);
}

// ── the crash model (§8, A16) ───────────────────────────────────────────────

/// Every persistence mode the matrix exercises for one crash point.
fn modes(seeds: u64) -> Vec<(Persist, u64)> {
    let mut m = vec![(Persist::Nothing, 0), (Persist::Everything, 0)];
    m.extend((0..seeds).map(|s| (Persist::Subset, s)));
    m
}

#[test]
#[cfg_attr(miri, ignore)]
fn a_crash_anywhere_in_format_leaves_unformatted_or_generation_1() {
    let (mut unformatted, mut mounted) = (0, 0);
    for at in 0..=5 {
        for (persist, seed) in modes(24) {
            let mut d = MemDevice::new(SMALL);
            d.arm_crash(CrashPlan {
                at_write: at,
                seed,
                persist,
            });
            let r = format(&mut d, &mut Workspace::new(), &params());
            assert_eq!(r.is_ok(), at >= 5, "at {at}");
            d.power_cycle(seed);
            match mount_image(d.image()) {
                Outcome::Unformatted => {
                    assert!(at < 5);
                    unformatted += 1;
                }
                Outcome::Mounted {
                    gen: 1, slot: 1, ..
                } => mounted += 1,
                other => panic!("at {at} {persist:?}/{seed}: {other:?}"),
            }
        }
    }
    // Both outcomes really happen: the matrix is not vacuous.
    assert!(unformatted > 0 && mounted > 0, "{unformatted} / {mounted}");
}

/// Build a two-commit volume, then crash a third (allocating and freeing)
/// commit at every write index under every persistence mode: the next mount
/// must find generation 2 or 3, intact, with exactly that generation's free
/// space — never `Corrupt`, never a mix.
#[test]
#[cfg_attr(miri, ignore)]
fn a_crash_anywhere_in_a_commit_recovers_the_previous_or_the_new_generation() {
    let mut base = formatted(DEV_WINDOW);
    let mut ws = Workspace::new();
    let mut v = mount(&mut base).unwrap();
    let old: Vec<BlockNo> = (0..6)
        .map(|_| v.alloc(AllocClass::Normal, None).unwrap())
        .collect();
    v.commit(&mut base, &mut ws, 1).unwrap();
    let base_img = base.into_image();
    let free_gen2 = 3836 - 6;

    let mut writes_in_commit = 0;
    let (mut saw_old, mut saw_new) = (0, 0);
    for at in 0..=4u64 {
        for (persist, seed) in modes(16) {
            let mut d = MemDevice::from_image(base_img.clone());
            let mut v = mount(&mut d).unwrap();
            assert_eq!(v.info().gen, 2);
            let new: Vec<BlockNo> = (0..5)
                .map(|_| v.alloc(AllocClass::Normal, None).unwrap())
                .collect();
            v.free(old[0]).unwrap();
            v.free(old[1]).unwrap();
            let before = d.writes();
            d.arm_crash(CrashPlan {
                at_write: at,
                seed,
                persist,
            });
            let committed = v.commit(&mut d, &mut ws, 2).is_ok();
            writes_in_commit = writes_in_commit.max(d.writes() - before);
            d.power_cycle(seed);
            let mut d2 = MemDevice::from_image(d.into_image());
            let mut v2 = match mount(&mut d2) {
                Ok(v2) => v2,
                Err(e) => panic!("at {at} {persist:?}/{seed}: {e:?}"),
            };
            let i = v2.info();
            match i.gen {
                2 => {
                    saw_old += 1;
                    assert!(!committed, "a completed commit must survive");
                    assert_eq!(i.free, free_gen2);
                    // Gen 2 never saw the new blocks: they are free.
                    for b in &new {
                        assert_eq!(v2.free(*b), Err(AllocError::Invalid));
                    }
                }
                3 => {
                    saw_new += 1;
                    assert_eq!(i.free, free_gen2 - 5 + 2);
                    for b in &new {
                        assert!(v2.free(*b).is_ok(), "gen 3 owns {b:?}");
                    }
                    assert_eq!(v2.free(old[0]), Err(AllocError::Invalid));
                }
                g => panic!("at {at}: mounted generation {g}"),
            }
        }
    }
    assert_eq!(writes_in_commit, 3, "bitmap + index + superblock");
    // Both outcomes really happen: the matrix is not vacuous.
    assert!(saw_old > 0 && saw_new > 0, "{saw_old} / {saw_new}");
}

#[test]
#[cfg_attr(miri, ignore)]
fn slot_alternation_survives_a_torn_commit_followed_by_a_good_one() {
    let mut d = formatted(SMALL);
    let mut ws = Workspace::new();
    let (mut lost, mut landed) = (0, 0);
    for round in 0..16u64 {
        let mut v = mount(&mut d).unwrap();
        let gen = v.info().gen;
        // Tear this round's superblock write (index 0 of an empty commit).
        d.arm_crash(CrashPlan {
            at_write: 0,
            seed: round,
            persist: Persist::Subset,
        });
        assert!(v.commit(&mut d, &mut ws, round).is_err());
        d.power_cycle(round);
        let mut v = mount(&mut d).unwrap();
        let after = v.info();
        if after.gen == gen {
            lost += 1;
        } else {
            assert_eq!(after.gen, gen + 1);
            landed += 1;
        }
        assert_eq!(u64::from(after.slot), after.gen % 2);
        // A clean commit then always moves on to the other slot.
        let c = v.commit(&mut d, &mut ws, round).unwrap();
        assert_eq!(c.gen, after.gen + 1);
        assert_eq!(c.slot, 1 - after.slot);
    }
    assert!(lost > 0 && landed > 0, "{lost} / {landed}");
}

// ── the adversarial mount corpus (A23) ─────────────────────────────────────

/// A small volume at generation 3 (slot 1), generation 2 in slot 0.
fn corpus_base() -> Vec<u8> {
    let mut d = formatted(SMALL);
    let mut ws = Workspace::new();
    let mut v = mount(&mut d).unwrap();
    v.alloc(AllocClass::Normal, None).unwrap();
    v.commit(&mut d, &mut ws, 10).unwrap();
    v.alloc(AllocClass::Normal, None).unwrap();
    v.commit(&mut d, &mut ws, 20).unwrap();
    d.into_image()
}

/// Re-seal a hand-edited superblock (a forger who knows the format).
fn reseal(img: &mut [u8], slot: usize, edit: impl FnOnce(&mut Block)) {
    let b = block_mut(img, slot);
    edit(b);
    seal_metadata(b);
}

fn active_index_block(img: &[u8]) -> usize {
    let (sb, _) = superblock::decode(block(img, 1).try_into().unwrap(), SMALL).unwrap();
    sb.free.block.0 as usize
}

fn active_bitmap_block(img: &[u8]) -> usize {
    let mut d = MemDevice::from_image(img.to_vec());
    let v = mount(&mut d).unwrap();
    v.allocator().group_pointer(0).unwrap().block.0 as usize
}

#[test]
#[cfg_attr(miri, ignore)]
fn corpus_base_is_what_the_cases_assume() {
    let img = corpus_base();
    assert_eq!(
        mount_image(&img),
        Outcome::Mounted {
            gen: 3,
            slot: 1,
            free: 252 - 2
        }
    );
}

/// One corpus entry: a name, the image, and the outcome it must classify as.
type CorpusCase = (&'static str, Vec<u8>, fn(Outcome) -> bool);

#[test]
#[cfg_attr(miri, ignore)]
fn adversarial_mount_corpus() {
    let base = corpus_base();
    let gen3 = Outcome::Mounted {
        gen: 3,
        slot: 1,
        free: 250,
    };
    let index = active_index_block(&base);
    let bitmap = active_bitmap_block(&base);
    let mut cases: Vec<CorpusCase> = Vec::new();
    let case = |name: &'static str,
                cases: &mut Vec<CorpusCase>,
                f: &dyn Fn(&mut Vec<u8>),
                want: fn(Outcome) -> bool| {
        let mut img = base.clone();
        f(&mut img);
        cases.push((name, img, want));
    };
    let is_unformatted: fn(Outcome) -> bool = |o| o == Outcome::Unformatted;
    let is_corrupt_slots: fn(Outcome) -> bool =
        |o| matches!(o, Outcome::Corrupt(Damage::Slots { .. }));
    let is_gen2: fn(Outcome) -> bool = |o| {
        matches!(
            o,
            Outcome::Mounted {
                gen: 2,
                slot: 0,
                ..
            }
        )
    };

    // Nothing there.
    case("zeroed", &mut cases, &|i| i.fill(0), is_unformatted);
    case(
        "noise without the magic in both slots",
        &mut cases,
        &|i| {
            let mut r = SplitMix64::new(1);
            for b in &mut i[..2 * BLOCK_SIZE] {
                *b = r.next_u64() as u8;
            }
            i[64..72].copy_from_slice(b"NOTMAGIC");
            i[BLOCK_SIZE + 64..BLOCK_SIZE + 72].copy_from_slice(b"NOTMAGIC");
        },
        is_unformatted,
    );
    // The old `kernel::fs` image (FS-2 moves the window onto it).
    case(
        "old SNTLFS01 superblock in slot 0, slot 1 blank",
        &mut cases,
        &|i| {
            i[..2 * BLOCK_SIZE].fill(0);
            i[..8].copy_from_slice(b"SNTLFS01");
            i[8..12].copy_from_slice(&100u32.to_le_bytes());
            i[SECTOR_SIZE..SECTOR_SIZE + 100].fill(0x5A);
        },
        is_unformatted,
    );
    case(
        "SNTLFS01 at the magic offset in both slots (resealed)",
        &mut cases,
        &|i| {
            reseal(i, 0, |b| b[64..72].copy_from_slice(b"SNTLFS01"));
            reseal(i, 1, |b| b[64..72].copy_from_slice(b"SNTLFS01"));
        },
        is_unformatted,
    );
    // Torn and stale.
    case(
        "torn newest slot (sector 0 lost)",
        &mut cases,
        &|i| block_mut(i, 1)[..SECTOR_SIZE].fill(0),
        is_gen2,
    );
    case(
        "torn newest slot (garbage sector)",
        &mut cases,
        &|i| block_mut(i, 1)[3 * SECTOR_SIZE..4 * SECTOR_SIZE].fill(0xEE),
        is_gen2,
    );
    case(
        "stale generation newer than the device allows (total > device)",
        &mut cases,
        &|i| {
            reseal(i, 1, |b| {
                b[80..88].copy_from_slice(&(SMALL + 1).to_le_bytes())
            })
        },
        is_gen2,
    );
    case(
        "both slots claim more blocks than the device",
        &mut cases,
        &|i| {
            reseal(i, 0, |b| {
                b[80..88].copy_from_slice(&(SMALL * 2).to_le_bytes())
            });
            reseal(i, 1, |b| {
                b[80..88].copy_from_slice(&(SMALL * 2).to_le_bytes())
            });
        },
        is_corrupt_slots,
    );
    case(
        "future version in both slots (resealed)",
        &mut cases,
        &|i| {
            reseal(i, 0, |b| b[72] = 3);
            reseal(i, 1, |b| b[72] = 3);
        },
        is_corrupt_slots,
    );
    case(
        "kind confusion: newest slot claims to be a tree node (resealed)",
        &mut cases,
        &|i| reseal(i, 1, |b| b[40] = 2),
        is_gen2,
    );
    case(
        "newest slot points `free` at a superblock slot (resealed)",
        &mut cases,
        &|i| reseal(i, 1, |b| b[272..276].copy_from_slice(&1u32.to_le_bytes())),
        is_gen2,
    );
    case(
        "non-zero kdf slot (resealed)",
        &mut cases,
        &|i| reseal(i, 1, |b| b[360] = 1),
        is_gen2,
    );
    // Metadata under a valid superblock.
    case(
        "flipped bit in the group index payload",
        &mut cases,
        &move |i| block_mut(i, index)[HEADER_LEN + 3] ^= 0x80,
        |o| o == Outcome::Corrupt(Damage::Index),
    );
    case(
        "flipped bit in the group index header (kind)",
        &mut cases,
        &move |i| block_mut(i, index)[40] ^= 0x01,
        |o| o == Outcome::Corrupt(Damage::Index),
    );
    case(
        "flipped bit in the group bitmap payload",
        &mut cases,
        &move |i| block_mut(i, bitmap)[HEADER_LEN + 100] ^= 0x01,
        |o| o == Outcome::Corrupt(Damage::Bitmap(0)),
    );
    case(
        "flipped bit in the group bitmap header (fs_uuid)",
        &mut cases,
        &move |i| block_mut(i, bitmap)[50] ^= 0x01,
        |o| o == Outcome::Corrupt(Damage::Bitmap(0)),
    );
    case(
        "index from another filesystem, resealed (uuid mismatch)",
        &mut cases,
        &move |i| reseal(i, index, |b| b[48] ^= 1),
        |o| o == Outcome::Corrupt(Damage::Index),
    );

    // Every flipped bit of the newest superblock — header and payload — falls
    // back to the previous generation; magic flips read as foreign.
    for off in (0..superblock::SB_END).chain([1000, 4095]) {
        let mut img = base.clone();
        block_mut(&mut img, 1)[off] ^= 1 << (off % 8);
        let o = mount_image(&img);
        assert!(is_gen2(o), "flip at {off}: {o:?}");
        let err = superblock::decode(block(&img, 1).try_into().unwrap(), SMALL).unwrap_err();
        assert_eq!(
            err.carries_magic(),
            !(64..72).contains(&off),
            "flip at {off}"
        );
        // And with both slots flipped there is nothing to mount: Corrupt
        // unless both magics were destroyed.
        block_mut(&mut img, 0)[off] ^= 1 << (off % 8);
        let both = mount_image(&img);
        if (64..72).contains(&off) {
            assert_eq!(both, Outcome::Unformatted, "flip at {off}");
        } else {
            assert!(is_corrupt_slots(both), "flip at {off}: {both:?}");
        }
    }

    for (name, img, want) in &cases {
        let o = mount_image(img);
        assert!(want(o), "{name}: {o:?}");
    }
    assert_eq!(mount_image(&base), gen3);
    assert_eq!(mount_image(&base[..BLOCK_SIZE]), Outcome::Io);
}

/// Fuzz-shaped: random byte mutations of a valid image, raw and re-sealed —
/// never a panic, and every mount that succeeds is one of the two real
/// generations.
#[test]
#[cfg_attr(miri, ignore)]
fn random_mutations_never_panic_and_never_invent_a_generation() {
    let base = corpus_base();
    let index = active_index_block(&base);
    let bitmap = active_bitmap_block(&base);
    let targets = [0usize, 1, index, bitmap];
    let iterations = if cfg!(miri) { 4 } else { 600 };
    let mut rng = SplitMix64::new(0x5EED);
    for it in 0..iterations {
        let mut img = base.clone();
        let target = targets[rng.below(targets.len() as u64) as usize];
        let flips = 1 + rng.below(8);
        for _ in 0..flips {
            let off = rng.below(BLOCK_SIZE as u64) as usize;
            block_mut(&mut img, target)[off] ^= 1 << rng.below(8);
        }
        // Half the time play a forger who re-seals the edited block. Without a
        // signature (FS-5) such a forger can make *any* consistent state
        // mount, so only the raw mutations are held to "no new generation".
        let resealed = rng.coin();
        if resealed {
            seal_metadata(block_mut(&mut img, target));
        }
        if let Outcome::Mounted { gen, .. } = mount_image(&img) {
            assert!(
                resealed || gen == 2 || gen == 3,
                "iteration {it}: gen {gen}"
            );
        }
    }
}

// ── determinism (principle 4) ──────────────────────────────────────────────

#[test]
#[cfg_attr(miri, ignore)]
fn replaying_the_same_operations_yields_the_same_superblock_hashes_and_image() {
    let run = || {
        let mut d = formatted(DEV_WINDOW);
        let mut ws = Workspace::new();
        let mut v = mount(&mut d).unwrap();
        let mut hashes = Vec::new();
        let mut held = Vec::new();
        for round in 0..5u64 {
            for _ in 0..(3 + round) {
                held.push(v.alloc(AllocClass::Normal, None).unwrap());
            }
            held.push(v.alloc_run(8, AllocClass::Normal, None).unwrap().start());
            if round % 2 == 1 {
                let b = held.remove(0);
                v.free(b).unwrap();
            }
            hashes.push(v.commit(&mut d, &mut ws, round).unwrap().sb_hash);
        }
        (hashes, d.into_image())
    };
    let (h1, i1) = run();
    let (h2, i2) = run();
    assert_eq!(h1, h2);
    assert!(i1 == i2, "same operations, same image");
}

// ── bounded memory (principle 7, A23) ──────────────────────────────────────

/// The whole FS footprint — cache slab, allocator tables, commit plan, the
/// workspace — is fixed at mount and independent of the device size: a 1 GiB
/// device costs exactly what the 16 MiB window costs, and nothing grows
/// across transactions. (A process-wide counting allocator needs an
/// `unsafe impl GlobalAlloc`, which this crate forbids; every FS structure is
/// a fixed-size `Box<[T]>` built once, so its size is its heap use.)
#[test]
#[cfg_attr(miri, ignore)]
fn heap_footprint_is_fixed_capped_and_independent_of_device_size() {
    const CAP: usize = 300 * 1024;
    let footprint = |blocks: u64| {
        let mut d = MemDevice::untracked(blocks);
        let mut ws = Workspace::new();
        format(&mut d, &mut ws, &params()).unwrap();
        let mut v = Volume::mount(&mut d, &mut ws).unwrap();
        let at_mount = v.heap_bytes() + ws.heap_bytes();
        for round in 0..20u64 {
            let b: Vec<BlockNo> = (0..10)
                .map(|_| v.alloc(AllocClass::Normal, None).unwrap())
                .collect();
            v.commit(&mut d, &mut ws, round).unwrap();
            for x in b {
                v.free(x).unwrap();
            }
            v.commit(&mut d, &mut ws, round).unwrap();
        }
        assert_eq!(v.heap_bytes() + ws.heap_bytes(), at_mount);
        (at_mount, v.info().groups)
    };
    let (small, g_small) = footprint(DEV_WINDOW);
    let (large, g_large) = footprint(1 << 18); // 1 GiB
    assert_eq!((g_small, g_large), (1, 9));
    assert_eq!(small, large, "no allocation proportional to image size");
    assert!(small <= CAP, "footprint {small} > cap {CAP}");
}

#[test]
fn magic_constant_is_the_v2_one() {
    assert_eq!(&MAGIC, b"SNTLFS02");
    assert!(SlotError::BadHash.carries_magic());
    assert!(!SlotError::Foreign.carries_magic());
}
