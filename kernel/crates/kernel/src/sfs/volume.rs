//! A SentinelFS volume over any [`BlockDevice`]: format, mount, and the §8
//! commit protocol. No locks, no statics, no threads — the kernel's
//! `sfs-commit` task ([`super::service`]) and the host tests drive the same
//! code; only who holds which lock around which call differs.
//!
//! # The commit, in three phases
//!
//! 1. [`Volume::begin_commit`] — in memory, bounded: seal the allocator (copy
//!    and hash every changed bitmap and the index), stage the next superblock
//!    (`gen + 1`, into the inactive slot). The kernel runs this under the
//!    `Sfs` lock.
//! 2. [`write_commit`] — the device I/O, **with no lock held**: every dirty
//!    block → `flush` → the superblock → `flush`. The bytes are fetched
//!    through a callback, so the kernel can copy one block at a time under the
//!    lock while the host tests read straight from the volume.
//! 3. [`Volume::finish_commit`] — in memory: on success the dirty set becomes
//!    clean and verified, freed blocks become allocatable, the volume moves to
//!    the new slot. On failure the volume becomes read-only (the previous
//!    superblock is still intact on disk; mount it again).
//!
//! Between 1 and 3 the volume refuses changes, so a commit only ever publishes
//! a transaction exactly as it was sealed — commits happen at quiescent
//! points (§8).
//!
//! # Format
//!
//! [`format`] zeroes both superblock slots first, then writes every group's
//! bitmap and the index, then the generation-1 superblock into slot 1, with a
//! flush after each step. A crash anywhere leaves the device either
//! `Unformatted` (no magic yet, so the next boot formats again) or mounted at
//! generation 1 — never `Corrupt` (the superblock lives in its first sector;
//! see [`superblock`]).

use super::key::Key;
use super::superblock::{self, Candidate, Selection, SlotError, Superblock};
use super::tree::{Tree, TreeError, TreeWs};
use crate::blk::allocator::{
    self as alloc_mod, AllocClass, AllocError, Allocator, DirtyRef, RESERVE,
};
use crate::blk::cache::{Cache, CacheError, SlotId, DIRTY_MAX};
use crate::blk::geometry::{Extent, Geometry, GeometryError, MAX_GROUPS};
use crate::blk::layout::{Hash, HashRule, Pointer, TreeId, Uuid, HEADER_LEN, UUID_LEN};
use crate::blk::{bitmap, zeroed_blocks, BlkError, Block, BlockDevice, BlockNo, Blocks};
use alloc::boxed::Box;
use alloc::vec;

/// First object id a fresh filesystem hands out.
pub const FIRST_OBJ: u64 = 1;
/// How many misses one commit's seal may report before the volume gives up
/// and goes read-only ([`Volume::begin_commit`] counts them). Today a seal can
/// only miss group 0's committed bitmap (every other group it touches was
/// copied when the transaction changed it); the bound is generous, and it is
/// what guarantees a caller's resolve-and-retry loop ends.
pub const MAX_SEAL_RETRIES: usize = MAX_GROUPS as usize + 2;

/// Caller-owned I/O scratch for format / mount / commit: two staging blocks
/// and format's group-pointer table, allocated once. Apart from `mount`,
/// which builds the volume's fixed structures, nothing in this module
/// allocates.
pub struct Workspace {
    staging: Blocks,
    ptrs: Box<[Pointer]>,
}

impl Default for Workspace {
    fn default() -> Self {
        Self::new()
    }
}

impl Workspace {
    /// A workspace (8 KiB of staging + 4 KiB of pointers).
    #[must_use]
    pub fn new() -> Workspace {
        Workspace {
            staging: zeroed_blocks(2),
            ptrs: vec![Pointer::NULL; MAX_GROUPS as usize].into_boxed_slice(),
        }
    }

    /// Heap bytes held.
    #[must_use]
    pub fn heap_bytes(&self) -> usize {
        core::mem::size_of_val(&*self.staging) + core::mem::size_of_val(&*self.ptrs)
    }

    /// The first staging block, for callers doing their own device I/O.
    pub fn block(&mut self) -> &mut Block {
        &mut self.staging[0]
    }

    /// The first staging block as a one-block transfer buffer.
    fn one(&mut self) -> &mut [Block] {
        &mut self.staging[..1]
    }
}

/// Identity of a filesystem being formatted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FormatParams {
    /// Stamped into every metadata header.
    pub uuid: Uuid,
    /// Key for the dirent name hash (not secret).
    pub dirent_key: [u8; 16],
    /// `committed_at` of generation 1.
    pub now: u64,
}

impl FormatParams {
    /// Derive the uuid and dirent key from `seed` (deterministic: the same
    /// seed formats the same image, principle 4). The kernel seeds from its
    /// clocks; tests seed from a constant.
    #[must_use]
    pub fn from_seed(seed: &[u8], now: u64) -> FormatParams {
        let derive = |label: &[u8]| {
            let mut h = crate::hash::Sha256::new();
            h.update(b"sentinelfs:v2:");
            h.update(label);
            h.update(&(seed.len() as u64).to_le_bytes());
            h.update(seed);
            h.finalize()
        };
        let mut uuid = [0u8; UUID_LEN];
        uuid.copy_from_slice(&derive(b"uuid")[..UUID_LEN]);
        let mut dirent_key = [0u8; 16];
        dirent_key.copy_from_slice(&derive(b"dirent-key")[..16]);
        FormatParams {
            uuid,
            dirent_key,
            now,
        }
    }
}

/// Why `format` failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FormatError {
    /// The device is too small or too large for the v2 format.
    Geometry(GeometryError),
    /// A group could not hold its own metadata (internal).
    Layout(AllocError),
    /// The device failed.
    Io(BlkError),
}

impl FormatError {
    /// Fixed label for `fmt`-free console output.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            FormatError::Geometry(e) => e.label(),
            FormatError::Layout(e) => e.label(),
            FormatError::Io(e) => e.label(),
        }
    }
}

impl From<BlkError> for FormatError {
    fn from(e: BlkError) -> Self {
        FormatError::Io(e)
    }
}

/// What `format` wrote.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FormatInfo {
    /// Hash of the generation-1 superblock.
    pub sb_hash: Hash,
    /// Allocation groups.
    pub groups: u32,
    /// Total blocks.
    pub total: u64,
    /// Free blocks.
    pub free: u64,
}

/// Format `dev` (module docs for the crash argument).
///
/// # Errors
///
/// [`FormatError::Geometry`] for an unusable size; [`FormatError::Io`] if the
/// device fails (the device is then `Unformatted` or partly written — never
/// `Corrupt`).
pub fn format<D: BlockDevice>(
    dev: &mut D,
    ws: &mut Workspace,
    p: &FormatParams,
) -> Result<FormatInfo, FormatError> {
    let geo = Geometry::new(dev.blocks()).map_err(FormatError::Geometry)?;
    // 1. Destroy any previous superblocks: nothing below can then leave a
    //    slot that carries the magic without a valid hash.
    for b in ws.staging.iter_mut() {
        b.fill(0);
    }
    dev.write_blocks(BlockNo(0), &ws.staging)?;
    dev.flush()?;
    // 2. Every group's bitmap, then the index naming them.
    let mut index_at = None;
    let mut free = 0u64;
    for g in 0..geo.groups() {
        let block = &mut ws.staging[0];
        let (own, index) = alloc_mod::format_bitmap(block, &geo, g).map_err(FormatError::Layout)?;
        let len = geo.group_len(g).unwrap_or(0);
        free += u64::from(bitmap::count_zeros(&block[HEADER_LEN..], len));
        let hash = alloc_mod::seal_bitmap(block, &p.uuid, 1);
        if let Some(slot) = ws.ptrs.get_mut(g as usize) {
            *slot = Pointer {
                block: own,
                hash,
                gen: 1,
            };
        }
        index_at = index_at.or(index);
        dev.write_blocks(own, &ws.staging[..1])?;
    }
    let index_at = index_at.ok_or(FormatError::Layout(AllocError::Corrupt))?;
    let ptrs = &ws.ptrs;
    let index_hash = alloc_mod::encode_index(&mut ws.staging[0], &p.uuid, 1, geo.groups(), |g| {
        ptrs.get(g as usize).copied().unwrap_or(Pointer::NULL)
    });
    dev.write_blocks(index_at, &ws.staging[..1])?;
    dev.flush()?;
    // 3. Generation 1 into slot 1 (`gen % 2`).
    let sb = Superblock {
        total_blocks: u64::from(geo.total()),
        gen: 1,
        uuid: p.uuid,
        root: Pointer::NULL,
        blobs: Pointer::NULL,
        roots: Pointer::NULL,
        free: Pointer {
            block: index_at,
            hash: index_hash,
            gen: 1,
        },
        next_obj: FIRST_OBJ,
        committed_at: p.now,
        dirent_key: p.dirent_key,
        kdf: [0; superblock::KDF_LEN],
        reserve_per_group: u64::from(RESERVE),
    };
    let sb_hash = superblock::encode(&sb, &mut ws.staging[0]);
    dev.write_blocks(BlockNo(1), &ws.staging[..1])?;
    dev.flush()?;
    Ok(FormatInfo {
        sb_hash,
        groups: geo.groups(),
        total: u64::from(geo.total()),
        free,
    })
}

/// Which part of a filesystem failed verification at mount.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Damage {
    /// Neither slot is valid, and at least one carries the magic.
    Slots {
        /// Why slot 0 is invalid.
        slot0: SlotError,
        /// Why slot 1 is invalid.
        slot1: SlotError,
    },
    /// The superblock describes an impossible geometry.
    Geometry,
    /// The group index failed its hash or a format rule.
    Index,
    /// This group's bitmap failed its hash or a format rule.
    Bitmap(u32),
}

impl Damage {
    /// Fixed label for `fmt`-free console output.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Damage::Slots { .. } => "superblocks",
            Damage::Geometry => "geometry",
            Damage::Index => "group-index",
            Damage::Bitmap(_) => "bitmap",
        }
    }
}

/// Why mount failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MountError {
    /// Both slots are blank or foreign: nothing was here. Format is allowed.
    Unformatted,
    /// A filesystem was here and is damaged: never format automatically; the
    /// facade mounts read-only-empty and reports (A9).
    Corrupt(Damage),
    /// A valid superblock describes more than [`MAX_GROUPS`] groups.
    TooLarge,
    /// The device failed.
    Io(BlkError),
}

impl MountError {
    /// Fixed label for `fmt`-free console output.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            MountError::Unformatted => "unformatted",
            MountError::Corrupt(_) => "corrupt",
            MountError::TooLarge => "too-large",
            MountError::Io(e) => e.label(),
        }
    }
}

/// A mounted volume's identity and space, for the boot line and the shell.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MountInfo {
    /// Committed generation.
    pub gen: u64,
    /// Slot holding it.
    pub slot: u8,
    /// Its superblock hash.
    pub sb_hash: Hash,
    /// Allocation groups.
    pub groups: u32,
    /// Total blocks.
    pub total: u64,
    /// Free blocks by the committed bitmaps.
    pub free: u64,
    /// Metadata reserve per group.
    pub reserve: u32,
}

/// Why a commit did not happen (or did not complete).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CommitError {
    /// A commit is already in progress.
    Busy,
    /// The volume is read-only after an earlier failure.
    ReadOnly,
    /// Read this committed block into the cache (verified), then retry.
    Miss(Pointer),
    /// The allocator could not seal (the volume is now read-only).
    Alloc(AllocError),
    /// The commit's I/O failed (the volume is now read-only; the previous
    /// generation is intact on disk).
    Io(BlkError),
    /// A block read to resolve a miss failed its hash.
    Corrupt,
    /// The generation counter is exhausted.
    GenExhausted,
    /// An internal invariant broke (the volume is now read-only).
    Internal,
}

impl CommitError {
    /// Fixed label for `fmt`-free console output.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            CommitError::Busy => "busy",
            CommitError::ReadOnly => "read-only",
            CommitError::Miss(_) => "miss",
            CommitError::Alloc(e) => e.label(),
            CommitError::Io(e) => e.label(),
            CommitError::Corrupt => "corrupt",
            CommitError::GenExhausted => "gen-exhausted",
            CommitError::Internal => "internal",
        }
    }
}

/// A staged commit: what [`write_commit`] must write.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CommitPlan {
    /// Dirty blocks to write before the first flush.
    pub dirty: usize,
    /// Slot the new superblock goes to.
    pub slot: u8,
    /// The new generation.
    pub gen: u64,
}

/// What a completed commit did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CommitInfo {
    /// The new committed generation.
    pub gen: u64,
    /// The slot it landed in.
    pub slot: u8,
    /// Its superblock hash.
    pub sb_hash: Hash,
    /// Blocks written (dirty set + the superblock).
    pub blocks: u64,
    /// Flushes issued.
    pub flushes: u64,
}

/// One block of a staged commit, as [`write_commit`] asks for it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Stage {
    /// The `i`-th dirty block.
    Dirty(usize),
    /// The staged superblock.
    Superblock,
}

/// Phase 2 of a commit (§8): every dirty block → flush → the superblock into
/// the inactive slot → flush. `fetch` copies the requested block into
/// `staging` and returns where it goes (`None` aborts the commit). Holds no
/// lock; does no allocation.
///
/// # Errors
///
/// The device's error, or [`BlkError::BadBuffer`] if `fetch` could not supply
/// a block. Either way the caller passes the result to
/// [`Volume::finish_commit`].
pub fn write_commit<D: BlockDevice>(
    dev: &mut D,
    staging: &mut Block,
    plan: &CommitPlan,
    mut fetch: impl FnMut(Stage, &mut Block) -> Option<BlockNo>,
) -> Result<(), BlkError> {
    for i in 0..plan.dirty {
        let at = fetch(Stage::Dirty(i), staging).ok_or(BlkError::BadBuffer)?;
        dev.write_blocks(at, core::slice::from_ref(&*staging))?;
    }
    dev.flush()?;
    let at = fetch(Stage::Superblock, staging).ok_or(BlkError::BadBuffer)?;
    dev.write_blocks(at, core::slice::from_ref(&*staging))?;
    dev.flush()
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    Ready,
    Committing,
    ReadOnly,
}

/// What a commit in flight changes in the superblock (the rest is the
/// committed one); its encoding is staged in `sb_buf`.
#[derive(Clone, Copy, Debug)]
struct Staged {
    gen: u64,
    free: Pointer,
    root: Pointer,
    committed_at: u64,
    hash: Hash,
    slot: u8,
}

/// A mounted SentinelFS volume.
pub struct Volume {
    sb: Superblock,
    sb_hash: Hash,
    slot: u8,
    alloc: Allocator,
    cache: Cache,
    state: State,
    plan: Box<[DirtyRef]>,
    nplan: usize,
    next: Option<Staged>,
    sb_buf: Blocks,
    /// Misses the current seal has reported (reset once a seal succeeds).
    seal_misses: usize,
    /// The metadata tree (FS-1b) and its fixed scratch.
    tree: Tree,
    tws: Box<TreeWs>,
}

/// Read `p` into the cache through `staging`, verifying its metadata hash
/// before it enters (a resident verified copy is reused).
fn read_verified<D: BlockDevice>(
    dev: &mut D,
    cache: &mut Cache,
    staging: &mut [Block],
    p: &Pointer,
) -> Result<SlotId, ReadError> {
    if let Some(id) = cache.lookup(p.block, &p.hash) {
        return Ok(id);
    }
    dev.read_blocks(p.block, staging).map_err(ReadError::Io)?;
    let src = staging.first().ok_or(ReadError::Io(BlkError::BadBuffer))?;
    cache
        .insert_verified(p.block, HashRule::Metadata, &p.hash, src)
        .map_err(|_| ReadError::Corrupt)
}

enum ReadError {
    Io(BlkError),
    Corrupt,
}

impl ReadError {
    fn at(self, damage: Damage) -> MountError {
        match self {
            ReadError::Io(e) => MountError::Io(e),
            ReadError::Corrupt => MountError::Corrupt(damage),
        }
    }
}

/// Mount step 1: read both slots and apply the §7.1 rule.
fn choose_superblock<D: BlockDevice>(
    dev: &mut D,
    ws: &mut Workspace,
) -> Result<(u8, Superblock, Hash), MountError> {
    let device_blocks = dev.blocks();
    dev.read_blocks(BlockNo(0), &mut ws.staging[..2])
        .map_err(MountError::Io)?;
    let d0 = superblock::decode(&ws.staging[0], device_blocks);
    let d1 = superblock::decode(&ws.staging[1], device_blocks);
    let (slot, chosen) = match superblock::select([Candidate::of(&d0), Candidate::of(&d1)]) {
        Selection::Use { slot: 0, .. } => (0u8, d0),
        Selection::Use { .. } => (1u8, d1),
        Selection::Corrupt => {
            return Err(MountError::Corrupt(Damage::Slots {
                slot0: d0.err().unwrap_or(SlotError::Blank),
                slot1: d1.err().unwrap_or(SlotError::Blank),
            }))
        }
        Selection::Unformatted => return Err(MountError::Unformatted),
    };
    // `select` only names a slot whose decode succeeded.
    let (sb, hash) = chosen.map_err(|_| MountError::Corrupt(Damage::Geometry))?;
    Ok((slot, sb, hash))
}

/// Mount step 2: read and verify the group index and every group's bitmap
/// into `cache`, and build the allocator from them.
fn load_allocator<D: BlockDevice>(
    dev: &mut D,
    ws: &mut Workspace,
    cache: &mut Cache,
    sb: &Superblock,
    geo: Geometry,
    reserve: u32,
) -> Result<Allocator, MountError> {
    let iid = read_verified(dev, cache, ws.one(), &sb.free).map_err(|e| e.at(Damage::Index))?;
    let iblock = cache.read(iid).ok_or(MountError::Corrupt(Damage::Index))?;
    let mut alloc = Allocator::from_index(geo, sb.uuid, reserve, sb.free, iblock, sb.gen)
        .map_err(|_| MountError::Corrupt(Damage::Index))?;
    for g in 0..geo.groups() {
        let bad = MountError::Corrupt(Damage::Bitmap(g));
        let p = alloc.group_pointer(g).ok_or(bad)?;
        let id = read_verified(dev, cache, ws.one(), &p).map_err(|e| e.at(Damage::Bitmap(g)))?;
        let block = cache.read(id).ok_or(bad)?;
        alloc.load_group(g, block).map_err(|_| bad)?;
    }
    Ok(alloc)
}

impl Volume {
    /// Mount `dev`: read both slots, take the valid one with the higher
    /// generation (§7.1), then read and verify the group index and every
    /// group's bitmap (checking each against its pointer's hash *before* it
    /// enters the cache, and against the format rules after).
    ///
    /// The volume lives on the heap: it is moved between the task and the
    /// `Sfs` lock as a pointer, never as a kilobyte-sized value (kernel task
    /// stacks are small and debug-build frames are not).
    ///
    /// # Errors
    ///
    /// [`MountError::Unformatted`] / [`MountError::Corrupt`] per A9;
    /// [`MountError::TooLarge`] beyond [`MAX_GROUPS`]; [`MountError::Io`].
    pub fn mount<D: BlockDevice>(
        dev: &mut D,
        ws: &mut Workspace,
    ) -> Result<Box<Volume>, MountError> {
        let (slot, sb, sb_hash) = choose_superblock(dev, ws)?;
        let geo = Geometry::new(sb.total_blocks).map_err(|e| match e {
            GeometryError::TooLarge => MountError::TooLarge,
            GeometryError::TooSmall => MountError::Corrupt(Damage::Geometry),
        })?;
        let reserve = u32::try_from(sb.reserve_per_group)
            .map_err(|_| MountError::Corrupt(Damage::Geometry))?;
        let mut cache = Cache::new();
        let alloc = load_allocator(dev, ws, &mut cache, &sb, geo, reserve)?;
        Ok(Box::new(Volume {
            sb,
            sb_hash,
            slot,
            alloc,
            cache,
            state: State::Ready,
            plan: vec![DirtyRef::NONE; DIRTY_MAX].into_boxed_slice(),
            nplan: 0,
            next: None,
            sb_buf: zeroed_blocks(1),
            seal_misses: 0,
            tree: Tree::new(TreeId::Root, sb.uuid, sb.root),
            tws: Box::new(TreeWs::new()),
        }))
    }

    /// Identity and space of the committed state.
    #[must_use]
    pub fn info(&self) -> MountInfo {
        MountInfo {
            gen: self.sb.gen,
            slot: self.slot,
            sb_hash: self.sb_hash,
            groups: self.alloc.geometry().groups(),
            total: self.sb.total_blocks,
            free: self.alloc.committed_free(),
            reserve: self.alloc.reserve(),
        }
    }

    /// The committed superblock.
    #[must_use]
    pub const fn superblock(&self) -> &Superblock {
        &self.sb
    }

    /// Whether the transaction has anything to commit.
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        self.alloc.is_dirty() || self.cache.dirty_count() > 0
    }

    /// Whether the volume refuses changes after a failed commit or a failed
    /// miss resolution ([`Volume::resolve_miss`], [`Volume::load`]).
    #[must_use]
    pub fn is_read_only(&self) -> bool {
        self.state == State::ReadOnly
    }

    /// Heap bytes held (fixed for the volume's lifetime: no structure grows).
    #[must_use]
    pub fn heap_bytes(&self) -> usize {
        self.cache.heap_bytes()
            + self.alloc.heap_bytes()
            + core::mem::size_of_val(&*self.plan)
            + core::mem::size_of_val(&*self.sb_buf)
            + self.tree.heap_bytes()
            + self.tws.heap_bytes()
    }

    /// The allocator (read-only view).
    #[must_use]
    pub const fn allocator(&self) -> &Allocator {
        &self.alloc
    }

    fn writable(&self) -> Result<(), AllocError> {
        match self.state {
            State::Ready => Ok(()),
            State::Committing | State::ReadOnly => Err(AllocError::Sealed),
        }
    }

    /// Allocate one block in this transaction.
    ///
    /// # Errors
    ///
    /// [`AllocError::Sealed`] while committing or read-only; otherwise as
    /// [`Allocator::alloc`].
    pub fn alloc(&mut self, class: AllocClass, hint: Option<u32>) -> Result<BlockNo, AllocError> {
        self.writable()?;
        self.alloc.alloc(&mut self.cache, class, hint)
    }

    /// Allocate a run of blocks in this transaction.
    ///
    /// # Errors
    ///
    /// As [`alloc`](Self::alloc).
    pub fn alloc_run(
        &mut self,
        len: u32,
        class: AllocClass,
        hint: Option<u32>,
    ) -> Result<Extent, AllocError> {
        self.writable()?;
        self.alloc.alloc_run(&mut self.cache, len, class, hint)
    }

    /// Free a block in this transaction (allocatable after the commit).
    ///
    /// # Errors
    ///
    /// As [`alloc`](Self::alloc), and [`Allocator::free`].
    pub fn free(&mut self, b: BlockNo) -> Result<(), AllocError> {
        self.writable()?;
        self.alloc.free(&mut self.cache, b)
    }

    /// Drop the clean cached copy of `block` (memory pressure; tests). Dirty
    /// entries are never dropped. Returns whether something was dropped.
    pub fn drop_clean(&mut self, block: BlockNo) -> bool {
        self.cache.evict(block)
    }

    /// Resolve a miss ([`AllocError::Miss`] / [`CommitError::Miss`]) for `p`
    /// with `read`, the outcome of reading block `p.block` from the device
    /// (the caller does the I/O, with no lock held): the block enters the
    /// cache only if it hashes to `p`.
    ///
    /// **A failed read, or a block that no longer matches its hash, leaves the
    /// volume read-only.** Committed metadata that cannot be read back intact
    /// means this transaction can never be sealed; staying writable would
    /// only re-read the same bad block every commit interval. The committed
    /// generation on disk is untouched either way.
    ///
    /// # Errors
    ///
    /// [`CommitError::Io`] (the read failed), [`CommitError::Corrupt`] (the
    /// block failed its hash) or [`CommitError::Internal`] (the cache refused
    /// a verified block) — the volume is read-only after each.
    pub fn resolve_miss(
        &mut self,
        p: &Pointer,
        read: Result<&Block, BlkError>,
    ) -> Result<(), CommitError> {
        let block = read.map_err(|e| self.fail(CommitError::Io(e)))?;
        match self
            .cache
            .insert_verified(p.block, HashRule::Metadata, &p.hash, block)
        {
            Ok(_) => Ok(()),
            Err(CacheError::Corrupt) => Err(self.fail(CommitError::Corrupt)),
            Err(_) => Err(self.fail(CommitError::Internal)),
        }
    }

    /// Read `p` from `dev` and insert it — the synchronous form of
    /// [`Volume::resolve_miss`], with the same rule: on failure the volume
    /// is read-only. A resident verified copy is reused without I/O.
    ///
    /// # Errors
    ///
    /// [`CommitError::Io`] / [`CommitError::Corrupt`], volume read-only.
    pub fn load<D: BlockDevice>(
        &mut self,
        dev: &mut D,
        ws: &mut Workspace,
        p: &Pointer,
    ) -> Result<(), CommitError> {
        match read_verified(dev, &mut self.cache, ws.one(), p) {
            Ok(_) => Ok(()),
            Err(ReadError::Io(e)) => Err(self.fail(CommitError::Io(e))),
            Err(ReadError::Corrupt) => Err(self.fail(CommitError::Corrupt)),
        }
    }

    fn tree_writable(&self) -> Result<(), TreeError> {
        match self.state {
            State::Ready => Ok(()),
            State::Committing | State::ReadOnly => Err(TreeError::Sealed),
        }
    }

    /// A tree error that means the metadata cannot be trusted (or an
    /// operation broke half-way) leaves the volume read-only (§12).
    fn tree_outcome<T>(&mut self, r: Result<T, TreeError>) -> Result<T, TreeError> {
        if matches!(r, Err(TreeError::Corrupt | TreeError::Internal)) {
            self.state = State::ReadOnly;
        }
        r
    }

    /// Insert `data` at `key` in the metadata tree, or replace the item there
    /// (spec §7.2; bounded, in memory: the kernel runs it under the `Sfs`
    /// lock). All-or-nothing: every refusal but `Corrupt`/`Internal` changes
    /// nothing — resolve a [`TreeError::Miss`] with
    /// [`resolve_miss`](Self::resolve_miss), answer
    /// [`TreeError::NeedCommit`] with a commit, and retry.
    ///
    /// # Errors
    ///
    /// [`TreeError`]; `Corrupt` / `Internal` leave the volume read-only.
    pub fn put(&mut self, key: Key, data: &[u8]) -> Result<(), TreeError> {
        self.tree_writable()?;
        let r = self
            .tree
            .put(&mut self.cache, &mut self.alloc, &mut self.tws, key, data);
        self.tree_outcome(r)
    }

    /// Remove the item at `key`; returns whether it was there. As
    /// [`put`](Self::put), and may use the metadata reserve (§5.8).
    ///
    /// # Errors
    ///
    /// As [`put`](Self::put).
    pub fn remove(&mut self, key: &Key) -> Result<bool, TreeError> {
        self.tree_writable()?;
        let r = self
            .tree
            .remove(&mut self.cache, &mut self.alloc, &mut self.tws, key);
        self.tree_outcome(r)
    }

    /// Copy the item at `key` into `out` (which must hold it; [`super::tree::ITEM_MAX`]
    /// always does); returns its length or `None`. Reads see this
    /// transaction's changes first.
    ///
    /// # Errors
    ///
    /// [`TreeError::Miss`] (resolve, retry); `Corrupt` leaves the volume
    /// read-only.
    pub fn get(&mut self, key: &Key, out: &mut [u8]) -> Result<Option<usize>, TreeError> {
        let r = self.tree.get(&mut self.cache, &mut self.tws, key, out);
        self.tree_outcome(r)
    }

    /// The lowest key above `after` (above nothing for `None`); `None` past
    /// the last. Iterate by feeding each result back.
    ///
    /// # Errors
    ///
    /// As [`get`](Self::get).
    pub fn next_key(&mut self, after: Option<&Key>) -> Result<Option<Key>, TreeError> {
        let r = self.tree.next_key(&mut self.cache, &mut self.tws, after);
        self.tree_outcome(r)
    }

    /// Dirty cache entries in the transaction (tree nodes plus allocator
    /// metadata): the §8 footprint the host tests bound per operation.
    #[must_use]
    pub fn dirty_blocks(&self) -> usize {
        self.cache.dirty_count()
    }

    /// The metadata tree's working root.
    #[must_use]
    pub const fn tree_root(&self) -> Pointer {
        self.tree.root()
    }

    fn fail(&mut self, e: CommitError) -> CommitError {
        self.state = State::ReadOnly;
        e
    }

    /// Encode the next superblock (the committed one with `gen`, `free`,
    /// `root` and `committed_at` replaced) into `sb_buf`; returns its hash.
    fn stage_superblock(&mut self, gen: u64, free: Pointer, root: Pointer, now: u64) -> Hash {
        let mut sb = self.sb;
        sb.gen = gen;
        sb.free = free;
        sb.root = root;
        sb.committed_at = now;
        match self.sb_buf.first_mut() {
            Some(buf) => superblock::encode(&sb, buf),
            None => [0; 32],
        }
    }

    /// Phase 1: seal the transaction and stage the next superblock (`gen + 1`
    /// into the inactive slot, `committed_at = now`). In memory and bounded;
    /// the kernel holds the `Sfs` lock around it. A [`CommitError::Miss`]
    /// changes nothing but a count: read the block, hand it to
    /// [`resolve_miss`](Self::resolve_miss) and call again. Past
    /// [`MAX_SEAL_RETRIES`] misses in one seal the volume goes read-only
    /// ([`CommitError::Internal`]), so that loop always ends.
    ///
    /// # Errors
    ///
    /// [`CommitError::Busy`], [`CommitError::ReadOnly`],
    /// [`CommitError::Miss`], [`CommitError::GenExhausted`]; anything else
    /// leaves the volume read-only.
    pub fn begin_commit(&mut self, now: u64) -> Result<CommitPlan, CommitError> {
        match self.state {
            State::Ready => {}
            State::Committing => return Err(CommitError::Busy),
            State::ReadOnly => return Err(CommitError::ReadOnly),
        }
        let gen = self
            .sb
            .gen
            .checked_add(1)
            .ok_or(CommitError::GenExhausted)?;
        let index = match self.alloc.seal(&mut self.cache, gen) {
            Ok(i) => i,
            Err(AllocError::Miss(_)) if self.seal_misses >= MAX_SEAL_RETRIES => {
                return Err(self.fail(CommitError::Internal))
            }
            Err(AllocError::Miss(p)) => {
                self.seal_misses += 1;
                return Err(CommitError::Miss(p));
            }
            Err(e) => return Err(self.fail(CommitError::Alloc(e))),
        };
        self.seal_misses = 0;
        // The tree's seal cannot miss: every node it hashes is dirty.
        let Ok(root) = self.tree.seal(&mut self.cache, gen) else {
            return Err(self.fail(CommitError::Internal));
        };
        let n = match self.alloc.sealed_entries(&mut self.plan) {
            Ok(n) => n,
            Err(e) => return Err(self.fail(CommitError::Alloc(e))),
        };
        let m = match self
            .plan
            .get_mut(n..)
            .map(|rest| self.tree.sealed_entries(rest))
        {
            Some(Ok(m)) => m,
            _ => return Err(self.fail(CommitError::Internal)),
        };
        // Every dirty block must have been sealed by its owner.
        if n + m != self.cache.dirty_count() {
            return Err(self.fail(CommitError::Internal));
        }
        self.nplan = n + m;
        let free = index.unwrap_or(self.sb.free);
        let hash = self.stage_superblock(gen, free, root, now);
        let slot = 1 - self.slot;
        self.next = Some(Staged {
            gen,
            free,
            root,
            committed_at: now,
            hash,
            slot,
        });
        self.state = State::Committing;
        Ok(CommitPlan {
            dirty: self.nplan,
            slot,
            gen,
        })
    }

    /// Copy one block of the staged commit into `out`; returns where it goes.
    /// `None` when nothing is staged or `stage` is out of range.
    pub fn fetch(&self, stage: Stage, out: &mut Block) -> Option<BlockNo> {
        if self.state != State::Committing {
            return None;
        }
        match stage {
            Stage::Dirty(i) => {
                if i >= self.nplan {
                    return None;
                }
                let r = self.plan.get(i)?;
                out.copy_from_slice(self.cache.read(r.slot)?);
                Some(r.block)
            }
            Stage::Superblock => {
                let staged = self.next?;
                out.copy_from_slice(self.sb_buf.first()?);
                Some(BlockNo(u32::from(staged.slot)))
            }
        }
    }

    /// Phase 3: publish the outcome of [`write_commit`].
    ///
    /// # Errors
    ///
    /// [`CommitError::Io`] when `io` failed (the volume is now read-only;
    /// the previous generation is intact on disk); [`CommitError::Internal`]
    /// if no commit was in flight.
    pub fn finish_commit(&mut self, io: Result<(), BlkError>) -> Result<CommitInfo, CommitError> {
        if self.state != State::Committing {
            return Err(CommitError::Internal);
        }
        if let Err(e) = io {
            return Err(self.fail(CommitError::Io(e)));
        }
        let Some(staged) = self.next.take() else {
            return Err(self.fail(CommitError::Internal));
        };
        for r in self.plan.iter().take(self.nplan) {
            if self.cache.mark_clean(r.slot, r.hash).is_err() {
                return Err(self.fail(CommitError::Internal));
            }
        }
        self.alloc.commit_done();
        self.tree.commit_done();
        let blocks = self.nplan as u64 + 1;
        self.nplan = 0;
        self.sb.gen = staged.gen;
        self.sb.free = staged.free;
        self.sb.root = staged.root;
        self.sb.committed_at = staged.committed_at;
        self.sb_hash = staged.hash;
        self.slot = staged.slot;
        self.state = State::Ready;
        Ok(CommitInfo {
            gen: staged.gen,
            slot: staged.slot,
            sb_hash: staged.hash,
            blocks,
            flushes: 2,
        })
    }

    /// The whole commit, synchronously (host tests, and anything that owns the
    /// device outright): phase 1 — resolving misses by reading — then the I/O,
    /// then phase 3.
    ///
    /// # Errors
    ///
    /// As the three phases; a miss that cannot be resolved leaves the volume
    /// read-only ([`Volume::load`]).
    pub fn commit<D: BlockDevice>(
        &mut self,
        dev: &mut D,
        ws: &mut Workspace,
        now: u64,
    ) -> Result<CommitInfo, CommitError> {
        // Ends: `begin_commit` stops reporting misses after MAX_SEAL_RETRIES.
        let plan = loop {
            match self.begin_commit(now) {
                Ok(plan) => break plan,
                Err(CommitError::Miss(p)) => self.load(dev, ws, &p)?,
                Err(e) => return Err(e),
            }
        };
        let io = write_commit(dev, &mut ws.staging[0], &plan, |stage, out| {
            self.fetch(stage, out)
        });
        self.finish_commit(io)
    }
}
