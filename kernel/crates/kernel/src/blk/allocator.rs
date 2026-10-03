//! Free-space allocation: per-group bitmaps under one group-index block
//! (spec §7.4), copy-on-write like every other metadata block.
//!
//! # On disk
//!
//! - **Bitmap block** (kind 3, tree `Free`): header + [`GROUP_BLOCKS`] bits,
//!   one per block of the group, set = in use. Bits past the end of a partial
//!   last group are **set** (padding is never free). A group's bitmap block
//!   lives **inside its own group**; group 0's bitmap also marks the two
//!   superblock slots and the index block as used.
//! - **Group-index block** (kind 5, tree `Free`): header + one 48-byte
//!   [`Pointer`] per group (`groups` of them, at most [`MAX_GROUPS`]), the rest
//!   of the block zero. It lives **in group 0**; the superblock's `free`
//!   pointer names it.
//!
//! Mount checks every one of those rules ([`Allocator::from_index`],
//! [`Allocator::load_group`]); a violation is [`AllocError::Corrupt`].
//!
//! # In memory
//!
//! The committed bitmaps are ordinary clean cache entries (verified, immutable,
//! evictable). The first change to a group in a transaction copies its bitmap
//! into a dirty entry at a fresh location inside the group (first-fit), and
//! the old location becomes a *pending free*. Frees are pending too: a block
//! freed in a transaction stays marked in use until [`Allocator::seal`]
//! clears it for the commit that frees it, and nothing allocates between a
//! seal and the end of its commit — so a freed block is never reused while the
//! previous root can still reference it (§7.4).
//!
//! Allocation is **deterministic given committed state** (§5.4): first-fit in
//! the hinted group, else the group with the most free blocks by the
//! *committed* counts, ties to the lowest index — never a function of what
//! happens to be cached. A committed bitmap that is not resident is reported
//! as [`AllocError::Miss`]; the caller has it read (verified) into the cache
//! and retries. Every operation checks its budgets before it mutates, so a
//! refused operation changes nothing.
//!
//! # The metadata reserve (§5.8)
//!
//! [`AllocClass::Normal`] allocations leave at least `reserve` free blocks in
//! every group; [`AllocClass::Reclaim`] (remove / reclaim commits) may use the
//! reserve, but never the last block of a group (the next transaction's
//! copy-on-write of that group's bitmap needs it). Group 0 additionally keeps
//! two blocks for the commit's own index and group-0 bitmap copies. The
//! allocator's own copy-on-write may borrow from the reserve: it is net-zero
//! across a commit, because the commit that writes the new copy frees the old.

use super::bitmap;
use super::cache::{Cache, CacheError, SlotId};
use super::geometry::{Extent, Geometry, GROUP_BLOCKS, MAX_EXTENT, MAX_GROUPS};
use super::layout::{
    decode_header, decode_pointer, seal_metadata, Hash, Header, Kind, Pointer, TreeId, Uuid,
    HASH_LEN, HEADER_LEN, POINTER_LEN,
};
use super::{Block, BlockNo};
use alloc::boxed::Box;
use alloc::vec;

/// Blocks per group held back for remove / reclaim commits (§5.8).
pub const RESERVE: u32 = 64;
/// Frees one transaction may defer before it must commit.
pub const PENDING_MAX: usize = 512;
/// Blocks group 0 keeps for a commit's own index and bitmap copies.
const SEAL_BLOCKS: u32 = 2;
/// Dirty entries / pending slots a seal may still need (index + group 0).
const SEAL_SLOTS: usize = 2;

/// Why an allocator operation was refused. A refused operation changed
/// nothing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AllocError {
    /// No group can satisfy the request within its class's floor.
    NoSpace,
    /// This committed block must be read into the cache (verified) first.
    Miss(Pointer),
    /// The dirty or pending-free budget is exhausted: commit, then retry.
    NeedCommit,
    /// Not a block the caller may free (out of range, a superblock slot,
    /// allocator metadata, not allocated, or already pending), or a bad length.
    Invalid,
    /// A commit is in progress (the allocator is sealed).
    Sealed,
    /// Allocator metadata breaks a format rule or an internal invariant.
    Corrupt,
    /// The cache refused (should not happen once budgets were checked).
    Cache(CacheError),
}

impl AllocError {
    /// Fixed label for `fmt`-free console output.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            AllocError::NoSpace => "no-space",
            AllocError::Miss(_) => "miss",
            AllocError::NeedCommit => "need-commit",
            AllocError::Invalid => "invalid",
            AllocError::Sealed => "sealed",
            AllocError::Corrupt => "corrupt",
            AllocError::Cache(e) => e.label(),
        }
    }
}

impl From<CacheError> for AllocError {
    fn from(e: CacheError) -> Self {
        AllocError::Cache(e)
    }
}

/// Who is allocating: ordinary writes, or a remove / reclaim commit that may
/// use the metadata reserve.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AllocClass {
    /// Leaves the per-group reserve untouched.
    Normal,
    /// May use the reserve (§5.8).
    Reclaim,
}

/// A dirty cache entry a commit must write, with the hash it was sealed with.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DirtyRef {
    /// The cache entry.
    pub slot: SlotId,
    /// Where it goes.
    pub block: BlockNo,
    /// Its sealed hash (the header hash: these are metadata blocks).
    pub hash: Hash,
}

impl DirtyRef {
    /// A placeholder for fixed arrays.
    pub const NONE: DirtyRef = DirtyRef {
        slot: SlotId::NONE,
        block: BlockNo(0),
        hash: [0; HASH_LEN],
    };
}

/// A group's working copy: the dirty cache entry and where it will be written.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Work {
    slot: SlotId,
    at: BlockNo,
}

#[derive(Clone, Copy, Debug)]
struct Group {
    /// The bitmap as named by the committed index.
    committed: Pointer,
    /// Free blocks in the committed bitmap.
    committed_free: u32,
    /// Free blocks in the working view (the dirty copy, if any).
    free: u32,
    /// The dirty copy, once the group changed in this transaction.
    work: Option<Work>,
    /// The pointer the dirty copy was sealed under.
    sealed: Option<Pointer>,
}

impl Group {
    const EMPTY: Group = Group {
        committed: Pointer::NULL,
        committed_free: 0,
        free: 0,
        work: None,
        sealed: None,
    };
}

/// The free-space allocator of one mounted filesystem.
pub struct Allocator {
    geo: Geometry,
    uuid: Uuid,
    reserve: u32,
    /// The committed group-index pointer (the superblock's `free`).
    index: Pointer,
    groups: Box<[Group]>,
    pending: Box<[BlockNo]>,
    npending: usize,
    /// The new index block, once a seal placed it.
    index_work: Option<Work>,
    /// The new index pointer, once sealed.
    new_index: Option<Pointer>,
    sealed: bool,
}

/// Check the header of a free-space metadata block read through `ptr`.
fn check_free_header(
    block: &Block,
    kind: Kind,
    uuid: &Uuid,
    ptr: &Pointer,
) -> Result<(), AllocError> {
    let h = decode_header(block).map_err(|_| AllocError::Corrupt)?;
    if h.kind != kind || h.tree != TreeId::Free || h.uuid != *uuid || h.gen != ptr.gen {
        return Err(AllocError::Corrupt);
    }
    Ok(())
}

/// The bitmap payload of a bitmap block.
fn bits(block: &Block) -> &[u8] {
    &block[HEADER_LEN..]
}

/// The bitmap payload of a bitmap block, mutably.
fn bits_mut(block: &mut Block) -> &mut [u8] {
    &mut block[HEADER_LEN..]
}

/// Stamp `block`'s header for a free-space metadata block and seal it.
fn stamp_and_seal(block: &mut Block, kind: Kind, uuid: &Uuid, gen: u64) -> Hash {
    let header = Header {
        hash: [0; HASH_LEN],
        gen,
        kind,
        tree: TreeId::Free,
        uuid: *uuid,
    };
    // `block` is 4 KiB, so the 64-byte header always fits.
    let _ = header.encode(block);
    seal_metadata(block)
}

/// Write a group-index block naming `groups` bitmap pointers — `ptr_of(g)` for
/// each group `g` — and seal it. Every other byte is zero.
pub fn encode_index(
    block: &mut Block,
    uuid: &Uuid,
    gen: u64,
    groups: u32,
    mut ptr_of: impl FnMut(u32) -> Pointer,
) -> Hash {
    block.fill(0);
    for g in 0..groups.min(MAX_GROUPS) {
        let at = HEADER_LEN + g as usize * POINTER_LEN;
        if let Some(dst) = block.get_mut(at..at + POINTER_LEN) {
            let _ = ptr_of(g).encode(dst);
        }
    }
    stamp_and_seal(block, Kind::GroupIndex, uuid, gen)
}

/// Build group `g`'s initial bitmap for `format` in `block`: padding past the
/// group's end and (group 0) the two superblock slots marked used, then the
/// bitmap's own location — and, for group 0, the index's — placed first-fit
/// and marked. Returns `(own location, index location for group 0)`. The block
/// is not sealed yet; see [`seal_bitmap`].
///
/// # Errors
///
/// [`AllocError::Invalid`] for a group outside `geo`; [`AllocError::NoSpace`]
/// if the group cannot hold its own metadata.
pub fn format_bitmap(
    block: &mut Block,
    geo: &Geometry,
    g: u32,
) -> Result<(BlockNo, Option<BlockNo>), AllocError> {
    block.fill(0);
    let len = geo.group_len(g).ok_or(AllocError::Invalid)?;
    let b = bits_mut(block);
    bitmap::set_range(b, len, GROUP_BLOCKS);
    if g == 0 {
        bitmap::set_range(b, 0, 2);
    }
    let own = bitmap::find_zero(b, 0, len).ok_or(AllocError::NoSpace)?;
    bitmap::set(b, own);
    let index = if g == 0 {
        let i = bitmap::find_zero(b, 0, len).ok_or(AllocError::NoSpace)?;
        bitmap::set(b, i);
        Some(geo.block_at(g, i).ok_or(AllocError::Corrupt)?)
    } else {
        None
    };
    let own = geo.block_at(g, own).ok_or(AllocError::Corrupt)?;
    Ok((own, index))
}

/// Seal a bitmap block (header + hash) built by [`format_bitmap`].
pub fn seal_bitmap(block: &mut Block, uuid: &Uuid, gen: u64) -> Hash {
    stamp_and_seal(block, Kind::Bitmap, uuid, gen)
}

/// A free-space pointer must name a block inside group `g` (never a slot),
/// written by a generation in `1..=gen`.
fn check_pointer(geo: &Geometry, p: &Pointer, g: u32, gen: u64) -> Result<(), AllocError> {
    let (pg, _) = geo.locate(p.block).ok_or(AllocError::Corrupt)?;
    if pg != g || p.block.0 < 2 || p.gen == 0 || p.gen > gen {
        return Err(AllocError::Corrupt);
    }
    Ok(())
}

impl Allocator {
    /// Start mounting: decode the verified group-index block `index_block`
    /// (read through `index`) of a filesystem with geometry `geo`, identity
    /// `uuid`, reserve `reserve`, committed at generation `gen`. Follow with
    /// [`load_group`](Self::load_group) for every group.
    ///
    /// # Errors
    ///
    /// [`AllocError::Corrupt`] if the index or its placement breaks a format
    /// rule (see the module docs).
    pub fn from_index(
        geo: Geometry,
        uuid: Uuid,
        reserve: u32,
        index: Pointer,
        index_block: &Block,
        gen: u64,
    ) -> Result<Allocator, AllocError> {
        check_pointer(&geo, &index, 0, gen)?;
        check_free_header(index_block, Kind::GroupIndex, &uuid, &index)?;
        let mut groups = vec![Group::EMPTY; MAX_GROUPS as usize].into_boxed_slice();
        for (g, slot) in groups.iter_mut().enumerate() {
            let at = HEADER_LEN + g * POINTER_LEN;
            let raw = index_block
                .get(at..at + POINTER_LEN)
                .ok_or(AllocError::Corrupt)?;
            if (g as u32) < geo.groups() {
                let p = decode_pointer(raw).map_err(|_| AllocError::Corrupt)?;
                check_pointer(&geo, &p, g as u32, gen)?;
                if p.block == index.block {
                    return Err(AllocError::Corrupt);
                }
                slot.committed = p;
            } else if raw.iter().any(|&x| x != 0) {
                return Err(AllocError::Corrupt);
            }
        }
        // Bytes after the last possible entry must be zero too.
        let tail = HEADER_LEN + MAX_GROUPS as usize * POINTER_LEN;
        if index_block[tail..].iter().any(|&x| x != 0) {
            return Err(AllocError::Corrupt);
        }
        Ok(Allocator {
            geo,
            uuid,
            reserve,
            index,
            groups,
            pending: vec![BlockNo(0); PENDING_MAX].into_boxed_slice(),
            npending: 0,
            index_work: None,
            new_index: None,
            sealed: false,
        })
    }

    /// The committed bitmap pointer of group `g`.
    #[must_use]
    pub fn group_pointer(&self, g: u32) -> Option<Pointer> {
        if g < self.geo.groups() {
            self.groups.get(g as usize).map(|s| s.committed)
        } else {
            None
        }
    }

    /// Finish mounting group `g` from its verified bitmap block: check the
    /// header, the padding, and that the bitmap's own location (and, for
    /// group 0, the superblock slots and the index) are marked used; record
    /// the free count.
    ///
    /// # Errors
    ///
    /// [`AllocError::Corrupt`] on any violation.
    pub fn load_group(&mut self, g: u32, block: &Block) -> Result<(), AllocError> {
        let len = self.geo.group_len(g).ok_or(AllocError::Corrupt)?;
        let ptr = self.group_pointer(g).ok_or(AllocError::Corrupt)?;
        check_free_header(block, Kind::Bitmap, &self.uuid, &ptr)?;
        let b = bits(block);
        if !bitmap::all_set(b, len, GROUP_BLOCKS) {
            return Err(AllocError::Corrupt);
        }
        let mut must_be_used = [Some(ptr.block), None, None, None];
        if g == 0 {
            must_be_used[1] = Some(BlockNo(0));
            must_be_used[2] = Some(BlockNo(1));
            must_be_used[3] = Some(self.index.block);
        }
        for blk in must_be_used.into_iter().flatten() {
            let (bg, bit) = self.geo.locate(blk).ok_or(AllocError::Corrupt)?;
            if bg != g || bitmap::get(b, bit) != Some(true) {
                return Err(AllocError::Corrupt);
            }
        }
        let free = bitmap::count_zeros(b, len);
        let slot = self.groups.get_mut(g as usize).ok_or(AllocError::Corrupt)?;
        slot.committed_free = free;
        slot.free = free;
        Ok(())
    }

    /// The geometry.
    #[must_use]
    pub const fn geometry(&self) -> &Geometry {
        &self.geo
    }

    /// The per-group reserve in force.
    #[must_use]
    pub const fn reserve(&self) -> u32 {
        self.reserve
    }

    /// The committed group-index pointer.
    #[must_use]
    pub const fn index(&self) -> Pointer {
        self.index
    }

    /// Free blocks by the committed bitmaps.
    #[must_use]
    pub fn committed_free(&self) -> u64 {
        self.active().map(|s| u64::from(s.committed_free)).sum()
    }

    /// Free blocks in the working view (this transaction's allocations
    /// subtracted; its frees not yet added).
    #[must_use]
    pub fn working_free(&self) -> u64 {
        self.active().map(|s| u64::from(s.free)).sum()
    }

    /// Whether this transaction changed anything.
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        self.npending > 0 || self.active().any(|s| s.work.is_some())
    }

    /// Frees deferred in this transaction.
    #[must_use]
    pub const fn pending_frees(&self) -> usize {
        self.npending
    }

    /// Whether a seal is in force (a commit is in progress).
    #[must_use]
    pub const fn is_sealed(&self) -> bool {
        self.sealed
    }

    /// Heap bytes held (fixed for the allocator's lifetime).
    #[must_use]
    pub fn heap_bytes(&self) -> usize {
        core::mem::size_of_val(&*self.groups) + core::mem::size_of_val(&*self.pending)
    }

    fn active(&self) -> impl Iterator<Item = &Group> {
        self.groups.iter().take(self.geo.groups() as usize)
    }

    fn group(&self, g: u32) -> Result<&Group, AllocError> {
        if g >= self.geo.groups() {
            return Err(AllocError::Invalid);
        }
        self.groups.get(g as usize).ok_or(AllocError::Invalid)
    }

    fn group_mut(&mut self, g: u32) -> Result<&mut Group, AllocError> {
        if g >= self.geo.groups() {
            return Err(AllocError::Invalid);
        }
        self.groups.get_mut(g as usize).ok_or(AllocError::Invalid)
    }

    /// Free blocks group `g` must keep after an allocation of `class`.
    fn floor(&self, g: u32, class: AllocClass) -> u32 {
        let base = match class {
            AllocClass::Normal => self.reserve.max(1),
            AllocClass::Reclaim => 1,
        };
        if g == 0 {
            base + SEAL_BLOCKS
        } else {
            base
        }
    }

    /// Dirty entries / pending slots a seal will still need.
    fn seal_need(&self) -> usize {
        let group0_clean = self.groups.first().is_some_and(|s| s.work.is_none());
        usize::from(group0_clean) + usize::from(self.index_work.is_none())
    }

    fn push_pending(&mut self, b: BlockNo) -> Result<(), AllocError> {
        let slot = self
            .pending
            .get_mut(self.npending)
            .ok_or(AllocError::NeedCommit)?;
        *slot = b;
        self.npending += 1;
        Ok(())
    }

    /// The resident bitmap that is current for group `g` in this transaction:
    /// its dirty copy if it has one, else the committed one (or a miss).
    fn current_view(&self, cache: &mut Cache, g: u32) -> Result<SlotId, AllocError> {
        let grp = self.group(g)?;
        match grp.work {
            Some(w) => Ok(w.slot),
            None => cache
                .lookup(grp.committed.block, &grp.committed.hash)
                .ok_or(AllocError::Miss(grp.committed)),
        }
    }

    /// Give group `g` a working copy (copy-on-write of its committed bitmap to
    /// a fresh in-group location), if it has none yet. Atomic: every check
    /// runs before the first change.
    fn ensure_work(&mut self, cache: &mut Cache, g: u32) -> Result<Work, AllocError> {
        let grp = *self.group(g)?;
        if let Some(w) = grp.work {
            return Ok(w);
        }
        let c = grp.committed;
        let src = cache.lookup(c.block, &c.hash).ok_or(AllocError::Miss(c))?;
        // After this copy the seal needs one slot fewer if this is group 0.
        let seal_after = self.seal_need() - usize::from(g == 0);
        if cache.dirty_room() < 1 + seal_after || PENDING_MAX - self.npending < 1 + seal_after {
            return Err(AllocError::NeedCommit);
        }
        if grp.free == 0 {
            return Err(AllocError::NoSpace);
        }
        let len = self.geo.group_len(g).ok_or(AllocError::Corrupt)?;
        let committed = cache.read(src).ok_or(AllocError::Miss(c))?;
        let bit = bitmap::find_zero(bits(committed), 0, len).ok_or(AllocError::Corrupt)?;
        let at = self.geo.block_at(g, bit).ok_or(AllocError::Corrupt)?;
        let slot = cache.copy_to_dirty(src, at)?;
        let dst = cache.dirty_mut(slot).ok_or(AllocError::Corrupt)?;
        if bitmap::set(bits_mut(dst), bit) != Some(false) {
            return Err(AllocError::Corrupt);
        }
        let work = Work { slot, at };
        let grp = self.group_mut(g)?;
        grp.free -= 1;
        grp.work = Some(work);
        self.push_pending(c.block)?;
        Ok(work)
    }

    /// Groups in allocation-preference order: `hint` first, then by committed
    /// free blocks (descending), ties to the lowest index. Pure function of
    /// committed state and the hint.
    fn preference(&self, hint: Option<u32>) -> ([u8; MAX_GROUPS as usize], usize) {
        let groups = self.geo.groups().min(MAX_GROUPS);
        let mut order = [0u8; MAX_GROUPS as usize];
        let mut n = 0;
        let mut taken: u128 = 0;
        if let Some(h) = hint.filter(|&h| h < groups) {
            order[0] = h as u8;
            n = 1;
            taken |= 1u128 << h;
        }
        while n < groups as usize {
            let mut best: Option<(u32, u32)> = None;
            for g in 0..groups {
                if taken & (1u128 << g) != 0 {
                    continue;
                }
                let free = self.groups.get(g as usize).map_or(0, |s| s.committed_free);
                if best.is_none_or(|(_, f)| free > f) {
                    best = Some((g, free));
                }
            }
            let Some((g, _)) = best else {
                break;
            };
            order[n] = g as u8;
            n += 1;
            taken |= 1u128 << g;
        }
        (order, n)
    }

    /// Allocate one block. See [`alloc_run`](Self::alloc_run).
    ///
    /// # Errors
    ///
    /// As [`alloc_run`](Self::alloc_run).
    pub fn alloc(
        &mut self,
        cache: &mut Cache,
        class: AllocClass,
        hint: Option<u32>,
    ) -> Result<BlockNo, AllocError> {
        Ok(self.alloc_run(cache, 1, class, hint)?.start())
    }

    /// Allocate `len` (`1..=MAX_EXTENT`) contiguous blocks inside one group,
    /// first-fit, trying groups in preference order (module docs).
    ///
    /// # Errors
    ///
    /// [`AllocError::Sealed`] during a commit; [`AllocError::Invalid`] for a
    /// bad `len`; [`AllocError::Miss`] when a committed bitmap must be read
    /// first; [`AllocError::NeedCommit`] when the dirty / pending budget is
    /// spent; [`AllocError::NoSpace`] when no group can satisfy `class`.
    pub fn alloc_run(
        &mut self,
        cache: &mut Cache,
        len: u32,
        class: AllocClass,
        hint: Option<u32>,
    ) -> Result<Extent, AllocError> {
        if self.sealed {
            return Err(AllocError::Sealed);
        }
        if len == 0 || len > MAX_EXTENT {
            return Err(AllocError::Invalid);
        }
        let (order, n) = self.preference(hint);
        for &g in order.iter().take(n) {
            let g = u32::from(g);
            let grp = *self.group(g)?;
            let cow = u32::from(grp.work.is_none());
            if grp.free < len + cow + self.floor(g, class) {
                continue;
            }
            // Enough free blocks may still not be contiguous: look before
            // copying anything.
            let glen = self.geo.group_len(g).ok_or(AllocError::Corrupt)?;
            let view = self.current_view(cache, g)?;
            let current = cache.read(view).ok_or(AllocError::Corrupt)?;
            if bitmap::find_zero_run(bits(current), len, 0, glen).is_none() {
                continue;
            }
            let work = self.ensure_work(cache, g)?;
            let dst = cache.dirty_mut(work.slot).ok_or(AllocError::Corrupt)?;
            let Some(start) = bitmap::find_zero_run(bits(dst), len, 0, glen) else {
                // The copy took the only gap: the group stays changed (net-zero
                // after the commit), the search moves on.
                continue;
            };
            bitmap::set_range(bits_mut(dst), start, start + len);
            self.group_mut(g)?.free -= len;
            let first = self.geo.block_at(g, start).ok_or(AllocError::Corrupt)?;
            return Extent::new(first, len).map_err(|_| AllocError::Corrupt);
        }
        Err(AllocError::NoSpace)
    }

    /// Whether `b` is allocator metadata (never freeable by callers).
    fn is_metadata(&self, b: BlockNo) -> bool {
        b.0 < 2
            || b == self.index.block
            || self.index_work.is_some_and(|w| w.at == b)
            || self
                .active()
                .any(|s| s.committed.block == b || s.work.is_some_and(|w| w.at == b))
    }

    /// Free `b`: it stays in use until the commit that frees it, and becomes
    /// allocatable only after that commit (§7.4).
    ///
    /// # Errors
    ///
    /// [`AllocError::Sealed`] during a commit; [`AllocError::Invalid`] for a
    /// block that is not an allocated, freeable block (superblock slots and
    /// allocator metadata are never freeable by callers);
    /// [`AllocError::Miss`] / [`AllocError::NeedCommit`] /
    /// [`AllocError::NoSpace`] as for allocation (the group's bitmap is copied
    /// first).
    pub fn free(&mut self, cache: &mut Cache, b: BlockNo) -> Result<(), AllocError> {
        if self.sealed {
            return Err(AllocError::Sealed);
        }
        let (g, bit) = self.geo.locate(b).ok_or(AllocError::Invalid)?;
        if self.is_metadata(b) || self.pending[..self.npending].contains(&b) {
            return Err(AllocError::Invalid);
        }
        // Room for this entry, the copy-on-write's own entry, and the seal.
        let cow = usize::from(self.group(g)?.work.is_none());
        if PENDING_MAX - self.npending < 1 + cow + SEAL_SLOTS {
            return Err(AllocError::NeedCommit);
        }
        // Allocated in the working view? Check before copying anything.
        let view = self.current_view(cache, g)?;
        let current = cache.read(view).ok_or(AllocError::Corrupt)?;
        if bitmap::get(bits(current), bit) != Some(true) {
            return Err(AllocError::Invalid);
        }
        self.ensure_work(cache, g)?;
        self.push_pending(b)
    }

    /// Seal the transaction for a commit at generation `gen`: place the new
    /// index (copying group 0's bitmap if needed), apply the pending frees,
    /// seal every changed bitmap and the index. Returns the new index pointer,
    /// or `None` when nothing changed (the index stays where it is). After
    /// `Ok`, nothing allocates or frees until [`commit_done`](Self::commit_done).
    ///
    /// A [`AllocError::Miss`] is returned before anything changes: read the
    /// block into the cache and call again.
    ///
    /// # Errors
    ///
    /// [`AllocError::Miss`] (read and retry); [`AllocError::Sealed`] if
    /// already sealed; [`AllocError::NoSpace`] / [`AllocError::NeedCommit`]
    /// only if the budgets the operations reserved were violated;
    /// [`AllocError::Corrupt`] on a broken invariant.
    pub fn seal(&mut self, cache: &mut Cache, gen: u64) -> Result<Option<Pointer>, AllocError> {
        if self.sealed {
            return Err(AllocError::Sealed);
        }
        if !self.is_dirty() {
            self.sealed = true;
            self.new_index = None;
            return Ok(None);
        }
        // Four steps, each its own (small) frame: debug builds do not reuse
        // stack slots, and this runs on a kernel task's stack.
        self.place_index(cache)?;
        self.apply_pending(cache)?;
        self.seal_bitmaps(cache, gen)?;
        let index = self.seal_index(cache, gen)?;
        self.new_index = Some(index);
        self.sealed = true;
        Ok(Some(index))
    }

    /// Seal step 1: place the new index in group 0 (copying group 0's bitmap
    /// first if it is not yet changed); the old index becomes a pending free.
    fn place_index(&mut self, cache: &mut Cache) -> Result<(), AllocError> {
        let w0 = self.ensure_work(cache, 0)?;
        if self.index_work.is_some() {
            return Ok(());
        }
        let len0 = self.geo.group_len(0).ok_or(AllocError::Corrupt)?;
        if self.group(0)?.free == 0 {
            return Err(AllocError::NoSpace);
        }
        if cache.dirty_room() < 1 || self.npending >= PENDING_MAX {
            return Err(AllocError::NeedCommit);
        }
        let bits0 = bits(cache.read(w0.slot).ok_or(AllocError::Corrupt)?);
        let bit = bitmap::find_zero(bits0, 0, len0).ok_or(AllocError::Corrupt)?;
        let at = self.geo.block_at(0, bit).ok_or(AllocError::Corrupt)?;
        let slot = cache.new_dirty(at)?;
        let dst = cache.dirty_mut(w0.slot).ok_or(AllocError::Corrupt)?;
        bitmap::set(bits_mut(dst), bit);
        self.group_mut(0)?.free -= 1;
        let old = self.index.block;
        self.push_pending(old)?;
        self.index_work = Some(Work { slot, at });
        Ok(())
    }

    /// Seal step 2: apply the deferred frees — they are free in the bitmaps
    /// this commit writes (and allocatable once it is durable).
    fn apply_pending(&mut self, cache: &mut Cache) -> Result<(), AllocError> {
        for i in 0..self.npending {
            let b = *self.pending.get(i).ok_or(AllocError::Corrupt)?;
            let (g, bit) = self.geo.locate(b).ok_or(AllocError::Corrupt)?;
            let w = self.group(g)?.work.ok_or(AllocError::Corrupt)?;
            let dst = cache.dirty_mut(w.slot).ok_or(AllocError::Corrupt)?;
            if bitmap::clear(bits_mut(dst), bit) != Some(true) {
                return Err(AllocError::Corrupt);
            }
            self.group_mut(g)?.free += 1;
        }
        self.npending = 0;
        Ok(())
    }

    /// Seal step 3: stamp and hash every changed bitmap.
    fn seal_bitmaps(&mut self, cache: &mut Cache, gen: u64) -> Result<(), AllocError> {
        for g in 0..self.geo.groups() {
            let Some(w) = self.group(g)?.work else {
                continue;
            };
            let dst = cache.dirty_mut(w.slot).ok_or(AllocError::Corrupt)?;
            let hash = seal_bitmap(dst, &self.uuid, gen);
            self.group_mut(g)?.sealed = Some(Pointer {
                block: w.at,
                hash,
                gen,
            });
        }
        Ok(())
    }

    /// Seal step 4: the new index names every group's current bitmap.
    fn seal_index(&mut self, cache: &mut Cache, gen: u64) -> Result<Pointer, AllocError> {
        let iw = self.index_work.ok_or(AllocError::Corrupt)?;
        let groups = &self.groups;
        let dst = cache.dirty_mut(iw.slot).ok_or(AllocError::Corrupt)?;
        let hash = encode_index(dst, &self.uuid, gen, self.geo.groups(), |g| {
            groups
                .get(g as usize)
                .map_or(Pointer::NULL, |s| s.sealed.unwrap_or(s.committed))
        });
        Ok(Pointer {
            block: iw.at,
            hash,
            gen,
        })
    }

    /// The dirty entries the sealed transaction must write, into `out`;
    /// returns how many. `out` needs room for every changed group plus one.
    ///
    /// # Errors
    ///
    /// [`AllocError::Corrupt`] if not sealed or `out` is too small.
    pub fn sealed_entries(&self, out: &mut [DirtyRef]) -> Result<usize, AllocError> {
        if !self.sealed {
            return Err(AllocError::Corrupt);
        }
        let mut n = 0;
        let groups = self.active().filter_map(|s| match (s.work, s.sealed) {
            (Some(w), Some(p)) => Some((w, p)),
            _ => None,
        });
        let index = match (self.index_work, self.new_index) {
            (Some(w), Some(p)) => Some((w, p)),
            _ => None,
        };
        for (w, p) in groups.chain(index) {
            *out.get_mut(n).ok_or(AllocError::Corrupt)? = DirtyRef {
                slot: w.slot,
                block: w.at,
                hash: p.hash,
            };
            n += 1;
        }
        Ok(n)
    }

    /// The sealed transaction is durable (its superblock landed): the sealed
    /// bitmaps and index become the committed ones, and the frees it applied
    /// become allocatable. The caller marks the cache entries clean.
    pub fn commit_done(&mut self) {
        for s in self.groups.iter_mut() {
            if let Some(p) = s.sealed.take() {
                s.committed = p;
            }
            s.work = None;
            s.committed_free = s.free;
        }
        if let Some(p) = self.new_index.take() {
            self.index = p;
        }
        self.index_work = None;
        self.npending = 0;
        self.sealed = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blk::geometry::MIN_BLOCKS;
    use crate::blk::layout::{verify, HashRule};
    use crate::blk::zeroed_blocks;
    use alloc::vec::Vec;

    const UUID: Uuid = [0x11; 16];

    /// Format-like setup entirely in memory: an allocator whose committed
    /// bitmaps and index are clean, verified cache entries.
    fn fresh(total: u64) -> (Allocator, Cache) {
        let geo = Geometry::new(total).unwrap();
        let mut cache = Cache::new();
        let mut buf = zeroed_blocks(1);
        let mut ptrs = Vec::new();
        let mut bitmaps = Vec::new();
        let mut index_at = BlockNo(0);
        for g in 0..geo.groups() {
            let (own, idx) = format_bitmap(&mut buf[0], &geo, g).unwrap();
            if let Some(i) = idx {
                index_at = i;
            }
            let hash = seal_bitmap(&mut buf[0], &UUID, 1);
            ptrs.push(Pointer {
                block: own,
                hash,
                gen: 1,
            });
            bitmaps.push(buf[0]);
        }
        let mut ib = zeroed_blocks(1);
        let ih = encode_index(&mut ib[0], &UUID, 1, geo.groups(), |g| ptrs[g as usize]);
        let index = Pointer {
            block: index_at,
            hash: ih,
            gen: 1,
        };
        cache
            .insert_verified(index.block, HashRule::Metadata, &ih, &ib[0])
            .unwrap();
        let mut a = Allocator::from_index(geo, UUID, RESERVE, index, &ib[0], 1).unwrap();
        for (g, bm) in bitmaps.iter().enumerate() {
            let p = ptrs[g];
            cache
                .insert_verified(p.block, HashRule::Metadata, &p.hash, bm)
                .unwrap();
            a.load_group(g as u32, bm).unwrap();
        }
        (a, cache)
    }

    /// Commit in memory: seal, mark every sealed entry clean, done.
    fn commit(a: &mut Allocator, cache: &mut Cache, gen: u64) -> Option<Pointer> {
        let idx = a.seal(cache, gen).unwrap();
        let mut refs = [DirtyRef::NONE; 90];
        let n = a.sealed_entries(&mut refs).unwrap();
        assert_eq!(n, cache.dirty_count(), "every dirty entry is sealed");
        for r in &refs[..n] {
            assert!(verify(
                HashRule::Metadata,
                cache.read(r.slot).unwrap(),
                &r.hash
            ));
            cache.mark_clean(r.slot, r.hash).unwrap();
        }
        a.commit_done();
        idx
    }

    #[test]
    fn format_layout_of_the_dev_window() {
        let (a, _) = fresh(3840);
        // Slots 0/1, bitmap at 2, index at 3.
        assert_eq!(a.group_pointer(0).unwrap().block, BlockNo(2));
        assert_eq!(a.index().block, BlockNo(3));
        assert_eq!(a.committed_free(), 3836);
        assert!(!a.is_dirty());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn alloc_copies_the_bitmap_once_and_free_is_deferred_to_after_commit() {
        let (mut a, mut c) = fresh(3840);
        let b1 = a.alloc(&mut c, AllocClass::Normal, None).unwrap();
        // The bitmap's copy took block 4 (first fit), so the caller gets 5.
        assert_eq!(b1, BlockNo(5));
        let b2 = a.alloc(&mut c, AllocClass::Normal, None).unwrap();
        assert_eq!(b2, BlockNo(6));
        assert_eq!(c.dirty_count(), 1, "one bitmap copy per group per txn");
        let idx = commit(&mut a, &mut c, 2).unwrap();
        // The new index went to the next free block; the old bitmap (2) and
        // old index (3) are free again after the commit.
        assert_eq!(idx.block, BlockNo(7));
        assert_eq!(a.group_pointer(0).unwrap().block, BlockNo(4));
        assert_eq!(a.committed_free(), 3836 - 2);
        // Free b1: not reusable inside this transaction…
        a.free(&mut c, b1).unwrap();
        assert_eq!(a.free(&mut c, b1), Err(AllocError::Invalid), "double free");
        let x = a.alloc(&mut c, AllocClass::Normal, None).unwrap();
        assert_ne!(x, b1);
        // …and after the commit that freed it, it is.
        commit(&mut a, &mut c, 3).unwrap();
        let got: Vec<BlockNo> = (0..8)
            .map(|_| a.alloc(&mut c, AllocClass::Normal, None).unwrap())
            .collect();
        assert!(got.contains(&b1));
    }

    #[test]
    fn metadata_and_unallocated_blocks_are_not_freeable() {
        let (mut a, mut c) = fresh(3840);
        for b in [0u32, 1, 2, 3, 100, 9999] {
            assert_eq!(a.free(&mut c, BlockNo(b)), Err(AllocError::Invalid), "{b}");
        }
        assert!(!a.is_dirty(), "refused frees change nothing");
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn normal_stops_at_the_reserve_and_reclaim_may_use_it() {
        let (mut a, mut c) = fresh(MIN_BLOCKS);
        let mut normal = 0u32;
        loop {
            match a.alloc(&mut c, AllocClass::Normal, None) {
                Ok(_) => normal += 1,
                Err(AllocError::NoSpace) => break,
                Err(e) => panic!("{e:?}"),
            }
        }
        // 128 blocks - 4 metadata - 1 bitmap copy - (64 reserve + 2 seal).
        assert_eq!(normal, 128 - 4 - 1 - 66);
        let mut reclaim = 0u32;
        while a.alloc(&mut c, AllocClass::Reclaim, None).is_ok() {
            reclaim += 1;
        }
        assert_eq!(reclaim, 63, "reclaim keeps 1 + 2 in group 0");
        // The commit still fits (index; group 0 is already copied).
        assert!(commit(&mut a, &mut c, 2).is_some());
        // 3 left - 1 for the new index + the old bitmap and index freed.
        assert_eq!(a.committed_free(), 3 - 1 + 2);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn allocation_prefers_the_hint_then_the_most_free_committed_group() {
        let total = 3 * u64::from(GROUP_BLOCKS);
        let (mut a, mut c) = fresh(total);
        // Group 0 holds slots + index, so groups 1 and 2 have more free; ties
        // go to the lower index.
        let b = a.alloc(&mut c, AllocClass::Normal, None).unwrap();
        assert_eq!(a.geometry().locate(b).unwrap().0, 1);
        let h = a.alloc(&mut c, AllocClass::Normal, Some(2)).unwrap();
        assert_eq!(a.geometry().locate(h).unwrap().0, 2);
        // Committed counts decide, not working ones: still group 1 first.
        let again = a.alloc(&mut c, AllocClass::Normal, None).unwrap();
        assert_eq!(a.geometry().locate(again).unwrap().0, 1);
        let e = a
            .alloc_run(&mut c, 32, AllocClass::Normal, Some(2))
            .unwrap();
        assert_eq!(e.len(), 32);
        assert_eq!(
            a.alloc_run(&mut c, 33, AllocClass::Normal, None),
            Err(AllocError::Invalid)
        );
        commit(&mut a, &mut c, 2).unwrap();
    }

    #[test]
    fn a_missing_committed_bitmap_is_reported_not_guessed() {
        let (mut a, mut c) = fresh(3840);
        let p = a.group_pointer(0).unwrap();
        assert!(c.evict(p.block));
        assert_eq!(
            a.alloc(&mut c, AllocClass::Normal, None),
            Err(AllocError::Miss(p))
        );
        assert!(!a.is_dirty());
    }

    #[test]
    fn sealed_allocator_refuses_changes_and_an_empty_seal_is_none() {
        let (mut a, mut c) = fresh(3840);
        assert_eq!(a.seal(&mut c, 2), Ok(None));
        assert_eq!(
            a.alloc(&mut c, AllocClass::Normal, None),
            Err(AllocError::Sealed)
        );
        assert_eq!(a.seal(&mut c, 2), Err(AllocError::Sealed));
        a.commit_done();
        assert!(a.alloc(&mut c, AllocClass::Normal, None).is_ok());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn pending_budget_forces_a_commit_instead_of_failing_the_seal() {
        let (mut a, mut c) = fresh(3840);
        let mut got = Vec::new();
        while got.len() < PENDING_MAX + 8 {
            match a.alloc(&mut c, AllocClass::Normal, None) {
                Ok(b) => got.push(b),
                Err(e) => panic!("{e:?}"),
            }
        }
        commit(&mut a, &mut c, 2).unwrap();
        let mut freed = 0;
        for b in &got {
            match a.free(&mut c, *b) {
                Ok(()) => freed += 1,
                Err(AllocError::NeedCommit) => break,
                Err(e) => panic!("{e:?}"),
            }
        }
        // One pending slot went to the bitmap copy's old location, two stay
        // reserved for the seal.
        assert_eq!(freed, PENDING_MAX - 1 - SEAL_SLOTS);
        let before = a.committed_free();
        commit(&mut a, &mut c, 3).unwrap();
        assert_eq!(a.committed_free(), before + freed as u64);
    }

    #[test]
    fn mount_checks_refuse_broken_free_space_metadata() {
        let geo = Geometry::new(3840).unwrap();
        let (a, mut c) = fresh(3840);
        let index = a.index();
        let ib_id = c.lookup(index.block, &index.hash).unwrap();
        let ib = *c.read(ib_id).unwrap();
        // Index entry pointing at a superblock slot.
        let mut bad = ib;
        let mut p = a.group_pointer(0).unwrap();
        p.block = BlockNo(1);
        p.encode(&mut bad[HEADER_LEN..]).unwrap();
        assert!(matches!(
            Allocator::from_index(geo, UUID, RESERVE, index, &bad, 1),
            Err(AllocError::Corrupt)
        ));
        // Wrong uuid; generation from the future; non-zero tail.
        assert!(Allocator::from_index(geo, [9; 16], RESERVE, index, &ib, 1).is_err());
        assert!(Allocator::from_index(geo, UUID, RESERVE, index, &ib, 0).is_err());
        let mut bad = ib;
        bad[4095] = 1;
        assert!(Allocator::from_index(geo, UUID, RESERVE, index, &bad, 1).is_err());
        // A bitmap that says a superblock slot is free.
        let mut a2 = Allocator::from_index(geo, UUID, RESERVE, index, &ib, 1).unwrap();
        let bp = a2.group_pointer(0).unwrap();
        let bm_id = c.lookup(bp.block, &bp.hash).unwrap();
        let good = *c.read(bm_id).unwrap();
        let mut bm = good;
        bitmap::clear(&mut bm[HEADER_LEN..], 0);
        assert_eq!(a2.load_group(0, &bm), Err(AllocError::Corrupt));
        // Padding that claims blocks past the end are free.
        let mut bm = good;
        bitmap::clear(&mut bm[HEADER_LEN..], 3840);
        assert_eq!(a2.load_group(0, &bm), Err(AllocError::Corrupt));
        // A bitmap that frees the index block.
        let mut bm = good;
        bitmap::clear(&mut bm[HEADER_LEN..], index.block.0);
        assert_eq!(a2.load_group(0, &bm), Err(AllocError::Corrupt));
        assert_eq!(a2.load_group(0, &good), Ok(()));
    }
}
