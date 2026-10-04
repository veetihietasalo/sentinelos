//! The one block cache (spec §6, amendment A7): a fixed slab of
//! [`CACHE_BLOCKS`] 4 KiB entries — 256 KiB, allocated once — that holds both
//! verified clean blocks and the transaction's dirty set.
//!
//! Two rules make reads safe to parse:
//!
//! 1. **Verify before entry.** [`Cache::insert_verified`] checks the caller's
//!    expected hash against the source bytes *before* anything is copied into
//!    the slab. A block that fails is never resident.
//! 2. **Resident verified entries are immutable.** There is no `&mut` path to
//!    a clean entry: [`Cache::dirty_mut`] only hands out dirty ones. Parsers
//!    read the cached copy, never the device, so hash-then-parse has no
//!    time-of-check/time-of-use window (the TOCTOU the review named).
//!
//! Dirty entries are **unevictable** and capped at [`DIRTY_MAX`] (48 of the
//! 64), so a clean victim always exists and the dirty set can never push the
//! cache over its one budget. Eviction among clean entries is least recently
//! used. Nothing here allocates after [`Cache::new`].
//!
//! A [`SlotId`] names one residency of one entry: it carries a tag that changes
//! whenever the slot is reused, so a stale id reads as `None`, never as some
//! other block's bytes.

use super::layout::{self, Hash, HashRule};
use super::{zeroed_blocks, Block, BlockNo, Blocks};
use alloc::boxed::Box;
use alloc::vec;

/// Entries in the slab (256 KiB of 4 KiB blocks).
pub const CACHE_BLOCKS: usize = 64;
/// Most entries that may be dirty at once (§8's dirty budget).
pub const DIRTY_MAX: usize = 48;

/// Why a cache operation was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CacheError {
    /// The source bytes do not match the expected hash; nothing was cached.
    Corrupt,
    /// The dirty budget ([`DIRTY_MAX`]) is exhausted: commit first.
    DirtyFull,
    /// The block already has a dirty entry (it is being rewritten).
    Conflict,
    /// The [`SlotId`] no longer names a resident entry of the required kind.
    Stale,
}

impl CacheError {
    /// Fixed label for `fmt`-free console output.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            CacheError::Corrupt => "corrupt",
            CacheError::DirtyFull => "dirty-full",
            CacheError::Conflict => "conflict",
            CacheError::Stale => "stale",
        }
    }
}

/// What a slot holds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    /// Nothing.
    Empty,
    /// A verified copy of `block` whose hash is this value. Immutable.
    Clean(Hash),
    /// A block being written by the current transaction. Unevictable.
    Dirty,
}

#[derive(Clone, Copy, Debug)]
struct Slot {
    block: BlockNo,
    state: State,
    /// Last-use time for LRU eviction.
    stamp: u64,
    /// Bumped on every reuse; see [`SlotId`].
    tag: u32,
}

impl Slot {
    const EMPTY: Slot = Slot {
        block: BlockNo(0),
        state: State::Empty,
        stamp: 0,
        tag: 0,
    };
}

/// A handle to one residency of one cache entry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SlotId {
    idx: u8,
    tag: u32,
}

impl SlotId {
    /// An id that never names a resident entry (a placeholder for fixed
    /// arrays); every lookup through it reads as stale.
    pub const NONE: SlotId = SlotId {
        idx: u8::MAX,
        tag: u32::MAX,
    };
}

/// The 64-entry block cache.
pub struct Cache {
    data: Blocks,
    slots: Box<[Slot]>,
    clock: u64,
    dirty: usize,
}

impl Default for Cache {
    fn default() -> Self {
        Self::new()
    }
}

impl Cache {
    /// An empty cache: the slab and its slot table, allocated once.
    #[must_use]
    pub fn new() -> Cache {
        Cache {
            data: zeroed_blocks(CACHE_BLOCKS),
            slots: vec![Slot::EMPTY; CACHE_BLOCKS].into_boxed_slice(),
            clock: 0,
            dirty: 0,
        }
    }

    /// Heap bytes this cache holds (fixed for its lifetime).
    #[must_use]
    pub fn heap_bytes(&self) -> usize {
        core::mem::size_of_val(&*self.data) + core::mem::size_of_val(&*self.slots)
    }

    /// Number of dirty entries.
    #[must_use]
    pub const fn dirty_count(&self) -> usize {
        self.dirty
    }

    /// Dirty entries that may still be created before [`DIRTY_MAX`].
    #[must_use]
    pub const fn dirty_room(&self) -> usize {
        DIRTY_MAX - self.dirty
    }

    fn tick(&mut self) -> u64 {
        self.clock = self.clock.wrapping_add(1);
        self.clock
    }

    fn position(&self, block: BlockNo) -> Option<usize> {
        self.slots
            .iter()
            .position(|s| s.state != State::Empty && s.block == block)
    }

    fn id_of(&self, idx: usize) -> Option<SlotId> {
        let slot = self.slots.get(idx)?;
        Some(SlotId {
            idx: u8::try_from(idx).ok()?,
            tag: slot.tag,
        })
    }

    fn check(&self, id: SlotId) -> Option<usize> {
        let idx = usize::from(id.idx);
        let slot = self.slots.get(idx)?;
        (slot.tag == id.tag && slot.state != State::Empty).then_some(idx)
    }

    /// A slot to reuse: an empty one, else the least recently used clean one
    /// other than `except`. Dirty slots are never chosen.
    fn victim(&self, except: Option<usize>) -> Option<usize> {
        let candidates = self
            .slots
            .iter()
            .enumerate()
            .filter(|&(i, _)| Some(i) != except);
        let mut best: Option<(usize, u64)> = None;
        for (i, s) in candidates {
            match s.state {
                State::Empty => return Some(i),
                State::Clean(_) => {
                    if best.is_none_or(|(_, stamp)| s.stamp < stamp) {
                        best = Some((i, s.stamp));
                    }
                }
                State::Dirty => {}
            }
        }
        best.map(|(i, _)| i)
    }

    /// Make slot `idx` hold `block` in `state`, invalidating old ids.
    fn occupy(&mut self, idx: usize, block: BlockNo, state: State) -> Option<SlotId> {
        let stamp = self.tick();
        let slot = self.slots.get_mut(idx)?;
        slot.block = block;
        slot.state = state;
        slot.stamp = stamp;
        slot.tag = slot.tag.wrapping_add(1);
        self.id_of(idx)
    }

    /// The clean entry for `block` if it holds exactly `hash`; refreshes its
    /// LRU position. A clean entry with another hash is a stale copy of a
    /// block that has since been reused, and does not match.
    pub fn lookup(&mut self, block: BlockNo, hash: &Hash) -> Option<SlotId> {
        let idx = self.position(block)?;
        if self.slots.get(idx)?.state != State::Clean(*hash) {
            return None;
        }
        let stamp = self.tick();
        if let Some(s) = self.slots.get_mut(idx) {
            s.stamp = stamp;
        }
        self.id_of(idx)
    }

    /// Verify `src` against `expected` under `rule`, then — only then — copy it
    /// into the slab as the clean entry for `block`.
    ///
    /// # Errors
    ///
    /// [`CacheError::Corrupt`] if the hash does not match (nothing cached);
    /// [`CacheError::Conflict`] if `block` has a dirty entry.
    pub fn insert_verified(
        &mut self,
        block: BlockNo,
        rule: HashRule,
        expected: &Hash,
        src: &Block,
    ) -> Result<SlotId, CacheError> {
        if !layout::verify(rule, src, expected) {
            return Err(CacheError::Corrupt);
        }
        let idx = match self.position(block) {
            Some(i) if self.slots.get(i).map(|s| s.state) == Some(State::Dirty) => {
                return Err(CacheError::Conflict)
            }
            Some(i) => i,
            None => self.victim(None).ok_or(CacheError::DirtyFull)?,
        };
        let dst = self.data.get_mut(idx).ok_or(CacheError::Stale)?;
        dst.copy_from_slice(src);
        self.occupy(idx, block, State::Clean(*expected))
            .ok_or(CacheError::Stale)
    }

    /// The bytes of a resident entry (clean or dirty), or `None` for a stale id.
    #[must_use]
    pub fn read(&self, id: SlotId) -> Option<&Block> {
        self.data.get(self.check(id)?)
    }

    /// Mutable bytes of a **dirty** entry. Clean entries are immutable: `None`.
    pub fn dirty_mut(&mut self, id: SlotId) -> Option<&mut Block> {
        let idx = self.check(id)?;
        if self.slots.get(idx)?.state != State::Dirty {
            return None;
        }
        self.data.get_mut(idx)
    }

    /// Start a dirty, zero-filled entry for `block`. A clean (now stale) copy
    /// of `block` is replaced.
    ///
    /// # Errors
    ///
    /// [`CacheError::DirtyFull`] at [`DIRTY_MAX`]; [`CacheError::Conflict`] if
    /// `block` already has a dirty entry.
    pub fn new_dirty(&mut self, block: BlockNo) -> Result<SlotId, CacheError> {
        let idx = self.dirty_slot_for(block, None)?;
        let dst = self.data.get_mut(idx).ok_or(CacheError::Stale)?;
        dst.fill(0);
        self.make_dirty(idx, block)
    }

    /// Copy-on-write: a new dirty entry for `block` holding a copy of the
    /// resident entry `src`. `src` itself is untouched (and stays resident).
    ///
    /// # Errors
    ///
    /// [`CacheError::Stale`] for a stale `src`, otherwise as
    /// [`new_dirty`](Self::new_dirty).
    pub fn copy_to_dirty(&mut self, src: SlotId, block: BlockNo) -> Result<SlotId, CacheError> {
        let from = self.check(src).ok_or(CacheError::Stale)?;
        if self.slots.get(from).map(|s| s.block) == Some(block) {
            // CoW onto the block being copied would overwrite a live block.
            return Err(CacheError::Conflict);
        }
        let idx = self.dirty_slot_for(block, Some(from))?;
        self.data.copy_within(from..from + 1, idx);
        self.make_dirty(idx, block)
    }

    /// Pick the slot a new dirty entry for `block` will occupy.
    fn dirty_slot_for(&self, block: BlockNo, except: Option<usize>) -> Result<usize, CacheError> {
        if self.dirty >= DIRTY_MAX {
            return Err(CacheError::DirtyFull);
        }
        match self.position(block) {
            Some(i) if self.slots.get(i).map(|s| s.state) == Some(State::Dirty) => {
                Err(CacheError::Conflict)
            }
            Some(i) if Some(i) != except => Ok(i),
            _ => self.victim(except).ok_or(CacheError::DirtyFull),
        }
    }

    fn make_dirty(&mut self, idx: usize, block: BlockNo) -> Result<SlotId, CacheError> {
        let id = self
            .occupy(idx, block, State::Dirty)
            .ok_or(CacheError::Stale)?;
        self.dirty += 1;
        Ok(id)
    }

    /// The transaction that wrote dirty entry `id` has committed: it becomes a
    /// clean, verified, immutable entry with hash `hash`.
    ///
    /// # Errors
    ///
    /// [`CacheError::Stale`] unless `id` names a dirty entry.
    pub fn mark_clean(&mut self, id: SlotId, hash: Hash) -> Result<(), CacheError> {
        let idx = self.check(id).ok_or(CacheError::Stale)?;
        let slot = self.slots.get_mut(idx).ok_or(CacheError::Stale)?;
        if slot.state != State::Dirty {
            return Err(CacheError::Stale);
        }
        slot.state = State::Clean(hash);
        self.dirty -= 1;
        Ok(())
    }

    /// Drop a **dirty** entry outright: the transaction that created it no
    /// longer references the block (a tree node merged away before it was
    /// ever committed), so its bytes must not be written. Frees one unit of
    /// the dirty budget.
    ///
    /// # Errors
    ///
    /// [`CacheError::Stale`] unless `id` names a dirty entry.
    pub fn discard_dirty(&mut self, id: SlotId) -> Result<(), CacheError> {
        let idx = self.check(id).ok_or(CacheError::Stale)?;
        let slot = self.slots.get_mut(idx).ok_or(CacheError::Stale)?;
        if slot.state != State::Dirty {
            return Err(CacheError::Stale);
        }
        slot.state = State::Empty;
        slot.tag = slot.tag.wrapping_add(1);
        self.dirty -= 1;
        Ok(())
    }

    /// Entries not dirty (clean or empty): what eviction may choose from.
    #[must_use]
    pub const fn not_dirty(&self) -> usize {
        CACHE_BLOCKS - self.dirty
    }

    /// The block a resident entry belongs to.
    #[must_use]
    pub fn block_of(&self, id: SlotId) -> Option<BlockNo> {
        self.slots.get(self.check(id)?).map(|s| s.block)
    }

    /// Drop the clean entry for `block`, if any. Dirty entries are never
    /// dropped. Returns whether something was evicted.
    pub fn evict(&mut self, block: BlockNo) -> bool {
        let Some(idx) = self.position(block) else {
            return false;
        };
        match self.slots.get_mut(idx) {
            Some(s) if matches!(s.state, State::Clean(_)) => {
                s.state = State::Empty;
                s.tag = s.tag.wrapping_add(1);
                true
            }
            _ => false,
        }
    }

    /// Whether `block` has a resident entry (clean or dirty).
    #[must_use]
    pub fn is_resident(&self, block: BlockNo) -> bool {
        self.position(block).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blk::layout::{seal_metadata, HEADER_LEN};

    /// A sealed metadata block whose payload starts with `tag`.
    fn sealed(tag: u8) -> (Blocks, Hash) {
        let mut b = zeroed_blocks(1);
        b[0][HEADER_LEN] = tag;
        let h = seal_metadata(&mut b[0]);
        (b, h)
    }

    #[test]
    fn verify_happens_before_entry() {
        let mut c = Cache::new();
        let (b, h) = sealed(1);
        let mut wrong = h;
        wrong[0] ^= 1;
        assert_eq!(
            c.insert_verified(BlockNo(7), HashRule::Metadata, &wrong, &b[0]),
            Err(CacheError::Corrupt)
        );
        assert!(
            !c.is_resident(BlockNo(7)),
            "a failing block is never resident"
        );
        let id = c
            .insert_verified(BlockNo(7), HashRule::Metadata, &h, &b[0])
            .unwrap();
        assert_eq!(c.read(id).unwrap()[HEADER_LEN], 1);
        assert_eq!(c.lookup(BlockNo(7), &h), Some(id));
        assert_eq!(c.lookup(BlockNo(7), &wrong), None);
    }

    #[test]
    fn clean_entries_are_immutable() {
        let mut c = Cache::new();
        let (b, h) = sealed(2);
        let id = c
            .insert_verified(BlockNo(3), HashRule::Metadata, &h, &b[0])
            .unwrap();
        assert!(c.dirty_mut(id).is_none());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn dirty_entries_are_unevictable_and_capped() {
        let mut c = Cache::new();
        let mut dirty = vec::Vec::new();
        for i in 0..DIRTY_MAX as u32 {
            dirty.push(c.new_dirty(BlockNo(1000 + i)).unwrap());
        }
        assert_eq!(c.new_dirty(BlockNo(5000)), Err(CacheError::DirtyFull));
        assert_eq!(c.dirty_room(), 0);
        // Stream far more clean blocks than the slab holds: every insert
        // succeeds and no dirty entry is lost.
        for i in 0..(3 * CACHE_BLOCKS) as u32 {
            let (b, h) = sealed(i as u8);
            c.insert_verified(BlockNo(i), HashRule::Metadata, &h, &b[0])
                .unwrap();
        }
        for (i, id) in dirty.iter().enumerate() {
            assert!(c.dirty_mut(*id).is_some(), "dirty entry {i} was evicted");
        }
        assert!(!c.evict(BlockNo(1000)), "evict never drops a dirty entry");
        // Committing one frees budget.
        c.mark_clean(dirty[0], [0; 32]).unwrap();
        assert_eq!(c.dirty_count(), DIRTY_MAX - 1);
        assert!(c.new_dirty(BlockNo(5000)).is_ok());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn lru_keeps_recently_used_entries() {
        let mut c = Cache::new();
        let mut hashes = vec::Vec::new();
        for i in 0..CACHE_BLOCKS as u32 {
            let (b, h) = sealed(i as u8);
            c.insert_verified(BlockNo(i), HashRule::Metadata, &h, &b[0])
                .unwrap();
            hashes.push(h);
        }
        // Touch block 0, then insert one more: block 1 (now LRU) goes.
        assert!(c.lookup(BlockNo(0), &hashes[0]).is_some());
        let (b, h) = sealed(200);
        c.insert_verified(BlockNo(500), HashRule::Metadata, &h, &b[0])
            .unwrap();
        assert!(c.is_resident(BlockNo(0)));
        assert!(!c.is_resident(BlockNo(1)));
    }

    #[test]
    fn stale_ids_read_as_none_and_cow_preserves_the_source() {
        let mut c = Cache::new();
        let (b, h) = sealed(9);
        let src = c
            .insert_verified(BlockNo(4), HashRule::Metadata, &h, &b[0])
            .unwrap();
        let cow = c.copy_to_dirty(src, BlockNo(5)).unwrap();
        assert_eq!(c.read(cow).unwrap()[HEADER_LEN], 9);
        c.dirty_mut(cow).unwrap()[HEADER_LEN] = 10;
        assert_eq!(c.read(src).unwrap()[HEADER_LEN], 9, "source untouched");
        assert_eq!(c.copy_to_dirty(src, BlockNo(4)), Err(CacheError::Conflict));
        assert!(c.evict(BlockNo(4)));
        assert!(c.read(src).is_none(), "evicted id is stale");
        assert_eq!(c.copy_to_dirty(src, BlockNo(6)), Err(CacheError::Stale));
        // A dirty block cannot also be inserted clean.
        let (b2, h2) = sealed(11);
        assert_eq!(
            c.insert_verified(BlockNo(5), HashRule::Metadata, &h2, &b2[0]),
            Err(CacheError::Conflict)
        );
        assert_eq!(c.new_dirty(BlockNo(5)), Err(CacheError::Conflict));
        // A clean copy of a block being rewritten is replaced, not duplicated.
        let id = c
            .insert_verified(BlockNo(8), HashRule::Metadata, &h2, &b2[0])
            .unwrap();
        let d = c.new_dirty(BlockNo(8)).unwrap();
        assert!(c.read(id).is_none());
        assert!(c.read(d).unwrap().iter().all(|&x| x == 0));
        assert_eq!(c.block_of(d), Some(BlockNo(8)));
    }

    #[test]
    fn discarding_a_dirty_entry_frees_its_budget_and_stales_its_id() {
        let mut c = Cache::new();
        let d = c.new_dirty(BlockNo(9)).unwrap();
        assert_eq!(c.dirty_count(), 1);
        c.discard_dirty(d).unwrap();
        assert_eq!(c.dirty_count(), 0);
        assert!(c.read(d).is_none());
        assert!(!c.is_resident(BlockNo(9)));
        assert_eq!(c.discard_dirty(d), Err(CacheError::Stale));
        let (b, h) = sealed(3);
        let id = c
            .insert_verified(BlockNo(4), HashRule::Metadata, &h, &b[0])
            .unwrap();
        assert_eq!(
            c.discard_dirty(id),
            Err(CacheError::Stale),
            "clean entries are not discarded"
        );
    }

    #[test]
    fn heap_footprint_is_the_slab_plus_the_slot_table() {
        let c = Cache::new();
        assert!(c.heap_bytes() >= CACHE_BLOCKS * 4096);
        assert!(c.heap_bytes() < CACHE_BLOCKS * 4096 + 8 * 1024);
    }
}
