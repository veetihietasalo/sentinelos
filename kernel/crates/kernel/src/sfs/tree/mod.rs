//! The copy-on-write B+tree (spec §7.2, FS-1b): items keyed by
//! [`Key`], nodes are 4 KiB metadata blocks (kind 2), children are hashed
//! [`Pointer`]s.
//!
//! - [`node`] — the algebra, `Node<V, CAP>`: sorted entries, split at half,
//!   merge below a quarter, all deterministic. Kani proves it at `CAP = 4`.
//! - [`codec`] — the block encoding, separate from the algebra (decode checks,
//!   canonical leaf packing). Kani proves it total over a shrunken block.
//! - [`item`] — the leaf item payloads (`INODE`, `DIRENT`, `INLINE`,
//!   `EXTENT`, `XATTR`); their semantics are FS-2's.
//! - [`Tree`] (this file) — operations over the [`Cache`] and the
//!   [`Allocator`]: lookup, insert-or-replace, remove, iteration, and the seal
//!   that hashes the dirty nodes bottom-up at commit.
//!
//! # One operation, three steps
//!
//! A mutation is **planned in memory**, **preflighted**, then **applied**:
//!
//! 1. *Plan.* Walk from the root, decoding every node on the path (and, for a
//!    remove, the siblings a merge needs) into the fixed [`TreeWs`] — leaf
//!    bytes are copied, so nothing later depends on a cache entry staying
//!    resident. Apply the change to the decoded nodes: insert or remove the
//!    item, split overflowing nodes at half, rebalance underflowing ones with
//!    a sibling, keep every parent entry's key equal to its child's lowest
//!    key, grow or shrink the root. A non-resident node is reported as
//!    [`TreeError::Miss`] and nothing has changed.
//! 2. *Preflight.* Count what applying needs — one fresh block per node that
//!    is new or still clean (path copying: a node is copied once per
//!    transaction, then edited in place while dirty), one free per clean node
//!    replaced or dropped — and ask [`Allocator::check_ops`] whether exactly
//!    those calls, plus that many new dirty entries, can all succeed now.
//!    If not ([`TreeError::NeedCommit`], [`TreeError::NoSpace`], a bitmap
//!    [`TreeError::Miss`]), nothing has changed.
//! 3. *Apply.* Make the allocator calls, write every surviving node into its
//!    dirty entry (fresh blocks get `Pointer { block, hash: 0, gen: 0 }` in
//!    their parent until the seal), discard dirty entries of nodes merged
//!    away. No step here can be refused once the preflight passed; a failure
//!    would be a broken invariant ([`TreeError::Internal`]), and the volume
//!    goes read-only rather than publish it.
//!
//! So an operation is all-or-nothing in memory, and the commit protocol —
//! which only runs between operations — never sees half of one (§8).
//!
//! # Invariants every writer keeps and every reader checks
//!
//! - A node's level is its parent's minus one; leaves are level 0; the root
//!   is at most [`MAX_LEVEL`] (an insert that would grow past it is refused
//!   with [`TreeError::TreeFull`]).
//! - Keys are strictly increasing within a node, and every internal entry's
//!   key is **exactly the lowest key of its child** (checked at every step of
//!   every walk: a mismatch is [`TreeError::Corrupt`]).
//! - A committed node's header is `kind = Node`, the tree's `tree_id`, the
//!   filesystem's uuid, and the generation its pointer names; its hash is
//!   verified before it enters the cache (by [`Cache::insert_verified`]).
//! - Every ancestor of a dirty node is dirty (path copying), so the seal can
//!   hash children first and write each hash into its dirty parent.
//! - An empty tree is the null pointer; a non-root node is never empty.

pub mod codec;
pub mod item;
pub mod node;

use self::codec::{CodecError, Span};
use self::node::{Node, Rebalance};
use crate::blk::allocator::{AllocClass, AllocError, Allocator, DirtyRef};
use crate::blk::cache::{Cache, SlotId, DIRTY_MAX};
use crate::blk::layout::{
    decode_header, seal_metadata, Header, Kind, Pointer, TreeId, Uuid, HASH_LEN, HEADER_LEN,
    POINTER_LEN,
};
use crate::blk::{zeroed_blocks, BlockNo, Blocks, BLOCK_SIZE};
use crate::sfs::key::{Key, KEY_LEN};
use alloc::boxed::Box;
use alloc::vec;

/// Bytes before a node's entries: the metadata header plus the node head.
pub const NODE_HDR: usize = HEADER_LEN + 8;
/// A leaf table slot: key, `data_off`, `data_len`.
pub const LEAF_SLOT: usize = KEY_LEN + 4;
/// An internal entry: key and child pointer.
pub const CHILD_LEN: usize = KEY_LEN + POINTER_LEN;
/// Highest node level: four levels (0..=3) address millions of objects.
pub const MAX_LEVEL: u8 = 3;
/// Levels a path can have.
const LEVELS: usize = MAX_LEVEL as usize + 1;
/// Largest leaf item payload: an extent of 32 hashes (12 + 32 × 32 bytes).
/// Every item kind fits it ([`item`] checks at compile time), and it is at
/// most half a node, which the split argument needs.
pub const ITEM_MAX: usize = 1036;
/// The node payload limit at the real block size (the algebra's `limit`).
pub const LIMIT: u32 = codec::payload_limit(BLOCK_SIZE);
/// In-memory leaf capacity: a fitting leaf holds at most `LIMIT / 21` = 191
/// entries, a rebalance briefly holds two nodes' worth of an underflowing
/// pair (< 1.25 × `LIMIT`, so < 240 entries).
pub const LEAF_CAP: usize = 256;
/// In-memory internal capacity: 61 fit, a rebalanced pair < 78.
pub const INNER_CAP: usize = 80;

const _: () = {
    // Every entry is at most half a node, so a split at half always yields two
    // fitting, non-underflowing halves (node.rs).
    assert!(LEAF_SLOT + ITEM_MAX <= LIMIT as usize / 2);
    assert!(CHILD_LEN <= LIMIT as usize / 2);
    // The in-memory nodes hold an overflowing node and a rebalancing pair.
    assert!(LEAF_CAP * LEAF_SLOT > LIMIT as usize * 5 / 4 + LEAF_SLOT);
    assert!(INNER_CAP * CHILD_LEN > LIMIT as usize * 5 / 4 + CHILD_LEN);
};

/// Leaf spans: bytes of the path leaf (a copy), of its sibling (a copy), and
/// of the item being written.
const SRC_A: u8 = 0;
const SRC_B: u8 = 1;
const SRC_NEW: u8 = 2;

/// Why a tree operation was refused. Every refusal leaves the tree and the
/// allocator exactly as they were, except [`TreeError::Internal`] (the
/// volume goes read-only).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TreeError {
    /// Read this committed block into the cache (verified), then retry.
    Miss(Pointer),
    /// The dirty or pending budget is spent: commit, then retry.
    NeedCommit,
    /// No space for the blocks the operation needs.
    NoSpace,
    /// The item is over [`ITEM_MAX`] bytes.
    TooBig,
    /// The tree would grow past [`MAX_LEVEL`].
    TreeFull,
    /// A commit is in progress or the volume is read-only.
    Sealed,
    /// A verified node breaks a §7.2 rule or a tree invariant.
    Corrupt,
    /// A broken internal invariant.
    Internal,
}

impl TreeError {
    /// Fixed label for `fmt`-free console output.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            TreeError::Miss(_) => "miss",
            TreeError::NeedCommit => "need-commit",
            TreeError::NoSpace => "no-space",
            TreeError::TooBig => "too-big",
            TreeError::TreeFull => "tree-full",
            TreeError::Sealed => "sealed",
            TreeError::Corrupt => "corrupt",
            TreeError::Internal => "internal",
        }
    }
}

impl From<AllocError> for TreeError {
    fn from(e: AllocError) -> Self {
        match e {
            AllocError::Miss(p) => TreeError::Miss(p),
            AllocError::NeedCommit => TreeError::NeedCommit,
            AllocError::NoSpace => TreeError::NoSpace,
            AllocError::Sealed => TreeError::Sealed,
            AllocError::Corrupt => TreeError::Corrupt,
            AllocError::Invalid | AllocError::Cache(_) => TreeError::Internal,
        }
    }
}

impl From<CodecError> for TreeError {
    fn from(e: CodecError) -> Self {
        match e {
            CodecError::Corrupt => TreeError::Corrupt,
            CodecError::Size | CodecError::Source => TreeError::Internal,
        }
    }
}

/// A node of the current transaction: where it will be written, its cache
/// entry, its level.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct DirtyNode {
    block: BlockNo,
    slot: SlotId,
    level: u8,
    /// Set by the seal.
    hash: [u8; HASH_LEN],
}

impl DirtyNode {
    const NONE: DirtyNode = DirtyNode {
        block: BlockNo(0),
        slot: SlotId::NONE,
        level: 0,
        hash: [0; HASH_LEN],
    };
}

/// Where a node of a planned operation comes from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Origin {
    /// Not part of the plan.
    Unused,
    /// A committed node (read through `ptr`): replaced by a copy if it
    /// survives, freed either way.
    Clean(Pointer),
    /// A node already dirty in this transaction: edited in place, or
    /// discarded and freed if it does not survive.
    Dirty(BlockNo, SlotId),
    /// A node the operation creates (a split's right half, a new root).
    New,
}

/// One node position of a planned operation.
#[derive(Clone, Copy, Debug)]
struct Pos {
    origin: Origin,
    /// Whether the node survives the operation.
    live: bool,
    /// The block it is written to (known once applied).
    block: BlockNo,
}

impl Pos {
    const UNUSED: Pos = Pos {
        origin: Origin::Unused,
        live: false,
        block: BlockNo(0),
    };

    const fn new(origin: Origin) -> Pos {
        Pos {
            origin,
            live: true,
            block: BlockNo(0),
        }
    }
}

/// The plan of one operation, level by level: `a` is the node on the search
/// path, `b` the node beside it (a split's new right half, or the sibling a
/// rebalance used); `c` is the index, in `a`, of the entry that leads to the
/// level below.
#[derive(Clone, Copy, Debug)]
struct Level {
    a: Pos,
    b: Pos,
    c: usize,
}

impl Level {
    const EMPTY: Level = Level {
        a: Pos::UNUSED,
        b: Pos::UNUSED,
        c: 0,
    };
}

/// What the root becomes after an operation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum NewRoot {
    /// The tree is empty.
    Null,
    /// Node `a` (`false`) or `b` (`true`) of this level.
    At(usize, bool),
}

/// Fixed scratch for tree operations, allocated once with the volume (about
/// 50 KiB): the decoded path, siblings and splits, two leaf copies and the
/// item being written. Nothing allocates per operation.
pub struct TreeWs {
    leaf: [Node<Span, LEAF_CAP>; 2],
    /// `inner[l - 1][0/1]`: the `a` / `b` node of level `l`.
    inner: Box<[[Node<Pointer, INNER_CAP>; 2]]>,
    copies: Blocks,
    item: Box<[u8]>,
    levels: [Level; LEVELS + 1],
}

impl Default for TreeWs {
    fn default() -> Self {
        Self::new()
    }
}

impl TreeWs {
    /// The workspace.
    #[must_use]
    pub fn new() -> TreeWs {
        let pair = || [Node::new(Pointer::NULL), Node::new(Pointer::NULL)];
        TreeWs {
            leaf: [Node::new(Span::EMPTY), Node::new(Span::EMPTY)],
            inner: (0..LEVELS).map(|_| pair()).collect(),
            copies: zeroed_blocks(2),
            item: vec![0u8; ITEM_MAX].into_boxed_slice(),
            levels: [Level::EMPTY; LEVELS + 1],
        }
    }

    /// Heap bytes held.
    #[must_use]
    pub fn heap_bytes(&self) -> usize {
        let leaf = LEAF_CAP * (core::mem::size_of::<Key>() + core::mem::size_of::<Span>());
        let inner = INNER_CAP * (core::mem::size_of::<Key>() + core::mem::size_of::<Pointer>());
        2 * leaf + 2 * LEVELS * inner + core::mem::size_of_val(&*self.copies) + self.item.len()
    }

    fn inner(&self, level: usize, b: bool) -> Option<&Node<Pointer, INNER_CAP>> {
        self.inner
            .get(level.checked_sub(1)?)
            .map(|p| &p[usize::from(b)])
    }

    fn inner_mut(&mut self, level: usize, b: bool) -> Option<&mut Node<Pointer, INNER_CAP>> {
        self.inner
            .get_mut(level.checked_sub(1)?)
            .map(|p| &mut p[usize::from(b)])
    }

    fn level(&self, l: usize) -> Result<Level, TreeError> {
        self.levels.get(l).copied().ok_or(TreeError::Internal)
    }

    fn level_mut(&mut self, l: usize) -> Result<&mut Level, TreeError> {
        self.levels.get_mut(l).ok_or(TreeError::Internal)
    }

    /// The first key of node `a`/`b` at level `l`.
    fn first_key(&self, l: usize, b: bool) -> Option<Key> {
        if l == 0 {
            self.leaf.get(usize::from(b))?.key(0)
        } else {
            self.inner(l, b)?.key(0)
        }
    }

    fn is_empty(&self, l: usize, b: bool) -> bool {
        if l == 0 {
            self.leaf.get(usize::from(b)).is_none_or(Node::is_empty)
        } else {
            self.inner(l, b).is_none_or(Node::is_empty)
        }
    }

    fn underflows(&self, l: usize) -> bool {
        if l == 0 {
            self.leaf[0].underflows(LIMIT)
        } else {
            self.inner(l, false).is_some_and(|n| n.underflows(LIMIT))
        }
    }

    /// Rebalance `a` and `b` of level `l` (`b_left`: `b` is `a`'s left
    /// sibling). Returns whether they merged (the right one is then empty).
    fn rebalance(&mut self, l: usize, b_left: bool) -> Result<bool, TreeError> {
        let out = if l == 0 {
            let [a, b] = &mut self.leaf;
            if b_left {
                Node::rebalance(b, a, LIMIT)
            } else {
                Node::rebalance(a, b, LIMIT)
            }
        } else {
            let [a, b] = self.inner.get_mut(l - 1).ok_or(TreeError::Internal)?;
            if b_left {
                Node::rebalance(b, a, LIMIT)
            } else {
                Node::rebalance(a, b, LIMIT)
            }
        };
        match out {
            Ok(Rebalance::Merged) => Ok(true),
            Ok(Rebalance::Split(_)) => Ok(false),
            Err(_) => Err(TreeError::Internal),
        }
    }
}

/// One CoW B+tree of a mounted volume (FS-1b: the metadata tree, `tree_id
/// = Root`), with its transaction's dirty nodes.
pub struct Tree {
    tree_id: TreeId,
    uuid: Uuid,
    /// The committed root (the superblock's pointer).
    committed: Pointer,
    /// The working root: `committed`, or a dirty node (`hash`/`gen` zero
    /// until the seal), or null.
    root: Pointer,
    dirty: Box<[DirtyNode]>,
    ndirty: usize,
    /// The root the last seal produced.
    sealed: Option<Pointer>,
}

/// Header checks for a committed node read through `ptr`.
fn check_header(buf: &[u8], tree: TreeId, uuid: &Uuid, ptr: &Pointer) -> Result<(), TreeError> {
    let h = decode_header(buf).map_err(|_| TreeError::Corrupt)?;
    if h.kind != Kind::Node || h.tree != tree || h.uuid != *uuid || h.gen != ptr.gen {
        return Err(TreeError::Corrupt);
    }
    Ok(())
}

impl Tree {
    /// The tree named by `root` (null for empty) in filesystem `uuid`.
    #[must_use]
    pub fn new(tree_id: TreeId, uuid: Uuid, root: Pointer) -> Tree {
        Tree {
            tree_id,
            uuid,
            committed: root,
            root,
            dirty: vec![DirtyNode::NONE; DIRTY_MAX].into_boxed_slice(),
            ndirty: 0,
            sealed: None,
        }
    }

    /// The working root (dirty roots have a zero hash until sealed).
    #[must_use]
    pub const fn root(&self) -> Pointer {
        self.root
    }

    /// The committed root.
    #[must_use]
    pub const fn committed_root(&self) -> Pointer {
        self.committed
    }

    /// Dirty nodes in this transaction.
    #[must_use]
    pub const fn dirty_nodes(&self) -> usize {
        self.ndirty
    }

    /// Heap bytes held.
    #[must_use]
    pub fn heap_bytes(&self) -> usize {
        core::mem::size_of_val(&*self.dirty)
    }

    fn dirty_of(&self, block: BlockNo) -> Option<&DirtyNode> {
        self.dirty
            .iter()
            .take(self.ndirty)
            .find(|d| d.block == block)
    }

    /// The bytes of the node `ptr` names, and where they come from: the dirty
    /// copy if this transaction has one, else the verified committed copy
    /// (header checked) or a miss.
    fn node_bytes<'c>(
        &self,
        cache: &'c mut Cache,
        ptr: &Pointer,
    ) -> Result<(&'c [u8], Origin), TreeError> {
        if let Some(d) = self.dirty_of(ptr.block) {
            let (block, slot) = (d.block, d.slot);
            let bytes = cache.read(slot).ok_or(TreeError::Internal)?;
            return Ok((bytes, Origin::Dirty(block, slot)));
        }
        let id = cache
            .lookup(ptr.block, &ptr.hash)
            .ok_or(TreeError::Miss(*ptr))?;
        let bytes = cache.read(id).ok_or(TreeError::Miss(*ptr))?;
        check_header(bytes, self.tree_id, &self.uuid, ptr)?;
        Ok((bytes, Origin::Clean(*ptr)))
    }

    /// Load the node `ptr` names into position `b` of level `level` (leaf
    /// bytes are copied into `ws.copies[b]`). Checks the level and, when
    /// `first` is given, that the node's lowest key is exactly `first` (the
    /// parent entry's key).
    fn load(
        &self,
        cache: &mut Cache,
        ws: &mut TreeWs,
        ptr: &Pointer,
        level: Option<usize>,
        b: bool,
        first: Option<Key>,
    ) -> Result<(usize, Origin), TreeError> {
        let (bytes, origin) = self.node_bytes(cache, ptr)?;
        let (got, _) = codec::decode_head(bytes)?;
        let got = usize::from(got);
        if level.is_some_and(|l| l != got) {
            return Err(TreeError::Corrupt);
        }
        if got == 0 {
            let copy = ws
                .copies
                .get_mut(usize::from(b))
                .ok_or(TreeError::Internal)?;
            copy.copy_from_slice(bytes);
            let src = if b { SRC_B } else { SRC_A };
            let (copies, leaf) = (&ws.copies, &mut ws.leaf);
            let node = leaf.get_mut(usize::from(b)).ok_or(TreeError::Internal)?;
            let copy = copies.get(usize::from(b)).ok_or(TreeError::Internal)?;
            codec::decode_leaf(copy, src, node)?;
        } else {
            let node = ws.inner_mut(got, b).ok_or(TreeError::Internal)?;
            codec::decode_inner(bytes, node)?;
        }
        if first.is_some_and(|k| ws.first_key(got, b) != Some(k)) {
            return Err(TreeError::Corrupt);
        }
        Ok((got, origin))
    }

    /// Walk from the root towards `key`, filling `ws.levels[..=top].a` and
    /// the decoded path; returns the root's level (`None`: empty tree).
    fn walk(
        &self,
        cache: &mut Cache,
        ws: &mut TreeWs,
        key: &Key,
    ) -> Result<Option<usize>, TreeError> {
        ws.levels = [Level::EMPTY; LEVELS + 1];
        if self.root.is_null() {
            return Ok(None);
        }
        let (top, origin) = self.load(cache, ws, &self.root, None, false, None)?;
        ws.level_mut(top)?.a = Pos::new(origin);
        let mut l = top;
        while l > 0 {
            let node = ws.inner(l, false).ok_or(TreeError::Internal)?;
            let c = node.child_index(key);
            let (first, ptr) = (
                node.key(c).ok_or(TreeError::Internal)?,
                node.val(c).ok_or(TreeError::Internal)?,
            );
            ws.level_mut(l)?.c = c;
            let (_, origin) = self.load(cache, ws, &ptr, Some(l - 1), false, Some(first))?;
            ws.level_mut(l - 1)?.a = Pos::new(origin);
            l -= 1;
        }
        Ok(Some(top))
    }

    /// Copy the item at `key` into `out`; returns its length, or `None` if
    /// absent. `out` must hold [`ITEM_MAX`] bytes (or at least the item).
    ///
    /// # Errors
    ///
    /// [`TreeError::Miss`] (resolve and retry), [`TreeError::Corrupt`],
    /// [`TreeError::TooBig`] when `out` is too small for the item.
    pub fn get(
        &self,
        cache: &mut Cache,
        ws: &mut TreeWs,
        key: &Key,
        out: &mut [u8],
    ) -> Result<Option<usize>, TreeError> {
        if self.walk(cache, ws, key)?.is_none() {
            return Ok(None);
        }
        let leaf = &ws.leaf[0];
        let Ok(i) = leaf.search(key) else {
            return Ok(None);
        };
        let span = leaf.val(i).ok_or(TreeError::Internal)?;
        let data = codec::span_bytes(&ws.copies[0], &span).ok_or(TreeError::Corrupt)?;
        out.get_mut(..data.len())
            .ok_or(TreeError::TooBig)?
            .copy_from_slice(data);
        Ok(Some(data.len()))
    }

    /// The lowest key strictly above `after` (the lowest key overall for
    /// `None`), or `None` past the last. Stateless: iterate by feeding each
    /// result back.
    ///
    /// # Errors
    ///
    /// [`TreeError::Miss`] (resolve and retry), [`TreeError::Corrupt`].
    pub fn next_key(
        &self,
        cache: &mut Cache,
        ws: &mut TreeWs,
        after: Option<&Key>,
    ) -> Result<Option<Key>, TreeError> {
        let probe = after.copied().unwrap_or(node::KEY_ZERO);
        let Some(top) = self.walk(cache, ws, &probe)? else {
            return Ok(None);
        };
        let leaf = &ws.leaf[0];
        let i = match after {
            None => 0,
            Some(k) => match leaf.search(k) {
                Ok(i) => i + 1,
                Err(i) => i,
            },
        };
        if let Some(k) = leaf.key(i) {
            return Ok(Some(k));
        }
        // Past this leaf: the next subtree's lowest key is its parent entry's.
        for l in 1..=top {
            let c = ws.level(l)?.c;
            if let Some(k) = ws.inner(l, false).and_then(|n| n.key(c + 1)) {
                return Ok(Some(k));
            }
        }
        Ok(None)
    }

    /// Insert `data` at `key`, or replace the item already there.
    ///
    /// # Errors
    ///
    /// [`TreeError::TooBig`] past [`ITEM_MAX`]; otherwise as the module docs
    /// describe (every refusal changes nothing).
    pub fn put(
        &mut self,
        cache: &mut Cache,
        alloc: &mut Allocator,
        ws: &mut TreeWs,
        key: Key,
        data: &[u8],
    ) -> Result<(), TreeError> {
        if data.len() > ITEM_MAX {
            return Err(TreeError::TooBig);
        }
        ws.item
            .get_mut(..data.len())
            .ok_or(TreeError::TooBig)?
            .copy_from_slice(data);
        let span = Span {
            src: SRC_NEW,
            off: 0,
            len: data.len() as u16,
        };
        let root = self.plan_put(cache, ws, key, span)?;
        self.apply(cache, alloc, ws, root, AllocClass::Normal)
    }

    /// Remove the item at `key`; returns whether it was there.
    ///
    /// # Errors
    ///
    /// As [`put`](Self::put). A remove may use the metadata reserve
    /// (`AllocClass::Reclaim`, §5.8), so a full disk can always shrink.
    pub fn remove(
        &mut self,
        cache: &mut Cache,
        alloc: &mut Allocator,
        ws: &mut TreeWs,
        key: &Key,
    ) -> Result<bool, TreeError> {
        let Some(root) = self.plan_remove(cache, ws, key)? else {
            return Ok(false);
        };
        self.apply(cache, alloc, ws, root, AllocClass::Reclaim)?;
        Ok(true)
    }

    /// Plan an insert-or-replace (module docs, step 1).
    fn plan_put(
        &self,
        cache: &mut Cache,
        ws: &mut TreeWs,
        key: Key,
        span: Span,
    ) -> Result<NewRoot, TreeError> {
        let Some(top) = self.walk(cache, ws, &key)? else {
            let leaf = &mut ws.leaf[0];
            leaf.clear();
            leaf.push(key, span).map_err(|_| TreeError::Internal)?;
            ws.level_mut(0)?.a = Pos::new(Origin::New);
            return Ok(NewRoot::At(0, false));
        };
        {
            let [a, b] = &mut ws.leaf;
            let r = match a.search(&key) {
                Ok(i) => a.set_val(i, span),
                Err(i) => a.insert(i, key, span),
            };
            r.map_err(|_| TreeError::Internal)?;
            if a.overflows(LIMIT) {
                a.split(b).map_err(|_| TreeError::Internal)?;
                ws.levels[0].b = Pos::new(Origin::New);
            }
        }
        for l in 1..=top {
            let below = ws.level(l - 1)?;
            let c = ws.level(l)?.c;
            let a_key = ws.first_key(l - 1, false).ok_or(TreeError::Internal)?;
            let b_key = ws.first_key(l - 1, true);
            let [a, b] = ws.inner.get_mut(l - 1).ok_or(TreeError::Internal)?;
            a.set_key(c, a_key).map_err(|_| TreeError::Internal)?;
            if below.b.live {
                let b_key = b_key.ok_or(TreeError::Internal)?;
                a.insert(c + 1, b_key, Pointer::NULL)
                    .map_err(|_| TreeError::Internal)?;
            }
            if a.overflows(LIMIT) {
                a.split(b).map_err(|_| TreeError::Internal)?;
                ws.level_mut(l)?.b = Pos::new(Origin::New);
            }
        }
        if !ws.level(top)?.b.live {
            return Ok(NewRoot::At(top, false));
        }
        // The root split: a new root one level up.
        if top >= usize::from(MAX_LEVEL) {
            return Err(TreeError::TreeFull);
        }
        let (a_key, b_key) = (
            ws.first_key(top, false).ok_or(TreeError::Internal)?,
            ws.first_key(top, true).ok_or(TreeError::Internal)?,
        );
        let r = ws.inner_mut(top + 1, false).ok_or(TreeError::Internal)?;
        r.clear();
        r.push(a_key, Pointer::NULL)
            .and_then(|()| r.push(b_key, Pointer::NULL))
            .map_err(|_| TreeError::Internal)?;
        ws.level_mut(top + 1)?.a = Pos::new(Origin::New);
        Ok(NewRoot::At(top + 1, false))
    }

    /// Plan a remove (module docs, step 1); `None` if `key` is absent.
    fn plan_remove(
        &self,
        cache: &mut Cache,
        ws: &mut TreeWs,
        key: &Key,
    ) -> Result<Option<NewRoot>, TreeError> {
        let Some(top) = self.walk(cache, ws, key)? else {
            return Ok(None);
        };
        let Ok(i) = ws.leaf[0].search(key) else {
            return Ok(None);
        };
        ws.leaf[0].remove(i).map_err(|_| TreeError::Internal)?;
        for l in 0..top {
            let c = ws.level(l + 1)?.c;
            let plen = ws.inner(l + 1, false).map_or(0, Node::len);
            if !ws.underflows(l) {
                let k = ws.first_key(l, false).ok_or(TreeError::Internal)?;
                let p = ws.inner_mut(l + 1, false).ok_or(TreeError::Internal)?;
                p.set_key(c, k).map_err(|_| TreeError::Internal)?;
                continue;
            }
            if plen < 2 {
                // No sibling (the parent is a one-child root). An empty node
                // goes; otherwise the root collapse below takes care of it.
                if ws.is_empty(l, false) {
                    ws.level_mut(l)?.a.live = false;
                    let p = ws.inner_mut(l + 1, false).ok_or(TreeError::Internal)?;
                    p.remove(c).map_err(|_| TreeError::Internal)?;
                } else {
                    let k = ws.first_key(l, false).ok_or(TreeError::Internal)?;
                    let p = ws.inner_mut(l + 1, false).ok_or(TreeError::Internal)?;
                    p.set_key(c, k).map_err(|_| TreeError::Internal)?;
                }
                continue;
            }
            // Rebalance with the left sibling, or the right one for child 0.
            let b_left = c > 0;
            let s = if b_left { c - 1 } else { c + 1 };
            let p = ws.inner(l + 1, false).ok_or(TreeError::Internal)?;
            let (sk, sp) = (
                p.key(s).ok_or(TreeError::Internal)?,
                p.val(s).ok_or(TreeError::Internal)?,
            );
            let (_, origin) = self.load(cache, ws, &sp, Some(l), true, Some(sk))?;
            ws.level_mut(l)?.b = Pos::new(origin);
            let merged = ws.rebalance(l, b_left)?;
            let left = c.min(s);
            if merged {
                // Everything is in the left node; the right one goes.
                let lv = ws.level_mut(l)?;
                if b_left {
                    lv.a.live = false;
                } else {
                    lv.b.live = false;
                }
                let lk = ws.first_key(l, b_left).ok_or(TreeError::Internal)?;
                let p = ws.inner_mut(l + 1, false).ok_or(TreeError::Internal)?;
                p.remove(left + 1).map_err(|_| TreeError::Internal)?;
                p.set_key(left, lk).map_err(|_| TreeError::Internal)?;
            } else {
                let lk = ws.first_key(l, b_left).ok_or(TreeError::Internal)?;
                let rk = ws.first_key(l, !b_left).ok_or(TreeError::Internal)?;
                let p = ws.inner_mut(l + 1, false).ok_or(TreeError::Internal)?;
                p.set_key(left, lk)
                    .and_then(|()| p.set_key(left + 1, rk))
                    .map_err(|_| TreeError::Internal)?;
            }
        }
        // The root: gone when empty; an internal root with one child hands
        // the root to that child.
        if ws.is_empty(top, false) {
            ws.level_mut(top)?.a.live = false;
            return Ok(Some(NewRoot::Null));
        }
        if top > 0 && ws.inner(top, false).map_or(0, Node::len) == 1 {
            ws.level_mut(top)?.a.live = false;
            let below = ws.level(top - 1)?;
            let b = !below.a.live;
            if b && !below.b.live {
                return Err(TreeError::Internal);
            }
            return Ok(Some(NewRoot::At(top - 1, b)));
        }
        Ok(Some(NewRoot::At(top, false)))
    }

    /// Steps 2 and 3: preflight the plan against the allocator and the cache,
    /// then apply it.
    fn apply(
        &mut self,
        cache: &mut Cache,
        alloc: &mut Allocator,
        ws: &mut TreeWs,
        root: NewRoot,
        class: AllocClass,
    ) -> Result<(), TreeError> {
        // Count, in the fixed order applying uses (level by level, a then b).
        let mut allocs = 0u32;
        let mut frees = [BlockNo(0); 2 * (LEVELS + 1)];
        let mut nfrees = 0usize;
        let mut hint = None;
        for lv in ws.levels.iter() {
            for pos in [lv.a, lv.b] {
                match pos.origin {
                    Origin::Unused => {}
                    Origin::New => allocs += u32::from(pos.live),
                    Origin::Clean(p) => {
                        allocs += u32::from(pos.live);
                        *frees.get_mut(nfrees).ok_or(TreeError::Internal)? = p.block;
                        nfrees += 1;
                        hint = hint.or_else(|| alloc.geometry().locate(p.block).map(|g| g.0));
                    }
                    Origin::Dirty(b, _) => {
                        hint = hint.or_else(|| alloc.geometry().locate(b).map(|g| g.0));
                        if !pos.live {
                            *frees.get_mut(nfrees).ok_or(TreeError::Internal)? = b;
                            nfrees += 1;
                        }
                    }
                }
            }
        }
        let frees = frees.get(..nfrees).ok_or(TreeError::Internal)?;
        let new_nodes = allocs as usize;
        if self.ndirty + new_nodes > self.dirty.len() {
            return Err(TreeError::NeedCommit);
        }
        alloc.check_ops(cache, allocs, hint, frees, class, new_nodes)?;
        // Past the preflight nothing may be refused: any error is a broken
        // invariant and the caller makes the volume read-only.
        self.apply_checked(cache, alloc, ws, root, class, hint, frees)
            .map_err(|_| TreeError::Internal)
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_checked(
        &mut self,
        cache: &mut Cache,
        alloc: &mut Allocator,
        ws: &mut TreeWs,
        root: NewRoot,
        class: AllocClass,
        hint: Option<u32>,
        frees: &[BlockNo],
    ) -> Result<(), TreeError> {
        // 1. Every allocation, then every free, in the preflight's order.
        for lv in ws.levels.iter_mut() {
            for pos in [&mut lv.a, &mut lv.b] {
                match pos.origin {
                    Origin::Unused => {}
                    Origin::Dirty(b, _) => pos.block = b,
                    Origin::New | Origin::Clean(_) => {
                        if pos.live {
                            pos.block = alloc.alloc(cache, class, hint)?;
                        }
                    }
                }
            }
        }
        for &b in frees {
            alloc.free(cache, b)?;
        }
        // 2. Drop dirty nodes that did not survive.
        for lv in ws.levels {
            for pos in [lv.a, lv.b] {
                if let (Origin::Dirty(b, slot), false) = (pos.origin, pos.live) {
                    cache.discard_dirty(slot).map_err(|_| TreeError::Internal)?;
                    self.forget(b)?;
                }
            }
        }
        // 3. Bottom-up: point each parent at its children's blocks, then write
        //    every surviving node into its dirty entry.
        for l in 0..=LEVELS {
            let lv = ws.level(l)?;
            for (pos, b) in [(lv.a, false), (lv.b, true)] {
                if !pos.live {
                    continue;
                }
                if l < LEVELS {
                    self.point_parent(ws, l, b, pos.block)?;
                }
                let slot = match pos.origin {
                    Origin::Dirty(_, slot) => slot,
                    Origin::New | Origin::Clean(_) => {
                        let slot = cache
                            .new_dirty(pos.block)
                            .map_err(|_| TreeError::Internal)?;
                        self.remember(pos.block, slot, l)?;
                        slot
                    }
                    Origin::Unused => return Err(TreeError::Internal),
                };
                let out = cache.dirty_mut(slot).ok_or(TreeError::Internal)?;
                if l == 0 {
                    let srcs: [&[u8]; 3] = [&ws.copies[0], &ws.copies[1], &ws.item];
                    let node = ws.leaf.get(usize::from(b)).ok_or(TreeError::Internal)?;
                    codec::encode_leaf(node, &srcs, out)?;
                } else {
                    let node = ws.inner(l, b).ok_or(TreeError::Internal)?;
                    codec::encode_inner(node, l as u8, out)?;
                }
            }
        }
        // 4. The root.
        self.root = match root {
            NewRoot::Null => Pointer::NULL,
            NewRoot::At(l, b) => {
                let lv = ws.level(l)?;
                let pos = if b { lv.b } else { lv.a };
                if !pos.live {
                    return Err(TreeError::Internal);
                }
                Pointer {
                    block: pos.block,
                    hash: [0; HASH_LEN],
                    gen: 0,
                }
            }
        };
        Ok(())
    }

    /// Point the parent entry of node `b` at level `l` (found by its exact
    /// lowest key in level `l + 1`'s surviving nodes) at `block`. A node with
    /// no surviving parent is the new root (or the collapsed root's child).
    fn point_parent(
        &self,
        ws: &mut TreeWs,
        l: usize,
        b: bool,
        block: BlockNo,
    ) -> Result<(), TreeError> {
        let up = ws.level(l + 1)?;
        if !up.a.live && !up.b.live {
            return Ok(());
        }
        let k = ws.first_key(l, b).ok_or(TreeError::Internal)?;
        let ptr = Pointer {
            block,
            hash: [0; HASH_LEN],
            gen: 0,
        };
        for (pos, pb) in [(up.a, false), (up.b, true)] {
            if !pos.live {
                continue;
            }
            let p = ws.inner_mut(l + 1, pb).ok_or(TreeError::Internal)?;
            if let Ok(i) = p.search(&k) {
                return p.set_val(i, ptr).map_err(|_| TreeError::Internal);
            }
        }
        Err(TreeError::Internal)
    }

    fn remember(&mut self, block: BlockNo, slot: SlotId, level: usize) -> Result<(), TreeError> {
        let d = self.dirty.get_mut(self.ndirty).ok_or(TreeError::Internal)?;
        *d = DirtyNode {
            block,
            slot,
            level: u8::try_from(level).map_err(|_| TreeError::Internal)?,
            hash: [0; HASH_LEN],
        };
        self.ndirty += 1;
        Ok(())
    }

    fn forget(&mut self, block: BlockNo) -> Result<(), TreeError> {
        let i = self
            .dirty
            .iter()
            .take(self.ndirty)
            .position(|d| d.block == block)
            .ok_or(TreeError::Internal)?;
        let last = self.ndirty - 1;
        self.dirty.swap(i, last);
        self.ndirty = last;
        Ok(())
    }

    /// Seal the transaction for generation `gen`: stamp and hash every dirty
    /// node, children before parents, writing each hash into its dirty parent
    /// (or the root pointer). Returns the new root pointer. Bounded:
    /// ≤ [`DIRTY_MAX`] nodes, each parent search ≤ `DIRTY_MAX × 61` entries.
    ///
    /// # Errors
    ///
    /// [`TreeError::Internal`] if a dirty node has no dirty parent and is not
    /// the root (path copying broke), or a cache entry went missing.
    pub fn seal(&mut self, cache: &mut Cache, gen: u64) -> Result<Pointer, TreeError> {
        for level in 0..=MAX_LEVEL {
            for i in 0..self.ndirty {
                let d = *self.dirty.get(i).ok_or(TreeError::Internal)?;
                if d.level != level {
                    continue;
                }
                let buf = cache.dirty_mut(d.slot).ok_or(TreeError::Internal)?;
                let header = Header {
                    hash: [0; HASH_LEN],
                    gen,
                    kind: Kind::Node,
                    tree: self.tree_id,
                    uuid: self.uuid,
                };
                header.encode(buf).map_err(|_| TreeError::Internal)?;
                let hash = seal_metadata(buf);
                if let Some(slot) = self.dirty.get_mut(i) {
                    slot.hash = hash;
                }
                let ptr = Pointer {
                    block: d.block,
                    hash,
                    gen,
                };
                if self.root.block == d.block {
                    self.root = ptr;
                } else {
                    self.point_dirty_parent(cache, &d, &ptr)?;
                }
            }
        }
        if self.ndirty > 0 && (self.root.is_null() || self.root.gen != gen) {
            // A dirty tree whose root was not among its dirty nodes.
            return Err(TreeError::Internal);
        }
        self.sealed = Some(self.root);
        Ok(self.root)
    }

    fn point_dirty_parent(
        &self,
        cache: &mut Cache,
        child: &DirtyNode,
        ptr: &Pointer,
    ) -> Result<(), TreeError> {
        for p in self.dirty.iter().take(self.ndirty) {
            if p.level != child.level + 1 {
                continue;
            }
            let buf = cache.dirty_mut(p.slot).ok_or(TreeError::Internal)?;
            let (_, n) = codec::decode_head(buf).map_err(|_| TreeError::Internal)?;
            for i in 0..n {
                if codec::child_block_at(buf, i) == Some(child.block.0) {
                    return codec::set_child_pointer(buf, i, ptr).map_err(|_| TreeError::Internal);
                }
            }
        }
        Err(TreeError::Internal)
    }

    /// The sealed dirty nodes, for the commit plan; returns how many were
    /// written into `out`.
    ///
    /// # Errors
    ///
    /// [`TreeError::Internal`] if not sealed or `out` is too small.
    pub fn sealed_entries(&self, out: &mut [DirtyRef]) -> Result<usize, TreeError> {
        if self.sealed.is_none() {
            return Err(TreeError::Internal);
        }
        for (i, d) in self.dirty.iter().take(self.ndirty).enumerate() {
            *out.get_mut(i).ok_or(TreeError::Internal)? = DirtyRef {
                slot: d.slot,
                block: d.block,
                hash: d.hash,
            };
        }
        Ok(self.ndirty)
    }

    /// The sealed transaction is durable: its root is the committed one. The
    /// caller marks the cache entries clean (with the hashes
    /// [`sealed_entries`](Self::sealed_entries) reported).
    pub fn commit_done(&mut self) {
        if let Some(root) = self.sealed.take() {
            self.committed = root;
            self.root = root;
        }
        self.ndirty = 0;
    }
}

#[cfg(test)]
mod tests;
