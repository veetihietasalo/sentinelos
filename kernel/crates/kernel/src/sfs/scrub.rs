//! Scrub (spec §4, §11 FS-1b): read every block the committed generation can
//! reach, verify every hash, and check the structure that hashes alone do
//! not — then report, and name what is damaged.
//!
//! Reachable from a superblock: the superblock itself, the group index, every
//! group's bitmap, every node of the metadata tree, and every data block an
//! `EXTENT` item names (each against its own per-block hash, A3). For each:
//!
//! - **hash** — metadata blocks by the whole-block rule with the hash field
//!   zeroed (A1), data blocks by SHA-256 of the 4 KiB;
//! - **header** — kind, `tree_id`, uuid, and the generation the pointer names;
//! - **structure** — tree nodes decode (§7.2 checks), levels step down by
//!   one, every parent entry's key is exactly its child's lowest key, every
//!   item payload decodes for its kind;
//! - **allocation** — every reachable block is marked in use in its group's
//!   bitmap (§2 goal 1: "no live block marked free"); a reachable block that
//!   is marked free is damage to the free map.
//!
//! The scrub reads the **device**, never the cache: it runs on the
//! `sfs-commit` task with no lock held (A7), and since the task also does
//! every commit, no commit can run underneath it; mutations in memory only
//! ever write to blocks that are free in the committed state, never to one
//! the scrub reads. Counters are deterministic (`blocks`, `hashed`, §13:
//! hash cost reported as a count, never a wall-clock gate). Every loop is
//! bounded by a block's size or the tree's depth; nothing allocates after
//! [`ScrubWs::new`].

use super::key::{item as kinds, Key};
use super::superblock::{self, Superblock};
use super::tree::codec::{self, Span};
use super::tree::item::{Dirent, ExtentItem, Inode, Xattr};
use super::tree::node::Node;
use super::tree::{INNER_CAP, LEAF_CAP, MAX_LEVEL};
use crate::blk::allocator::encode_index;
use crate::blk::geometry::{Geometry, MAX_GROUPS};
use crate::blk::layout::{
    data_hash, decode_header, decode_pointer, metadata_hash, Hash, Kind, Pointer, TreeId, HASH_LEN,
    HEADER_LEN, POINTER_LEN,
};
use crate::blk::{bitmap, zeroed_blocks, BlkError, Block, BlockDevice, BlockNo, Blocks};
use alloc::boxed::Box;
use alloc::vec;

/// Damaged objects a report names (the count in `bad` is exact; past this
/// many the names are dropped).
pub const NAMED_MAX: usize = 8;

const LEVELS: usize = MAX_LEVEL as usize + 1;

/// What a damaged block was.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum What {
    /// The superblock the volume was mounted from.
    Superblock,
    /// The group index.
    Index,
    /// Group `g`'s bitmap.
    Bitmap(u32),
    /// A tree node at `level` whose subtree starts at `first` (the parent
    /// entry's key; the root's is the zero key).
    Node {
        /// Level of the node.
        level: u8,
        /// Lowest key its parent says it holds: the first object affected.
        first: Key,
    },
    /// Block `i` of the extent at `key` (the file object `key.obj`).
    Data {
        /// The `EXTENT` item's key.
        key: Key,
        /// Index of the block within the extent.
        i: u32,
    },
    /// A leaf item whose payload does not decode for its kind.
    Item(Key),
    /// A reachable block the bitmaps mark free.
    MarkedFree,
}

impl What {
    /// Fixed label for `fmt`-free console output.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            What::Superblock => "superblock",
            What::Index => "group-index",
            What::Bitmap(_) => "bitmap",
            What::Node { .. } => "tree-node",
            What::Data { .. } => "data",
            What::Item(_) => "item",
            What::MarkedFree => "marked-free",
        }
    }

    /// The object id a damaged block affects, where there is one.
    #[must_use]
    pub const fn obj(self) -> Option<u64> {
        match self {
            What::Node { first, .. } => Some(first.obj),
            What::Data { key, .. } | What::Item(key) => Some(key.obj),
            _ => None,
        }
    }
}

/// One damaged block.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Bad {
    /// Where.
    pub block: BlockNo,
    /// What it was.
    pub what: What,
}

impl Bad {
    const NONE: Bad = Bad {
        block: BlockNo(0),
        what: What::Superblock,
    };
}

/// What a scrub found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Report {
    /// Reachable blocks read.
    pub blocks: u64,
    /// Blocks hashed (every block read is hashed exactly once).
    pub hashed: u64,
    /// Damaged objects (hash, header, structure or allocation).
    pub bad: u64,
    /// The first [`NAMED_MAX`] of them.
    pub named: [Bad; NAMED_MAX],
    /// Tree nodes visited.
    pub nodes: u64,
    /// Leaf items checked.
    pub items: u64,
}

impl Report {
    const fn new() -> Report {
        Report {
            blocks: 0,
            hashed: 0,
            bad: 0,
            named: [Bad::NONE; NAMED_MAX],
            nodes: 0,
            items: 0,
        }
    }

    /// The named damaged objects.
    #[must_use]
    pub fn named(&self) -> &[Bad] {
        let n = usize::try_from(self.bad)
            .unwrap_or(NAMED_MAX)
            .min(NAMED_MAX);
        self.named.get(..n).unwrap_or(&[])
    }

    fn damage(&mut self, block: BlockNo, what: What) {
        if let Some(slot) = usize::try_from(self.bad)
            .ok()
            .and_then(|i| self.named.get_mut(i))
        {
            *slot = Bad { block, what };
        }
        self.bad += 1;
    }
}

/// Scrub scratch, allocated once (≈ 70 KiB): one block per tree level plus
/// one for data and one for the current bitmap, the decoded path, and the
/// group pointers.
pub struct ScrubWs {
    path: Blocks,
    data: Blocks,
    bitmap: Blocks,
    bitmap_group: Option<u32>,
    inner: Box<[Node<Pointer, INNER_CAP>]>,
    leaf: Box<[Node<Span, LEAF_CAP>]>,
    groups: Box<[Pointer]>,
}

impl Default for ScrubWs {
    fn default() -> Self {
        Self::new()
    }
}

impl ScrubWs {
    /// The workspace.
    #[must_use]
    pub fn new() -> ScrubWs {
        ScrubWs {
            path: zeroed_blocks(LEVELS),
            data: zeroed_blocks(1),
            bitmap: zeroed_blocks(1),
            bitmap_group: None,
            inner: super::tree::node::boxed(LEVELS, Pointer::NULL),
            leaf: super::tree::node::boxed(1, Span::EMPTY),
            groups: vec![Pointer::NULL; MAX_GROUPS as usize].into_boxed_slice(),
        }
    }
}

/// Read one block into `out`.
fn read<D: BlockDevice>(dev: &mut D, b: BlockNo, out: &mut Block) -> Result<(), BlkError> {
    dev.read_blocks(b, core::slice::from_mut(out))
}

/// Verify a metadata block read through `ptr`: hash, then header.
fn metadata_ok(block: &Block, ptr: &Pointer, kind: Kind, tree: TreeId, sb: &Superblock) -> bool {
    if block[..HASH_LEN] != ptr.hash[..] || metadata_hash(block) != ptr.hash {
        return false;
    }
    decode_header(block)
        .is_ok_and(|h| h.kind == kind && h.tree == tree && h.uuid == sb.uuid && h.gen == ptr.gen)
}

/// Scrub the committed state `sb` (whose superblock hashes to `sb_hash`, in
/// slot `slot`) on `dev`.
///
/// # Errors
///
/// The device's error; damage is reported, never an error.
pub fn scrub<D: BlockDevice>(
    dev: &mut D,
    ws: &mut ScrubWs,
    sb: &Superblock,
    sb_hash: &Hash,
    slot: u8,
) -> Result<Report, BlkError> {
    let mut r = Report::new();
    ws.bitmap_group = None;
    // 1. The superblock, as it is on the device now.
    let sb_block = BlockNo(u32::from(slot));
    let buf = ws.data.first_mut().ok_or(BlkError::BadBuffer)?;
    read(dev, sb_block, buf)?;
    r.blocks += 1;
    r.hashed += 1;
    if superblock::decode(buf, dev.blocks()).map_or(true, |(_, h)| h != *sb_hash) {
        r.damage(sb_block, What::Superblock);
    }
    let Ok(geo) = Geometry::new(sb.total_blocks) else {
        r.damage(sb_block, What::Superblock);
        return Ok(r);
    };
    // 2. The group index and every bitmap.
    let index_ok = scrub_free_space(dev, ws, sb, &geo, &mut r)?;
    // 3. The tree, and every extent's data.
    if !sb.root.is_null() {
        scrub_tree(dev, ws, sb, &geo, index_ok, &mut r)?;
    }
    Ok(r)
}

/// The index and the bitmaps; returns whether the index was intact (only then
/// can reachable blocks be checked against the bitmaps).
fn scrub_free_space<D: BlockDevice>(
    dev: &mut D,
    ws: &mut ScrubWs,
    sb: &Superblock,
    geo: &Geometry,
    r: &mut Report,
) -> Result<bool, BlkError> {
    let buf = ws.data.first_mut().ok_or(BlkError::BadBuffer)?;
    read(dev, sb.free.block, buf)?;
    r.blocks += 1;
    r.hashed += 1;
    let groups = geo.groups().min(MAX_GROUPS);
    let mut index_ok = metadata_ok(buf, &sb.free, Kind::GroupIndex, TreeId::Free, sb);
    if index_ok {
        for g in 0..groups as usize {
            let at = HEADER_LEN + g * POINTER_LEN;
            match buf.get(at..at + POINTER_LEN).map(decode_pointer) {
                Some(Ok(p)) => {
                    if let Some(slot) = ws.groups.get_mut(g) {
                        *slot = p;
                    }
                }
                _ => index_ok = false,
            }
        }
        // Canonical: re-encoding the pointers gives exactly this block.
        let mut copy = zeroed_blocks(1);
        if let Some(c) = copy.first_mut() {
            let ptrs = &ws.groups;
            encode_index(c, &sb.uuid, sb.free.gen, groups, |g| {
                ptrs.get(g as usize).copied().unwrap_or(Pointer::NULL)
            });
            index_ok &= c[HASH_LEN..] == buf[HASH_LEN..];
        }
    }
    if !index_ok {
        r.damage(sb.free.block, What::Index);
        return Ok(false);
    }
    for g in 0..groups {
        let p = ws.groups.get(g as usize).copied().unwrap_or(Pointer::NULL);
        let buf = ws.data.first_mut().ok_or(BlkError::BadBuffer)?;
        read(dev, p.block, buf)?;
        r.blocks += 1;
        r.hashed += 1;
        if !metadata_ok(buf, &p, Kind::Bitmap, TreeId::Free, sb) {
            r.damage(p.block, What::Bitmap(g));
        }
    }
    // The metadata the bitmaps must mark: both slots, the index, the bitmaps.
    for b in [BlockNo(0), BlockNo(1), sb.free.block] {
        check_marked(dev, ws, sb, geo, b, r)?;
    }
    for g in 0..groups {
        let p = ws.groups.get(g as usize).copied().unwrap_or(Pointer::NULL);
        check_marked(dev, ws, sb, geo, p.block, r)?;
    }
    Ok(true)
}

/// Count `b` as damage to the free map unless its group's bitmap marks it in
/// use. The bitmap of the group last asked about is kept; another group's is
/// read (and verified) without counting it again.
fn check_marked<D: BlockDevice>(
    dev: &mut D,
    ws: &mut ScrubWs,
    sb: &Superblock,
    geo: &Geometry,
    b: BlockNo,
    r: &mut Report,
) -> Result<(), BlkError> {
    let Some((g, bit)) = geo.locate(b) else {
        r.damage(b, What::MarkedFree);
        return Ok(());
    };
    if ws.bitmap_group != Some(g) {
        let p = ws.groups.get(g as usize).copied().unwrap_or(Pointer::NULL);
        let buf = ws.bitmap.first_mut().ok_or(BlkError::BadBuffer)?;
        read(dev, p.block, buf)?;
        if !metadata_ok(buf, &p, Kind::Bitmap, TreeId::Free, sb) {
            // Already counted as a bad bitmap; nothing in it can be trusted.
            ws.bitmap_group = None;
            return Ok(());
        }
        ws.bitmap_group = Some(g);
    }
    let bits = ws
        .bitmap
        .first()
        .and_then(|blk| blk.get(HEADER_LEN..))
        .unwrap_or(&[]);
    if bitmap::get(bits, bit) != Some(true) {
        r.damage(b, What::MarkedFree);
    }
    Ok(())
}

/// Depth-first over the tree with one block and one decoded node per level.
fn scrub_tree<D: BlockDevice>(
    dev: &mut D,
    ws: &mut ScrubWs,
    sb: &Superblock,
    geo: &Geometry,
    marks: bool,
    r: &mut Report,
) -> Result<(), BlkError> {
    // (pointer, expected level, expected first key) of the node to visit
    // next, and per level the index of the next child.
    let mut next = [0usize; LEVELS];
    let root_key = super::tree::node::KEY_ZERO;
    let mut top = None;
    let mut depth_ptr: [(Pointer, Key); LEVELS] = [(Pointer::NULL, root_key); LEVELS];
    let mut pending: Option<(Pointer, Option<u8>, Option<Key>)> = Some((sb.root, None, None));
    // Each iteration visits a node or pops a finished level: bounded by twice
    // the number of reachable nodes, itself bounded by the device.
    loop {
        if let Some((ptr, level, first)) = pending.take() {
            if let Some(l) = visit(dev, ws, sb, geo, marks, &ptr, level, first, r)? {
                top = top.or(Some(l));
                if l > 0 {
                    if let Some(n) = next.get_mut(usize::from(l)) {
                        *n = 0;
                    }
                    if let Some(d) = depth_ptr.get_mut(usize::from(l)) {
                        *d = (ptr, first.unwrap_or(root_key));
                    }
                }
            }
        }
        // Find the lowest internal level on the current path with a child
        // left to visit.
        let Some(t) = top else {
            return Ok(());
        };
        let mut found = None;
        for l in 1..=usize::from(t) {
            let Some(node) = ws.inner.get(l) else {
                continue;
            };
            let i = next.get(l).copied().unwrap_or(usize::MAX);
            if i < node.len() && depth_ptr.get(l).is_some_and(|d| !d.0.is_null()) {
                found = Some((l, i, node.key(i), node.val(i)));
                break;
            }
        }
        let Some((l, i, Some(k), Some(child))) = found else {
            return Ok(());
        };
        if let Some(n) = next.get_mut(l) {
            *n = i + 1;
        }
        // Everything below `l` is finished: forget it.
        for below in depth_ptr.iter_mut().take(l) {
            *below = (Pointer::NULL, root_key);
        }
        pending = Some((child, u8::try_from(l - 1).ok(), Some(k)));
    }
}

/// Visit one node: read, verify, decode into the per-level scratch, check
/// its items (and their data). Returns its level when it is intact.
#[allow(clippy::too_many_arguments)]
fn visit<D: BlockDevice>(
    dev: &mut D,
    ws: &mut ScrubWs,
    sb: &Superblock,
    geo: &Geometry,
    marks: bool,
    ptr: &Pointer,
    level: Option<u8>,
    first: Option<Key>,
    r: &mut Report,
) -> Result<Option<u8>, BlkError> {
    let first_key = first.unwrap_or(super::tree::node::KEY_ZERO);
    let bad_node = What::Node {
        level: level.unwrap_or(0),
        first: first_key,
    };
    let slot = usize::from(level.unwrap_or(MAX_LEVEL));
    let buf = ws.path.get_mut(slot).ok_or(BlkError::BadBuffer)?;
    read(dev, ptr.block, buf)?;
    r.blocks += 1;
    r.hashed += 1;
    r.nodes += 1;
    if marks {
        check_marked(dev, ws, sb, geo, ptr.block, r)?;
    }
    let buf = ws.path.get(slot).ok_or(BlkError::BadBuffer)?;
    if ptr.gen > sb.gen || !metadata_ok(buf, ptr, Kind::Node, TreeId::Root, sb) {
        r.damage(ptr.block, bad_node);
        return Ok(None);
    }
    let Ok((got, _)) = codec::decode_head(buf) else {
        r.damage(ptr.block, bad_node);
        return Ok(None);
    };
    if level.is_some_and(|l| l != got) {
        r.damage(ptr.block, bad_node);
        return Ok(None);
    }
    // The root sits in the slot of its own level from here on.
    if usize::from(got) != slot {
        let (a, b) = (slot.min(usize::from(got)), slot.max(usize::from(got)));
        if let (Some(_), Some(_)) = (ws.path.get(a), ws.path.get(b)) {
            ws.path.swap(a, b);
        }
    }
    let buf = ws.path.get(usize::from(got)).ok_or(BlkError::BadBuffer)?;
    if got > 0 {
        let node = ws
            .inner
            .get_mut(usize::from(got))
            .ok_or(BlkError::BadBuffer)?;
        if codec::decode_inner(buf, node).is_err() || first.is_some_and(|k| node.key(0) != Some(k))
        {
            node.clear();
            r.damage(ptr.block, bad_node);
            return Ok(None);
        }
        return Ok(Some(got));
    }
    if codec::decode_leaf(buf, 0, &mut ws.leaf[0]).is_err()
        || first.is_some_and(|k| ws.leaf[0].key(0) != Some(k))
    {
        r.damage(ptr.block, bad_node);
        return Ok(None);
    }
    for i in 0..ws.leaf[0].len() {
        let (Some(key), Some(span)) = (ws.leaf[0].key(i), ws.leaf[0].val(i)) else {
            continue;
        };
        r.items += 1;
        let buf = ws.path.first().ok_or(BlkError::BadBuffer)?;
        let Some(payload) = codec::span_bytes(buf, &span) else {
            r.damage(ptr.block, What::Item(key));
            continue;
        };
        let ok = match key.kind {
            kinds::INODE => Inode::decode(payload).is_ok(),
            kinds::DIRENT => Dirent::decode(payload).is_ok(),
            kinds::XATTR => Xattr::decode(payload).is_ok(),
            kinds::EXTENT => ExtentItem::decode(payload).is_ok(),
            // INLINE bytes are any bytes (≤ 1 KiB); other kinds are FS-2's.
            kinds::INLINE => payload.len() <= super::tree::item::INLINE_MAX,
            _ => true,
        };
        if !ok {
            r.damage(ptr.block, What::Item(key));
            continue;
        }
        if key.kind == kinds::EXTENT {
            scrub_extent(dev, ws, sb, geo, marks, key, span, r)?;
        }
    }
    Ok(Some(0))
}

/// Read and verify every data block of the extent item at `key`.
#[allow(clippy::too_many_arguments)]
fn scrub_extent<D: BlockDevice>(
    dev: &mut D,
    ws: &mut ScrubWs,
    sb: &Superblock,
    geo: &Geometry,
    marks: bool,
    key: Key,
    span: Span,
    r: &mut Report,
) -> Result<(), BlkError> {
    // At most MAX_EXTENT (32) blocks per item.
    for i in 0..crate::blk::geometry::MAX_EXTENT {
        let (b, want) = {
            let leaf_buf = ws.path.first().ok_or(BlkError::BadBuffer)?;
            let Some(e) =
                codec::span_bytes(leaf_buf, &span).and_then(|p| ExtentItem::decode(p).ok())
            else {
                return Ok(());
            };
            if i >= e.len {
                return Ok(());
            }
            let (Some(b), Some(h)) = (e.start.0.checked_add(i), e.hash(i)) else {
                return Ok(());
            };
            (BlockNo(b), h)
        };
        if u64::from(b.0) >= sb.total_blocks || b.0 < 2 {
            r.damage(b, What::Data { key, i });
            continue;
        }
        let buf = ws.data.first_mut().ok_or(BlkError::BadBuffer)?;
        read(dev, b, buf)?;
        r.blocks += 1;
        r.hashed += 1;
        if data_hash(buf) != want {
            r.damage(b, What::Data { key, i });
        }
        if marks {
            check_marked(dev, ws, sb, geo, b, r)?;
        }
    }
    Ok(())
}
