//! The tree-node block encoding (spec §7.2), kept apart from the node algebra
//! ([`super::node`]) so the algebra can be proven at `CAP = 4` and the
//! encoding at a shrunken block (A19), each without the other.
//!
//! Every function here works on a byte slice whose **length is the block
//! size**: 4096 in the kernel, 128–160 bytes in the Kani harnesses. Bytes
//! `[0, 64)` are the metadata header ([`crate::blk::layout`]), which the tree
//! stamps and seals itself; this module reads and writes only `[64, len)`:
//!
//! ```text
//!  64   1  level (0 = leaf)   65  1  pad = 0   66  2  nitems   68  4  pad = 0
//!  72  …   internal: nitems × { Key (17 B), Pointer (48 B) }
//!          leaf:     nitems × { Key, data_off u16, data_len u16 } then the item
//!                    data packed from the end of the block backwards
//! ```
//!
//! # What decoding checks (all `Corrupt` on failure)
//!
//! - pads zero, `level ≤ MAX_LEVEL`, `nitems ≥ 1`, the table inside the block;
//! - keys strictly increasing;
//! - leaf: **canonical packing** — item 0's data ends at the end of the
//!   block, every later item's data ends where the previous one starts, each
//!   `data_len ≤ ITEM_MAX`, and every data range starts at or after the end of
//!   the table. That is stronger than the spec's "`72 + 21·nitems ≤
//!   data_off`, `data_off + data_len ≤ len`, no overlap" (it implies all three)
//!   and it makes the encoding a function of the items, so the bytes between
//!   the table and the data — which the encoder zeroes — must be zero too;
//! - internal: every pointer canonical (pad zero), non-null, at block ≥ 2.
//!
//! Every loop is bounded by `nitems`, which is itself bounded by the block
//! length before the loop starts (never by the raw on-disk field), and every
//! read is a checked `get`: decoding is total over any bytes.

use super::node::{Entry, Node, NodeError};
use super::{CHILD_LEN, ITEM_MAX, LEAF_SLOT, MAX_LEVEL, NODE_HDR};
use crate::blk::layout::{decode_pointer, Pointer, HEADER_LEN, POINTER_LEN};
use crate::sfs::key::{Key, KEY_LEN};

/// Offset of the `level` byte.
const OFF_LEVEL: usize = HEADER_LEN;
/// Offset of the `nitems` field.
const OFF_NITEMS: usize = HEADER_LEN + 2;

/// Why a node failed to decode or encode.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CodecError {
    /// The block breaks a §7.2 rule (decode).
    Corrupt,
    /// The node does not fit the block, or its in-memory form overflowed
    /// (encode / decode into too small a `Node`).
    Size,
    /// A leaf item names a data source the encoder was not given.
    Source,
}

impl CodecError {
    /// Fixed label for `fmt`-free console output.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            CodecError::Corrupt => "corrupt",
            CodecError::Size => "size",
            CodecError::Source => "source",
        }
    }
}

impl From<NodeError> for CodecError {
    fn from(e: NodeError) -> Self {
        match e {
            NodeError::Full => CodecError::Size,
            NodeError::Index | NodeError::Order => CodecError::Corrupt,
        }
    }
}

/// A leaf item's data, by reference: `len` bytes at `off` of source `src`
/// (the encoder's `sources[src]`). Its weight is its table slot plus its data.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Span {
    /// Which source buffer holds the bytes.
    pub src: u8,
    /// Offset in that buffer.
    pub off: u16,
    /// Length (≤ [`ITEM_MAX`]).
    pub len: u16,
}

impl Span {
    /// A placeholder for unused slots.
    pub const EMPTY: Span = Span {
        src: 0,
        off: 0,
        len: 0,
    };
}

impl Entry for Span {
    fn weight(&self) -> u32 {
        LEAF_SLOT as u32 + u32::from(self.len)
    }
}

impl Entry for Pointer {
    fn weight(&self) -> u32 {
        CHILD_LEN as u32
    }
}

/// Payload bytes a node may use in a block of `block_len` bytes (the
/// algebra's `limit`).
#[must_use]
pub const fn payload_limit(block_len: usize) -> u32 {
    block_len.saturating_sub(NODE_HDR) as u32
}

fn u16_at(buf: &[u8], off: usize) -> Option<u16> {
    let b = buf.get(off..off.checked_add(2)?)?;
    Some(u16::from_le_bytes([*b.first()?, *b.get(1)?]))
}

fn put_u16(buf: &mut [u8], off: usize, v: u16) -> Result<(), CodecError> {
    buf.get_mut(off..off + 2)
        .ok_or(CodecError::Size)?
        .copy_from_slice(&v.to_le_bytes());
    Ok(())
}

/// The node head: `(level, nitems)`, with the pads and the level bound
/// checked and `nitems ≥ 1`.
///
/// # Errors
///
/// [`CodecError::Corrupt`] for a short block, a non-zero pad, a level past
/// [`MAX_LEVEL`] or zero items.
pub fn decode_head(buf: &[u8]) -> Result<(u8, usize), CodecError> {
    let head = buf.get(HEADER_LEN..NODE_HDR).ok_or(CodecError::Corrupt)?;
    let level = *head.first().ok_or(CodecError::Corrupt)?;
    let pad1 = *head.get(1).ok_or(CodecError::Corrupt)?;
    let pad2 = head.get(4..8).ok_or(CodecError::Corrupt)?;
    if pad1 != 0 || pad2.iter().any(|&b| b != 0) || level > MAX_LEVEL {
        return Err(CodecError::Corrupt);
    }
    let n = usize::from(u16_at(buf, OFF_NITEMS).ok_or(CodecError::Corrupt)?);
    if n == 0 {
        return Err(CodecError::Corrupt);
    }
    Ok((level, n))
}

/// Most entries of `stride` bytes a block of `block_len` bytes can hold.
const fn max_entries(block_len: usize, stride: usize) -> usize {
    block_len.saturating_sub(NODE_HDR) / stride
}

/// Whether `buf[from..to]` is all zero, scanning the payload by position so
/// the loop's bound is the block length (not the on-disk offsets).
fn zero_between(buf: &[u8], from: usize, to: usize) -> bool {
    buf.iter()
        .enumerate()
        .skip(NODE_HDR)
        .all(|(j, &b)| j < from || j >= to || b == 0)
}

/// The key of entry `i` of a node whose entries are `stride` bytes.
fn key_at(buf: &[u8], i: usize, stride: usize) -> Result<Key, CodecError> {
    let at = NODE_HDR + i * stride;
    let bytes = buf.get(at..at + KEY_LEN).ok_or(CodecError::Corrupt)?;
    Key::decode(bytes).map_err(|_| CodecError::Corrupt)
}

/// Decode a leaf into `out` (cleared first); each item's [`Span`] names
/// source `src` (this block's bytes as the encoder will be given them).
///
/// # Errors
///
/// [`CodecError::Corrupt`] for anything that breaks §7.2 (module docs) or a
/// non-leaf; [`CodecError::Size`] if `out` has fewer than `nitems` slots.
pub fn decode_leaf<const C: usize>(
    buf: &[u8],
    src: u8,
    out: &mut Node<Span, C>,
) -> Result<(), CodecError> {
    out.clear();
    let (level, n) = decode_head(buf)?;
    if level != 0 {
        return Err(CodecError::Corrupt);
    }
    let table_end = n
        .checked_mul(LEAF_SLOT)
        .and_then(|t| t.checked_add(NODE_HDR))
        .filter(|&end| end <= buf.len())
        .ok_or(CodecError::Corrupt)?;
    let mut cursor = buf.len();
    // The loop bound is the most items the block can hold — a constant of
    // the block length, never the on-disk count (`n` only ends it early).
    for i in 0..max_entries(buf.len(), LEAF_SLOT) {
        if i >= n {
            break;
        }
        let slot = NODE_HDR + i * LEAF_SLOT;
        let key = key_at(buf, i, LEAF_SLOT)?;
        let off = u16_at(buf, slot + KEY_LEN).ok_or(CodecError::Corrupt)?;
        let len = u16_at(buf, slot + KEY_LEN + 2).ok_or(CodecError::Corrupt)?;
        if usize::from(len) > ITEM_MAX {
            return Err(CodecError::Corrupt);
        }
        let start = cursor
            .checked_sub(usize::from(len))
            .filter(|&s| s >= table_end && s == usize::from(off))
            .ok_or(CodecError::Corrupt)?;
        out.push(key, Span { src, off, len })?;
        cursor = start;
    }
    // Canonical: nothing but zeros between the table and the data.
    if !zero_between(buf, table_end, cursor) {
        return Err(CodecError::Corrupt);
    }
    Ok(())
}

/// Decode an internal node into `out` (cleared first); returns its level.
///
/// # Errors
///
/// [`CodecError::Corrupt`] for anything that breaks §7.2, a leaf, or a
/// pointer that is non-canonical, null, or below block 2;
/// [`CodecError::Size`] if `out` has fewer than `nitems` slots.
pub fn decode_inner<const C: usize>(
    buf: &[u8],
    out: &mut Node<Pointer, C>,
) -> Result<u8, CodecError> {
    out.clear();
    let (level, n) = decode_head(buf)?;
    if level == 0 {
        return Err(CodecError::Corrupt);
    }
    let end = n
        .checked_mul(CHILD_LEN)
        .and_then(|t| t.checked_add(NODE_HDR))
        .filter(|&end| end <= buf.len())
        .ok_or(CodecError::Corrupt)?;
    for i in 0..max_entries(buf.len(), CHILD_LEN) {
        if i >= n {
            break;
        }
        let key = key_at(buf, i, CHILD_LEN)?;
        let at = NODE_HDR + i * CHILD_LEN + KEY_LEN;
        let ptr = buf
            .get(at..at + POINTER_LEN)
            .ok_or(CodecError::Corrupt)
            .and_then(|b| decode_pointer(b).map_err(|_| CodecError::Corrupt))?;
        if ptr.is_null() || ptr.block.0 < 2 {
            return Err(CodecError::Corrupt);
        }
        out.push(key, ptr)?;
    }
    if !zero_between(buf, end, buf.len()) {
        return Err(CodecError::Corrupt);
    }
    Ok(level)
}

/// Write the head and zero everything after it.
fn start(out: &mut [u8], level: u8, n: usize) -> Result<(), CodecError> {
    let n = u16::try_from(n).map_err(|_| CodecError::Size)?;
    out.get_mut(HEADER_LEN..).ok_or(CodecError::Size)?.fill(0);
    *out.get_mut(OFF_LEVEL).ok_or(CodecError::Size)? = level;
    put_u16(out, OFF_NITEMS, n)
}

/// Encode a leaf into `out[64..]` (the header is the caller's), canonically
/// packed (module docs). `sources[s]` holds the bytes every span with
/// `src == s` points into.
///
/// # Errors
///
/// [`CodecError::Size`] if the node is empty, does not fit, or an item is
/// over [`ITEM_MAX`]; [`CodecError::Source`] for a span outside its source.
pub fn encode_leaf<const C: usize>(
    node: &Node<Span, C>,
    sources: &[&[u8]],
    out: &mut [u8],
) -> Result<(), CodecError> {
    let n = node.len();
    if n == 0 || node.weight() > u64::from(payload_limit(out.len())) {
        return Err(CodecError::Size);
    }
    start(out, 0, n)?;
    let mut cursor = out.len();
    // Bounded by the node's capacity (a constant), ended early at `n`.
    for i in 0..C {
        if i >= n {
            break;
        }
        let (key, span) = (
            node.key(i).ok_or(CodecError::Size)?,
            node.val(i).ok_or(CodecError::Size)?,
        );
        let len = usize::from(span.len);
        if len > ITEM_MAX {
            return Err(CodecError::Size);
        }
        let from = usize::from(span.off);
        let data = sources
            .get(usize::from(span.src))
            .and_then(|s| s.get(from..from.checked_add(len)?))
            .ok_or(CodecError::Source)?;
        cursor = cursor.checked_sub(len).ok_or(CodecError::Size)?;
        out.get_mut(cursor..cursor + len)
            .ok_or(CodecError::Size)?
            .copy_from_slice(data);
        let slot = NODE_HDR + i * LEAF_SLOT;
        out.get_mut(slot..slot + KEY_LEN)
            .ok_or(CodecError::Size)?
            .copy_from_slice(&key.encode());
        let off = u16::try_from(cursor).map_err(|_| CodecError::Size)?;
        put_u16(out, slot + KEY_LEN, off)?;
        put_u16(out, slot + KEY_LEN + 2, span.len)?;
    }
    Ok(())
}

/// Encode an internal node at `level` (≥ 1) into `out[64..]`.
///
/// # Errors
///
/// [`CodecError::Size`] if the node is empty, the level is out of range, or
/// the node does not fit.
pub fn encode_inner<const C: usize>(
    node: &Node<Pointer, C>,
    level: u8,
    out: &mut [u8],
) -> Result<(), CodecError> {
    let n = node.len();
    if n == 0 || level == 0 || level > MAX_LEVEL {
        return Err(CodecError::Size);
    }
    if node.weight() > u64::from(payload_limit(out.len())) {
        return Err(CodecError::Size);
    }
    start(out, level, n)?;
    for i in 0..C {
        if i >= n {
            break;
        }
        let (key, ptr) = (
            node.key(i).ok_or(CodecError::Size)?,
            node.val(i).ok_or(CodecError::Size)?,
        );
        let at = NODE_HDR + i * CHILD_LEN;
        out.get_mut(at..at + KEY_LEN)
            .ok_or(CodecError::Size)?
            .copy_from_slice(&key.encode());
        ptr.encode(
            out.get_mut(at + KEY_LEN..at + CHILD_LEN)
                .ok_or(CodecError::Size)?,
        )
        .map_err(|_| CodecError::Size)?;
    }
    Ok(())
}

/// Overwrite the pointer of entry `i` of an encoded internal node (the seal
/// fills in a dirty child's hash this way).
///
/// # Errors
///
/// [`CodecError::Size`] past the block.
pub fn set_child_pointer(out: &mut [u8], i: usize, ptr: &Pointer) -> Result<(), CodecError> {
    let at = NODE_HDR + i * CHILD_LEN + KEY_LEN;
    ptr.encode(out.get_mut(at..at + POINTER_LEN).ok_or(CodecError::Size)?)
        .map_err(|_| CodecError::Size)
}

/// The child block of entry `i` of an encoded internal node, without
/// decoding the rest (the seal's parent search).
#[must_use]
pub fn child_block_at(buf: &[u8], i: usize) -> Option<u32> {
    let at = NODE_HDR + i * CHILD_LEN + KEY_LEN;
    let b = buf.get(at..at + 4)?;
    Some(u32::from_le_bytes([
        *b.first()?,
        *b.get(1)?,
        *b.get(2)?,
        *b.get(3)?,
    ]))
}

/// The bytes of leaf item `i`, read from the encoded block (bounds-checked
/// again here, so a caller never trusts a span blindly).
#[must_use]
pub fn span_bytes<'a>(buf: &'a [u8], span: &Span) -> Option<&'a [u8]> {
    let off = usize::from(span.off);
    buf.get(off..off.checked_add(usize::from(span.len))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blk::layout::Pointer;
    use crate::blk::BlockNo;
    use alloc::vec;

    fn k(n: u64) -> Key {
        Key {
            obj: n,
            kind: 0x20,
            off: n * 3,
        }
    }

    #[test]
    fn leaf_round_trips_and_packs_from_the_end() {
        let data = b"hello world, and a second item";
        let mut n: Node<Span, 8> = Node::new(Span::EMPTY);
        n.push(
            k(1),
            Span {
                src: 0,
                off: 0,
                len: 5,
            },
        )
        .unwrap();
        n.push(
            k(2),
            Span {
                src: 0,
                off: 6,
                len: 0,
            },
        )
        .unwrap();
        n.push(
            k(3),
            Span {
                src: 0,
                off: 6,
                len: 24,
            },
        )
        .unwrap();
        let mut blk = vec![0xAAu8; 4096];
        encode_leaf(&n, &[&data[..]], &mut blk).unwrap();
        assert!(
            blk[..HEADER_LEN].iter().all(|&b| b == 0xAA),
            "header untouched"
        );
        // Item 0 at the very end.
        assert_eq!(&blk[4096 - 5..], b"hello");
        let mut back: Node<Span, 8> = Node::new(Span::EMPTY);
        decode_leaf(&blk, 1, &mut back).unwrap();
        assert_eq!(back.keys(), n.keys());
        for i in 0..3 {
            let want = span_bytes(data, &n.val(i).unwrap()).unwrap();
            let got = span_bytes(&blk, &back.val(i).unwrap()).unwrap();
            assert_eq!(want, got);
            assert_eq!(back.val(i).unwrap().src, 1);
        }
        // Re-encoding the decoded node from the block itself is byte-identical.
        let mut again = vec![0xAAu8; 4096];
        encode_leaf(&back, &[&[][..], &blk[..]], &mut again).unwrap();
        assert_eq!(again[HEADER_LEN..], blk[HEADER_LEN..]);
    }

    #[test]
    fn leaf_decode_rejects_every_non_canonical_form() {
        let mut n: Node<Span, 8> = Node::new(Span::EMPTY);
        n.push(
            k(1),
            Span {
                src: 0,
                off: 0,
                len: 4,
            },
        )
        .unwrap();
        n.push(
            k(2),
            Span {
                src: 0,
                off: 0,
                len: 4,
            },
        )
        .unwrap();
        let mut good = vec![0u8; 512];
        encode_leaf(&n, &[b"abcd"], &mut good).unwrap();
        let mut out: Node<Span, 8> = Node::new(Span::EMPTY);
        assert!(decode_leaf(&good, 0, &mut out).is_ok());
        let edits: &[(usize, u8)] = &[
            (OFF_LEVEL, 1),                          // not a leaf
            (OFF_LEVEL + 1, 1),                      // pad
            (OFF_NITEMS, 0),                         // zero items
            (OFF_NITEMS, 200),                       // table past the block
            (NODE_HDR, 0xFF),                        // key 0 obj past key 1: unsorted
            (NODE_HDR + KEY_LEN, 0),                 // off of item 0 not at the end
            (NODE_HDR + LEAF_SLOT + KEY_LEN + 2, 5), // len of item 1 changed
            (200, 1),                                // garbage in the gap
            (68, 1),                                 // pad
        ];
        for &(at, v) in edits {
            let mut bad = good.clone();
            bad[at] = v;
            assert_eq!(
                decode_leaf(&bad, 0, &mut out),
                Err(CodecError::Corrupt),
                "edit at {at}"
            );
        }
        // Too small an in-memory node.
        let mut tiny: Node<Span, 1> = Node::new(Span::EMPTY);
        assert_eq!(decode_leaf(&good, 0, &mut tiny), Err(CodecError::Size));
    }

    #[test]
    fn inner_round_trips_and_checks_pointers() {
        let mut n: Node<Pointer, 8> = Node::new(Pointer::NULL);
        for i in 0..3u32 {
            let p = Pointer {
                block: BlockNo(10 + i),
                hash: [i as u8 + 1; 32],
                gen: 4,
            };
            n.push(k(u64::from(i) * 10), p).unwrap();
        }
        let mut blk = vec![0u8; 4096];
        encode_inner(&n, 2, &mut blk).unwrap();
        let mut back: Node<Pointer, 8> = Node::new(Pointer::NULL);
        assert_eq!(decode_inner(&blk, &mut back), Ok(2));
        assert_eq!(back.keys(), n.keys());
        assert_eq!(back.val(2), n.val(2));
        assert_eq!(child_block_at(&blk, 1), Some(11));
        let p = Pointer {
            block: BlockNo(99),
            hash: [7; 32],
            gen: 5,
        };
        set_child_pointer(&mut blk, 1, &p).unwrap();
        decode_inner(&blk, &mut back).unwrap();
        assert_eq!(back.val(1), Some(p));
        // A pointer to block 1 (a superblock slot) is corrupt.
        let mut bad = blk.clone();
        set_child_pointer(
            &mut bad,
            0,
            &Pointer {
                block: BlockNo(1),
                ..p
            },
        )
        .unwrap();
        assert_eq!(decode_inner(&bad, &mut back), Err(CodecError::Corrupt));
        // Level 0 is not an internal node; level 4 is past MAX_LEVEL.
        assert_eq!(encode_inner(&n, 0, &mut blk), Err(CodecError::Size));
        assert_eq!(
            encode_inner(&n, MAX_LEVEL + 1, &mut blk),
            Err(CodecError::Size)
        );
    }

    #[test]
    fn encode_refuses_what_does_not_fit() {
        let mut n: Node<Span, 8> = Node::new(Span::EMPTY);
        n.push(
            k(1),
            Span {
                src: 0,
                off: 0,
                len: 60,
            },
        )
        .unwrap();
        let data = [1u8; 60];
        let mut small = vec![0u8; NODE_HDR + 80];
        assert_eq!(encode_leaf(&n, &[&data], &mut small), Err(CodecError::Size));
        let mut fits = vec![0u8; NODE_HDR + 81];
        assert!(encode_leaf(&n, &[&data], &mut fits).is_ok());
        let mut empty: Node<Span, 8> = Node::new(Span::EMPTY);
        assert_eq!(
            encode_leaf(&empty, &[&data], &mut fits),
            Err(CodecError::Size)
        );
        empty
            .push(
                k(1),
                Span {
                    src: 3,
                    off: 0,
                    len: 1,
                },
            )
            .unwrap();
        assert_eq!(
            encode_leaf(&empty, &[&data], &mut fits),
            Err(CodecError::Source)
        );
    }
}

/// Kani harnesses over a shrunken block (A19: never 4 KiB, never SHA-256).
#[cfg(kani)]
mod proofs {
    use super::*;

    /// A leaf block of 72 + 2 × 21 + 4 bytes: two items with 4 data bytes
    /// between them, or one with up to 25.
    const SMALL: usize = NODE_HDR + 2 * LEAF_SLOT + 4;
    /// Decode harness blocks: room for exactly one entry of each kind plus a
    /// few spare bytes. Every decoder loop is bounded by the block length (a
    /// constant here), so the unwind is the block length plus one and CBMC
    /// never explores a symbolic trip count.
    const LEAF_ONE: usize = NODE_HDR + LEAF_SLOT + 6;
    const INNER_ONE: usize = NODE_HDR + CHILD_LEN + 3;

    /// Leaf decode totality: any bytes decode to `Ok` or `Err` — no panic, no
    /// out-of-bounds read, every loop bounded by the block.
    #[kani::proof]
    #[kani::unwind(100)]
    fn leaf_decode_is_total() {
        let buf: [u8; LEAF_ONE] = kani::any();
        let mut leaf: Node<Span, 2> = Node::new(Span::EMPTY);
        let _ = decode_leaf(&buf, 0, &mut leaf);
    }

    /// Internal-node decode totality, as above.
    #[kani::proof]
    #[kani::unwind(141)]
    fn inner_decode_is_total() {
        let buf: [u8; INNER_ONE] = kani::any();
        let mut inner: Node<Pointer, 2> = Node::new(Pointer::NULL);
        let _ = decode_inner(&buf, &mut inner);
    }

    /// Leaf-packing totality: every in-memory leaf of up to two items whose
    /// weight fits the shrunken block encodes `Ok`, and decodes back to the
    /// same keys with the same bytes for every item.
    #[kani::proof]
    #[kani::unwind(119)]
    fn leaf_packing_is_total_and_round_trips() {
        // Distinct bytes, so a copy from the wrong place cannot match; the
        // offsets, lengths, keys and item count are symbolic.
        let src: [u8; 4] = [0xA1, 0xB2, 0xC3, 0xD4];
        let n: usize = kani::any();
        kani::assume(n >= 1 && n <= 2);
        let mut node: Node<Span, 2> = Node::new(Span::EMPTY);
        let mut prev: Option<Key> = None;
        for j in 0..2 {
            if j >= n {
                break;
            }
            let obj: u8 = kani::any();
            let key = Key {
                obj: u64::from(obj),
                kind: 0x20,
                off: 0,
            };
            if let Some(p) = prev {
                kani::assume(p < key);
            }
            let off: u8 = kani::any();
            let len: u8 = kani::any();
            kani::assume(usize::from(off) + usize::from(len) <= src.len());
            let pushed = node.push(
                key,
                Span {
                    src: 0,
                    off: u16::from(off),
                    len: u16::from(len),
                },
            );
            assert!(pushed.is_ok());
            prev = Some(key);
        }
        kani::assume(node.weight() <= u64::from(payload_limit(SMALL)));
        let mut blk = [0u8; SMALL];
        let enc = encode_leaf(&node, &[&src[..]], &mut blk);
        assert!(enc.is_ok());
        let mut back: Node<Span, 2> = Node::new(Span::EMPTY);
        assert!(decode_leaf(&blk, 1, &mut back).is_ok());
        assert!(back.len() == n);
        for i in 0..2 {
            if i >= n {
                break;
            }
            assert!(back.key(i) == node.key(i));
            let (a, b) = (node.val(i), back.val(i));
            assert!(a.is_some() && b.is_some());
            if let (Some(a), Some(b)) = (a, b) {
                assert!(a.len == b.len);
                let want = span_bytes(&src, &a);
                let got = span_bytes(&blk, &b);
                assert!(want.is_some() && want == got);
            }
        }
    }
}
