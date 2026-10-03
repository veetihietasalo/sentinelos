//! On-disk primitives shared by every metadata block (spec §4, §7).
//!
//! Every metadata block begins with a 64-byte header, little-endian:
//!
//! ```text
//! off len field
//!  0   32  hash      SHA-256 of the WHOLE block with these 32 bytes zeroed —
//!                    covers kind, gen, tree_id, fs_uuid and the payload (A1)
//! 32    8  gen       generation that wrote this block (informational)
//! 40    4  kind      1 superblock · 2 tree node · 3 bitmap · 5 group index
//! 44    4  tree_id   0 none · 1 root · 2 blobs · 3 roots · 4 free
//! 48   16  fs_uuid   the filesystem this block belongs to
//! ```
//!
//! Data blocks (kind 4) have no header; their hash is SHA-256 of the whole
//! 4 KiB and lives in the extent item that points at them (§7.2).
//!
//! A [`Pointer`] is `{ block u32, pad u32 (= 0), hash [32], gen u64 }`, 48
//! bytes. The all-zero pointer is [`Pointer::NULL`]; block 0 is a superblock
//! slot, never the target of a real pointer, so the encoding is unambiguous.
//!
//! Every decoder here is `&[u8] -> Result` and total (Kani:
//! `proofs::header_decode_is_total_and_canonical`,
//! `proofs::pointer_decode_is_total_and_canonical`); every encoder writes the
//! one canonical form the decoder accepts.

use super::{Block, BlockNo};
use crate::hash::{Digest, Sha256};

/// A SHA-256 digest as stored on disk.
pub type Hash = Digest;
/// A filesystem identity, stamped into every metadata block header.
pub type Uuid = [u8; UUID_LEN];

/// Length of the metadata header.
pub const HEADER_LEN: usize = 64;
/// Length of a hash on disk.
pub const HASH_LEN: usize = 32;
/// Length of a filesystem uuid.
pub const UUID_LEN: usize = 16;
/// Length of an encoded [`Pointer`].
pub const POINTER_LEN: usize = 48;

const OFF_HASH: usize = 0;
const OFF_GEN: usize = 32;
const OFF_KIND: usize = 40;
const OFF_TREE: usize = 44;
const OFF_UUID: usize = 48;

const PTR_OFF_BLOCK: usize = 0;
const PTR_OFF_PAD: usize = 4;
const PTR_OFF_HASH: usize = 8;
const PTR_OFF_GEN: usize = 40;

/// What a metadata block is. The value is the on-disk `kind` field; data
/// blocks (4) carry no header and so never decode from one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// A superblock slot (§7.1).
    Superblock,
    /// A CoW B+tree node (§7.2, FS-1b).
    Node,
    /// One allocation group's bitmap (§7.4).
    Bitmap,
    /// The one-level allocation-group index (§7.4).
    GroupIndex,
}

impl Kind {
    /// The on-disk value.
    #[must_use]
    pub const fn to_wire(self) -> u32 {
        match self {
            Kind::Superblock => 1,
            Kind::Node => 2,
            Kind::Bitmap => 3,
            Kind::GroupIndex => 5,
        }
    }

    /// Decode an on-disk value. `4` (data) and unknown values are refused: a
    /// header can never claim to be a data block.
    pub const fn from_wire(v: u32) -> Result<Kind, LayoutError> {
        match v {
            1 => Ok(Kind::Superblock),
            2 => Ok(Kind::Node),
            3 => Ok(Kind::Bitmap),
            5 => Ok(Kind::GroupIndex),
            _ => Err(LayoutError::Kind),
        }
    }
}

/// Which tree a metadata block belongs to (the header's `tree_id`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TreeId {
    /// Not part of a tree (the superblock).
    None,
    /// The metadata tree (files, directories).
    Root,
    /// The content-addressed blob tree.
    Blobs,
    /// The snapshots tree.
    Roots,
    /// Free-space metadata: group bitmaps and the group index.
    Free,
}

impl TreeId {
    /// The on-disk value.
    #[must_use]
    pub const fn to_wire(self) -> u32 {
        match self {
            TreeId::None => 0,
            TreeId::Root => 1,
            TreeId::Blobs => 2,
            TreeId::Roots => 3,
            TreeId::Free => 4,
        }
    }

    /// Decode an on-disk value; unknown values are refused.
    pub const fn from_wire(v: u32) -> Result<TreeId, LayoutError> {
        match v {
            0 => Ok(TreeId::None),
            1 => Ok(TreeId::Root),
            2 => Ok(TreeId::Blobs),
            3 => Ok(TreeId::Roots),
            4 => Ok(TreeId::Free),
            _ => Err(LayoutError::Tree),
        }
    }
}

/// Why bytes are not a canonical header or pointer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LayoutError {
    /// Fewer bytes than the structure needs.
    Short,
    /// Unknown (or data) `kind`.
    Kind,
    /// Unknown `tree_id`.
    Tree,
    /// A reserved pad field is not zero.
    Pad,
}

impl LayoutError {
    /// Fixed label for `fmt`-free console output.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            LayoutError::Short => "short",
            LayoutError::Kind => "kind",
            LayoutError::Tree => "tree",
            LayoutError::Pad => "pad",
        }
    }
}

/// A decoded metadata header.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Header {
    /// The stored self-hash (see [`metadata_hash`]).
    pub hash: Hash,
    /// Generation that wrote the block.
    pub gen: u64,
    /// What the block is.
    pub kind: Kind,
    /// Which tree it belongs to.
    pub tree: TreeId,
    /// Which filesystem it belongs to.
    pub uuid: Uuid,
}

impl Header {
    /// Write the canonical 64-byte encoding into `out[..64]`.
    ///
    /// # Errors
    ///
    /// [`LayoutError::Short`] if `out` is shorter than [`HEADER_LEN`].
    pub fn encode(&self, out: &mut [u8]) -> Result<(), LayoutError> {
        let out = out.get_mut(..HEADER_LEN).ok_or(LayoutError::Short)?;
        out[OFF_HASH..OFF_HASH + HASH_LEN].copy_from_slice(&self.hash);
        out[OFF_GEN..OFF_GEN + 8].copy_from_slice(&self.gen.to_le_bytes());
        out[OFF_KIND..OFF_KIND + 4].copy_from_slice(&self.kind.to_wire().to_le_bytes());
        out[OFF_TREE..OFF_TREE + 4].copy_from_slice(&self.tree.to_wire().to_le_bytes());
        out[OFF_UUID..OFF_UUID + UUID_LEN].copy_from_slice(&self.uuid);
        Ok(())
    }
}

/// Decode the header at the start of `bytes`. Total: never panics, reads
/// nothing past `bytes[..64]`.
///
/// # Errors
///
/// [`LayoutError::Short`] for fewer than 64 bytes, [`LayoutError::Kind`] /
/// [`LayoutError::Tree`] for unknown discriminants.
pub fn decode_header(bytes: &[u8]) -> Result<Header, LayoutError> {
    let h: &[u8; HEADER_LEN] = bytes
        .get(..HEADER_LEN)
        .and_then(|s| s.try_into().ok())
        .ok_or(LayoutError::Short)?;
    Ok(Header {
        hash: array_at(h, OFF_HASH),
        gen: u64::from_le_bytes(array_at(h, OFF_GEN)),
        kind: Kind::from_wire(u32::from_le_bytes(array_at(h, OFF_KIND)))?,
        tree: TreeId::from_wire(u32::from_le_bytes(array_at(h, OFF_TREE)))?,
        uuid: array_at(h, OFF_UUID),
    })
}

/// A reference from one block to another: where, what it must hash to, and
/// which generation wrote it (§4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Pointer {
    /// Target block.
    pub block: BlockNo,
    /// Expected hash of the target (its header hash, for metadata).
    pub hash: Hash,
    /// Generation that wrote the target.
    pub gen: u64,
}

impl Pointer {
    /// The null pointer: all zero. Used for empty trees.
    pub const NULL: Pointer = Pointer {
        block: BlockNo(0),
        hash: [0; HASH_LEN],
        gen: 0,
    };

    /// `true` for [`Pointer::NULL`].
    #[must_use]
    pub fn is_null(&self) -> bool {
        *self == Pointer::NULL
    }

    /// Write the canonical 48-byte encoding into `out[..48]`.
    ///
    /// # Errors
    ///
    /// [`LayoutError::Short`] if `out` is shorter than [`POINTER_LEN`].
    pub fn encode(&self, out: &mut [u8]) -> Result<(), LayoutError> {
        let out = out.get_mut(..POINTER_LEN).ok_or(LayoutError::Short)?;
        out[PTR_OFF_BLOCK..PTR_OFF_BLOCK + 4].copy_from_slice(&self.block.0.to_le_bytes());
        out[PTR_OFF_PAD..PTR_OFF_PAD + 4].fill(0);
        out[PTR_OFF_HASH..PTR_OFF_HASH + HASH_LEN].copy_from_slice(&self.hash);
        out[PTR_OFF_GEN..PTR_OFF_GEN + 8].copy_from_slice(&self.gen.to_le_bytes());
        Ok(())
    }
}

/// Decode the pointer at the start of `bytes`. Total.
///
/// # Errors
///
/// [`LayoutError::Short`] for fewer than 48 bytes, [`LayoutError::Pad`] when
/// the reserved pad is not zero (non-canonical).
pub fn decode_pointer(bytes: &[u8]) -> Result<Pointer, LayoutError> {
    let p: &[u8; POINTER_LEN] = bytes
        .get(..POINTER_LEN)
        .and_then(|s| s.try_into().ok())
        .ok_or(LayoutError::Short)?;
    if u32::from_le_bytes(array_at(p, PTR_OFF_PAD)) != 0 {
        return Err(LayoutError::Pad);
    }
    Ok(Pointer {
        block: BlockNo(u32::from_le_bytes(array_at(p, PTR_OFF_BLOCK))),
        hash: array_at(p, PTR_OFF_HASH),
        gen: u64::from_le_bytes(array_at(p, PTR_OFF_GEN)),
    })
}

/// Copy `N` bytes at `off` out of a fixed array. Every call site passes
/// constant offsets inside the array, so the fallback (zeros) is never taken;
/// it exists so this helper has no panic path at all.
fn array_at<const N: usize, const M: usize>(src: &[u8; M], off: usize) -> [u8; N] {
    let mut out = [0u8; N];
    if let Some(s) = off.checked_add(N).and_then(|end| src.get(off..end)) {
        out.copy_from_slice(s);
    }
    out
}

/// Which hash rule covers a block (§4 "Block hash").
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HashRule {
    /// SHA-256 over the whole block with the 32-byte hash field zeroed, and
    /// the stored field must equal the result.
    Metadata,
    /// SHA-256 over the whole block (no header).
    Data,
}

/// The metadata hash of `block`: SHA-256 of the whole block with bytes
/// `[0, 32)` taken as zero, whatever they hold (amendment A1).
#[must_use]
pub fn metadata_hash(block: &Block) -> Hash {
    let mut h = Sha256::new();
    h.update(&[0u8; HASH_LEN]);
    h.update(&block[HASH_LEN..]);
    h.finalize()
}

/// Compute the metadata hash of `block`, store it in the header's hash field,
/// and return it. Call after every other byte of the block is final.
pub fn seal_metadata(block: &mut Block) -> Hash {
    let hash = metadata_hash(block);
    block[..HASH_LEN].copy_from_slice(&hash);
    hash
}

/// The data hash of `block`: SHA-256 of all 4 KiB.
#[must_use]
pub fn data_hash(block: &Block) -> Hash {
    crate::hash::sha256(block)
}

/// Does `block` match `expected` under `rule`? For metadata both the stored
/// field and the recomputed hash must equal `expected` (otherwise a block with
/// a garbage hash field but intact payload would pass, and `Pointer.hash ==
/// header.hash` would not hold).
#[must_use]
pub fn verify(rule: HashRule, block: &Block, expected: &Hash) -> bool {
    match rule {
        HashRule::Metadata => {
            block[..HASH_LEN] == expected[..] && metadata_hash(block) == *expected
        }
        HashRule::Data => data_hash(block) == *expected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blk::zeroed_blocks;

    fn sample_header() -> Header {
        Header {
            hash: [0xAB; HASH_LEN],
            gen: 0x0102_0304_0506_0708,
            kind: Kind::Bitmap,
            tree: TreeId::Free,
            uuid: [0x5A; UUID_LEN],
        }
    }

    #[test]
    fn header_round_trips_and_is_little_endian() {
        let h = sample_header();
        let mut buf = [0u8; HEADER_LEN];
        h.encode(&mut buf).unwrap();
        assert_eq!(&buf[OFF_GEN..OFF_GEN + 8], &[8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(&buf[OFF_KIND..OFF_KIND + 4], &[3, 0, 0, 0]);
        assert_eq!(&buf[OFF_TREE..OFF_TREE + 4], &[4, 0, 0, 0]);
        assert_eq!(decode_header(&buf), Ok(h));
    }

    #[test]
    fn header_decode_refuses_short_data_kind_and_unknown_tree() {
        let mut buf = [0u8; HEADER_LEN];
        sample_header().encode(&mut buf).unwrap();
        assert_eq!(
            decode_header(&buf[..HEADER_LEN - 1]),
            Err(LayoutError::Short)
        );
        let mut bad = buf;
        bad[OFF_KIND] = 4; // data blocks have no header
        assert_eq!(decode_header(&bad), Err(LayoutError::Kind));
        let mut bad = buf;
        bad[OFF_KIND] = 0;
        assert_eq!(decode_header(&bad), Err(LayoutError::Kind));
        let mut bad = buf;
        bad[OFF_TREE] = 5;
        assert_eq!(decode_header(&bad), Err(LayoutError::Tree));
        let mut bad = buf;
        bad[OFF_KIND + 3] = 1; // high byte of kind
        assert_eq!(decode_header(&bad), Err(LayoutError::Kind));
    }

    #[test]
    fn pointer_round_trips_and_refuses_pad() {
        let p = Pointer {
            block: BlockNo(0xDEAD_BEEF),
            hash: [7; HASH_LEN],
            gen: 42,
        };
        let mut buf = [0u8; POINTER_LEN];
        p.encode(&mut buf).unwrap();
        assert_eq!(&buf[..4], &0xDEAD_BEEFu32.to_le_bytes());
        assert_eq!(decode_pointer(&buf), Ok(p));
        let mut bad = buf;
        bad[PTR_OFF_PAD + 2] = 1;
        assert_eq!(decode_pointer(&bad), Err(LayoutError::Pad));
        assert_eq!(decode_pointer(&buf[..47]), Err(LayoutError::Short));
        assert!(decode_pointer(&[0u8; POINTER_LEN]).unwrap().is_null());
        assert!(!p.is_null());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn metadata_hash_ignores_the_hash_field_and_covers_everything_else() {
        let mut blocks = zeroed_blocks(2);
        let (a, b) = blocks.split_at_mut(1);
        let (a, b) = (&mut a[0], &mut b[0]);
        a[100] = 1;
        b[100] = 1;
        b[..HASH_LEN].fill(0xFF); // differs only in the hash field
        assert_eq!(metadata_hash(a), metadata_hash(b));
        // Every header field and the payload are inside the hash (A1).
        for off in [OFF_GEN, OFF_KIND, OFF_TREE, OFF_UUID, HEADER_LEN, 4095] {
            let before = metadata_hash(a);
            a[off] ^= 0x10;
            assert_ne!(metadata_hash(a), before, "offset {off} must be hashed");
            a[off] ^= 0x10;
        }
    }

    #[test]
    fn verify_requires_the_stored_field_to_match() {
        let mut blocks = zeroed_blocks(1);
        let block = &mut blocks[0];
        block[HEADER_LEN] = 9;
        let hash = seal_metadata(block);
        assert!(verify(HashRule::Metadata, block, &hash));
        // Payload flip: recomputed hash differs.
        block[HEADER_LEN] ^= 1;
        assert!(!verify(HashRule::Metadata, block, &hash));
        block[HEADER_LEN] ^= 1;
        // Stored-field flip alone: the recomputation still matches, but the
        // field does not — refused.
        block[3] ^= 1;
        assert!(!verify(HashRule::Metadata, block, &hash));
        block[3] ^= 1;
        assert!(verify(HashRule::Metadata, block, &hash));
        // Data rule covers the whole block, field included.
        let d = data_hash(block);
        assert!(verify(HashRule::Data, block, &d));
        block[0] ^= 1;
        assert!(!verify(HashRule::Data, block, &d));
    }
}

/// Kani proof harnesses (A19: shrunken inputs, never SHA-256, never a 4 KiB
/// block). Compiled only under `cargo kani`.
#[cfg(kani)]
mod proofs {
    use super::*;

    /// Header decode is total over every byte string up to 66 bytes, and every
    /// accepted header re-encodes to exactly the bytes it was decoded from
    /// (canonical: there is one encoding per header).
    #[kani::proof]
    fn header_decode_is_total_and_canonical() {
        const N: usize = HEADER_LEN + 2;
        let bytes: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        if let Ok(h) = decode_header(&bytes[..len]) {
            assert!(len >= HEADER_LEN);
            let mut out = [0u8; HEADER_LEN];
            assert!(h.encode(&mut out).is_ok());
            assert!(out == bytes[..HEADER_LEN]);
        }
    }

    /// Pointer decode is total and canonical in the same sense.
    #[kani::proof]
    fn pointer_decode_is_total_and_canonical() {
        const N: usize = POINTER_LEN + 2;
        let bytes: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        if let Ok(p) = decode_pointer(&bytes[..len]) {
            assert!(len >= POINTER_LEN);
            let mut out = [0u8; POINTER_LEN];
            assert!(p.encode(&mut out).is_ok());
            assert!(out == bytes[..POINTER_LEN]);
        }
    }
}
