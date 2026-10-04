//! Leaf item payloads (spec §7.2): the byte encodings of `INODE`, `DIRENT`,
//! `INLINE`, `EXTENT` and `XATTR`. FS-1b pins the bytes and their decode
//! checks; what the items *mean* — files, directories, the dirent hash chain
//! and its re-chaining delete — is FS-2's.
//!
//! Every decoder is `&[u8] -> Result`, total, and demands the **exact**
//! length its fields imply (no trailing bytes), so an item has one encoding.
//! Every payload is at most [`ITEM_MAX`] bytes, which is what keeps any one
//! leaf entry at or under half a node (§7.2's split argument, [`super::node`]).
//!
//! ```text
//! INODE   size u64 | kind u8 | nlink u32 | gen u64 | flags u32          (25 B)
//! DIRENT  child_obj u64 | name_len u16 | name                  (10 + ≤ 255 B)
//! INLINE  file bytes                                                (≤ 1024 B)
//! EXTENT  start u32 | len u32 (1..=32) | flags u32 | hashes [32] × len
//! XATTR   key_len u16 | val_len u16 | key | value     (key ≤ 255, value ≤ 768)
//! ```

use super::ITEM_MAX;
use crate::blk::geometry::MAX_EXTENT;
use crate::blk::layout::{Hash, HASH_LEN};
use crate::blk::BlockNo;

/// Largest inline file (§4: two inline items always share a leaf).
pub const INLINE_MAX: usize = 1024;
/// Longest dirent name.
pub const NAME_MAX: usize = 255;
/// Longest xattr key.
pub const XATTR_KEY_MAX: usize = 255;
/// Longest xattr value.
pub const XATTR_VAL_MAX: usize = 768;
/// Encoded `INODE` length.
pub const INODE_LEN: usize = 25;
/// Fixed part of an `EXTENT` item.
pub const EXTENT_HEAD: usize = 12;
/// Fixed part of a `DIRENT` item.
pub const DIRENT_HEAD: usize = 10;
/// Fixed part of an `XATTR` item.
pub const XATTR_HEAD: usize = 4;

/// Largest encoded payload of each kind fits [`ITEM_MAX`] (checked at
/// compile time, so a constant changed in one place cannot break the leaf
/// split argument silently).
const _: () = {
    assert!(INLINE_MAX <= ITEM_MAX);
    assert!(EXTENT_HEAD + MAX_EXTENT as usize * HASH_LEN <= ITEM_MAX);
    assert!(DIRENT_HEAD + NAME_MAX <= ITEM_MAX);
    assert!(XATTR_HEAD + XATTR_KEY_MAX + XATTR_VAL_MAX <= ITEM_MAX);
    assert!(INODE_LEN <= ITEM_MAX);
};

/// An item's bytes break its encoding.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BadItem;

/// What an inode describes (FS-2 assigns the semantics).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InodeKind {
    /// A directory.
    Dir,
    /// A regular file.
    File,
    /// A file that references a blob (FS-4).
    BlobRef,
}

impl InodeKind {
    const fn to_wire(self) -> u8 {
        match self {
            InodeKind::Dir => 1,
            InodeKind::File => 2,
            InodeKind::BlobRef => 3,
        }
    }

    const fn from_wire(v: u8) -> Result<InodeKind, BadItem> {
        match v {
            1 => Ok(InodeKind::Dir),
            2 => Ok(InodeKind::File),
            3 => Ok(InodeKind::BlobRef),
            _ => Err(BadItem),
        }
    }
}

/// An `INODE` item.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Inode {
    /// Size in bytes.
    pub size: u64,
    /// Directory, file or blob reference.
    pub kind: InodeKind,
    /// Link count.
    pub nlink: u32,
    /// Generation of the last change.
    pub gen: u64,
    /// Reserved flags (FS-2).
    pub flags: u32,
}

/// `N` bytes at `off`, or [`BadItem`].
fn arr<const N: usize>(b: &[u8], off: usize) -> Result<[u8; N], BadItem> {
    b.get(off..off.checked_add(N).ok_or(BadItem)?)
        .and_then(|s| s.try_into().ok())
        .ok_or(BadItem)
}

fn put(out: &mut [u8], off: usize, bytes: &[u8]) -> Result<(), BadItem> {
    out.get_mut(off..off.checked_add(bytes.len()).ok_or(BadItem)?)
        .ok_or(BadItem)?
        .copy_from_slice(bytes);
    Ok(())
}

impl Inode {
    /// Encode into `out`; returns the length ([`INODE_LEN`]).
    ///
    /// # Errors
    ///
    /// [`BadItem`] if `out` is too short.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, BadItem> {
        put(out, 0, &self.size.to_le_bytes())?;
        put(out, 8, &[self.kind.to_wire()])?;
        put(out, 9, &self.nlink.to_le_bytes())?;
        put(out, 13, &self.gen.to_le_bytes())?;
        put(out, 21, &self.flags.to_le_bytes())?;
        Ok(INODE_LEN)
    }

    /// Decode exactly [`INODE_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// [`BadItem`] for another length or an unknown kind.
    pub fn decode(b: &[u8]) -> Result<Inode, BadItem> {
        if b.len() != INODE_LEN {
            return Err(BadItem);
        }
        Ok(Inode {
            size: u64::from_le_bytes(arr(b, 0)?),
            kind: InodeKind::from_wire(*b.get(8).ok_or(BadItem)?)?,
            nlink: u32::from_le_bytes(arr(b, 9)?),
            gen: u64::from_le_bytes(arr(b, 13)?),
            flags: u32::from_le_bytes(arr(b, 21)?),
        })
    }
}

/// A decoded `DIRENT` item, borrowing its name.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Dirent<'a> {
    /// The object the name refers to.
    pub child_obj: u64,
    /// The name (1..=[`NAME_MAX`] bytes; FS-2 decides the character set).
    pub name: &'a [u8],
}

impl Dirent<'_> {
    /// Encode into `out`; returns the length.
    ///
    /// # Errors
    ///
    /// [`BadItem`] for an empty or over-long name, or a short `out`.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, BadItem> {
        if self.name.is_empty() || self.name.len() > NAME_MAX {
            return Err(BadItem);
        }
        put(out, 0, &self.child_obj.to_le_bytes())?;
        put(out, 8, &(self.name.len() as u16).to_le_bytes())?;
        put(out, DIRENT_HEAD, self.name)?;
        Ok(DIRENT_HEAD + self.name.len())
    }

    /// Decode a whole `DIRENT` payload.
    ///
    /// # Errors
    ///
    /// [`BadItem`] if the length field disagrees with the payload, or the
    /// name is empty or over [`NAME_MAX`].
    pub fn decode(b: &[u8]) -> Result<Dirent<'_>, BadItem> {
        let child_obj = u64::from_le_bytes(arr(b, 0)?);
        let len = usize::from(u16::from_le_bytes(arr(b, 8)?));
        if len == 0 || len > NAME_MAX || b.len() != DIRENT_HEAD + len {
            return Err(BadItem);
        }
        Ok(Dirent {
            child_obj,
            name: b.get(DIRENT_HEAD..).ok_or(BadItem)?,
        })
    }
}

/// Check an `INLINE` payload (any bytes, at most [`INLINE_MAX`]).
///
/// # Errors
///
/// [`BadItem`] past [`INLINE_MAX`].
pub fn check_inline(b: &[u8]) -> Result<&[u8], BadItem> {
    if b.len() > INLINE_MAX {
        return Err(BadItem);
    }
    Ok(b)
}

/// A decoded `EXTENT` item: `len` data blocks from `start`, one hash each
/// (so any block verifies alone, A3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ExtentItem<'a> {
    /// First data block.
    pub start: BlockNo,
    /// Blocks (1..=[`MAX_EXTENT`]).
    pub len: u32,
    /// Reserved flags (`BLOB_REF` in FS-4).
    pub flags: u32,
    /// `len × 32` bytes: the data hash of each block in order.
    hashes: &'a [u8],
}

impl<'a> ExtentItem<'a> {
    /// An extent over `hashes` (`len × 32` bytes).
    ///
    /// # Errors
    ///
    /// [`BadItem`] unless `1 ≤ len ≤ MAX_EXTENT`, `hashes.len() == 32·len`
    /// and the run does not wrap `u32`.
    pub fn new(start: BlockNo, len: u32, flags: u32, hashes: &'a [u8]) -> Result<Self, BadItem> {
        if len == 0 || len > MAX_EXTENT || hashes.len() != len as usize * HASH_LEN {
            return Err(BadItem);
        }
        start.0.checked_add(len).ok_or(BadItem)?;
        Ok(ExtentItem {
            start,
            len,
            flags,
            hashes,
        })
    }

    /// The data hash of block `i` of the run.
    #[must_use]
    pub fn hash(&self, i: u32) -> Option<Hash> {
        let at = (i as usize).checked_mul(HASH_LEN)?;
        self.hashes
            .get(at..at + HASH_LEN)
            .and_then(|s| s.try_into().ok())
    }

    /// Encode into `out`; returns the length.
    ///
    /// # Errors
    ///
    /// [`BadItem`] if `out` is too short.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, BadItem> {
        put(out, 0, &self.start.0.to_le_bytes())?;
        put(out, 4, &self.len.to_le_bytes())?;
        put(out, 8, &self.flags.to_le_bytes())?;
        put(out, EXTENT_HEAD, self.hashes)?;
        Ok(EXTENT_HEAD + self.hashes.len())
    }

    /// Decode a whole `EXTENT` payload.
    ///
    /// # Errors
    ///
    /// [`BadItem`] as [`ExtentItem::new`], or when the payload length is not
    /// exactly `12 + 32·len`.
    pub fn decode(b: &'a [u8]) -> Result<Self, BadItem> {
        let start = BlockNo(u32::from_le_bytes(arr(b, 0)?));
        let len = u32::from_le_bytes(arr(b, 4)?);
        let flags = u32::from_le_bytes(arr(b, 8)?);
        ExtentItem::new(start, len, flags, b.get(EXTENT_HEAD..).ok_or(BadItem)?)
    }
}

/// A decoded `XATTR` item, borrowing key and value.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Xattr<'a> {
    /// Key (1..=[`XATTR_KEY_MAX`] bytes).
    pub key: &'a [u8],
    /// Value (≤ [`XATTR_VAL_MAX`] bytes).
    pub value: &'a [u8],
}

impl Xattr<'_> {
    /// Encode into `out`; returns the length.
    ///
    /// # Errors
    ///
    /// [`BadItem`] for an empty or over-long key, an over-long value, or a
    /// short `out`.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, BadItem> {
        let (k, v) = (self.key.len(), self.value.len());
        if k == 0 || k > XATTR_KEY_MAX || v > XATTR_VAL_MAX {
            return Err(BadItem);
        }
        put(out, 0, &(k as u16).to_le_bytes())?;
        put(out, 2, &(v as u16).to_le_bytes())?;
        put(out, XATTR_HEAD, self.key)?;
        put(out, XATTR_HEAD + k, self.value)?;
        Ok(XATTR_HEAD + k + v)
    }

    /// Decode a whole `XATTR` payload.
    ///
    /// # Errors
    ///
    /// [`BadItem`] if the lengths disagree with the payload or break a bound.
    pub fn decode(b: &[u8]) -> Result<Xattr<'_>, BadItem> {
        let k = usize::from(u16::from_le_bytes(arr(b, 0)?));
        let v = usize::from(u16::from_le_bytes(arr(b, 2)?));
        if k == 0 || k > XATTR_KEY_MAX || v > XATTR_VAL_MAX || b.len() != XATTR_HEAD + k + v {
            return Err(BadItem);
        }
        Ok(Xattr {
            key: b.get(XATTR_HEAD..XATTR_HEAD + k).ok_or(BadItem)?,
            value: b.get(XATTR_HEAD + k..).ok_or(BadItem)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn inode_round_trips_exactly() {
        let i = Inode {
            size: 0x0102_0304_0506_0708,
            kind: InodeKind::File,
            nlink: 3,
            gen: 77,
            flags: 0,
        };
        let mut b = [0u8; 40];
        let n = i.encode(&mut b).unwrap();
        assert_eq!(n, INODE_LEN);
        assert_eq!(Inode::decode(&b[..n]), Ok(i));
        assert_eq!(Inode::decode(&b[..n - 1]), Err(BadItem));
        assert_eq!(Inode::decode(&b[..n + 1]), Err(BadItem));
        b[8] = 9;
        assert_eq!(Inode::decode(&b[..n]), Err(BadItem));
    }

    #[test]
    fn dirent_round_trips_and_bounds_the_name() {
        let d = Dirent {
            child_obj: 42,
            name: b"notes.txt",
        };
        let mut b = [0u8; 300];
        let n = d.encode(&mut b).unwrap();
        assert_eq!(Dirent::decode(&b[..n]), Ok(d));
        assert_eq!(Dirent::decode(&b[..n + 1]), Err(BadItem));
        assert!(Dirent {
            child_obj: 1,
            name: b""
        }
        .encode(&mut b)
        .is_err());
        let long = [b'a'; NAME_MAX + 1];
        assert!(Dirent {
            child_obj: 1,
            name: &long
        }
        .encode(&mut b)
        .is_err());
        let max = [b'a'; NAME_MAX];
        let n = Dirent {
            child_obj: 1,
            name: &max,
        }
        .encode(&mut b)
        .unwrap();
        assert!(n <= ITEM_MAX);
    }

    #[test]
    fn extent_round_trips_with_one_hash_per_block() {
        let hashes: vec::Vec<u8> = (0..3 * HASH_LEN).map(|i| i as u8).collect();
        let e = ExtentItem::new(BlockNo(100), 3, 0, &hashes).unwrap();
        assert_eq!(e.hash(2).unwrap()[0], (2 * HASH_LEN) as u8);
        assert_eq!(e.hash(3), None);
        let mut b = vec![0u8; ITEM_MAX];
        let n = e.encode(&mut b).unwrap();
        assert_eq!(n, EXTENT_HEAD + 3 * HASH_LEN);
        assert_eq!(ExtentItem::decode(&b[..n]), Ok(e));
        assert_eq!(ExtentItem::decode(&b[..n - 1]), Err(BadItem));
        assert!(ExtentItem::new(BlockNo(1), 0, 0, &[]).is_err());
        assert!(ExtentItem::new(BlockNo(1), 33, 0, &[0; 33 * HASH_LEN]).is_err());
        assert!(ExtentItem::new(BlockNo(u32::MAX), 1, 0, &[0; HASH_LEN]).is_err());
        let full = vec![7u8; 32 * HASH_LEN];
        let n = ExtentItem::new(BlockNo(5), 32, 0, &full)
            .unwrap()
            .encode(&mut b)
            .unwrap();
        assert_eq!(n, EXTENT_HEAD + 32 * HASH_LEN);
        assert!(n <= ITEM_MAX);
    }

    #[test]
    fn xattr_and_inline_bounds() {
        let x = Xattr {
            key: b"state.kind",
            value: b"mergeable",
        };
        let mut b = vec![0u8; ITEM_MAX];
        let n = x.encode(&mut b).unwrap();
        assert_eq!(Xattr::decode(&b[..n]), Ok(x));
        assert_eq!(Xattr::decode(&b[..n + 1]), Err(BadItem));
        assert!(Xattr {
            key: b"",
            value: b""
        }
        .encode(&mut b)
        .is_err());
        let v = vec![0u8; XATTR_VAL_MAX + 1];
        assert!(Xattr {
            key: b"k",
            value: &v
        }
        .encode(&mut b)
        .is_err());
        assert!(check_inline(&[0u8; INLINE_MAX]).is_ok());
        assert!(check_inline(&[0u8; INLINE_MAX + 1]).is_err());
    }

    #[test]
    fn decoders_are_total_over_short_and_garbage_input() {
        let mut rng = crate::blk::mem::SplitMix64::new(5);
        let mut buf = vec![0u8; 64];
        for len in 0..64 {
            for _ in 0..32 {
                for b in buf.iter_mut() {
                    *b = rng.next_u64() as u8;
                }
                let s = &buf[..len];
                let _ = Inode::decode(s);
                let _ = Dirent::decode(s);
                let _ = ExtentItem::decode(s);
                let _ = Xattr::decode(s);
                let _ = check_inline(s);
            }
        }
    }
}
