//! Item keys (§4, amendment A10) and blob domains (§7.3, amendment A12).
//!
//! FS-1a writes no tree, but these two encodings are on-disk decisions that
//! "cannot be added later" (A12): every tree item is found by a [`Key`], and
//! every blob key carries the [`BlobDomain`] that keeps dedup inside one
//! domain (`Public` for components and weights, `User(n)` per user — so dedup
//! never spans users and never reveals cross-domain equality). Pinning both
//! here means FS-1b's tree and FS-4's blob store inherit one definition.
//!
//! A key is 17 bytes, packed little-endian at fixed offsets, no alignment
//! assumed: `[0..8) obj`, `[8] kind`, `[9..17) off`. Keys sort by
//! `(obj, kind, off)` — the derived `Ord` below, field order matters.

use crate::blk::layout::Hash;

/// Encoded key length.
pub const KEY_LEN: usize = 17;

/// Item kinds (§7.2, §7.3).
pub mod item {
    /// File/directory/blob-ref inode.
    pub const INODE: u8 = 0x01;
    /// Directory entry (`off` = keyed name hash).
    pub const DIRENT: u8 = 0x10;
    /// Inline file bytes (≤ 1 KiB).
    pub const INLINE: u8 = 0x20;
    /// Extent (`off` = byte offset).
    pub const EXTENT: u8 = 0x21;
    /// Extended attribute (`off` = keyed key hash).
    pub const XATTR: u8 = 0x30;
    /// Content-addressed blob (in the blobs tree).
    pub const BLOB: u8 = 0x40;
}

/// A tree key. Ordering is `(obj, kind, off)`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Key {
    /// Object id (for blobs: domain ‖ first 6 hash bytes).
    pub obj: u64,
    /// Item kind ([`item`]).
    pub kind: u8,
    /// Kind-specific offset.
    pub off: u64,
}

/// `bytes` is not a key.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ShortKey;

impl Key {
    /// The canonical 17-byte encoding.
    #[must_use]
    pub fn encode(&self) -> [u8; KEY_LEN] {
        let mut out = [0u8; KEY_LEN];
        out[..8].copy_from_slice(&self.obj.to_le_bytes());
        out[8] = self.kind;
        out[9..].copy_from_slice(&self.off.to_le_bytes());
        out
    }

    /// Decode the key at the start of `bytes`. Total.
    ///
    /// # Errors
    ///
    /// [`ShortKey`] for fewer than 17 bytes.
    pub fn decode(bytes: &[u8]) -> Result<Key, ShortKey> {
        let k = bytes.get(..KEY_LEN).ok_or(ShortKey)?;
        let mut obj = [0u8; 8];
        obj.copy_from_slice(&k[..8]);
        let mut off = [0u8; 8];
        off.copy_from_slice(&k[9..]);
        Ok(Key {
            obj: u64::from_le_bytes(obj),
            kind: k[8],
            off: u64::from_le_bytes(off),
        })
    }
}

/// A blob dedup domain. On disk a `u16`: `0` is `Public`, `n ≥ 1` is
/// `User(n)`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum BlobDomain {
    /// Components and model weights: keyed by plain SHA-256.
    Public,
    /// One user's blobs: keyed hash (§10), never deduplicated across users.
    User(core::num::NonZeroU16),
}

impl BlobDomain {
    /// The on-disk value.
    #[must_use]
    pub const fn to_wire(self) -> u16 {
        match self {
            BlobDomain::Public => 0,
            BlobDomain::User(n) => n.get(),
        }
    }

    /// Decode an on-disk value (every `u16` is a domain).
    #[must_use]
    pub const fn from_wire(v: u16) -> BlobDomain {
        match core::num::NonZeroU16::new(v) {
            None => BlobDomain::Public,
            Some(n) => BlobDomain::User(n),
        }
    }
}

/// The blobs-tree key of `hash` in `domain` (§7.3): `obj` is the domain
/// followed by the first six hash bytes, `off` the next eight, both read
/// big-endian so numeric key order is domain-major, then hash-lexicographic.
/// The full hash is stored in the item; the key only has to spread and group.
#[must_use]
pub fn blob_key(domain: BlobDomain, hash: &Hash) -> Key {
    let d = domain.to_wire().to_be_bytes();
    let obj = [
        d[0], d[1], hash[0], hash[1], hash[2], hash[3], hash[4], hash[5],
    ];
    let mut off = [0u8; 8];
    off.copy_from_slice(&hash[6..14]);
    Key {
        obj: u64::from_be_bytes(obj),
        kind: item::BLOB,
        off: u64::from_be_bytes(off),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::NonZeroU16;

    #[test]
    fn key_encoding_is_packed_little_endian() {
        let k = Key {
            obj: 0x0102_0304_0506_0708,
            kind: 0x21,
            off: 0x1112_1314_1516_1718,
        };
        let e = k.encode();
        assert_eq!(e[0], 0x08);
        assert_eq!(e[7], 0x01);
        assert_eq!(e[8], 0x21);
        assert_eq!(e[9], 0x18);
        assert_eq!(e[16], 0x11);
        assert_eq!(Key::decode(&e), Ok(k));
        assert_eq!(Key::decode(&e[..16]), Err(ShortKey));
    }

    #[test]
    fn keys_sort_by_obj_then_kind_then_off() {
        let a = Key {
            obj: 1,
            kind: 0x30,
            off: 9,
        };
        let b = Key {
            obj: 2,
            kind: 0x01,
            off: 0,
        };
        let c = Key {
            obj: 2,
            kind: 0x10,
            off: 0,
        };
        let d = Key {
            obj: 2,
            kind: 0x10,
            off: 1,
        };
        assert!(a < b && b < c && c < d);
    }

    #[test]
    fn blob_keys_never_collide_across_domains() {
        let h = [0xAB; 32];
        let public = blob_key(BlobDomain::Public, &h);
        let user1 = blob_key(BlobDomain::User(NonZeroU16::MIN), &h);
        assert_ne!(public, user1);
        assert_eq!(public.kind, item::BLOB);
        assert_eq!(public.obj >> 48, 0);
        assert_eq!(user1.obj >> 48, 1);
        // Domain-major order: every Public key sorts before every User key.
        let low_user = blob_key(BlobDomain::User(NonZeroU16::MIN), &[0; 32]);
        assert!(public < low_user);
        for v in [0u16, 1, 7, u16::MAX] {
            assert_eq!(BlobDomain::from_wire(v).to_wire(), v);
        }
    }
}
