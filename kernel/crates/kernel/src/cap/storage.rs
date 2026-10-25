//! The storage-capability lattice — SentinelFS FS-1c
//! (`docs/specs/2026-09-18-sentinelfs-design.md` §9, §11, amendment A13;
//! component-model spec §8 "extension point"; threat entries T-STO-* in
//! `docs/security/threat-model.md` §6).
//!
//! A storage capability is an ordinary [`Capability`](super::Capability)
//! whose target is `Target::Service(ServiceId::Storage)` — the kernel's
//! storage service, the only kind of target `Target::Service` designates —
//! and whose attenuation is `Attenuation::Storage(`[`StorageAttenuation`]`)`.
//! The §9 lattice is the product of three things the capability already
//! carries and one this module adds:
//!
//! | §9 field | where it lives | order |
//! |---|---|---|
//! | `ops ⊆ {Read, Write, Snapshot, Rollback, Format}` | `Capability::ops` (bits 8–12, [`STORAGE_OPS`]) | `⊆` |
//! | `expires: Option<mono tick>` | `Capability::expires` | `≤`, `None` = never |
//! | `tree`, `prefix`, `blobs`, `quota` | [`StorageAttenuation`] | below |
//!
//! so `Capability::is_attenuation_of` — the one predicate `delegate`
//! consults — is the §9 `⊑` with no new code in the tables.
//!
//! # The order ([`StorageAttenuation::is_attenuation_of`])
//!
//! - **tree**: [`Tree::Live`] and each [`Tree::SnapshotRo`]`(name)` are
//!   pairwise incomparable (equal only). Reading an old snapshot is not a
//!   narrowing of the live tree: a snapshot can hold what the live tree
//!   deleted.
//! - **prefix**: by path *components* ([`StoragePath::is_within`]): `/app/foo`
//!   covers `/app/foo` and `/app/foo/x`, never `/app/foobar`. Paths are parsed
//!   once, canonically and totally; `.`, `..`, empty components and NUL are
//!   refused; one spelling per path.
//! - **blobs**: [`BlobScope::None`] is the bottom; `RefSet(R) ⊑ RefSet(R′)` iff
//!   `R ⊆ R′`; `RefSet(R) ⊑ Domain(d)` iff every reference in `R` is in `d`;
//!   `Domain(d) ⊑ Domain(d′)` iff `d = d′`; a `Domain` is never below a
//!   `RefSet`. There is no `List`: no scope enumerates a domain.
//! - **quota**: each of `bytes`, `inodes`, `blob_bytes` is `≤`.
//!
//! What a capability *permits* is [`StorageAttenuation::admits`]; Kani proves
//! `⊑` sound against it (`proofs::storage_delegate_never_amplifies`), a
//! partial order (`proofs::storage_order_is_a_partial_order`), component-wise
//! on prefixes (`proofs::prefix_order_is_component_wise`), and the wire form
//! total (`proofs::storage_decode_is_total`), canonical and round-tripping
//! field by field (`proofs::storage_wire_{tree,prefix,quota}_is_canonical_and_round_trips`,
//! `proofs::storage_wire_blobs_is_canonical`, `proofs::storage_wire_blobs_round_trips`).
//!
//! # Operations
//!
//! `Snapshot` and `Rollback` are distinct from `Write` and neither is implied
//! by it (an op set is a set: `⊆` never adds a bit). `Snapshot`, `Rollback`
//! and `Format` act on the whole volume, so `admits` grants them only to a
//! capability whose prefix is the root and whose tree is `Live`; `Format` is
//! the strongest — it implies nothing, nothing implies it, and nothing
//! narrower than the whole live tree can exercise it. A `SnapshotRo`
//! capability admits `Read` only.
//!
//! # Wire form (v2 attenuation kind [`KIND`])
//!
//! [`StorageAttenuation::encode`] writes one canonical form and
//! [`StorageAttenuation::decode`] is total and refuses every other byte
//! string (all integers little-endian):
//!
//! ```text
//! tree    u8 0 = Live | u8 1 = SnapshotRo, u8 n (1..=MAX_NAME), n name bytes
//! prefix  u8 n (0..=MAX_PATH_BYTES), n bytes of the canonical relative path ("a/b"; 0 = root)
//! blobs   u8 0 = None | u8 1 = Domain, le16 domain | u8 2 = RefSet, u8 k (1..=MAX_REFS),
//!         k × (le16 domain ‖ hash), strictly ascending by (domain, hash)
//! quota   le64 bytes ‖ le64 inodes ‖ le64 blob_bytes
//! ```
//!
//! Only the body is defined here; the identity framing (`u8 kind ‖ le16 len ‖
//! body`) belongs to `kernel::host` (component PR-2b).
//!
//! # Bounds
//!
//! Everything is fixed capacity — no heap, nothing sized by input:
//! [`MAX_DEPTH`] components and [`MAX_PATH_BYTES`] bytes per path,
//! [`MAX_NAME`] bytes per snapshot name, [`MAX_REFS`] references per set.
//! Under `cargo kani` the same code runs with shrunken bounds (2 components,
//! 5 path bytes, 2 name bytes, 2 references of 1-byte hashes).
//!
//! # Not here
//!
//! Enforcement — presenting a storage capability to the filesystem, quota
//! accounting, denial logging on the storage path — is FS-4. Nothing in
//! `kernel::sfs` or `kernel::fs` consults this module yet. The type holds no
//! secret (paths, names, quotas and blob hashes are identifiers), so it needs
//! no zeroization.

use super::{Op, OpSet};
use crate::sfs::key::BlobDomain;
use core::cmp::Ordering;

/// Attenuation kind of the storage lattice in the v2 identity framing
/// (`u8 kind ‖ le16 len ‖ body`; kind 0 is `Message`).
pub const KIND: u8 = 1;

/// Most components in a storage path.
#[cfg(not(kani))]
pub const MAX_DEPTH: usize = 8;
/// Most components in a storage path (shrunken for Kani).
#[cfg(kani)]
pub const MAX_DEPTH: usize = 2;

/// Most bytes in a canonical relative path (components and separators).
#[cfg(not(kani))]
pub const MAX_PATH_BYTES: usize = 64;
/// Most bytes in a canonical relative path (shrunken for Kani; 5 so that
/// `TooDeep` — `a/b/c` — is reachable before `TooLong`).
#[cfg(kani)]
pub const MAX_PATH_BYTES: usize = 5;

/// Most bytes in a snapshot name.
#[cfg(not(kani))]
pub const MAX_NAME: usize = 16;
/// Most bytes in a snapshot name (shrunken for Kani).
#[cfg(kani)]
pub const MAX_NAME: usize = 2;

/// Most blob references in a [`RefSet`].
#[cfg(not(kani))]
pub const MAX_REFS: usize = 4;
/// Most blob references in a [`RefSet`] (shrunken for Kani).
#[cfg(kani)]
pub const MAX_REFS: usize = 2;

/// Bytes of a blob hash in a reference: the full SHA-256 digest.
#[cfg(not(kani))]
pub const REF_HASH_LEN: usize = crate::hash::DIGEST_LEN;
/// Bytes of a blob hash in a reference (shrunken for Kani: equality and
/// order are all the lattice uses; one byte keeps the slab-level harnesses in
/// `cap::table::proofs` within their 60 s budget).
#[cfg(kani)]
pub const REF_HASH_LEN: usize = 1;

// Lengths and counts are stored and encoded with `as u8`.
const _: () = assert!(MAX_PATH_BYTES <= u8::MAX as usize);
const _: () = assert!(MAX_NAME <= u8::MAX as usize);
const _: () = assert!(MAX_REFS <= u8::MAX as usize);

/// Longest body [`StorageAttenuation::encode`] writes.
pub const MAX_ENCODED_LEN: usize =
    (1 + 1 + MAX_NAME) + (1 + MAX_PATH_BYTES) + (1 + 1 + MAX_REFS * (2 + REF_HASH_LEN)) + 3 * 8;

/// The storage operations (bits 8–12 of an [`OpSet`]). A storage capability
/// may carry these and `Delegate`, nothing else.
pub const STORAGE_OPS: OpSet =
    OpSet::of(&[Op::Read, Op::Write, Op::Snapshot, Op::Rollback, Op::Format]);

/// Everything a storage capability may carry: [`STORAGE_OPS`] and
/// `Delegate` (what `Target::allowed_ops` returns for the storage service).
pub const STORAGE_ALLOWED_OPS: OpSet = OpSet::from_bits(STORAGE_OPS.bits() | Op::Delegate.bit());

/// A blob hash as a reference carries it.
pub type RefHash = [u8; REF_HASH_LEN];

/// Why a path, a name, a reference set or an encoding was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StorageError {
    /// An absolute path did not start with `/`.
    NotAbsolute,
    /// An empty component (`//`, a trailing `/`) or an empty name.
    EmptyComponent,
    /// A `.` or `..` component.
    DotComponent,
    /// A NUL byte in a component or name.
    Nul,
    /// A `/` inside a snapshot name.
    Separator,
    /// More than [`MAX_PATH_BYTES`] path bytes or [`MAX_NAME`] name bytes.
    TooLong,
    /// More than [`MAX_DEPTH`] components.
    TooDeep,
    /// An empty reference set, or more than [`MAX_REFS`] references.
    RefCount,
    /// A reference set naming one blob twice.
    DuplicateRef,
    /// Encoded references not strictly ascending.
    NonCanonical,
    /// An unknown tag byte.
    BadTag,
    /// The input ended inside a field.
    Short,
    /// Bytes left over after the last field.
    Trailing,
    /// The output buffer is shorter than [`StorageAttenuation::encoded_len`].
    BufferTooSmall,
}

/// A canonical storage path: zero or more components, kept as the relative
/// form `a/b/c` (the root is empty) in a fixed array, zero padded, so the
/// derived equality is path equality. Built only by [`StoragePath::parse`]
/// and the decoder, which accept exactly one spelling per path.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StoragePath {
    len: u8,
    bytes: [u8; MAX_PATH_BYTES],
}

impl StoragePath {
    /// `/` — every path is within it.
    pub const ROOT: StoragePath = StoragePath {
        len: 0,
        bytes: [0; MAX_PATH_BYTES],
    };

    /// Parse an absolute path: `/`, or `/` followed by components separated
    /// by single `/`s, with no trailing `/`. Total.
    ///
    /// # Errors
    ///
    /// [`StorageError::NotAbsolute`], and every refusal of a component or a
    /// bound ([`StorageError::EmptyComponent`], [`StorageError::DotComponent`],
    /// [`StorageError::Nul`], [`StorageError::TooLong`],
    /// [`StorageError::TooDeep`]).
    pub fn parse(abs: &[u8]) -> Result<StoragePath, StorageError> {
        match abs.split_first() {
            Some((b'/', rest)) => Self::from_relative(rest),
            _ => Err(StorageError::NotAbsolute),
        }
    }

    /// The path whose canonical relative form is `rel` (`a/b`; empty is the
    /// root) — what the wire form carries. Total.
    ///
    /// # Errors
    ///
    /// As [`Self::parse`], less `NotAbsolute`.
    pub fn from_relative(rel: &[u8]) -> Result<StoragePath, StorageError> {
        if rel.len() > MAX_PATH_BYTES {
            return Err(StorageError::TooLong);
        }
        let len = rel.len();
        let mut bytes = [0u8; MAX_PATH_BYTES];
        copy_in(&mut bytes, rel);
        if len > 0 {
            // One pass with a virtual separator at `len`, as constant-range
            // index loops (the verifier shape `cap::table` documents).
            let mut depth = 1usize;
            let mut comp_len = 0usize;
            let mut dots = 0usize;
            for i in 0..=MAX_PATH_BYTES {
                if i > len {
                    break;
                }
                let b = if i < len { byte_at(&bytes, i) } else { b'/' };
                if b == b'/' {
                    if comp_len == 0 {
                        return Err(StorageError::EmptyComponent);
                    }
                    if comp_len == dots && dots <= 2 {
                        return Err(StorageError::DotComponent);
                    }
                    if i < len {
                        depth += 1;
                        if depth > MAX_DEPTH {
                            return Err(StorageError::TooDeep);
                        }
                    }
                    comp_len = 0;
                    dots = 0;
                } else {
                    if b == 0 {
                        return Err(StorageError::Nul);
                    }
                    comp_len += 1;
                    if b == b'.' {
                        dots += 1;
                    }
                }
            }
        }
        Ok(StoragePath {
            len: len as u8,
            bytes,
        })
    }

    /// The canonical relative form (`a/b`; empty for the root).
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.len)).unwrap_or(&[])
    }

    /// Whether this is `/`.
    pub const fn is_root(&self) -> bool {
        self.len == 0
    }

    /// Number of components (0 for the root).
    pub fn depth(&self) -> usize {
        let len = usize::from(self.len);
        if len == 0 {
            return 0;
        }
        let mut d = 1;
        for i in 0..MAX_PATH_BYTES {
            if i < len && byte_at(&self.bytes, i) == b'/' {
                d += 1;
            }
        }
        d
    }

    /// Component `i`, if the path has one.
    pub fn component(&self, i: usize) -> Option<&[u8]> {
        let len = usize::from(self.len);
        if len == 0 {
            return None;
        }
        let mut idx = 0;
        let mut start = 0;
        for k in 0..=MAX_PATH_BYTES {
            if k > len {
                break;
            }
            if k == len || byte_at(&self.bytes, k) == b'/' {
                if idx == i {
                    return self.bytes.get(start..k);
                }
                idx += 1;
                start = k + 1;
            }
        }
        None
    }

    /// `self` is `prefix` or below it, **by whole components**: the prefix's
    /// bytes start `self` and are followed by a separator or the end. So
    /// `/app/foo/x` is within `/app/foo` and `/app/foobar` is not.
    pub fn is_within(&self, prefix: &StoragePath) -> bool {
        let (cl, pl) = (usize::from(self.len), usize::from(prefix.len));
        if pl == 0 {
            return true;
        }
        if cl < pl {
            return false;
        }
        for k in 0..MAX_PATH_BYTES {
            if k < pl && byte_at(&self.bytes, k) != byte_at(&prefix.bytes, k) {
                return false;
            }
        }
        cl == pl || byte_at(&self.bytes, pl) == b'/'
    }
}

/// `bytes[i]`, or 0 past the end (callers stay in range; padding is 0).
fn byte_at<const N: usize>(bytes: &[u8; N], i: usize) -> u8 {
    bytes.get(i).copied().unwrap_or(0)
}

/// Copy `src` (at most `N` elements; the rest is ignored) to the start of
/// `dst`, element by element over a constant range: a copy of symbolic length
/// is a shape the verifier models imprecisely (measured: `RefSet`'s copy of a
/// symbolically sliced array produced spurious states), an indexed one is not.
fn copy_in<T: Copy, const N: usize>(dst: &mut [T; N], src: &[T]) {
    for (i, d) in dst.iter_mut().enumerate() {
        if let Some(v) = src.get(i) {
            *d = *v;
        }
    }
}

/// A snapshot's name: one path component of at most [`MAX_NAME`] bytes,
/// zero padded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SnapshotName {
    len: u8,
    bytes: [u8; MAX_NAME],
}

impl SnapshotName {
    /// Parse a name: the rules of a path component, `1..=MAX_NAME` bytes.
    ///
    /// # Errors
    ///
    /// [`StorageError::TooLong`], or the component refusals
    /// ([`StorageError::EmptyComponent`], [`StorageError::DotComponent`],
    /// [`StorageError::Nul`], [`StorageError::Separator`]).
    pub fn parse(name: &[u8]) -> Result<SnapshotName, StorageError> {
        if name.len() > MAX_NAME {
            return Err(StorageError::TooLong);
        }
        if name.is_empty() {
            return Err(StorageError::EmptyComponent);
        }
        let len = name.len();
        let mut bytes = [0u8; MAX_NAME];
        copy_in(&mut bytes, name);
        let mut dots = 0;
        for i in 0..MAX_NAME {
            if i < len {
                match byte_at(&bytes, i) {
                    0 => return Err(StorageError::Nul),
                    b'/' => return Err(StorageError::Separator),
                    b'.' => dots += 1,
                    _ => {}
                }
            }
        }
        if dots == len && len <= 2 {
            return Err(StorageError::DotComponent);
        }
        Ok(SnapshotName {
            len: len as u8,
            bytes,
        })
    }

    /// The name's bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.len)).unwrap_or(&[])
    }
}

/// Which tree a storage capability addresses.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tree {
    /// The live tree.
    Live,
    /// One retained snapshot, read-only.
    SnapshotRo(SnapshotName),
}

impl Tree {
    /// `self ⊑ parent`: equal only — the trees are pairwise incomparable.
    pub fn is_attenuation_of(&self, parent: &Tree) -> bool {
        self == parent
    }
}

/// One blob: its domain (as on disk, `kernel::sfs::key`) and its hash. The
/// domain is kept as its on-disk `u16` (every value is a domain, so this is
/// canonical and keeps the slab free of nested enums).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BlobRef {
    wire: u16,
    /// The blob's hash (keyed per domain for `User` domains).
    pub hash: RefHash,
}

impl BlobRef {
    const ZERO: BlobRef = BlobRef {
        wire: 0,
        hash: [0; REF_HASH_LEN],
    };

    /// The blob `hash` in `domain`.
    pub const fn new(domain: BlobDomain, hash: RefHash) -> BlobRef {
        BlobRef {
            wire: domain.to_wire(),
            hash,
        }
    }

    /// The dedup domain the hash lives in.
    pub const fn domain(&self) -> BlobDomain {
        BlobDomain::from_wire(self.wire)
    }

    /// The canonical order: domain (as on disk) first, then hash bytes —
    /// the blobs tree's own key order.
    pub fn canonical_cmp(&self, other: &BlobRef) -> Ordering {
        let (a, b) = (self.wire, other.wire);
        if a != b {
            return if a < b {
                Ordering::Less
            } else {
                Ordering::Greater
            };
        }
        // Byte by byte (not the slice `Ord`, which lowers to an intrinsic
        // the verifier models less precisely).
        for i in 0..REF_HASH_LEN {
            let (x, y) = (self.hash[i], other.hash[i]);
            if x != y {
                return if x < y {
                    Ordering::Less
                } else {
                    Ordering::Greater
                };
            }
        }
        Ordering::Equal
    }
}

/// A non-empty set of at most [`MAX_REFS`] blob references, kept strictly
/// ascending by [`BlobRef::canonical_cmp`] and zero padded, so the derived
/// equality is set equality.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RefSet {
    len: u8,
    refs: [BlobRef; MAX_REFS],
}

impl RefSet {
    /// The set of `refs`, in any order.
    ///
    /// # Errors
    ///
    /// [`StorageError::RefCount`] for none or more than [`MAX_REFS`];
    /// [`StorageError::DuplicateRef`] if one blob is named twice.
    pub fn new(refs: &[BlobRef]) -> Result<RefSet, StorageError> {
        if refs.is_empty() || refs.len() > MAX_REFS {
            return Err(StorageError::RefCount);
        }
        let n = refs.len();
        let mut out = [BlobRef::ZERO; MAX_REFS];
        copy_in(&mut out, refs);
        // Insertion sort over at most MAX_REFS entries.
        for i in 1..n {
            let mut j = i;
            while j > 0 && out[j].canonical_cmp(&out[j - 1]) == Ordering::Less {
                out.swap(j, j - 1);
                j -= 1;
            }
        }
        Self::from_array(n, out)
    }

    /// The set of the first `len` entries of `refs`, which must already be
    /// strictly ascending (the decoder's canonical-order rule); the rest of
    /// `refs` is ignored and stored as zero.
    fn from_array(len: usize, refs: [BlobRef; MAX_REFS]) -> Result<RefSet, StorageError> {
        if len == 0 || len > MAX_REFS {
            return Err(StorageError::RefCount);
        }
        let mut out = [BlobRef::ZERO; MAX_REFS];
        for i in 0..MAX_REFS {
            if i < len {
                if i > 0 {
                    match refs[i - 1].canonical_cmp(&refs[i]) {
                        Ordering::Less => {}
                        Ordering::Equal => return Err(StorageError::DuplicateRef),
                        Ordering::Greater => return Err(StorageError::NonCanonical),
                    }
                }
                out[i] = refs[i];
            }
        }
        Ok(RefSet {
            len: len as u8,
            refs: out,
        })
    }

    /// The references, ascending.
    pub fn as_slice(&self) -> &[BlobRef] {
        self.refs.get(..usize::from(self.len)).unwrap_or(&[])
    }

    /// `r ∈ self`.
    pub fn contains(&self, r: &BlobRef) -> bool {
        let n = usize::from(self.len);
        let mut found = false;
        for i in 0..MAX_REFS {
            if i < n && self.refs[i] == *r {
                found = true;
            }
        }
        found
    }

    /// `self ⊆ other`.
    pub fn is_subset_of(&self, other: &RefSet) -> bool {
        let n = usize::from(self.len);
        let mut all = true;
        for i in 0..MAX_REFS {
            if i < n && !other.contains(&self.refs[i]) {
                all = false;
            }
        }
        all
    }

    /// The references for which `keep` holds, as a scope: a `RefSet` (still
    /// strictly ascending — a subsequence of one), or `None` if none is kept.
    fn keep(&self, keep: impl Fn(&BlobRef) -> bool) -> BlobScope {
        let n = usize::from(self.len);
        let mut out = [BlobRef::ZERO; MAX_REFS];
        let mut k = 0;
        for i in 0..MAX_REFS {
            if i < n && keep(&self.refs[i]) {
                if let Some(slot) = out.get_mut(k) {
                    *slot = self.refs[i];
                }
                k += 1;
            }
        }
        match RefSet::from_array(k, out) {
            Ok(s) => BlobScope::RefSet(s),
            Err(_) => BlobScope::None,
        }
    }

    /// Every reference is in domain `d`.
    pub fn all_in(&self, d: BlobDomain) -> bool {
        let n = usize::from(self.len);
        let mut all = true;
        for i in 0..MAX_REFS {
            if i < n && self.refs[i].wire != d.to_wire() {
                all = false;
            }
        }
        all
    }
}

/// Which blobs a storage capability reaches. There is no `List`: no scope
/// enumerates a domain; an access always names one hash.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BlobScope {
    /// No blob at all (the bottom).
    None,
    /// Any blob of one domain, by hash.
    Domain(BlobDomain),
    /// Exactly these blobs.
    RefSet(RefSet),
}

impl BlobScope {
    /// `self ⊑ parent` (module docs).
    pub fn is_attenuation_of(&self, parent: &BlobScope) -> bool {
        match (self, parent) {
            (BlobScope::None, _) => true,
            (BlobScope::RefSet(a), BlobScope::RefSet(b)) => a.is_subset_of(b),
            (BlobScope::RefSet(a), BlobScope::Domain(d)) => a.all_in(*d),
            (BlobScope::Domain(a), BlobScope::Domain(b)) => a == b,
            (BlobScope::RefSet(_) | BlobScope::Domain(_), _) => false,
        }
    }

    /// The greatest lower bound by `⊑`. Total: `None` (no blobs) is the
    /// bottom, so two scopes always have one — an empty intersection is
    /// `None`.
    pub fn meet(&self, other: &BlobScope) -> BlobScope {
        match (self, other) {
            (BlobScope::None, _) | (_, BlobScope::None) => BlobScope::None,
            (BlobScope::Domain(a), BlobScope::Domain(b)) => {
                if a == b {
                    BlobScope::Domain(*a)
                } else {
                    BlobScope::None
                }
            }
            (BlobScope::RefSet(s), BlobScope::Domain(d))
            | (BlobScope::Domain(d), BlobScope::RefSet(s)) => s.keep(|r| r.wire == d.to_wire()),
            (BlobScope::RefSet(a), BlobScope::RefSet(b)) => a.keep(|r| b.contains(r)),
        }
    }

    /// Whether this scope reaches blob `r`.
    pub fn admits(&self, r: &BlobRef) -> bool {
        match self {
            BlobScope::None => false,
            BlobScope::Domain(d) => r.wire == d.to_wire(),
            BlobScope::RefSet(s) => s.contains(r),
        }
    }
}

/// A ceiling on a **shared, lineage-charged budget**, not a budget of its
/// own. `⊑` is `≤` on every field, so a delegate's ceiling never exceeds its
/// parent's — but a holder can hand a full-ceiling copy to every instance it
/// reaches (and revoke and re-delegate), so a per-capability counter would
/// multiply the budget. FS-4 therefore charges every write to the counter of
/// the root grant (equivalently, of every ancestor in the delegation chain),
/// and that usage survives revoke and re-delegate (threat T-STO-6, open until
/// FS-4). [`StorageAttenuation::admits`] checks only that one write fits under
/// the ceiling; `inodes` is not consulted there at all (creation is FS-2/FS-4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Quota {
    /// File bytes.
    pub bytes: u64,
    /// Inodes (files and directories).
    pub inodes: u64,
    /// Blob bytes.
    pub blob_bytes: u64,
}

impl Quota {
    /// No ceiling.
    pub const UNLIMITED: Quota = Quota {
        bytes: u64::MAX,
        inodes: u64::MAX,
        blob_bytes: u64::MAX,
    };

    /// `self ≤ parent` on every field.
    pub const fn is_attenuation_of(&self, parent: &Quota) -> bool {
        self.bytes <= parent.bytes
            && self.inodes <= parent.inodes
            && self.blob_bytes <= parent.blob_bytes
    }
}

/// What a storage access touches.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StorageObject {
    /// A file or directory (for volume-wide operations: the root).
    Path(StoragePath),
    /// One blob, by domain and hash.
    Blob(BlobRef),
}

/// One concrete storage operation — what `Access::Storage` asks a
/// capability to allow. FS-4's storage service builds one per operation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StorageAccess {
    /// The operation (one of [`STORAGE_OPS`]).
    pub op: Op,
    /// The tree it acts on.
    pub tree: Tree,
    /// What it touches.
    pub object: StorageObject,
    /// Bytes it would write (0 for reads).
    pub bytes: u64,
}

/// The storage lattice's attenuation: tree, path prefix, blob scope, quota
/// (the ops and expiry live on the capability; module docs).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StorageAttenuation {
    /// The tree addressed.
    pub tree: Tree,
    /// Paths reached: this one and everything below it, by components.
    pub prefix: StoragePath,
    /// Blobs reached.
    pub blobs: BlobScope,
    /// Ceilings.
    pub quota: Quota,
}

impl StorageAttenuation {
    /// `self ⊑ parent`: every storage access `self` admits, `parent` admits.
    /// Total and decidable: tree equal, prefix component-wise, blobs by
    /// scope, quota field-wise.
    pub fn is_attenuation_of(&self, parent: &StorageAttenuation) -> bool {
        self.tree.is_attenuation_of(&parent.tree)
            && self.prefix.is_within(&parent.prefix)
            && self.blobs.is_attenuation_of(&parent.blobs)
            && self.quota.is_attenuation_of(&parent.quota)
    }

    /// The greatest lower bound by `⊑` — what `grant` installs for a
    /// storage request ∧ policy — or `None` when the two share nothing:
    /// different trees, or prefixes neither of which is within the other
    /// (no path is within both). Otherwise: the same tree, the deeper prefix,
    /// the blob scopes' meet ([`BlobScope::meet`]), the field-wise minimum
    /// quota. (Expiry is the capability's: `Capability::meet` takes the
    /// earlier.) Kani: `proofs::storage_meet_is_the_greatest_lower_bound`.
    pub fn meet(&self, other: &StorageAttenuation) -> Option<StorageAttenuation> {
        if self.tree != other.tree {
            return None;
        }
        let prefix = if self.prefix.is_within(&other.prefix) {
            self.prefix
        } else if other.prefix.is_within(&self.prefix) {
            other.prefix
        } else {
            return None;
        };
        Some(StorageAttenuation {
            tree: self.tree,
            prefix,
            blobs: self.blobs.meet(&other.blobs),
            quota: Quota {
                bytes: self.quota.bytes.min(other.quota.bytes),
                inodes: self.quota.inodes.min(other.quota.inodes),
                blob_bytes: self.quota.blob_bytes.min(other.quota.blob_bytes),
            },
        })
    }

    /// Whether this attenuation lets `access` through (the op must also be in
    /// the capability's op set — `Capability::permits` checks that).
    ///
    /// - `Read`: same tree; a path within the prefix, or a blob in scope.
    /// - `Write`: the live tree; a path within the prefix with `bytes ≤
    ///   quota.bytes`, or a blob in scope with `bytes ≤ quota.blob_bytes`.
    /// - `Snapshot`, `Rollback`, `Format`: volume-wide — the live tree, a root
    ///   prefix, and the root path as the object.
    /// - anything else: never.
    pub fn admits(&self, access: &StorageAccess) -> bool {
        if access.tree != self.tree {
            return false;
        }
        match access.op {
            Op::Read => match &access.object {
                StorageObject::Path(p) => p.is_within(&self.prefix),
                StorageObject::Blob(r) => self.blobs.admits(r),
            },
            Op::Write => {
                self.tree == Tree::Live
                    && match &access.object {
                        StorageObject::Path(p) => {
                            p.is_within(&self.prefix) && access.bytes <= self.quota.bytes
                        }
                        StorageObject::Blob(r) => {
                            self.blobs.admits(r) && access.bytes <= self.quota.blob_bytes
                        }
                    }
            }
            Op::Snapshot | Op::Rollback | Op::Format => {
                self.tree == Tree::Live
                    && self.prefix.is_root()
                    && matches!(&access.object, StorageObject::Path(p) if p.is_root())
            }
            Op::Send | Op::Request | Op::Reply | Op::Delegate => false,
        }
    }

    /// Bytes [`Self::encode`] writes.
    pub fn encoded_len(&self) -> usize {
        tree_len(&self.tree) + prefix_len(&self.prefix) + blobs_len(&self.blobs) + QUOTA_LEN
    }

    /// Write the canonical body (module docs) to the start of `out`; the
    /// number of bytes written.
    ///
    /// # Errors
    ///
    /// [`StorageError::BufferTooSmall`] if `out` is shorter than
    /// [`Self::encoded_len`] (at most [`MAX_ENCODED_LEN`]); nothing is
    /// written then.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, StorageError> {
        let n = self.encoded_len();
        let buf = out.get_mut(..n).ok_or(StorageError::BufferTooSmall)?;
        let mut w = Writer { buf, pos: 0 };
        put_tree(&mut w, &self.tree)?;
        put_prefix(&mut w, &self.prefix)?;
        put_blobs(&mut w, &self.blobs)?;
        put_quota(&mut w, &self.quota)?;
        Ok(w.pos)
    }

    /// Decode a body. Total: every byte string is either exactly one
    /// canonical encoding — and then re-encodes to itself — or refused.
    /// The body is the four fields in order, each read by its own decoder
    /// (each of which re-encodes exactly the bytes it consumed — Kani,
    /// per field), then nothing.
    ///
    /// # Errors
    ///
    /// [`StorageError::Short`], [`StorageError::Trailing`],
    /// [`StorageError::BadTag`], [`StorageError::NonCanonical`],
    /// [`StorageError::DuplicateRef`], [`StorageError::RefCount`], and every
    /// path and name refusal.
    pub fn decode(bytes: &[u8]) -> Result<StorageAttenuation, StorageError> {
        let mut r = Reader { buf: bytes, pos: 0 };
        let tree = get_tree(&mut r)?;
        let prefix = get_prefix(&mut r)?;
        let blobs = get_blobs(&mut r)?;
        let quota = get_quota(&mut r)?;
        if r.pos != bytes.len() {
            return Err(StorageError::Trailing);
        }
        Ok(StorageAttenuation {
            tree,
            prefix,
            blobs,
            quota,
        })
    }
}

// ── The four fields of the wire form, each encoded and decoded on its own ──

/// Bytes of the quota field.
const QUOTA_LEN: usize = 3 * 8;

fn tree_len(t: &Tree) -> usize {
    match t {
        Tree::Live => 1,
        Tree::SnapshotRo(n) => 2 + n.as_bytes().len(),
    }
}

fn prefix_len(p: &StoragePath) -> usize {
    1 + p.as_bytes().len()
}

fn blobs_len(b: &BlobScope) -> usize {
    match b {
        BlobScope::None => 1,
        BlobScope::Domain(_) => 3,
        BlobScope::RefSet(s) => 2 + s.as_slice().len() * (2 + REF_HASH_LEN),
    }
}

fn put_tree(w: &mut Writer<'_>, t: &Tree) -> Result<(), StorageError> {
    match t {
        Tree::Live => w.put(&[0]),
        Tree::SnapshotRo(name) => {
            let b = name.as_bytes();
            w.put(&[1, b.len() as u8])?;
            w.put(b)
        }
    }
}

fn get_tree(r: &mut Reader<'_>) -> Result<Tree, StorageError> {
    match r.u8()? {
        0 => Ok(Tree::Live),
        1 => {
            let n = r.u8()?;
            if n == 0 {
                return Err(StorageError::EmptyComponent);
            }
            Ok(Tree::SnapshotRo(SnapshotName::parse(
                r.take(usize::from(n))?,
            )?))
        }
        _ => Err(StorageError::BadTag),
    }
}

fn put_prefix(w: &mut Writer<'_>, p: &StoragePath) -> Result<(), StorageError> {
    let b = p.as_bytes();
    w.put(&[b.len() as u8])?;
    w.put(b)
}

fn get_prefix(r: &mut Reader<'_>) -> Result<StoragePath, StorageError> {
    let n = usize::from(r.u8()?);
    if n > MAX_PATH_BYTES {
        return Err(StorageError::TooLong);
    }
    StoragePath::from_relative(r.take(n)?)
}

fn put_blobs(w: &mut Writer<'_>, b: &BlobScope) -> Result<(), StorageError> {
    match b {
        BlobScope::None => w.put(&[0]),
        BlobScope::Domain(d) => {
            w.put(&[1])?;
            w.put(&d.to_wire().to_le_bytes())
        }
        BlobScope::RefSet(s) => {
            let refs = s.as_slice();
            w.put(&[2, refs.len() as u8])?;
            for r in refs {
                w.put(&r.wire.to_le_bytes())?;
                w.put(&r.hash)?;
            }
            Ok(())
        }
    }
}

fn get_blobs(r: &mut Reader<'_>) -> Result<BlobScope, StorageError> {
    match r.u8()? {
        0 => Ok(BlobScope::None),
        1 => Ok(BlobScope::Domain(BlobDomain::from_wire(r.u16()?))),
        2 => {
            let k = usize::from(r.u8()?);
            if k == 0 || k > MAX_REFS {
                return Err(StorageError::RefCount);
            }
            let mut refs = [BlobRef::ZERO; MAX_REFS];
            for (i, slot) in refs.iter_mut().enumerate() {
                if i < k {
                    let wire = r.u16()?;
                    let mut hash = [0u8; REF_HASH_LEN];
                    copy_in(&mut hash, r.take(REF_HASH_LEN)?);
                    *slot = BlobRef { wire, hash };
                }
            }
            Ok(BlobScope::RefSet(RefSet::from_array(k, refs)?))
        }
        _ => Err(StorageError::BadTag),
    }
}

fn put_quota(w: &mut Writer<'_>, q: &Quota) -> Result<(), StorageError> {
    w.put(&q.bytes.to_le_bytes())?;
    w.put(&q.inodes.to_le_bytes())?;
    w.put(&q.blob_bytes.to_le_bytes())
}

fn get_quota(r: &mut Reader<'_>) -> Result<Quota, StorageError> {
    Ok(Quota {
        bytes: r.u64()?,
        inodes: r.u64()?,
        blob_bytes: r.u64()?,
    })
}

struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl Writer<'_> {
    fn put(&mut self, b: &[u8]) -> Result<(), StorageError> {
        let end = self
            .pos
            .checked_add(b.len())
            .ok_or(StorageError::BufferTooSmall)?;
        let dst = self
            .buf
            .get_mut(self.pos..end)
            .ok_or(StorageError::BufferTooSmall)?;
        // Element by element, like `copy_in` (lengths here are symbolic).
        for (d, v) in dst.iter_mut().zip(b) {
            *d = *v;
        }
        self.pos = end;
        Ok(())
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], StorageError> {
        let end = self.pos.checked_add(n).ok_or(StorageError::Short)?;
        let s = self.buf.get(self.pos..end).ok_or(StorageError::Short)?;
        self.pos = end;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, StorageError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, StorageError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u64(&mut self) -> Result<u64, StorageError> {
        let mut a = [0u8; 8];
        a.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(a))
    }
}

#[cfg(test)]
mod tests;

/// Kani harnesses for the storage lattice (shrunken bounds, module docs).
/// Compiled only under `cargo kani`.
#[cfg(kani)]
pub(crate) mod proofs {
    use super::*;

    /// A symbolic canonical path at the Kani bound — every one, through the
    /// real validator.
    pub(crate) fn any_path() -> StoragePath {
        let bytes: [u8; MAX_PATH_BYTES] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= MAX_PATH_BYTES);
        match StoragePath::from_relative(&bytes[..len]) {
            Ok(p) => p,
            Err(_) => {
                kani::assume(false);
                StoragePath::ROOT
            }
        }
    }

    fn any_domain() -> BlobDomain {
        BlobDomain::from_wire(kani::any())
    }

    fn any_ref() -> BlobRef {
        BlobRef {
            wire: kani::any(),
            hash: kani::any(),
        }
    }

    fn any_tree() -> Tree {
        if kani::any() {
            Tree::Live
        } else {
            let bytes: [u8; MAX_NAME] = kani::any();
            let len: usize = kani::any();
            kani::assume(len <= MAX_NAME);
            match SnapshotName::parse(&bytes[..len]) {
                Ok(n) => Tree::SnapshotRo(n),
                Err(_) => {
                    kani::assume(false);
                    Tree::Live
                }
            }
        }
    }

    fn any_blobs() -> BlobScope {
        match kani::any::<u8>() % 3 {
            0 => BlobScope::None,
            1 => BlobScope::Domain(any_domain()),
            _ => {
                let refs: [BlobRef; MAX_REFS] = core::array::from_fn(|_| any_ref());
                let n: usize = kani::any();
                kani::assume(n >= 1 && n <= MAX_REFS);
                match RefSet::from_array(n, refs) {
                    Ok(s) => BlobScope::RefSet(s),
                    Err(_) => {
                        kani::assume(false);
                        BlobScope::None
                    }
                }
            }
        }
    }

    /// A symbolic canonical storage attenuation.
    pub(crate) fn any_storage_attenuation() -> StorageAttenuation {
        StorageAttenuation {
            tree: any_tree(),
            prefix: any_path(),
            blobs: any_blobs(),
            quota: Quota {
                bytes: kani::any(),
                inodes: kani::any(),
                blob_bytes: kani::any(),
            },
        }
    }

    /// One of a few canonical paths that exercise every relation `is_within`
    /// distinguishes: the root, `/a`, its sibling `/ab` (a byte prefix but
    /// not a component prefix), and its child `/a/b`.
    fn some_path() -> StoragePath {
        let rel: &[u8] = match kani::any::<u8>() % 4 {
            0 => b"",
            1 => b"a",
            2 => b"ab",
            _ => b"a/b",
        };
        match StoragePath::from_relative(rel) {
            Ok(p) => p,
            Err(_) => StoragePath::ROOT,
        }
    }

    fn some_tree() -> Tree {
        match SnapshotName::parse(b"s") {
            Ok(n) if kani::any() => Tree::SnapshotRo(n),
            _ => Tree::Live,
        }
    }

    /// `None`, or a set of one symbolic reference.
    fn some_blobs() -> BlobScope {
        if kani::any() {
            return BlobScope::None;
        }
        match RefSet::from_array(1, [any_ref(); MAX_REFS]) {
            Ok(s) => BlobScope::RefSet(s),
            Err(_) => BlobScope::None,
        }
    }

    /// One constant storage attenuation (live tree, root prefix, no blobs, no
    /// ceiling): just enough for `cap::proofs` to reach every cross-kind arm
    /// of `is_attenuation_of`, `admits` and `fits`. Storage soundness itself
    /// is [`storage_delegate_never_amplifies`].
    pub(crate) fn constant_storage_attenuation() -> StorageAttenuation {
        StorageAttenuation {
            tree: Tree::Live,
            prefix: StoragePath::ROOT,
            blobs: BlobScope::None,
            quota: Quota::UNLIMITED,
        }
    }

    /// One constant storage access (read the root of the live tree), the
    /// companion of [`constant_storage_attenuation`].
    pub(crate) fn constant_storage_access() -> StorageAccess {
        StorageAccess {
            op: Op::Read,
            tree: Tree::Live,
            object: StorageObject::Path(StoragePath::ROOT),
            bytes: 0,
        }
    }

    /// A storage attenuation of constant shape — live tree, prefix `/a`
    /// (whose sibling `/ab`, parent `/` and child `/a/b` the children of
    /// [`some_storage_attenuation`] reach) — with a symbolic blob scope from
    /// [`some_blobs`] and a symbolic quota: the parent of
    /// `cap::table::proofs::delegate_never_amplifies_storage`.
    pub(crate) fn storage_parent_attenuation() -> StorageAttenuation {
        StorageAttenuation {
            tree: Tree::Live,
            prefix: StoragePath::from_relative(b"a").unwrap_or(StoragePath::ROOT),
            blobs: some_blobs(),
            quota: Quota {
                bytes: kani::any(),
                inodes: kani::any(),
                blob_bytes: kani::any(),
            },
        }
    }

    /// A symbolic storage attenuation of a cheaper shape, for the slab-level
    /// harness `cap::table::proofs::delegate_never_amplifies_storage`, whose
    /// cost is dominated by the slab rather than the lattice: paths from
    /// [`some_path`], tree `Live` or one snapshot, blobs from
    /// [`some_blobs`], any quota. The storage harnesses below use the full
    /// generator ([`any_storage_attenuation`]: every canonical value at the
    /// bound).
    pub(crate) fn some_storage_attenuation() -> StorageAttenuation {
        StorageAttenuation {
            tree: some_tree(),
            prefix: some_path(),
            blobs: some_blobs(),
            quota: Quota {
                bytes: kani::any(),
                inodes: kani::any(),
                blob_bytes: kani::any(),
            },
        }
    }

    /// A symbolic storage access over [`some_path`] and the trees of
    /// [`some_storage_attenuation`]; any op, blob and size.
    pub(crate) fn some_storage_access() -> StorageAccess {
        let op = match kani::any::<u8>() % 6 {
            0 => Op::Read,
            1 => Op::Write,
            2 => Op::Snapshot,
            3 => Op::Rollback,
            4 => Op::Format,
            _ => Op::Send,
        };
        StorageAccess {
            op,
            tree: some_tree(),
            object: if kani::any() {
                StorageObject::Path(some_path())
            } else {
                StorageObject::Blob(any_ref())
            },
            bytes: kani::any(),
        }
    }

    /// A symbolic storage access: any op (storage or not), tree, object and
    /// size.
    pub(crate) fn any_storage_access() -> StorageAccess {
        let op = match kani::any::<u8>() % 6 {
            0 => Op::Read,
            1 => Op::Write,
            2 => Op::Snapshot,
            3 => Op::Rollback,
            4 => Op::Format,
            _ => Op::Send,
        };
        StorageAccess {
            op,
            tree: any_tree(),
            object: if kani::any() {
                StorageObject::Path(any_path())
            } else {
                StorageObject::Blob(any_ref())
            },
            bytes: kani::any(),
        }
    }

    /// `⊑` on storage attenuations is a **partial order** on canonical
    /// values: reflexive, transitive, antisymmetric (`a ⊑ b ∧ b ⊑ a ⇒ a =
    /// b` — canonical representations make derived equality semantic).
    #[kani::proof]
    #[kani::unwind(7)]
    fn storage_order_is_a_partial_order() {
        let a = any_storage_attenuation();
        let b = any_storage_attenuation();
        let c = any_storage_attenuation();
        assert!(a.is_attenuation_of(&a));
        if a.is_attenuation_of(&b) && b.is_attenuation_of(&c) {
            assert!(a.is_attenuation_of(&c));
        }
        if a.is_attenuation_of(&b) && b.is_attenuation_of(&a) {
            assert!(a == b);
        }
        // Non-vacuity: strictly related values with two-element blob sets
        // exist at this bound.
        kani::cover!(
            a.is_attenuation_of(&b)
                && a != b
                && matches!(b.blobs, BlobScope::RefSet(s) if s.as_slice().len() == 2)
        );
    }

    /// The storage **meet is the greatest lower bound**: when it exists it
    /// is below both arguments and above every common lower bound; when it
    /// is `None` there is no common lower bound at all. Over every canonical
    /// value at the bound — what `grant` (manifest ∧ policy) installs for a
    /// storage request can never exceed either side.
    #[kani::proof]
    #[kani::unwind(7)]
    fn storage_meet_is_the_greatest_lower_bound() {
        let a = any_storage_attenuation();
        let b = any_storage_attenuation();
        let c = any_storage_attenuation();
        let lower = c.is_attenuation_of(&a) && c.is_attenuation_of(&b);
        match a.meet(&b) {
            Some(m) => {
                assert!(m.is_attenuation_of(&a));
                assert!(m.is_attenuation_of(&b));
                if lower {
                    assert!(c.is_attenuation_of(&m));
                }
            }
            None => assert!(!lower),
        }
        kani::cover!(a.meet(&b).is_some_and(|m| m != a && m != b));
    }

    /// **A delegate never amplifies** on `StorageAttenuation`: if `child ⊑
    /// parent`, every storage access the child admits, the parent admits —
    /// semantically, for any access (any op, tree, path, blob, size).
    #[kani::proof]
    #[kani::unwind(7)]
    fn storage_delegate_never_amplifies() {
        let parent = any_storage_attenuation();
        let child = any_storage_attenuation();
        let access = any_storage_access();
        if child.is_attenuation_of(&parent) && child.admits(&access) {
            assert!(parent.admits(&access));
        }
        kani::cover!(child.is_attenuation_of(&parent) && child != parent && child.admits(&access));
        // Volume-wide operations need the whole live tree.
        if matches!(access.op, Op::Snapshot | Op::Rollback | Op::Format) && child.admits(&access) {
            assert!(child.prefix.is_root() && child.tree == Tree::Live);
        }
        // A read-only snapshot capability admits reads only.
        if matches!(child.tree, Tree::SnapshotRo(_)) && child.admits(&access) {
            assert!(access.op == Op::Read);
        }
    }

    /// Prefix `⊑` is **component-wise**: `c.is_within(p)` iff `p` has at
    /// most as many components as `c` and each of them equals `c`'s at the
    /// same position. The sibling counterexample (`/a/b` vs `/a/bc` at this
    /// bound; `/app/foo` vs `/app/foobar` in the host tests) is refused.
    #[kani::proof]
    #[kani::unwind(7)]
    fn prefix_order_is_component_wise() {
        // Every refusal is reachable at this bound, `TooDeep` included.
        let raw: [u8; MAX_PATH_BYTES] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= MAX_PATH_BYTES);
        let parsed = StoragePath::from_relative(&raw[..n]);
        kani::cover!(parsed == Err(StorageError::TooDeep));
        kani::cover!(parsed == Err(StorageError::DotComponent));
        kani::cover!(parsed == Err(StorageError::EmptyComponent));

        let c = any_path();
        let p = any_path();
        let mut same = p.depth() <= c.depth();
        let mut i = 0;
        while i < MAX_DEPTH {
            if i < p.depth() && p.component(i) != c.component(i) {
                same = false;
            }
            i += 1;
        }
        assert!(c.is_within(&p) == same);

        let (Ok(foo), Ok(foobar)) = (StoragePath::parse(b"/a/b"), StoragePath::parse(b"/a/bc"))
        else {
            panic!("canonical paths must parse");
        };
        assert!(!foobar.is_within(&foo));
        assert!(!foo.is_within(&foobar));
    }

    /// Decode field `get` from any `N`-byte input (any length up to `N`);
    /// if it accepts, `put` must write exactly the bytes it consumed.
    fn field_is_canonical<T, const N: usize>(
        get: fn(&mut Reader<'_>) -> Result<T, StorageError>,
        put: fn(&mut Writer<'_>, &T) -> Result<(), StorageError>,
        len: fn(&T) -> usize,
    ) -> Option<T> {
        let bytes: [u8; N] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= N);
        let mut r = Reader {
            buf: &bytes[..n],
            pos: 0,
        };
        let v = get(&mut r).ok()?;
        let used = r.pos;
        assert!(used <= n && used == len(&v));
        let mut out = [0u8; N];
        let mut w = Writer {
            buf: &mut out,
            pos: 0,
        };
        assert!(put(&mut w, &v).is_ok());
        assert!(w.pos == used);
        for i in 0..N {
            if i < used {
                assert!(out[i] == bytes[i]);
            }
        }
        Some(v)
    }

    /// Encode any canonical value `v` of a field and decode it back: the
    /// decoder must return `v` having consumed exactly `len(v)` bytes.
    fn field_round_trips<T: PartialEq, const N: usize>(
        v: T,
        get: fn(&mut Reader<'_>) -> Result<T, StorageError>,
        put: fn(&mut Writer<'_>, &T) -> Result<(), StorageError>,
        len: fn(&T) -> usize,
    ) {
        let mut out = [0u8; N];
        let mut w = Writer {
            buf: &mut out,
            pos: 0,
        };
        assert!(put(&mut w, &v).is_ok());
        let n = w.pos;
        assert!(n == len(&v) && n <= N);
        let mut r = Reader {
            buf: &out[..n],
            pos: 0,
        };
        assert!(get(&mut r) == Ok(v));
        assert!(r.pos == n);
    }

    // The wire form is **canonical**, field by field: for every input up to
    // the field's bound, each field decoder either refuses or consumes bytes
    // that its encoder writes back exactly. `decode` is the four decoders in
    // sequence followed by "nothing left", and `encode` the four encoders in
    // the same sequence, so an accepted body re-encodes to exactly itself: no
    // attenuation has two encodings, and non-canonical bytes are refused.
    // Each harness also proves its field **round-trips** (`get ∘ put = id`,
    // consuming exactly what `put` wrote), so `decode ∘ encode = id` on the
    // whole body by the same composition. One harness per field keeps each
    // under the 60 s budget: whole-body canonicity and whole-body round-trip
    // harnesses ran past 8 minutes and were stopped. Both whole-body laws are
    // also checked at the production bounds by the host property tests.

    /// Wire form, `tree` field: canonical, and round-trips.
    #[kani::proof]
    #[kani::unwind(6)]
    fn storage_wire_tree_is_canonical_and_round_trips() {
        let t = field_is_canonical::<Tree, { 2 + MAX_NAME }>(get_tree, put_tree, tree_len);
        kani::cover!(matches!(t, Some(Tree::SnapshotRo(_))));
        field_round_trips::<Tree, { 2 + MAX_NAME }>(any_tree(), get_tree, put_tree, tree_len);
    }

    /// Wire form, `prefix` field: canonical, and round-trips.
    #[kani::proof]
    #[kani::unwind(8)]
    fn storage_wire_prefix_is_canonical_and_round_trips() {
        let p = field_is_canonical::<StoragePath, { 1 + MAX_PATH_BYTES }>(
            get_prefix, put_prefix, prefix_len,
        );
        kani::cover!(p.is_some_and(|p| p.depth() == 2));
        field_round_trips::<StoragePath, { 1 + MAX_PATH_BYTES }>(
            any_path(),
            get_prefix,
            put_prefix,
            prefix_len,
        );
    }

    /// Wire form, `blobs` field: canonical. (Split from its round-trip
    /// half: together they take just over the 60 s budget.)
    #[kani::proof]
    #[kani::unwind(12)]
    fn storage_wire_blobs_is_canonical() {
        let b = field_is_canonical::<BlobScope, { 2 + MAX_REFS * (2 + REF_HASH_LEN) }>(
            get_blobs, put_blobs, blobs_len,
        );
        kani::cover!(matches!(b, Some(BlobScope::RefSet(s)) if s.as_slice().len() == 2));
    }

    /// Wire form, `blobs` field: round-trips.
    #[kani::proof]
    #[kani::unwind(12)]
    fn storage_wire_blobs_round_trips() {
        field_round_trips::<BlobScope, { 2 + MAX_REFS * (2 + REF_HASH_LEN) }>(
            any_blobs(),
            get_blobs,
            put_blobs,
            blobs_len,
        );
    }

    /// Wire form, `quota` field: canonical, and round-trips.
    #[kani::proof]
    #[kani::unwind(26)]
    fn storage_wire_quota_is_canonical_and_round_trips() {
        let q = field_is_canonical::<Quota, QUOTA_LEN>(get_quota, put_quota, |_| QUOTA_LEN);
        kani::cover!(q.is_some());
        let any_quota = Quota {
            bytes: kani::any(),
            inodes: kani::any(),
            blob_bytes: kani::any(),
        };
        field_round_trips::<Quota, QUOTA_LEN>(any_quota, get_quota, put_quota, |_| QUOTA_LEN);
    }

    /// `decode` is **total** on the whole body: for every byte string up to
    /// [`MAX_ENCODED_LEN`] it returns — no panic, no overflow, no
    /// out-of-bounds — and what it accepts is exactly `encoded_len` long.
    #[kani::proof]
    #[kani::unwind(10)]
    fn storage_decode_is_total() {
        let bytes: [u8; MAX_ENCODED_LEN] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= MAX_ENCODED_LEN);
        if let Ok(a) = StorageAttenuation::decode(&bytes[..len]) {
            assert!(a.encoded_len() == len);
        }
    }
}
