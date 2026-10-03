//! The superblock (spec §7.1) and the mount-time slot choice.
//!
//! Two slots, blocks 0 and 1 of the device. Each is a metadata block (kind 1,
//! tree `None`) whose payload is:
//!
//! ```text
//!  64    8  magic "SNTLFS02"     72   4  version = 2       76   4  block_size = 4096
//!  80    8  total_blocks         88   8  gen               96  32  fs_uuid (16) + 16 zero
//! 128   48  root: Pointer        176  48  blobs: Pointer    224  48  roots: Pointer
//! 272   48  free: Pointer (the group index)
//! 320    8  next_obj             328   8  committed_at (mono ticks; informational)
//! 336   16  dirent_key           352  32  kdf_params + wrap slot (zero until the
//!                                          identity spec defines it)
//! 384    8  reserve_blocks_per_group
//! 392    …  zero
//! ```
//!
//! Every meaningful byte lives in the block's **first sector**; sectors 1–7
//! are zero. So on a slot whose old content is zero (format zeroes both slots
//! first) or an older superblock (every commit), a torn superblock write
//! leaves either the old first sector or the new one — never a mix that
//! carries the magic but fails its hash because of the write itself.
//!
//! [`decode`] accepts exactly the canonical encoding [`encode`] produces;
//! anything else is a [`SlotError`]. [`select`] is the whole mount rule over
//! the two decoded candidates, Kani-proven (`proofs`).

use crate::blk::geometry::{GROUP_BLOCKS, MIN_BLOCKS};
use crate::blk::layout::{
    decode_header, decode_pointer, verify, Hash, HashRule, Header, Kind, Pointer, TreeId, Uuid,
    HASH_LEN, HEADER_LEN, POINTER_LEN, UUID_LEN,
};
use crate::blk::{Block, BLOCK_SIZE, SECTOR_SIZE};

/// The superblock magic (`SNTLFS01` was the old `kernel::fs` image: foreign).
pub const MAGIC: [u8; 8] = *b"SNTLFS02";
/// The format version.
pub const VERSION: u32 = 2;
/// Length of the KDF-parameters + wrapped-key slot.
pub const KDF_LEN: usize = 32;
/// Length of the dirent-name hash key.
pub const DIRENT_KEY_LEN: usize = 16;
/// End of the encoded fields; everything after is zero.
pub const SB_END: usize = 392;

const OFF_MAGIC: usize = 64;
const OFF_VERSION: usize = 72;
const OFF_BLOCK_SIZE: usize = 76;
const OFF_TOTAL: usize = 80;
const OFF_GEN: usize = 88;
const OFF_UUID_DUP: usize = 96;
const OFF_ROOT: usize = 128;
const OFF_BLOBS: usize = 176;
const OFF_ROOTS: usize = 224;
const OFF_FREE: usize = 272;
const OFF_NEXT_OBJ: usize = 320;
const OFF_COMMITTED_AT: usize = 328;
const OFF_DIRENT_KEY: usize = 336;
const OFF_KDF: usize = 352;
const OFF_RESERVE: usize = 384;

// The single-sector property the module docs rely on, and the fields start
// after the metadata header.
const _: () = assert!(SB_END <= SECTOR_SIZE && HEADER_LEN <= OFF_MAGIC);

/// A decoded superblock.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Superblock {
    /// Blocks the filesystem spans (≤ the device's).
    pub total_blocks: u64,
    /// Generation: +1 per commit; the higher valid slot wins at mount.
    pub gen: u64,
    /// Filesystem identity, also in every metadata header.
    pub uuid: Uuid,
    /// The metadata tree (null until FS-1b).
    pub root: Pointer,
    /// The content-addressed blob tree (null until FS-4).
    pub blobs: Pointer,
    /// The snapshots tree (null until FS-4).
    pub roots: Pointer,
    /// The allocation-group index.
    pub free: Pointer,
    /// Next object id to hand out.
    pub next_obj: u64,
    /// `clock::mono_ticks` at commit — per boot, informational, never freshness.
    pub committed_at: u64,
    /// Key for the dirent name hash (§7.2): not secret.
    pub dirent_key: [u8; DIRENT_KEY_LEN],
    /// Reserved for the identity spec (§10): KDF parameters and the wrapped
    /// tree key, inside the hashed superblock. Must be zero in v2 until then.
    pub kdf: [u8; KDF_LEN],
    /// The metadata reserve per group (§5.8).
    pub reserve_per_group: u64,
}

/// Why a slot does not hold a valid superblock.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SlotError {
    /// Every byte is zero.
    Blank,
    /// No `SNTLFS02` magic (another format, or noise).
    Foreign,
    /// The magic is there but the hash is not.
    BadHash,
    /// The magic and hash are there but the version is not 2.
    Version,
    /// Hashed and versioned, but some field is not canonical.
    Malformed,
    /// Claims more blocks than the device has.
    TooBig,
}

impl SlotError {
    /// Whether the slot carries the SentinelFS magic: a filesystem was here,
    /// so the disk must never be formatted automatically (amendment A9).
    #[must_use]
    pub const fn carries_magic(self) -> bool {
        !matches!(self, SlotError::Blank | SlotError::Foreign)
    }

    /// Fixed label for `fmt`-free console output.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            SlotError::Blank => "blank",
            SlotError::Foreign => "foreign",
            SlotError::BadHash => "bad-hash",
            SlotError::Version => "version",
            SlotError::Malformed => "malformed",
            SlotError::TooBig => "too-big",
        }
    }
}

fn put_u32(block: &mut Block, off: usize, v: u32) {
    block[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_u64(block: &mut Block, off: usize, v: u64) {
    block[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

fn get_u32(block: &Block, off: usize) -> u32 {
    let mut b = [0u8; 4];
    b.copy_from_slice(&block[off..off + 4]);
    u32::from_le_bytes(b)
}

fn get_u64(block: &Block, off: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&block[off..off + 8]);
    u64::from_le_bytes(b)
}

/// Encode `sb` canonically into `out` and seal it; returns the superblock hash
/// (the 32-byte summary of the whole filesystem state, §1).
pub fn encode(sb: &Superblock, out: &mut Block) -> Hash {
    out.fill(0);
    let header = Header {
        hash: [0; HASH_LEN],
        gen: sb.gen,
        kind: Kind::Superblock,
        tree: TreeId::None,
        uuid: sb.uuid,
    };
    let _ = header.encode(out);
    out[OFF_MAGIC..OFF_MAGIC + 8].copy_from_slice(&MAGIC);
    put_u32(out, OFF_VERSION, VERSION);
    put_u32(out, OFF_BLOCK_SIZE, BLOCK_SIZE as u32);
    put_u64(out, OFF_TOTAL, sb.total_blocks);
    put_u64(out, OFF_GEN, sb.gen);
    out[OFF_UUID_DUP..OFF_UUID_DUP + UUID_LEN].copy_from_slice(&sb.uuid);
    for (off, p) in [
        (OFF_ROOT, sb.root),
        (OFF_BLOBS, sb.blobs),
        (OFF_ROOTS, sb.roots),
        (OFF_FREE, sb.free),
    ] {
        let _ = p.encode(&mut out[off..off + POINTER_LEN]);
    }
    put_u64(out, OFF_NEXT_OBJ, sb.next_obj);
    put_u64(out, OFF_COMMITTED_AT, sb.committed_at);
    out[OFF_DIRENT_KEY..OFF_DIRENT_KEY + DIRENT_KEY_LEN].copy_from_slice(&sb.dirent_key);
    out[OFF_KDF..OFF_KDF + KDF_LEN].copy_from_slice(&sb.kdf);
    put_u64(out, OFF_RESERVE, sb.reserve_per_group);
    crate::blk::layout::seal_metadata(out)
}

/// A tree pointer is either null or names a block in `[2, total)` written by
/// a generation in `1..=gen`.
fn tree_pointer_ok(p: &Pointer, total: u64, gen: u64) -> bool {
    p.is_null() || (p.block.0 >= 2 && p.block.get() < total && p.gen >= 1 && p.gen <= gen)
}

/// Decode slot `block` of a device with `device_blocks` blocks. Returns the
/// superblock and its hash.
///
/// Valid iff the magic matches, the hash matches, the version is 2,
/// `total_blocks ≤ device_blocks`, and every field is canonical (§7.1).
///
/// # Errors
///
/// The [`SlotError`] that disqualifies the slot; [`SlotError::carries_magic`]
/// separates "a filesystem was here" from "nothing was".
pub fn decode(block: &Block, device_blocks: u64) -> Result<(Superblock, Hash), SlotError> {
    if block[OFF_MAGIC..OFF_MAGIC + 8] != MAGIC {
        return Err(if block.iter().all(|&b| b == 0) {
            SlotError::Blank
        } else {
            SlotError::Foreign
        });
    }
    let mut hash = [0u8; HASH_LEN];
    hash.copy_from_slice(&block[..HASH_LEN]);
    if !verify(HashRule::Metadata, block, &hash) {
        return Err(SlotError::BadHash);
    }
    if get_u32(block, OFF_VERSION) != VERSION {
        return Err(SlotError::Version);
    }
    let header = decode_header(block).map_err(|_| SlotError::Malformed)?;
    let gen = get_u64(block, OFF_GEN);
    let total_blocks = get_u64(block, OFF_TOTAL);
    let mut uuid = [0u8; UUID_LEN];
    uuid.copy_from_slice(&block[OFF_UUID_DUP..OFF_UUID_DUP + UUID_LEN]);
    let pointer = |off: usize| decode_pointer(&block[off..off + POINTER_LEN]);
    let (Ok(root), Ok(blobs), Ok(roots), Ok(free)) = (
        pointer(OFF_ROOT),
        pointer(OFF_BLOBS),
        pointer(OFF_ROOTS),
        pointer(OFF_FREE),
    ) else {
        return Err(SlotError::Malformed);
    };
    let mut dirent_key = [0u8; DIRENT_KEY_LEN];
    dirent_key.copy_from_slice(&block[OFF_DIRENT_KEY..OFF_DIRENT_KEY + DIRENT_KEY_LEN]);
    let mut kdf = [0u8; KDF_LEN];
    kdf.copy_from_slice(&block[OFF_KDF..OFF_KDF + KDF_LEN]);
    let sb = Superblock {
        total_blocks,
        gen,
        uuid,
        root,
        blobs,
        roots,
        free,
        next_obj: get_u64(block, OFF_NEXT_OBJ),
        committed_at: get_u64(block, OFF_COMMITTED_AT),
        dirent_key,
        kdf,
        reserve_per_group: get_u64(block, OFF_RESERVE),
    };
    let canonical = get_u32(block, OFF_BLOCK_SIZE) == BLOCK_SIZE as u32
        && header.kind == Kind::Superblock
        && header.tree == TreeId::None
        && header.gen == gen
        && header.uuid == uuid
        && gen >= 1
        && block[OFF_UUID_DUP + UUID_LEN..OFF_ROOT]
            .iter()
            .all(|&b| b == 0)
        && total_blocks >= MIN_BLOCKS
        && !free.is_null()
        && tree_pointer_ok(&free, total_blocks, gen)
        && tree_pointer_ok(&root, total_blocks, gen)
        && tree_pointer_ok(&blobs, total_blocks, gen)
        && tree_pointer_ok(&roots, total_blocks, gen)
        && kdf.iter().all(|&b| b == 0)
        && sb.reserve_per_group <= u64::from(GROUP_BLOCKS)
        && block[SB_END..].iter().all(|&b| b == 0);
    if !canonical {
        return Err(SlotError::Malformed);
    }
    // Checked last so a superblock that is otherwise fine but describes a
    // bigger device than this one reads as `TooBig`, not `Malformed`.
    if total_blocks > device_blocks {
        return Err(SlotError::TooBig);
    }
    Ok((sb, hash))
}

/// One slot as the mount rule sees it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Candidate {
    /// A valid superblock of this generation.
    Valid {
        /// Its generation.
        gen: u64,
    },
    /// Not valid; `magic` says whether it carries the SentinelFS magic.
    Invalid {
        /// [`SlotError::carries_magic`].
        magic: bool,
    },
}

impl Candidate {
    /// The candidate a decode result stands for.
    #[must_use]
    pub fn of(decoded: &Result<(Superblock, Hash), SlotError>) -> Candidate {
        match decoded {
            Ok((sb, _)) => Candidate::Valid { gen: sb.gen },
            Err(e) => Candidate::Invalid {
                magic: e.carries_magic(),
            },
        }
    }
}

/// What mount does with the two slots.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Selection {
    /// Mount this slot.
    Use {
        /// Slot index (0 or 1).
        slot: usize,
        /// Its generation.
        gen: u64,
    },
    /// No valid slot, but a filesystem was here: never format automatically.
    Corrupt,
    /// No valid slot and no magic: nothing was here; format is allowed.
    Unformatted,
}

/// The mount rule (§7.1): the valid slot with the higher generation; with
/// none valid, `Corrupt` if either carries the magic, else `Unformatted`. Two
/// valid slots with the same generation (never written by this code) resolve
/// to slot `gen % 2`, the slot a commit of that generation writes.
#[must_use]
pub fn select(c: [Candidate; 2]) -> Selection {
    match (c[0], c[1]) {
        (Candidate::Valid { gen: a }, Candidate::Valid { gen: b }) => {
            if a > b {
                Selection::Use { slot: 0, gen: a }
            } else if b > a {
                Selection::Use { slot: 1, gen: b }
            } else {
                Selection::Use {
                    slot: (a % 2) as usize,
                    gen: a,
                }
            }
        }
        (Candidate::Valid { gen }, Candidate::Invalid { .. }) => Selection::Use { slot: 0, gen },
        (Candidate::Invalid { .. }, Candidate::Valid { gen }) => Selection::Use { slot: 1, gen },
        (Candidate::Invalid { magic: m0 }, Candidate::Invalid { magic: m1 }) => {
            if m0 || m1 {
                Selection::Corrupt
            } else {
                Selection::Unformatted
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blk::layout::Pointer;
    use crate::blk::{zeroed_blocks, BlockNo};

    fn sample() -> Superblock {
        Superblock {
            total_blocks: 3840,
            gen: 7,
            uuid: [0x42; UUID_LEN],
            root: Pointer::NULL,
            blobs: Pointer::NULL,
            roots: Pointer::NULL,
            free: Pointer {
                block: BlockNo(3),
                hash: [9; HASH_LEN],
                gen: 5,
            },
            next_obj: 1,
            committed_at: 1234,
            dirent_key: [0x77; DIRENT_KEY_LEN],
            kdf: [0; KDF_LEN],
            reserve_per_group: 64,
        }
    }

    #[test]
    fn round_trips_and_lives_in_the_first_sector() {
        let sb = sample();
        let mut b = zeroed_blocks(1);
        let h = encode(&sb, &mut b[0]);
        assert_eq!(&b[0][OFF_MAGIC..OFF_MAGIC + 8], b"SNTLFS02");
        assert!(b[0][SECTOR_SIZE..].iter().all(|&x| x == 0));
        assert_eq!(decode(&b[0], 3840), Ok((sb, h)));
        assert_eq!(decode(&b[0], 3839), Err(SlotError::TooBig));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn every_field_is_policed() {
        let mut b = zeroed_blocks(1);
        assert_eq!(decode(&b[0], 3840), Err(SlotError::Blank));
        b[0][4000] = 1;
        assert_eq!(decode(&b[0], 3840), Err(SlotError::Foreign));
        let base = sample();
        let reject = |f: &dyn Fn(&mut Superblock)| {
            let mut sb = base;
            f(&mut sb);
            let mut b = zeroed_blocks(1);
            encode(&sb, &mut b[0]);
            decode(&b[0], 1 << 20)
        };
        assert_eq!(reject(&|s| s.gen = 0), Err(SlotError::Malformed));
        assert_eq!(reject(&|s| s.total_blocks = 127), Err(SlotError::Malformed));
        assert_eq!(
            reject(&|s| s.free = Pointer::NULL),
            Err(SlotError::Malformed)
        );
        assert_eq!(
            reject(&|s| s.free.block = BlockNo(1)),
            Err(SlotError::Malformed)
        );
        assert_eq!(reject(&|s| s.free.gen = 8), Err(SlotError::Malformed));
        assert_eq!(
            reject(&|s| s.root.block = BlockNo(5)),
            Err(SlotError::Malformed)
        );
        assert_eq!(reject(&|s| s.kdf[31] = 1), Err(SlotError::Malformed));
        assert_eq!(
            reject(&|s| s.reserve_per_group = u64::from(GROUP_BLOCKS) + 1),
            Err(SlotError::Malformed)
        );
        assert!(reject(&|s| s.dirent_key = [0; 16]).is_ok());
        assert!(reject(&|s| s.committed_at = u64::MAX).is_ok());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn hash_version_and_header_breaks_are_distinguished() {
        let sb = sample();
        let mut b = zeroed_blocks(1);
        encode(&sb, &mut b[0]);
        let good = b[0];
        // Any flipped bit anywhere: invalid, and the magic still classifies it.
        for off in [0usize, 31, 32, 40, 44, 48, 70, 80, 300, 391, 392, 4095] {
            let mut x = good;
            x[off] ^= 0x04;
            let e = decode(&x, 3840).unwrap_err();
            assert_eq!(e.carries_magic(), !(64..72).contains(&off), "offset {off}");
        }
        // A re-sealed block with the wrong version / kind / tree / gen.
        let reseal = |f: &dyn Fn(&mut Block)| {
            let mut x = good;
            f(&mut x);
            crate::blk::layout::seal_metadata(&mut x);
            decode(&x, 3840)
        };
        assert_eq!(
            reseal(&|x| put_u32(x, OFF_VERSION, 3)),
            Err(SlotError::Version)
        );
        assert_eq!(reseal(&|x| x[40] = 2), Err(SlotError::Malformed));
        assert_eq!(reseal(&|x| x[44] = 4), Err(SlotError::Malformed));
        assert_eq!(reseal(&|x| x[32] ^= 1), Err(SlotError::Malformed));
        assert_eq!(reseal(&|x| x[OFF_UUID_DUP] ^= 1), Err(SlotError::Malformed));
        assert_eq!(reseal(&|x| x[120] = 1), Err(SlotError::Malformed));
        assert_eq!(reseal(&|x| x[3000] = 1), Err(SlotError::Malformed));
        assert_eq!(
            reseal(&|x| put_u32(x, OFF_BLOCK_SIZE, 512)),
            Err(SlotError::Malformed)
        );
        assert_eq!(reseal(&|x| x[OFF_FREE + 5] = 1), Err(SlotError::Malformed));
    }

    #[test]
    fn selection_table() {
        use Candidate::{Invalid, Valid};
        let none = Invalid { magic: false };
        let magic = Invalid { magic: true };
        assert_eq!(select([none, none]), Selection::Unformatted);
        assert_eq!(select([magic, none]), Selection::Corrupt);
        assert_eq!(select([none, magic]), Selection::Corrupt);
        assert_eq!(
            select([Valid { gen: 4 }, magic]),
            Selection::Use { slot: 0, gen: 4 }
        );
        assert_eq!(
            select([Valid { gen: 4 }, Valid { gen: 5 }]),
            Selection::Use { slot: 1, gen: 5 }
        );
        assert_eq!(
            select([Valid { gen: 9 }, Valid { gen: 2 }]),
            Selection::Use { slot: 0, gen: 9 }
        );
        assert_eq!(
            select([Valid { gen: 3 }, Valid { gen: 3 }]),
            Selection::Use { slot: 1, gen: 3 }
        );
    }
}

/// Kani proof harnesses (A19: over decoded candidates, never SHA-256).
/// Compiled only under `cargo kani`.
#[cfg(kani)]
mod proofs {
    use super::*;

    fn any_candidate() -> Candidate {
        if kani::any() {
            Candidate::Valid { gen: kani::any() }
        } else {
            Candidate::Invalid { magic: kani::any() }
        }
    }

    /// The mount rule over every pair of decoded candidates: a selected slot
    /// is valid and carries the highest valid generation; any valid slot means
    /// a mount; with none valid, a slot carrying the magic is never
    /// `Unformatted` (so the kernel never formats over a filesystem, A9), and
    /// `Corrupt` only ever appears when one does.
    #[kani::proof]
    fn superblock_selection_picks_the_highest_valid_gen() {
        let c = [any_candidate(), any_candidate()];
        let any_valid = c.iter().any(|x| matches!(x, Candidate::Valid { .. }));
        let any_magic = c
            .iter()
            .any(|x| matches!(x, Candidate::Invalid { magic: true }));
        match select(c) {
            Selection::Use { slot, gen } => {
                assert!(slot < 2);
                assert!(c[slot] == Candidate::Valid { gen });
                for other in c {
                    if let Candidate::Valid { gen: g } = other {
                        assert!(g <= gen);
                    }
                }
            }
            Selection::Corrupt => {
                assert!(!any_valid);
                assert!(any_magic);
            }
            Selection::Unformatted => {
                assert!(!any_valid);
                assert!(!any_magic);
            }
        }
        if any_valid {
            assert!(matches!(select(c), Selection::Use { .. }));
        }
    }
}
