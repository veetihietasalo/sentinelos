//! `kernel::sfs` — SentinelFS (spec `docs/specs/2026-09-18-sentinelfs-design.md`).
//!
//! FS-1a (spec §11) lands the parts every later stage stands on, all safe
//! Rust over [`crate::blk`]:
//!
//! - [`superblock`] — the §7.1 layout with every on-disk field that cannot be
//!   added later (A12: `dirent_key`, the KDF-parameters + wrap slot, the
//!   reserve), the 64-byte header with a whole-block hash (A1), and the mount
//!   rule over two generation-numbered slots: the valid slot with the higher
//!   generation wins; `Corrupt` vs `Unformatted` per A9 (never format over a
//!   disk that carries the magic).
//! - [`key`] — the 17-byte item key (A10) and the blob-domain encoding (A12).
//! - [`volume`] — format, mount, and the §8 commit protocol (dirty blocks →
//!   flush → superblock into the inactive slot → flush), over any
//!   [`crate::blk::BlockDevice`]; host-tested on `crate::blk::mem::MemDevice`
//!   with the crash model.
//! - [`service`] — the kernel instance: the `sfs-commit` task (the only code
//!   that touches the device; never I/O under the `Sfs` lock; pacing off
//!   `clock::mono_ticks`) and the boot proof [`prove_mount`].
//!
//! Not here (spec §11): the CoW B+tree, items and transactions over them, the
//! QEMU torn-commit proof and the `hal::ata` flush split (FS-1b); files and
//! the `kernel::fs` facade (FS-2); the storage-capability lattice (FS-1c, on
//! component PR-2's `kernel::cap`); blobs, snapshots and cap enforcement
//! (FS-4).

#![deny(missing_docs)]

pub mod key;
pub mod proof;
pub mod scrub;
pub mod service;
pub mod superblock;
pub mod tree;
pub mod volume;

#[cfg(test)]
mod crash;
#[cfg(test)]
mod heap;
#[cfg(test)]
mod testkit;
#[cfg(test)]
mod tests;

pub use service::prove_mount;

use crate::blk::layout::Hash;

/// The first four bytes of `h` as eight lowercase hex characters — the short
/// form boot lines print.
#[must_use]
pub fn short_hex(h: &Hash) -> [u8; 8] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 8];
    for (i, b) in h.iter().take(4).enumerate() {
        out[2 * i] = HEX[usize::from(b >> 4)];
        out[2 * i + 1] = HEX[usize::from(b & 0xF)];
    }
    out
}
