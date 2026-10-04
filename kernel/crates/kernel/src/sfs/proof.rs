//! The FS-1b boot proof (spec §11): a **ledger** in the metadata tree that
//! every boot verifies and extends, the scrub line, and the torn-commit
//! proof's two halves.
//!
//! # The ledger
//!
//! Each commit the boot proof makes (generation `N`) holds, under object
//! [`LEDGER_OBJ`], [`PER_GEN`] `INLINE` items of [`ITEM_LEN`] bytes whose
//! contents are a pure function of `(N, i)`, the items of the previous
//! [`WINDOW`]` − 1` generations (older ones are removed in the same commit),
//! and one `XATTR` item `ledger = first ‖ last` naming the first generation
//! the ledger ever wrote and `N`. So a mounted generation `M` must hold
//! exactly: `last == M` and every item of generations
//! `max(first, M − WINDOW + 1) ..= M`, byte for byte, and nothing else under
//! the object — "data intact". Six 900-byte items do not fit one leaf, so
//! every boot's commit splits, merges and copies a path: the commit writes
//! several tree blocks, which is what the torn-commit proof cuts into.
//!
//! # The torn-commit proof
//!
//! The boot test drives it through a **test-control sector** on the disk
//! ([`CONTROL_LBA`], between the old `kernel::fs` image and the SentinelFS
//! window — zero on every disk but the test's): `xtask` writes it before a
//! boot, the `sfs-commit` task reads it before mounting ([`parse_control`]).
//!
//! 1. `Cut { after: K }` — the task halts the machine (interrupts off, `hlt`)
//!    right after the K-th block write of this boot's ledger commit, inside
//!    the dirty set, before any flush; it prints
//!    `[sfs] torn-commit: cut-after=K gen=N dirty=D halting` first. `xtask`
//!    SIGKILLs QEMU (`cache=writeback`: the guest's writes are in the host's
//!    page cache, unflushed — what a power cut leaves).
//! 2. `Verify { after: K, gen: N }` — the next boot mounts, checks the
//!    ledger, and prints
//!    `[sfs] torn-commit: cut-after=K recovered-gen=N-1 data-intact=yes ok`
//!    only if it mounted generation `N − 1` and its ledger is intact.

use super::key::{item as kinds, Key};
use super::service::{read_block, request_scrub, scrub_outcome, wait_for, with_sfs};
use super::tree::item::Xattr;
use super::tree::{TreeError, ITEM_MAX};
use super::volume::Volume;
use crate::hash::Sha256;
use alloc::vec;
use hal::serial::{write_dec, write_str};

/// The ledger's object id ("SFSLEDGR").
pub const LEDGER_OBJ: u64 = u64::from_be_bytes(*b"SFSLEDGR");
/// Items the proof writes per generation.
pub const PER_GEN: u64 = 6;
/// Generations of items the ledger keeps.
pub const WINDOW: u64 = 4;
/// Bytes per ledger item (within `INLINE_MAX`).
pub const ITEM_LEN: usize = 900;
/// Disk sector of the test-control block: past the old `kernel::fs` image
/// (sectors 0..=128), before the SentinelFS window (sector 2048).
pub const CONTROL_LBA: u32 = 1024;
/// The control sector's magic.
pub const CONTROL_MAGIC: [u8; 8] = *b"SFSCTL01";
/// How many times one operation is retried (misses on a 4-level path plus
/// siblings and bitmaps).
const RETRIES: usize = 32;

/// What the test-control sector asks of this boot.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Control {
    /// Nothing (every disk but the boot test's torn-commit stage).
    None,
    /// Halt after the `after`-th block write of this boot's ledger commit.
    Cut {
        /// Block writes to let through.
        after: u32,
    },
    /// The previous boot was cut after `after` writes of the commit that
    /// would have made generation `gen`: report what this boot recovered.
    Verify {
        /// The cut point.
        after: u32,
        /// The generation the cut commit would have made.
        gen: u64,
    },
}

/// Parse the control sector: `magic[8] | mode u8 | pad[3] | after u32 |
/// gen u64`, all little-endian, mode 1 = cut, 2 = verify, everything after
/// byte 24 zero. Total; anything else is [`Control::None`].
#[must_use]
pub fn parse_control(sector: &[u8]) -> Control {
    let field = |a: usize, b: usize| sector.get(a..b);
    let (Some(magic), Some(mode), Some(after), Some(gen), Some(rest)) = (
        field(0, 8),
        sector.get(8),
        field(12, 16).and_then(|b| <[u8; 4]>::try_from(b).ok()),
        field(16, 24).and_then(|b| <[u8; 8]>::try_from(b).ok()),
        sector.get(24..),
    ) else {
        return Control::None;
    };
    let pad_zero = field(9, 12).is_some_and(|p| p.iter().all(|&b| b == 0));
    if magic != CONTROL_MAGIC || !pad_zero || rest.iter().any(|&b| b != 0) {
        return Control::None;
    }
    let after = u32::from_le_bytes(after);
    let gen = u64::from_le_bytes(gen);
    match *mode {
        1 => Control::Cut { after },
        2 => Control::Verify { after, gen },
        _ => Control::None,
    }
}

/// The ledger item key of item `i` of generation `gen`.
#[must_use]
pub const fn item_key(gen: u64, i: u64) -> Key {
    Key {
        obj: LEDGER_OBJ,
        kind: kinds::INLINE,
        off: gen.wrapping_mul(8).wrapping_add(i),
    }
}

/// The ledger's metadata key.
pub const META_KEY: Key = Key {
    obj: LEDGER_OBJ,
    kind: kinds::XATTR,
    off: 0,
};

/// The bytes of ledger item `i` of generation `gen`.
pub fn item_bytes(gen: u64, i: u64, out: &mut [u8]) {
    let mut h = Sha256::new();
    h.update(b"sentinelfs:ledger:");
    h.update(&gen.to_le_bytes());
    h.update(&i.to_le_bytes());
    let seed = h.finalize();
    for (j, b) in out.iter_mut().enumerate() {
        *b = seed[j % seed.len()] ^ (j / seed.len()) as u8;
    }
}

/// Encode the metadata xattr `ledger = first ‖ last` into `out`.
fn meta_bytes(first: u64, last: u64, out: &mut [u8]) -> Option<usize> {
    let mut value = [0u8; 16];
    value[..8].copy_from_slice(&first.to_le_bytes());
    value[8..].copy_from_slice(&last.to_le_bytes());
    Xattr {
        key: b"ledger",
        value: &value,
    }
    .encode(out)
    .ok()
}

/// Decode the metadata xattr into `(first, last)`.
fn parse_meta(b: &[u8]) -> Option<(u64, u64)> {
    let x = Xattr::decode(b).ok()?;
    if x.key != b"ledger" || x.value.len() != 16 {
        return None;
    }
    let first = u64::from_le_bytes(x.value.get(..8)?.try_into().ok()?);
    let last = u64::from_le_bytes(x.value.get(8..)?.try_into().ok()?);
    Some((first, last))
}

/// The lowest generation of items a ledger `first ..= last` still holds.
const fn window_start(first: u64, last: u64) -> u64 {
    let lo = (last + 1).saturating_sub(WINDOW);
    if lo > first {
        lo
    } else {
        first
    }
}

/// Run one tree operation on the kernel's volume under the `Sfs` lock,
/// having the `sfs-commit` task read each block it misses (with the lock
/// released) until it completes.
fn op<T>(
    timeout: u64,
    mut f: impl FnMut(&mut Volume) -> Result<T, TreeError>,
) -> Result<T, TreeError> {
    for _ in 0..RETRIES {
        let r = with_sfs(|s| match s.volume_mut() {
            Some(v) => f(v),
            None => Err(TreeError::Sealed),
        });
        match r {
            Err(TreeError::Miss(p)) => read_block(p, timeout).map_err(|_| TreeError::Corrupt)?,
            r => return r,
        }
    }
    Err(TreeError::Internal)
}

/// The ledger as a mounted generation `m` holds it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ledger {
    /// `(first, last)` from the metadata item, if any.
    pub meta: Option<(u64, u64)>,
    /// Ledger items found.
    pub items: u64,
    /// Whether everything matched (module docs).
    pub intact: bool,
}

/// Walk every key under [`LEDGER_OBJ`] at generation `m` and check it.
/// `get(key, out)` / `next(after)` are the tree reads (so the host tests can
/// run this against a [`Volume`] directly).
pub fn check_ledger(
    m: u64,
    mut get: impl FnMut(&Key, &mut [u8]) -> Result<Option<usize>, TreeError>,
    mut next: impl FnMut(Option<&Key>) -> Result<Option<Key>, TreeError>,
) -> Result<Ledger, TreeError> {
    let mut buf = vec![0u8; ITEM_MAX];
    let mut want = vec![0u8; ITEM_LEN];
    let meta = match get(&META_KEY, &mut buf)? {
        Some(n) => Some(parse_meta(buf.get(..n).unwrap_or(&[])).ok_or(TreeError::Corrupt)?),
        None => None,
    };
    let (lo, hi) = match meta {
        Some((first, last)) => (window_start(first, last), last),
        None => (1, 0),
    };
    let mut intact = meta.is_none_or(|(first, last)| last == m && first <= last);
    let mut items = 0u64;
    let mut seen = 0u64;
    let mut at = Key {
        obj: LEDGER_OBJ - 1,
        kind: u8::MAX,
        off: u64::MAX,
    };
    while let Some(k) = next(Some(&at))? {
        if k.obj != LEDGER_OBJ {
            break;
        }
        at = k;
        if k == META_KEY {
            continue;
        }
        items += 1;
        let (gen, i) = (k.off / 8, k.off % 8);
        if k.kind != kinds::INLINE || i >= PER_GEN || gen < lo || gen > hi {
            intact = false;
            continue;
        }
        let n = get(&k, &mut buf)?.ok_or(TreeError::Corrupt)?;
        item_bytes(gen, i, &mut want);
        if buf.get(..n) != Some(&want[..]) {
            intact = false;
        }
        seen += 1;
    }
    let expected = if hi >= lo { (hi - lo + 1) * PER_GEN } else { 0 };
    intact &= seen == expected && items == expected;
    Ok(Ledger {
        meta,
        items,
        intact,
    })
}

/// Stage generation `n`'s ledger changes on a ledger currently `meta`: put
/// its items, remove the generation that leaves the window, update the
/// metadata. `put` / `remove` are the tree writes.
pub fn stage_ledger(
    n: u64,
    meta: Option<(u64, u64)>,
    mut put: impl FnMut(Key, &[u8]) -> Result<(), TreeError>,
    mut remove: impl FnMut(&Key) -> Result<bool, TreeError>,
) -> Result<(), TreeError> {
    let first = meta.map_or(n, |(f, _)| f);
    let mut data = vec![0u8; ITEM_LEN];
    for i in 0..PER_GEN {
        item_bytes(n, i, &mut data);
        put(item_key(n, i), &data)?;
    }
    let old = n.checked_sub(WINDOW);
    if let Some(old) = old.filter(|&o| o >= first) {
        for i in 0..PER_GEN {
            remove(&item_key(old, i))?;
        }
    }
    let mut m = vec![0u8; 64];
    let len = meta_bytes(first, n, &mut m).ok_or(TreeError::Internal)?;
    put(META_KEY, m.get(..len).ok_or(TreeError::Internal)?)
}

fn fail(what: &str, e: TreeError) {
    write_str("[sfs] ledger: ");
    write_str(what);
    write_str(" ");
    write_str(e.label());
    write_str(" FAIL\n");
}

/// Boot step after the mount line: check the ledger of mounted generation
/// `m` and print `[sfs] ledger: gen=M items=K data-intact=yes ok`; on a
/// recovery boot print the torn-commit line; then stage generation `m + 1`'s
/// ledger changes for the commit the caller requests. Returns whether the
/// changes are staged.
pub fn check_and_stage(m: u64, timeout: u64) -> bool {
    let ledger = check_ledger(
        m,
        |k, out| op(timeout, |v| v.get(k, out)),
        |after| op(timeout, |v| v.next_key(after)),
    );
    let ledger = match ledger {
        Ok(l) => l,
        Err(e) => {
            fail("check", e);
            return false;
        }
    };
    write_str("[sfs] ledger: gen=");
    write_dec(m);
    write_str(" items=");
    write_dec(ledger.items);
    write_str(if ledger.intact {
        " data-intact=yes ok\n"
    } else {
        " data-intact=no FAIL\n"
    });
    if let Control::Verify { after, gen } = with_sfs(|s| s.control()) {
        write_str("[sfs] torn-commit: cut-after=");
        write_dec(u64::from(after));
        write_str(" recovered-gen=");
        write_dec(m);
        write_str(if ledger.intact {
            " data-intact=yes"
        } else {
            " data-intact=no"
        });
        write_str(if ledger.intact && gen.checked_sub(1) == Some(m) {
            " ok\n"
        } else {
            " FAIL\n"
        });
    }
    if !ledger.intact {
        return false;
    }
    let staged = stage_ledger(
        m + 1,
        ledger.meta,
        |k, d| op(timeout, |v| v.put(k, d)),
        |k| op(timeout, |v| v.remove(k)),
    );
    if let Err(e) = staged {
        fail("stage", e);
        return false;
    }
    true
}

/// After the commit line: scrub the new generation and print
/// `[sfs] scrub: blocks=N hashed=N bad=0 ok` — or, with damage,
/// `… bad=K FAIL` and one `[sfs] scrub: bad block=B what=… obj=…` line per
/// named object (the volume is then read-only).
pub fn prove_scrub(timeout: u64) {
    let Some(ticket) = request_scrub() else {
        write_str("[sfs] scrub: not mounted FAIL\n");
        return;
    };
    let report = match wait_for(timeout, || scrub_outcome(ticket)) {
        Some(Ok(r)) => r,
        Some(Err(e)) => {
            write_str("[sfs] scrub: io ");
            write_str(e.label());
            write_str(" FAIL\n");
            return;
        }
        None => {
            write_str("[sfs] scrub: TIMEOUT FAIL\n");
            return;
        }
    };
    write_str("[sfs] scrub: blocks=");
    write_dec(report.blocks);
    write_str(" hashed=");
    write_dec(report.hashed);
    write_str(" bad=");
    write_dec(report.bad);
    write_str(if report.bad == 0 { " ok\n" } else { " FAIL\n" });
    for b in report.named() {
        write_str("[sfs] scrub: bad block=");
        write_dec(u64::from(b.block.0));
        write_str(" what=");
        write_str(b.what.label());
        if let Some(obj) = b.what.obj() {
            write_str(" obj=");
            write_dec(obj);
        }
        write_str("\n");
    }
}

/// The line the cut prints just before it halts the machine.
pub fn print_cut(after: u32, gen: u64, dirty: usize) {
    write_str("[sfs] torn-commit: cut-after=");
    write_dec(u64::from(after));
    write_str(" gen=");
    write_dec(gen);
    write_str(" dirty=");
    write_dec(dirty as u64);
    write_str(" halting\n");
}

/// A cut that would land past the dirty set is refused (the commit runs
/// whole); the boot test fails on this line.
pub fn print_cut_refused(after: u32, dirty: usize) {
    write_str("[sfs] torn-commit: cut-after=");
    write_dec(u64::from(after));
    write_str(" outside dirty=");
    write_dec(dirty as u64);
    write_str(" FAIL\n");
}

/// The host side of the proof, for tests: a whole ledger session on a
/// [`Volume`] with synchronous misses.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::sfs::testkit::Fs;

    fn check(fs: &mut Fs) -> Ledger {
        let m = fs.v.info().gen;
        let fs = core::cell::RefCell::new(fs);
        check_ledger(
            m,
            |k, out| fs.borrow_mut().retry(|v| v.get(k, out)),
            |a| fs.borrow_mut().retry(|v| v.next_key(a)),
        )
        .unwrap()
    }

    fn boot(fs: &mut Fs) -> Ledger {
        let l = check(fs);
        assert!(l.intact, "{l:?}");
        let n = fs.v.info().gen + 1;
        {
            let fsc = core::cell::RefCell::new(&mut *fs);
            stage_ledger(
                n,
                l.meta,
                |k, d| fsc.borrow_mut().put(k, d),
                |k| fsc.borrow_mut().remove(k),
            )
            .unwrap();
        }
        assert_eq!(fs.commit().unwrap().gen, n);
        l
    }

    #[test]
    fn control_sector_parses_exactly() {
        let mut s = [0u8; 512];
        assert_eq!(parse_control(&s), Control::None);
        s[..8].copy_from_slice(&CONTROL_MAGIC);
        s[8] = 1;
        s[12..16].copy_from_slice(&3u32.to_le_bytes());
        assert_eq!(parse_control(&s), Control::Cut { after: 3 });
        s[8] = 2;
        s[16..24].copy_from_slice(&9u64.to_le_bytes());
        assert_eq!(parse_control(&s), Control::Verify { after: 3, gen: 9 });
        let mut bad = s;
        bad[300] = 1;
        assert_eq!(parse_control(&bad), Control::None);
        bad = s;
        bad[10] = 1;
        assert_eq!(parse_control(&bad), Control::None);
        bad = s;
        bad[8] = 3;
        assert_eq!(parse_control(&bad), Control::None);
        assert_eq!(parse_control(&s[..20]), Control::None);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn the_ledger_survives_boots_and_detects_tampering() {
        let mut fs = Fs::fresh(3840);
        let l = boot(&mut fs);
        assert_eq!((l.meta, l.items), (None, 0));
        for b in 0..8u64 {
            fs.remount();
            let l = boot(&mut fs);
            let m = l.meta.unwrap();
            assert_eq!(m, (2, 2 + b));
            assert_eq!(l.items, PER_GEN * (b + 1).min(WINDOW));
        }
        // The commit splits leaves: several tree blocks per boot.
        assert!(fs.scrub().nodes >= 3);
        // A missing item, a changed item, or a stale `last` is not intact.
        let m = fs.v.info().gen;
        fs.remove(&item_key(m, 2)).unwrap();
        assert!(!check(&mut fs).intact);
        let mut d = vec![0u8; ITEM_LEN];
        item_bytes(m, 2, &mut d);
        fs.put(item_key(m, 2), &d).unwrap();
        assert!(check(&mut fs).intact);
        d[5] ^= 1;
        fs.put(item_key(m, 2), &d).unwrap();
        assert!(!check(&mut fs).intact);
        d[5] ^= 1;
        fs.put(item_key(m, 2), &d).unwrap();
        fs.commit().unwrap();
        assert!(
            !check(&mut fs).intact,
            "last no longer names the mounted generation"
        );
    }
}
