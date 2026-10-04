//! Host test kit for SentinelFS (FS-1b): a volume on a [`MemDevice`] driven
//! synchronously — misses resolved by reading, `NeedCommit` answered with a
//! commit — plus a model to compare it against and a checker for everything
//! a committed image must satisfy.

use super::key::{item as kinds, Key};
use super::scrub::{scrub, Report, ScrubWs};
use super::tree::{TreeError, ITEM_MAX};
use super::volume::{format, CommitError, CommitInfo, FormatParams, MountError, Volume, Workspace};
use crate::blk::mem::{MemDevice, SplitMix64};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

/// The tests' format identity.
pub fn params() -> FormatParams {
    FormatParams::from_seed(b"sfs-host-tests", 7)
}

/// A mounted volume and its device.
pub struct Fs {
    pub dev: MemDevice,
    pub ws: Workspace,
    pub v: Box<Volume>,
    pub now: u64,
    /// Commits that `NeedCommit` forced in the middle of an operation series.
    pub forced: u64,
}

/// Retries one operation may take (misses on a 4-level path plus siblings
/// and bitmaps, and one forced commit).
const RETRIES: usize = 64;

impl Fs {
    /// Format a tracked device of `blocks` and mount it.
    pub fn fresh(blocks: u64) -> Fs {
        let mut dev = MemDevice::new(blocks);
        let mut ws = Workspace::new();
        format(&mut dev, &mut ws, &params()).unwrap();
        let v = Volume::mount(&mut dev, &mut ws).unwrap();
        Fs {
            dev,
            ws,
            v,
            now: 1,
            forced: 0,
        }
    }

    /// Mount `dev` (the cache starts cold, so every tree node misses).
    pub fn mount(mut dev: MemDevice) -> Result<Fs, MountError> {
        let mut ws = Workspace::new();
        let v = Volume::mount(&mut dev, &mut ws)?;
        Ok(Fs {
            dev,
            ws,
            v,
            now: 1,
            forced: 0,
        })
    }

    /// Unmount and mount again (cold cache).
    pub fn remount(&mut self) {
        self.v = Volume::mount(&mut self.dev, &mut self.ws).unwrap();
    }

    /// Commit now.
    pub fn commit(&mut self) -> Result<CommitInfo, CommitError> {
        self.now += 1;
        self.v.commit(&mut self.dev, &mut self.ws, self.now)
    }

    /// Run `op`, resolving misses and forced commits, until it is done.
    pub fn retry<T>(
        &mut self,
        mut op: impl FnMut(&mut Volume) -> Result<T, TreeError>,
    ) -> Result<T, TreeError> {
        for _ in 0..RETRIES {
            match op(&mut self.v) {
                Err(TreeError::Miss(p)) => {
                    self.v
                        .load(&mut self.dev, &mut self.ws, &p)
                        .map_err(|_| TreeError::Corrupt)?;
                }
                Err(TreeError::NeedCommit) => {
                    self.forced += 1;
                    self.commit().map_err(|_| TreeError::Internal)?;
                }
                r => return r,
            }
        }
        Err(TreeError::Internal)
    }

    pub fn put(&mut self, k: Key, d: &[u8]) -> Result<(), TreeError> {
        self.retry(|v| v.put(k, d))
    }

    pub fn remove(&mut self, k: &Key) -> Result<bool, TreeError> {
        self.retry(|v| v.remove(k))
    }

    pub fn get(&mut self, k: &Key) -> Result<Option<Vec<u8>>, TreeError> {
        let mut out = vec![0u8; ITEM_MAX];
        let n = self.retry(|v| v.get(k, &mut out))?;
        Ok(n.map(|n| out[..n].to_vec()))
    }

    /// Every item, in key order, through `next_key` + `get`.
    pub fn items(&mut self) -> Result<Vec<(Key, Vec<u8>)>, TreeError> {
        let mut out = Vec::new();
        let mut at: Option<Key> = None;
        loop {
            let after = at;
            let Some(k) = self.retry(|v| v.next_key(after.as_ref()))? else {
                return Ok(out);
            };
            let d = self.get(&k)?.ok_or(TreeError::Corrupt)?;
            out.push((k, d));
            at = Some(k);
        }
    }

    /// Scrub the committed state on the device.
    pub fn scrub(&mut self) -> Report {
        let sb = *self.v.superblock();
        let info = self.v.info();
        scrub(
            &mut self.dev,
            &mut ScrubWs::new(),
            &sb,
            &info.sb_hash,
            info.slot,
        )
        .unwrap()
    }
}

/// The model: what the tree must hold.
pub type Model = BTreeMap<Key, Vec<u8>>;

/// The model as an item list.
pub fn model_items(m: &Model) -> Vec<(Key, Vec<u8>)> {
    m.iter().map(|(k, v)| (*k, v.clone())).collect()
}

/// One randomised operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    Put(Key, Vec<u8>),
    Remove(Key),
    Commit,
}

/// An item kind FS-1b does not interpret (FS-2 owns the kind space): the
/// scrub accepts any payload under it, so tests can store arbitrary bytes up
/// to [`ITEM_MAX`]. `INLINE` items (≤ 1 KiB, any bytes) are used too.
pub const OPAQUE: u8 = 0x7E;

/// A key in a small space so removes and replaces hit.
pub fn rand_key(rng: &mut SplitMix64, space: u64) -> Key {
    Key {
        obj: rng.below(space),
        kind: if rng.coin() { kinds::INLINE } else { OPAQUE },
        off: rng.below(4),
    }
}

/// Item bytes whose size spans empty to the maximum, biased so leaves split
/// and merge often.
pub fn rand_data(rng: &mut SplitMix64) -> Vec<u8> {
    let len = match rng.below(4) {
        0 => rng.below(32),
        1 => rng.below(300),
        2 => 600 + rng.below(437),
        _ => ITEM_MAX as u64 - rng.below(2),
    } as usize;
    let tag = rng.next_u64();
    (0..len)
        .map(|i| (tag >> ((i % 8) * 8)) as u8 ^ i as u8)
        .collect()
}

/// A random op sequence: mostly puts, a third removes, a commit every ~12.
pub fn rand_ops(seed: u64, n: usize, space: u64) -> Vec<Op> {
    let mut rng = SplitMix64::new(seed);
    (0..n)
        .map(|_| match rng.below(12) {
            0 => Op::Commit,
            1..=4 => Op::Remove(rand_key(&mut rng, space)),
            _ => {
                let mut k = rand_key(&mut rng, space);
                let d = rand_data(&mut rng);
                if d.len() > super::tree::item::INLINE_MAX {
                    k.kind = OPAQUE;
                }
                Op::Put(k, d)
            }
        })
        .collect()
}

/// Apply `op` to `fs` and the working model.
pub fn apply(fs: &mut Fs, model: &mut Model, op: &Op) {
    match op {
        Op::Put(k, d) => {
            fs.put(*k, d).unwrap();
            model.insert(*k, d.clone());
        }
        Op::Remove(k) => {
            let had = fs.remove(k).unwrap();
            assert_eq!(had, model.remove(k).is_some(), "remove {k:?}");
        }
        Op::Commit => {
            fs.commit().unwrap();
        }
    }
}
