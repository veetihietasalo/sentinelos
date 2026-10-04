//! The crash-point property test (spec §2 goal 1, §8, §11 FS-1b, A16).
//!
//! A seeded random sequence of tree operations runs on a volume over a
//! [`MemDevice`]. Every commit's I/O is recorded; then, for **every** write
//! index of that commit and three persistence rules — nothing unflushed
//! survives, everything does, or a PRNG subset in a PRNG order with the
//! superblock slots torn sector by sector — the device is rebuilt from the
//! pre-commit image, the commit's I/O replayed into a crash at that index,
//! power-cycled, and mounted. The property:
//!
//! - the mount succeeds, at the previous generation or the new one;
//! - the tree holds **exactly** the shadow map of that generation (the shadow
//!   is advanced only when a commit completes);
//! - a scrub of the recovered image finds every reachable block intact and
//!   marked in use (no live block marked free).
//!
//! A failing sequence is shrunk by delta debugging ([`ddmin`]) to a minimal
//! op list before the test reports it, with the seed and the crash point.

use super::scrub::{scrub, ScrubWs};
use super::testkit::{model_items, rand_ops, Fs, Model, Op};
use super::volume::Volume;
use super::volume::Workspace;
use crate::blk::mem::{CrashPlan, MemDevice, Persist, SplitMix64};
use crate::blk::{BlkError, Block, BlockDevice, BlockNo, Blocks};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// One recorded device call.
enum Io {
    Write(BlockNo, Blocks),
    Flush,
}

/// A device wrapper that records every write and flush.
struct Recorder<'a> {
    dev: &'a mut MemDevice,
    log: Vec<Io>,
}

impl BlockDevice for Recorder<'_> {
    fn blocks(&self) -> u64 {
        self.dev.blocks()
    }

    fn read_blocks(&mut self, start: BlockNo, out: &mut [Block]) -> Result<(), BlkError> {
        self.dev.read_blocks(start, out)
    }

    fn write_blocks(&mut self, start: BlockNo, data: &[Block]) -> Result<(), BlkError> {
        for (i, b) in data.iter().enumerate() {
            let mut copy = Blocks::zeroed(1);
            copy[0].copy_from_slice(b);
            self.log.push(Io::Write(BlockNo(start.0 + i as u32), copy));
        }
        self.dev.write_blocks(start, data)
    }

    fn flush(&mut self) -> Result<(), BlkError> {
        self.log.push(Io::Flush);
        self.dev.flush()
    }
}

/// What one sequence's sweep covered.
#[derive(Default, Debug)]
struct Stats {
    commits: u64,
    crashes: u64,
    recovered_old: u64,
    recovered_new: u64,
}

/// Replay `log` into `dev`, which loses power at write `w`; stops there.
fn replay_into_crash(dev: &mut MemDevice, log: &[Io], w: u64, persist: Persist, seed: u64) {
    dev.arm_crash(CrashPlan {
        at_write: w,
        seed,
        persist,
    });
    for io in log {
        let r = match io {
            Io::Write(b, data) => dev.write_blocks(*b, data),
            Io::Flush => dev.flush(),
        };
        if r.is_err() {
            break;
        }
    }
    dev.power_cycle(seed);
}

/// Mount `img` and check it holds `old` (generation `g_old`) or `new`
/// (`g_old + 1`), intact. Returns whether it recovered the new generation.
fn check_recovered(img: Vec<u8>, g_old: u64, old: &Model, new: &Model) -> Result<bool, String> {
    let mut fs = Fs::mount(MemDevice::from_image(img)).map_err(|e| format!("mount: {e:?}"))?;
    let gen = fs.v.info().gen;
    let want = if gen == g_old {
        old
    } else if gen == g_old + 1 {
        new
    } else {
        return Err(format!(
            "mounted gen {gen}, expected {g_old} or {}",
            g_old + 1
        ));
    };
    let items = fs
        .items()
        .map_err(|e| format!("walk at gen {gen}: {e:?}"))?;
    if items != model_items(want) {
        return Err(format!(
            "gen {gen}: tree holds {} items, its shadow {}",
            items.len(),
            want.len()
        ));
    }
    let sb = *fs.v.superblock();
    let info = fs.v.info();
    let r = scrub(
        &mut fs.dev,
        &mut ScrubWs::new(),
        &sb,
        &info.sb_hash,
        info.slot,
    )
    .map_err(|e| format!("scrub io {e:?}"))?;
    if r.bad != 0 || r.blocks != r.hashed {
        return Err(format!("gen {gen}: scrub {r:?}"));
    }
    Ok(gen == g_old + 1)
}

/// Run `ops`, sweeping every crash point of every explicit commit.
fn sweep(ops: &[Op], seed: u64, blocks: u64) -> Result<Stats, String> {
    let mut fs = Fs::fresh(blocks);
    let mut model = Model::new();
    let mut shadow = Model::new();
    let mut st = Stats::default();
    let mut rng = SplitMix64::new(seed ^ 0x5EED);
    let commit_ops = ops.iter().chain(core::iter::once(&Op::Commit));
    for (i, op) in commit_ops.enumerate() {
        let forced = fs.forced;
        match op {
            Op::Put(k, d) => {
                fs.put(*k, d).map_err(|e| format!("op {i} put: {e:?}"))?;
            }
            Op::Remove(k) => {
                fs.remove(k).map_err(|e| format!("op {i} remove: {e:?}"))?;
            }
            Op::Commit => {
                let before = fs.dev.image().to_vec();
                let g_old = fs.v.info().gen;
                fs.now += 1;
                let mut rec = Recorder {
                    dev: &mut fs.dev,
                    log: Vec::new(),
                };
                fs.v.commit(&mut rec, &mut fs.ws, fs.now)
                    .map_err(|e| format!("op {i} commit: {e:?}"))?;
                let log = rec.log;
                let writes = log.iter().filter(|x| matches!(x, Io::Write(..))).count() as u64;
                for w in 0..writes {
                    let modes = [
                        (Persist::Nothing, 0),
                        (Persist::Everything, 0),
                        (Persist::Subset, rng.next_u64()),
                        (Persist::Subset, rng.next_u64()),
                    ];
                    for (persist, s) in modes {
                        let mut dev = MemDevice::from_image(before.clone());
                        replay_into_crash(&mut dev, &log, w, persist, s);
                        let new = check_recovered(dev.into_image(), g_old, &shadow, &model)
                            .map_err(|e| {
                                format!(
                                    "op {i}: crash at write {w}/{writes} ({persist:?}, {s}): {e}"
                                )
                            })?;
                        st.crashes += 1;
                        if new {
                            st.recovered_new += 1;
                        } else {
                            st.recovered_old += 1;
                        }
                    }
                }
                st.commits += 1;
                shadow = model.clone();
                continue;
            }
        }
        // A forced commit inside the operation published the state before it
        // (the operation was refused whole, the commit ran, then the retry
        // applied it): the model does not hold the operation yet.
        if fs.forced != forced {
            shadow = model.clone();
        }
        match op {
            Op::Put(k, d) => {
                model.insert(*k, d.clone());
            }
            Op::Remove(k) => {
                model.remove(k);
            }
            Op::Commit => {}
        }
    }
    Ok(st)
}

/// Delta debugging (Zeller's ddmin): the smallest sub-list of `xs` (by
/// removing chunks) on which `fails` still holds.
pub fn ddmin<T: Clone>(mut xs: Vec<T>, mut fails: impl FnMut(&[T]) -> bool) -> Vec<T> {
    let mut n = 2usize;
    while xs.len() >= 2 {
        let chunk = xs.len().div_ceil(n);
        let mut reduced = false;
        for i in 0..n {
            let (lo, hi) = (i * chunk, ((i + 1) * chunk).min(xs.len()));
            if lo >= hi {
                continue;
            }
            let rest: Vec<T> = xs[..lo].iter().chain(&xs[hi..]).cloned().collect();
            if fails(&rest) {
                xs = rest;
                n = (n - 1).max(2);
                reduced = true;
                break;
            }
        }
        if !reduced {
            if n >= xs.len() {
                break;
            }
            n = (2 * n).min(xs.len());
        }
    }
    xs
}

const SMALL: u64 = 256;

#[test]
#[cfg_attr(miri, ignore)]
fn crash_anywhere_in_any_commit_recovers_a_shadow_intact() {
    let mut total = Stats::default();
    for seed in 0..20u64 {
        let ops = rand_ops(1000 + seed, 60, 24);
        match sweep(&ops, seed, SMALL) {
            Ok(st) => {
                total.commits += st.commits;
                total.crashes += st.crashes;
                total.recovered_old += st.recovered_old;
                total.recovered_new += st.recovered_new;
            }
            Err(first) => {
                let min = ddmin(ops, |o| sweep(o, seed, SMALL).is_err());
                let why = sweep(&min, seed, SMALL).err().unwrap_or_default();
                panic!(
                    "seed {seed}: {first}\nshrunk to {} ops: {min:?}\nfails with: {why}",
                    min.len()
                );
            }
        }
    }
    // Both outcomes were reached, so the sweep straddled the superblock.
    assert!(
        total.recovered_old > 0 && total.recovered_new > 0,
        "{total:?}"
    );
    assert!(total.commits >= 60, "{total:?}");
}

#[test]
fn ddmin_finds_a_minimal_failing_subsequence() {
    let xs: Vec<u32> = (0..40).collect();
    // Fails whenever 7 and 31 are both present.
    let min = ddmin(xs, |s| s.contains(&7) && s.contains(&31));
    assert_eq!(min, [7, 31]);
    let min = ddmin((0..10).collect::<Vec<u32>>(), |s| s.contains(&3));
    assert_eq!(min, [3]);
}

#[test]
fn the_recorder_and_replay_reproduce_a_commit_exactly() {
    let mut fs = Fs::fresh(SMALL);
    fs.put(
        super::key::Key {
            obj: 1,
            kind: super::key::item::INLINE,
            off: 0,
        },
        b"x",
    )
    .unwrap();
    let before = fs.dev.image().to_vec();
    let mut rec = Recorder {
        dev: &mut fs.dev,
        log: Vec::new(),
    };
    fs.v.commit(&mut rec, &mut fs.ws, 2).unwrap();
    let log = rec.log;
    // Replaying with a crash past the end and "everything persists" lands
    // the same image the commit produced.
    let mut dev = MemDevice::from_image(before);
    replay_into_crash(&mut dev, &log, u64::MAX, Persist::Everything, 0);
    assert!(dev.image() == fs.dev.image());
    // And it mounts the new generation.
    let mut d = dev;
    assert_eq!(
        Volume::mount(&mut d, &mut Workspace::new())
            .unwrap()
            .info()
            .gen,
        2
    );
}
