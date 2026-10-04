//! The threaded host model of the cache / `sfs-commit` hand-off (spec §11,
//! A21; the race model the component review asked for).
//!
//! The kernel protocol, with real threads and a real lock:
//!
//! - one **task** thread owns the [`MemDevice`] — nothing else can reach it,
//!   as in the kernel — and serves, in this order, a caller's miss read
//!   (device read with the lock **released**, verified insert under it), then
//!   a commit (seal under the lock, every block fetched under the lock and
//!   written without it, publish under it);
//! - several **caller** threads run tree operations under the lock on
//!   disjoint key ranges, post a miss and wait for it, ask for commits when
//!   told `NeedCommit` (and now and then on their own), and read back their
//!   own items — also while a commit is being written, when the volume is
//!   sealed and their writes are refused (`Sealed`) until it is published.
//!
//! The volume sits in a `std::sync::Mutex`, the device outside it, so the
//! type system enforces "no device I/O under the lock" in the model as the
//! task's ownership does in the kernel. At the end the image is remounted
//! cold: it must hold exactly the union of the callers' models, and scrub
//! clean. Miri runs a shortened version (it checks the threads for data races
//! and the safe code for UB; the kernel crate has no `unsafe`).

extern crate std;

use super::key::Key;
use super::scrub::{scrub, ScrubWs};
use super::testkit::{rand_data, Fs, Model, OPAQUE};
use super::tree::{TreeError, ITEM_MAX};
use super::volume::{write_commit, CommitError, Volume, Workspace};
use crate::blk::layout::Pointer;
use crate::blk::mem::{MemDevice, SplitMix64};
use crate::blk::{Block, BlockDevice};
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

/// What the lock protects: the volume and the request slots (the kernel's
/// `Sfs`).
struct Shared {
    v: Box<Volume>,
    read_req: Option<(Pointer, u64)>,
    read_ticket: u64,
    read_served: u64,
    commit_req: u64,
    commit_served: u64,
    stop: bool,
    commits: u64,
    sealed_reads: u64,
}

type Sync2 = Arc<(Mutex<Shared>, Condvar)>;

fn lock(s: &Sync2) -> std::sync::MutexGuard<'_, Shared> {
    match s.0.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

/// The task: serve reads, then commits, never holding the lock across I/O.
fn task(s: Sync2, mut dev: MemDevice) -> MemDevice {
    let mut ws = Workspace::new();
    let mut staging = vec![0u8; 4096];
    loop {
        let (read, commit, stop) = {
            let mut g = lock(&s);
            while g.read_req.is_none() && g.commit_req <= g.commit_served && !g.stop {
                g = match s.1.wait(g) {
                    Ok(g) => g,
                    Err(p) => p.into_inner(),
                };
            }
            (g.read_req, g.commit_req > g.commit_served, g.stop)
        };
        if let Some((p, epoch)) = read {
            let buf: &mut Block = (&mut staging[..]).try_into().unwrap();
            let r = dev.read_blocks(p.block, core::slice::from_mut(buf));
            let mut g = lock(&s);
            g.v.resolve_tree_miss(&p, r.map(|()| &*buf), epoch).unwrap();
            g.read_req = None;
            g.read_served = g.read_ticket;
            s.1.notify_all();
            continue;
        }
        if commit {
            let ticket = lock(&s).commit_req;
            commit_once(&s, &mut dev, &mut ws);
            let mut g = lock(&s);
            g.commit_served = ticket;
            g.commits += 1;
            s.1.notify_all();
            continue;
        }
        if stop {
            return dev;
        }
    }
}

/// The kernel's `commit_once`, over the model's lock.
fn commit_once(s: &Sync2, dev: &mut MemDevice, ws: &mut Workspace) {
    let plan = loop {
        let begun = lock(s).v.begin_commit(7);
        match begun {
            Err(CommitError::Miss(p)) => {
                let buf = ws.block();
                let r = dev.read_blocks(p.block, core::slice::from_mut(buf));
                lock(s).v.resolve_miss(&p, r.map(|()| &*buf)).unwrap();
            }
            other => break other.unwrap(),
        }
    };
    // Give callers a window to run (and be refused) while the commit is in
    // flight.
    thread::yield_now();
    let io = write_commit(dev, ws.block(), &plan, |stage, out| {
        let g = lock(s);
        let r = g.v.fetch(stage, out);
        drop(g);
        thread::yield_now();
        r
    });
    let mut g = lock(s);
    g.v.finish_commit(io).unwrap();
    // A cold cache after every commit: the callers' next walks miss, so the
    // read hand-off runs concurrently with everything else.
    g.v.drop_all_clean();
}

/// Post a read of `p` and wait for it to be served.
fn read_miss(s: &Sync2, p: Pointer, epoch: u64) {
    let mut g = lock(s);
    while g.read_req.is_some() {
        g = s.1.wait(g).unwrap_or_else(|e| e.into_inner());
    }
    g.read_ticket += 1;
    let ticket = g.read_ticket;
    g.read_req = Some((p, epoch));
    s.1.notify_all();
    while g.read_served < ticket {
        g = s.1.wait(g).unwrap_or_else(|e| e.into_inner());
    }
}

/// Ask for a commit and wait until one has completed after the request.
fn commit_and_wait(s: &Sync2) {
    let mut g = lock(s);
    g.commit_req += 1;
    let ticket = g.commit_req;
    s.1.notify_all();
    while g.commit_served < ticket {
        g = s.1.wait(g).unwrap_or_else(|e| e.into_inner());
    }
}

/// One caller: `n` operations on keys `base..base + space`.
fn caller(s: Sync2, seed: u64, base: u64, space: u64, n: usize) -> Model {
    let mut rng = SplitMix64::new(seed);
    let mut model = Model::new();
    let mut out = vec![0u8; ITEM_MAX];
    for i in 0..n {
        let k = Key {
            obj: base + rng.below(space),
            kind: OPAQUE,
            off: 0,
        };
        let action = rng.below(10);
        let data = rand_data(&mut rng);
        loop {
            let (r, epoch) = {
                let mut g = lock(&s);
                let epoch = g.v.epoch();
                let r = match action {
                    0..=4 => g.v.put(k, &data).map(|()| None),
                    5..=6 => g.v.remove(&k).map(|_| None),
                    _ => {
                        let sealed = g.v.is_committing();
                        let r = g.v.get(&k, &mut out).map(Some);
                        if sealed && r.is_ok() {
                            g.sealed_reads += 1;
                        }
                        r
                    }
                };
                (r, epoch)
            };
            match r {
                Ok(Some(got)) => {
                    let want = model.get(&k).map(Vec::len);
                    assert_eq!(got, want, "caller {base}: read of {k:?}");
                    if let Some(n) = got {
                        assert_eq!(&out[..n], &model[&k][..]);
                    }
                    break;
                }
                Ok(None) => {
                    if action <= 4 {
                        model.insert(k, data.clone());
                    } else {
                        model.remove(&k);
                    }
                    break;
                }
                Err(TreeError::Miss(p)) => read_miss(&s, p, epoch),
                Err(TreeError::NeedCommit) => commit_and_wait(&s),
                Err(TreeError::Sealed) => {
                    // A commit is being written: wait for it to publish.
                    let g = lock(&s);
                    assert!(!g.v.is_read_only(), "caller {base}: volume went read-only");
                    if g.v.is_committing() {
                        drop(s.1.wait(g).unwrap_or_else(|e| e.into_inner()));
                    }
                }
                Err(e) => panic!("caller {base}: op {i}: {e:?}"),
            }
        }
        if rng.below(25) == 0 {
            commit_and_wait(&s);
        }
    }
    model
}

fn run(callers: u64, ops: usize, seed: u64) {
    let fs = Fs::fresh(1024);
    let Fs { dev, v, .. } = fs;
    let shared: Sync2 = Arc::new((
        Mutex::new(Shared {
            v,
            read_req: None,
            read_ticket: 0,
            read_served: 0,
            commit_req: 0,
            commit_served: 0,
            stop: false,
            commits: 0,
            sealed_reads: 0,
        }),
        Condvar::new(),
    ));
    let t = {
        let s = shared.clone();
        thread::spawn(move || task(s, dev))
    };
    let workers: Vec<_> = (0..callers)
        .map(|c| {
            let s = shared.clone();
            thread::spawn(move || caller(s, seed * 31 + c, c * 1000, 60, ops))
        })
        .collect();
    let mut all = Model::new();
    for w in workers {
        all.extend(w.join().unwrap());
    }
    commit_and_wait(&shared);
    lock(&shared).stop = true;
    shared.1.notify_all();
    let dev = t.join().unwrap();
    let (commits, reads, sealed_reads) = {
        let g = lock(&shared);
        (g.commits, g.read_served, g.sealed_reads)
    };
    std::eprintln!(
        "race model: {commits} commits, {reads} miss reads, {sealed_reads} reads during a commit"
    );
    // The shortened Miri run is too small to promise much contention.
    let min_reads = if cfg!(miri) { 1 } else { 10 };
    assert!(
        commits >= 2 && reads >= min_reads,
        "commits {commits}, reads {reads}"
    );
    // Cold remount: exactly the union of the callers' models, scrub clean.
    let mut fs = Fs::mount(MemDevice::from_image(dev.into_image())).unwrap();
    let items = fs.items().unwrap();
    let want: Vec<(Key, Vec<u8>)> = all.into_iter().collect();
    assert_eq!(items, want);
    let sb = *fs.v.superblock();
    let info = fs.v.info();
    let r = scrub(
        &mut fs.dev,
        &mut ScrubWs::new(),
        &sb,
        &info.sb_hash,
        info.slot,
    )
    .unwrap();
    assert_eq!(r.bad, 0, "{r:?}");
}

#[test]
fn concurrent_callers_and_the_commit_task_agree_with_the_models() {
    if cfg!(miri) {
        run(2, 12, 1);
    } else {
        for seed in 0..4 {
            run(3, 300, seed);
        }
    }
}
