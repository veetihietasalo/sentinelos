//! Host tests for the CoW B+tree and its transactions (spec §7.2, §8; FS-1b):
//! a randomised model check against a `BTreeMap` across commits and cold
//! remounts, depth growth and shrink, the per-operation dirty footprint
//! (≤ 13 blocks), all-or-nothing refusals, order independence and replay
//! determinism (principle 4), and read-only on corruption.

use super::{TreeError, ITEM_MAX, MAX_LEVEL};
use crate::blk::layout::{seal_metadata, HEADER_LEN};
use crate::blk::mem::{MemDevice, SplitMix64};
use crate::blk::BLOCK_SIZE;
use crate::sfs::key::Key;
use crate::sfs::testkit::{apply, model_items, params, rand_data, rand_ops, Fs, Model, Op, OPAQUE};
use crate::sfs::volume::{format, Volume, Workspace};
use alloc::vec;
use alloc::vec::Vec;

const DEV: u64 = 3840;

fn key(obj: u64) -> Key {
    Key {
        obj,
        kind: OPAQUE,
        off: 0,
    }
}

/// The level of the committed root, read from the device.
fn root_level(fs: &Fs) -> Option<u8> {
    let root = fs.v.superblock().root;
    if root.is_null() {
        return None;
    }
    let at = root.block.0 as usize * BLOCK_SIZE + HEADER_LEN;
    Some(fs.dev.image()[at])
}

#[test]
#[cfg_attr(miri, ignore)]
fn random_operations_match_a_model_across_commits_and_cold_remounts() {
    for seed in 0..6u64 {
        let mut fs = Fs::fresh(DEV);
        let mut model = Model::new();
        let ops = rand_ops(seed, 600, 120);
        for (i, op) in ops.iter().enumerate() {
            apply(&mut fs, &mut model, op);
            if i % 150 == 149 {
                fs.commit().unwrap();
                fs.remount();
                assert_eq!(
                    fs.items().unwrap(),
                    model_items(&model),
                    "seed {seed} op {i}"
                );
            }
        }
        fs.commit().unwrap();
        assert_eq!(fs.items().unwrap(), model_items(&model));
        let r = fs.scrub();
        assert_eq!((r.bad, r.blocks), (0, r.hashed), "seed {seed}: {r:?}");
        fs.remount();
        assert_eq!(fs.items().unwrap(), model_items(&model));
        for (k, d) in &model {
            assert_eq!(fs.get(k).unwrap().as_deref(), Some(&d[..]));
        }
    }
}

#[test]
#[cfg_attr(miri, ignore)]
fn the_tree_grows_to_three_levels_and_shrinks_back_to_empty() {
    let mut fs = Fs::fresh(DEV);
    // Empty items: 191 per leaf, 61 children per node — 13 000 keys need a
    // level-2 root.
    let n = 13_000u64;
    for i in 0..n {
        fs.put(key(i * 7), &[]).unwrap();
    }
    fs.commit().unwrap();
    assert_eq!(root_level(&fs), Some(2));
    let r = fs.scrub();
    assert_eq!(r.bad, 0, "{r:?}");
    assert_eq!(r.items, n);
    fs.remount();
    assert_eq!(fs.get(&key(7 * 4321)).unwrap(), Some(vec![]));
    assert_eq!(fs.get(&key(7 * 4321 + 1)).unwrap(), None);
    // Remove in an interleaved order so merges happen everywhere.
    for i in (0..n).step_by(2).chain((1..n).step_by(2)) {
        assert!(fs.remove(&key(i * 7)).unwrap());
    }
    fs.commit().unwrap();
    assert_eq!(root_level(&fs), None, "the empty tree is the null pointer");
    assert!(fs.v.superblock().root.is_null());
    // Everything the tree held is free again (after the commit that freed it).
    let before = Fs::fresh(DEV).v.info().free;
    assert_eq!(fs.v.info().free, before);
}

/// The worst dirty footprint of a single operation, measured as what the
/// commit of a transaction holding only that operation writes (tree nodes,
/// bitmaps, index, and the superblock): §8's bound is 13.
fn footprint(fs: &mut Fs, op: &Op) -> u64 {
    fs.commit().unwrap();
    match op {
        Op::Put(k, d) => fs.put(*k, d).unwrap(),
        Op::Remove(k) => {
            fs.remove(k).unwrap();
        }
        Op::Commit => {}
    }
    let forced = fs.forced;
    let info = fs.commit().unwrap();
    assert_eq!(fs.forced, forced, "one operation never needs two commits");
    info.blocks
}

#[test]
#[cfg_attr(miri, ignore)]
fn every_operation_kind_dirties_at_most_13_blocks() {
    for blocks in [DEV, 1 << 18] {
        let mut fs = Fs::fresh(blocks);
        let mut rng = SplitMix64::new(9);
        // A two-level tree of large items, so every operation can split,
        // merge, and copy a full path.
        let mut live = Vec::new();
        for i in 0..900u64 {
            fs.put(key(i * 3), &rand_data(&mut rng)).unwrap();
            live.push(i * 3);
        }
        fs.commit().unwrap();
        assert!(root_level(&fs) >= Some(2) || blocks == DEV);
        let mut worst = [0u64; 4];
        for round in 0..400u64 {
            let pick = live[rng.below(live.len() as u64) as usize];
            let kind = (round % 4) as usize;
            let op = match kind {
                // insert a new key next to an existing one
                0 => Op::Put(key(pick + 1 + round % 2), rand_data(&mut rng)),
                // replace with an item of another size
                1 => Op::Put(key(pick), rand_data(&mut rng)),
                // remove (merges as leaves thin out)
                2 => Op::Remove(key(pick)),
                // insert a maximal item (splits)
                _ => Op::Put(key(pick + 2), vec![0xEE; ITEM_MAX]),
            };
            let fp = footprint(&mut fs, &op);
            worst[kind] = worst[kind].max(fp);
            assert!(fp <= 13, "{op:?} dirtied {fp} blocks (device {blocks})");
        }
        extern crate std;
        std::eprintln!(
            "worst footprint on {blocks} blocks [insert, replace, remove, max-insert]: {worst:?}"
        );
        assert!(worst.iter().all(|&w| w >= 3), "{worst:?}");
        assert_eq!(fs.scrub().bad, 0);
    }
}

#[test]
#[cfg_attr(miri, ignore)]
fn refusals_change_nothing() {
    let mut fs = Fs::fresh(256);
    fs.put(key(1), b"one").unwrap();
    fs.commit().unwrap();
    let image = fs.dev.image().to_vec();
    // Too big.
    assert_eq!(
        fs.v.put(key(2), &vec![0; ITEM_MAX + 1]),
        Err(TreeError::TooBig)
    );
    // A miss after a cold remount: nothing changes until it is resolved.
    fs.remount();
    let dirty = fs.v.dirty_blocks();
    match fs.v.put(key(3), b"three") {
        Err(TreeError::Miss(_)) => {}
        other => panic!("expected a miss, got {other:?}"),
    }
    assert_eq!(fs.v.dirty_blocks(), dirty);
    assert!(!fs.v.is_dirty());
    assert_eq!(fs.dev.image(), &image[..]);
    // Fill the disk: NoSpace is refused whole, and removes still work.
    let mut i = 10u64;
    let err = loop {
        match fs.put(key(i), &[0x55; ITEM_MAX]) {
            Ok(()) => i += 1,
            Err(e) => break e,
        }
    };
    assert_eq!(err, TreeError::NoSpace);
    let before = fs.items().unwrap();
    assert_eq!(fs.put(key(i), &[0x55; ITEM_MAX]), Err(TreeError::NoSpace));
    assert_eq!(fs.items().unwrap(), before, "a refused put changed nothing");
    fs.commit().unwrap();
    for k in 10..i {
        assert!(fs.remove(&key(k)).unwrap(), "remove on a full disk");
    }
    fs.commit().unwrap();
    assert_eq!(fs.items().unwrap(), vec![(key(1), b"one".to_vec())]);
    assert_eq!(fs.scrub().bad, 0);
}

#[test]
fn reads_see_the_transaction_and_commits_publish_it() {
    let mut fs = Fs::fresh(256);
    assert_eq!(fs.get(&key(5)).unwrap(), None);
    assert_eq!(fs.items().unwrap(), vec![]);
    fs.put(key(5), b"five").unwrap();
    fs.put(key(5), b"FIVE!").unwrap();
    assert_eq!(fs.get(&key(5)).unwrap(), Some(b"FIVE!".to_vec()));
    assert!(fs.v.superblock().root.is_null(), "not committed yet");
    let info = fs.commit().unwrap();
    assert_eq!(info.blocks, 4, "leaf + bitmap + index + superblock");
    assert!(!fs.v.superblock().root.is_null());
    fs.remount();
    assert_eq!(fs.get(&key(5)).unwrap(), Some(b"FIVE!".to_vec()));
    assert!(fs.remove(&key(5)).unwrap());
    assert!(!fs.remove(&key(5)).unwrap());
    fs.commit().unwrap();
    assert!(fs.v.superblock().root.is_null());
}

#[test]
#[cfg_attr(miri, ignore)]
fn the_same_key_set_by_different_orders_holds_the_same_items() {
    let mut rng = SplitMix64::new(3);
    let set: Vec<(Key, Vec<u8>)> = (0..400u64)
        .map(|i| (key(i * 11 % 997), rand_data(&mut rng)))
        .collect();
    let build = |order: &[usize], churn: bool| {
        let mut fs = Fs::fresh(DEV);
        for (n, &i) in order.iter().enumerate() {
            let (k, d) = &set[i];
            fs.put(*k, d).unwrap();
            if churn && n % 3 == 0 {
                // Something extra that goes again: the set ends the same.
                fs.put(key(5000 + n as u64), &[1; 900]).unwrap();
                if n % 2 == 0 {
                    fs.commit().unwrap();
                }
                assert!(fs.remove(&key(5000 + n as u64)).unwrap());
            }
        }
        fs.commit().unwrap();
        fs.remount();
        fs.items().unwrap()
    };
    let forward: Vec<usize> = (0..set.len()).collect();
    let backward: Vec<usize> = (0..set.len()).rev().collect();
    let mut shuffled = forward.clone();
    for i in (1..shuffled.len()).rev() {
        shuffled.swap(i, rng.below(i as u64 + 1) as usize);
    }
    let a = build(&forward, false);
    assert_eq!(a.len(), set.len());
    assert_eq!(build(&backward, false), a);
    assert_eq!(build(&shuffled, true), a);
}

#[test]
#[cfg_attr(miri, ignore)]
fn replaying_the_same_operations_yields_the_same_superblocks_and_image() {
    let ops = rand_ops(77, 500, 90);
    let run = || {
        let mut fs = Fs::fresh(DEV);
        let mut model = Model::new();
        let mut hashes = Vec::new();
        for op in &ops {
            if *op == Op::Commit {
                hashes.push(fs.commit().unwrap().sb_hash);
            } else {
                apply(&mut fs, &mut model, op);
            }
        }
        hashes.push(fs.commit().unwrap().sb_hash);
        (hashes, fs.dev.image().to_vec())
    };
    let (h1, i1) = run();
    let (h2, i2) = run();
    assert!(h1.len() > 20);
    assert_eq!(h1, h2, "same operations, same superblock hashes");
    assert!(i1 == i2, "same operations, same image");
    // Cache state is not an input: the same run with cold remounts between
    // commits (every node read back from disk) ends identically.
    let mut fs = Fs::fresh(DEV);
    let mut model = Model::new();
    let mut h3 = Vec::new();
    for op in &ops {
        if *op == Op::Commit {
            h3.push(fs.commit().unwrap().sb_hash);
            fs.remount();
        } else {
            apply(&mut fs, &mut model, op);
        }
    }
    h3.push(fs.commit().unwrap().sb_hash);
    assert_eq!(h3, h1, "allocation never depends on what is cached");
}

#[test]
fn a_structurally_bad_node_with_a_valid_hash_is_corrupt_and_read_only() {
    let mut fs = Fs::fresh(256);
    for i in 0..30u64 {
        fs.put(key(i), &[i as u8; 300]).unwrap();
    }
    fs.commit().unwrap();
    assert_eq!(root_level(&fs), Some(1));
    // Re-seal the root with its first entry's key changed: the hash is
    // valid, the structure is not (the child's lowest key no longer matches).
    let root = fs.v.superblock().root;
    let at = root.block.0 as usize * BLOCK_SIZE;
    let mut img = fs.dev.image().to_vec();
    let blk: &mut [u8; BLOCK_SIZE] = (&mut img[at..at + BLOCK_SIZE]).try_into().unwrap();
    blk[super::NODE_HDR + 9] ^= 1; // key 0's `off`
    let hash = seal_metadata(blk);
    // Point the superblock at the re-sealed root (a consistent rewrite: what
    // an adversary or a buggy writer could produce).
    let mut sb = *fs.v.superblock();
    sb.root.hash = hash;
    let slot = fs.v.info().slot as usize;
    let sbb: &mut [u8; BLOCK_SIZE] = (&mut img[slot * BLOCK_SIZE..(slot + 1) * BLOCK_SIZE])
        .try_into()
        .unwrap();
    crate::sfs::superblock::encode(&sb, sbb);
    let mut fs = Fs::mount(MemDevice::from_image(img)).unwrap();
    assert_eq!(fs.get(&key(0)), Err(TreeError::Corrupt));
    assert!(fs.v.is_read_only());
    assert_eq!(fs.v.put(key(99), b"x"), Err(TreeError::Sealed));
    let r = fs.scrub();
    assert!(r.bad >= 1);
}

#[test]
fn a_flipped_bit_in_a_committed_node_is_refused_at_read() {
    let mut fs = Fs::fresh(256);
    for i in 0..30u64 {
        fs.put(key(i), &[i as u8; 300]).unwrap();
    }
    fs.commit().unwrap();
    let root = fs.v.superblock().root;
    let mut img = fs.dev.image().to_vec();
    img[root.block.0 as usize * BLOCK_SIZE + 3000] ^= 0x10;
    let mut fs = Fs::mount(MemDevice::from_image(img)).unwrap();
    assert_eq!(fs.get(&key(0)), Err(TreeError::Corrupt));
    assert!(fs.v.is_read_only());
}

#[test]
#[cfg_attr(miri, ignore)]
fn level_bound_is_enforced_by_decode() {
    // A node claiming a level past MAX_LEVEL never decodes.
    let mut b = vec![0u8; BLOCK_SIZE];
    b[HEADER_LEN] = MAX_LEVEL + 1;
    b[HEADER_LEN + 2] = 1;
    assert!(super::codec::decode_head(&b).is_err());
}

#[test]
#[cfg_attr(miri, ignore)]
fn a_one_gib_volume_mounts_and_works_like_the_small_one() {
    let mut dev = MemDevice::untracked(1 << 18);
    let mut ws = Workspace::new();
    format(&mut dev, &mut ws, &params()).unwrap();
    let v = Volume::mount(&mut dev, &mut ws).unwrap();
    assert_eq!(v.info().groups, 9);
    let mut fs = Fs {
        dev,
        ws,
        v,
        now: 1,
        forced: 0,
    };
    let mut model = Model::new();
    for op in rand_ops(5, 400, 200) {
        apply(&mut fs, &mut model, &op);
    }
    fs.commit().unwrap();
    fs.remount();
    assert_eq!(fs.items().unwrap(), model_items(&model));
    assert_eq!(fs.scrub().bad, 0);
}

#[test]
fn a_stale_miss_is_dropped_but_a_fresh_bad_one_is_damage() {
    use crate::sfs::volume::CommitError;
    let mut fs = Fs::fresh(256);
    fs.put(key(1), b"one").unwrap();
    fs.commit().unwrap();
    fs.remount();
    let epoch = fs.v.epoch();
    let p = match fs.v.get(&key(1), &mut [0u8; ITEM_MAX]) {
        Err(TreeError::Miss(p)) => p,
        other => panic!("expected a miss, got {other:?}"),
    };
    let garbage = [0x77u8; BLOCK_SIZE];
    // A commit since the miss: the block may have been reused — not damage.
    assert_eq!(fs.v.resolve_tree_miss(&p, Ok(&garbage), epoch + 1), Ok(()));
    assert!(!fs.v.is_read_only());
    // The same epoch: the committed tree itself is bad.
    assert_eq!(
        fs.v.resolve_tree_miss(&p, Ok(&garbage), epoch),
        Err(CommitError::Corrupt)
    );
    assert!(fs.v.is_read_only());
}
