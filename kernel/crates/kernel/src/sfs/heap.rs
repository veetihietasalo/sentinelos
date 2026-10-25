//! The heap-cap test (spec §5 principle 7, §11 FS-1b, A23/A31): the whole
//! filesystem — format, mount, the tree, transactions, commits, scrub — runs
//! under a counting global allocator, and its **peak** heap use is capped and
//! the same for the 16 MiB dev window and a 1 GiB device. Nothing allocates
//! proportionally to the image.

use super::key::Key;
use super::scrub::{scrub, ScrubWs};
use super::testkit::{params, Fs, OPAQUE};
use super::tree::ITEM_MAX;
use super::volume::{format, Volume, Workspace};
use crate::blk::mem::MemDevice;
use alloc::vec;

/// The cap: one 256 KiB cache slab plus the fixed tables and workspaces.
const CAP: isize = 512 * 1024;

/// Peak heap bytes of a full FS session on an untracked device of `blocks`
/// (the device's own image is allocated before counting starts).
fn session_peak(blocks: u64) -> (isize, isize) {
    let mut dev = MemDevice::untracked(blocks);
    let data = vec![0x5Au8; ITEM_MAX];
    test_alloc::reset();
    let mut ws = Workspace::new();
    format(&mut dev, &mut ws, &params()).unwrap();
    let v = Volume::mount(&mut dev, &mut ws).unwrap();
    let mut fs = Fs {
        dev,
        ws,
        v,
        now: 1,
        forced: 0,
    };
    let key = |i: u64| Key {
        obj: i,
        kind: OPAQUE,
        off: 0,
    };
    for round in 0..6u64 {
        for i in 0..300u64 {
            let len = ((i * 37 + round * 11) % ITEM_MAX as u64) as usize;
            fs.put(key(i * 8 + round), &data[..len]).unwrap();
        }
        fs.commit().unwrap();
        for i in (0..300u64).step_by(3) {
            fs.remove(&key(i * 8 + round)).unwrap();
        }
        fs.commit().unwrap();
        // No remount: `Fs::remount` builds the new volume before dropping
        // the old one (two volumes at once is the harness, not the kernel,
        // which mounts once). The tree outgrows the 64-block cache, so
        // operations miss and read back from the device anyway.
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
    .unwrap();
    assert_eq!(r.bad, 0);
    assert!(r.items > 1000, "{r:?}");
    let peak = test_alloc::peak();
    extern crate std;
    std::eprintln!("heap peak for {blocks} blocks: {peak} bytes");
    drop(fs);
    (peak, test_alloc::live())
}

#[test]
#[cfg_attr(miri, ignore)]
fn peak_heap_is_capped_and_independent_of_device_size() {
    let (small, small_left) = session_peak(3840);
    let (large, large_left) = session_peak(1 << 18); // 1 GiB, 9 groups
    assert!(
        small > 256 * 1024,
        "the count sees the cache slab ({small})"
    );
    assert!(small <= CAP, "dev window peak {small} > cap {CAP}");
    assert!(large <= CAP, "1 GiB peak {large} > cap {CAP}");
    // The only difference is the device itself (allocated before counting):
    // the filesystem's own peak does not grow with the image.
    assert!(
        large.abs_diff(small) <= 4096,
        "peak differs with device size: {small} vs {large}"
    );
    // Everything the session allocated was freed with it (the device is
    // dropped after counting started, hence ≤ 0).
    assert!(
        small_left <= 0 && large_left <= 0,
        "{small_left} {large_left}"
    );
}

#[test]
fn the_counter_counts_this_thread() {
    test_alloc::reset();
    let v = vec![0u8; 10_000];
    assert!(test_alloc::live() >= 10_000);
    drop(v);
    assert!(test_alloc::peak() >= 10_000);
    assert!(test_alloc::live() < 10_000);
}
