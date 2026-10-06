//! Host tests for the storage lattice (also run under Miri: `cap::`).

use super::*;
use crate::cap::table::CapSpace;
use crate::cap::{Access, Attenuation, Capability, DenyReason, ServiceId, Target, Tick};
use core::num::NonZeroU16;

fn path(s: &str) -> StoragePath {
    StoragePath::parse(s.as_bytes()).unwrap()
}

fn user(n: u16) -> BlobDomain {
    BlobDomain::User(NonZeroU16::new(n).unwrap())
}

fn blob(d: BlobDomain, b: u8) -> BlobRef {
    BlobRef::new(d, [b; REF_HASH_LEN])
}

fn refs(r: &[BlobRef]) -> BlobScope {
    BlobScope::RefSet(RefSet::new(r).unwrap())
}

fn att(prefix: &str, blobs: BlobScope, bytes: u64) -> StorageAttenuation {
    StorageAttenuation {
        tree: Tree::Live,
        prefix: path(prefix),
        blobs,
        quota: Quota {
            bytes,
            inodes: 64,
            blob_bytes: 4096,
        },
    }
}

fn read(p: &str) -> StorageAccess {
    StorageAccess {
        op: Op::Read,
        tree: Tree::Live,
        object: StorageObject::Path(path(p)),
        bytes: 0,
    }
}

fn write(p: &str, bytes: u64) -> StorageAccess {
    StorageAccess {
        op: Op::Write,
        tree: Tree::Live,
        object: StorageObject::Path(path(p)),
        bytes,
    }
}

#[test]
fn paths_parse_canonically_and_refuse_every_other_spelling() {
    assert_eq!(path("/"), StoragePath::ROOT);
    assert!(path("/").is_root());
    let p = path("/app/foo");
    assert_eq!(p.as_bytes(), b"app/foo");
    assert_eq!(p.depth(), 2);
    assert_eq!(p.component(0), Some(&b"app"[..]));
    assert_eq!(p.component(1), Some(&b"foo"[..]));
    assert_eq!(p.component(2), None);
    assert_eq!(StoragePath::ROOT.depth(), 0);
    assert_eq!(StoragePath::ROOT.component(0), None);

    let bad: &[(&[u8], StorageError)] = &[
        (b"", StorageError::NotAbsolute),
        (b"app", StorageError::NotAbsolute),
        (b"//", StorageError::EmptyComponent),
        (b"/app//foo", StorageError::EmptyComponent),
        (b"/app/", StorageError::EmptyComponent),
        (b"/./app", StorageError::DotComponent),
        (b"/app/..", StorageError::DotComponent),
        (b"/app/../etc", StorageError::DotComponent),
        (b"/ap\0p", StorageError::Nul),
    ];
    for (input, why) in bad {
        assert_eq!(StoragePath::parse(input), Err(*why), "{input:?}");
    }
    // `...` and `.x` are ordinary names.
    assert!(StoragePath::parse(b"/.../.x/x.").is_ok());
}

#[test]
fn paths_are_bounded_in_bytes_and_depth() {
    let mut deep = [0u8; 2 * (MAX_DEPTH + 1)];
    for c in deep.chunks_mut(2) {
        c.copy_from_slice(b"/a");
    }
    assert!(StoragePath::parse(&deep[..2 * MAX_DEPTH]).is_ok());
    assert_eq!(StoragePath::parse(&deep), Err(StorageError::TooDeep));

    let mut long = [b'x'; MAX_PATH_BYTES + 2];
    long[0] = b'/';
    assert!(StoragePath::parse(&long[..=MAX_PATH_BYTES]).is_ok());
    assert_eq!(StoragePath::parse(&long), Err(StorageError::TooLong));
}

#[test]
fn prefix_is_by_components_never_bytes() {
    let foo = path("/app/foo");
    assert!(foo.is_within(&foo));
    assert!(path("/app/foo/x").is_within(&foo));
    assert!(path("/app/foo/x/y").is_within(&foo));
    assert!(foo.is_within(&path("/app")));
    assert!(foo.is_within(&StoragePath::ROOT));
    // The sibling counterexample, both ways.
    assert!(!path("/app/foobar").is_within(&foo));
    assert!(!foo.is_within(&path("/app/foobar")));
    assert!(!path("/app/fo").is_within(&foo));
    assert!(!path("/app").is_within(&foo), "a wider path is not within");
    assert!(!StoragePath::ROOT.is_within(&foo));
    assert!(!path("/apps/foo").is_within(&path("/app")));
}

#[test]
fn snapshot_names_are_single_components() {
    assert!(SnapshotName::parse(b"pre-update").is_ok());
    assert_eq!(SnapshotName::parse(b""), Err(StorageError::EmptyComponent));
    assert_eq!(SnapshotName::parse(b".."), Err(StorageError::DotComponent));
    assert_eq!(SnapshotName::parse(b"a/b"), Err(StorageError::Separator));
    assert_eq!(SnapshotName::parse(b"a\0"), Err(StorageError::Nul));
    assert_eq!(
        SnapshotName::parse(&[b'n'; MAX_NAME + 1]),
        Err(StorageError::TooLong)
    );
    assert!(SnapshotName::parse(&[b'n'; MAX_NAME]).is_ok());
}

#[test]
fn ref_sets_are_canonical() {
    let (a, b, c) = (
        blob(user(1), 1),
        blob(user(1), 2),
        blob(BlobDomain::Public, 9),
    );
    assert_eq!(RefSet::new(&[b, a]), RefSet::new(&[a, b]), "order-free");
    let s = RefSet::new(&[b, c, a]).unwrap();
    assert_eq!(s.as_slice(), &[c, a, b], "Public (0) sorts first");
    assert_eq!(RefSet::new(&[]), Err(StorageError::RefCount));
    assert_eq!(RefSet::new(&[a, a]), Err(StorageError::DuplicateRef));
    assert_eq!(RefSet::new(&[a; MAX_REFS + 1]), Err(StorageError::RefCount));

    // Hashes that differ only in their last byte (and only in their first):
    // the order is the whole hash, byte by byte, and equality is exact.
    let mut lo = [7u8; REF_HASH_LEN];
    let mut hi = lo;
    lo[REF_HASH_LEN - 1] = 1;
    hi[REF_HASH_LEN - 1] = 2;
    let (x, y) = (BlobRef::new(user(1), lo), BlobRef::new(user(1), hi));
    assert_eq!(x.canonical_cmp(&y), core::cmp::Ordering::Less);
    let s = RefSet::new(&[y, x]).unwrap();
    assert_eq!(s.as_slice(), &[x, y]);
    assert!(s.contains(&x) && s.contains(&y));
    assert!(!RefSet::new(&[x]).unwrap().contains(&y));
    let mut first = hi;
    first[0] = 0;
    let z = BlobRef::new(user(1), first);
    assert_eq!(
        z.canonical_cmp(&x),
        core::cmp::Ordering::Less,
        "first byte dominates"
    );
    // And through the wire form: re-ordered last-byte-only references refused.
    let a = StorageAttenuation {
        tree: Tree::Live,
        prefix: StoragePath::ROOT,
        blobs: BlobScope::RefSet(s),
        quota: Quota::UNLIMITED,
    };
    let mut out = [0u8; MAX_ENCODED_LEN];
    let n = a.encode(&mut out).unwrap();
    assert_eq!(StorageAttenuation::decode(&out[..n]), Ok(a));
    let r0 = 1 + 1 + 2; // tree, prefix len, blobs tag, count
    let w = 2 + REF_HASH_LEN;
    let mut swapped = out;
    swapped[r0..r0 + w].copy_from_slice(&out[r0 + w..r0 + 2 * w]);
    swapped[r0 + w..r0 + 2 * w].copy_from_slice(&out[r0..r0 + w]);
    assert_eq!(
        StorageAttenuation::decode(&swapped[..n]),
        Err(StorageError::NonCanonical)
    );
}

#[test]
fn blob_scopes_never_widen() {
    let (h1, h2) = (blob(user(1), 1), blob(user(1), 2));
    let other = blob(user(2), 1);
    let one = refs(&[h1]);
    let both = refs(&[h1, h2]);
    let d1 = BlobScope::Domain(user(1));
    assert!(BlobScope::None.is_attenuation_of(&one));
    assert!(BlobScope::None.is_attenuation_of(&BlobScope::None));
    assert!(one.is_attenuation_of(&both));
    assert!(!both.is_attenuation_of(&one));
    assert!(both.is_attenuation_of(&d1), "every hash is in d");
    assert!(
        !refs(&[h1, other]).is_attenuation_of(&d1),
        "one hash outside d"
    );
    assert!(!d1.is_attenuation_of(&both), "a Domain from a RefSet");
    assert!(!d1.is_attenuation_of(&BlobScope::Domain(user(2))));
    assert!(!d1.is_attenuation_of(&BlobScope::Domain(BlobDomain::Public)));
    assert!(!one.is_attenuation_of(&BlobScope::None));
    assert!(d1.admits(&h2) && !d1.admits(&other));
    assert!(one.admits(&h1) && !one.admits(&h2));
    assert!(!BlobScope::None.admits(&h1));
}

#[test]
fn the_order_is_tree_prefix_blobs_and_quota() {
    let parent = att("/app/foo", BlobScope::Domain(user(1)), 1000);
    assert!(parent.is_attenuation_of(&parent));
    assert!(att("/app/foo/x", BlobScope::None, 10).is_attenuation_of(&parent));
    assert!(!att("/app", BlobScope::None, 10).is_attenuation_of(&parent));
    assert!(!att("/app/foobar", BlobScope::None, 10).is_attenuation_of(&parent));
    assert!(!att("/app/foo", BlobScope::None, 1001).is_attenuation_of(&parent));
    let mut more_inodes = att("/app/foo", BlobScope::None, 10);
    more_inodes.quota.inodes = 65;
    assert!(!more_inodes.is_attenuation_of(&parent));
    let mut more_blob_bytes = att("/app/foo", BlobScope::None, 10);
    more_blob_bytes.quota.blob_bytes = 4097;
    assert!(!more_blob_bytes.is_attenuation_of(&parent));

    let snap = StorageAttenuation {
        tree: Tree::SnapshotRo(SnapshotName::parse(b"s1").unwrap()),
        ..att("/app/foo", BlobScope::None, 10)
    };
    assert!(!snap.is_attenuation_of(&parent), "snapshot from live");
    assert!(!parent.is_attenuation_of(&snap), "live from snapshot");
    let other_snap = StorageAttenuation {
        tree: Tree::SnapshotRo(SnapshotName::parse(b"s2").unwrap()),
        ..snap
    };
    assert!(!snap.is_attenuation_of(&other_snap));
}

#[test]
fn admits_follows_prefix_quota_tree_and_volume_rules() {
    let a = att("/app/foo", refs(&[blob(user(1), 1)]), 100);
    assert!(a.admits(&read("/app/foo")));
    assert!(a.admits(&read("/app/foo/bar")));
    assert!(!a.admits(&read("/app/foobar")));
    assert!(!a.admits(&read("/app")));
    assert!(a.admits(&write("/app/foo/x", 100)));
    assert!(!a.admits(&write("/app/foo/x", 101)), "over quota");
    let blob_read = |r| StorageAccess {
        op: Op::Read,
        tree: Tree::Live,
        object: StorageObject::Blob(r),
        bytes: 0,
    };
    assert!(a.admits(&blob_read(blob(user(1), 1))));
    assert!(!a.admits(&blob_read(blob(user(1), 2))));
    let blob_write = StorageAccess {
        op: Op::Write,
        bytes: 4097,
        ..blob_read(blob(user(1), 1))
    };
    assert!(!a.admits(&blob_write), "over blob quota");

    // Volume-wide operations need the whole live tree.
    let vol = |op| StorageAccess {
        op,
        tree: Tree::Live,
        object: StorageObject::Path(StoragePath::ROOT),
        bytes: 0,
    };
    let whole = att("/", BlobScope::None, 0);
    for op in [Op::Snapshot, Op::Rollback, Op::Format] {
        assert!(whole.admits(&vol(op)));
        assert!(!a.admits(&vol(op)), "a prefix-narrowed capability");
        let not_root = StorageAccess {
            object: StorageObject::Path(path("/x")),
            ..vol(op)
        };
        assert!(!whole.admits(&not_root));
    }
    // Snapshots are read-only and only their own tree.
    let s1 = Tree::SnapshotRo(SnapshotName::parse(b"s1").unwrap());
    let snap = StorageAttenuation { tree: s1, ..whole };
    assert!(snap.admits(&StorageAccess {
        tree: s1,
        ..read("/x")
    }));
    assert!(!snap.admits(&read("/x")), "the live tree");
    assert!(!snap.admits(&StorageAccess {
        tree: s1,
        ..write("/x", 0)
    }));
    assert!(!snap.admits(&StorageAccess {
        tree: s1,
        ..vol(Op::Rollback)
    }));
    // Non-storage operations never.
    for op in [Op::Send, Op::Request, Op::Reply, Op::Delegate] {
        assert!(!whole.admits(&StorageAccess { op, ..read("/x") }));
    }
}

#[test]
fn encoding_round_trips_and_is_exact() {
    let samples = [
        att("/", BlobScope::None, 0),
        att("/app/foo", BlobScope::Domain(user(7)), u64::MAX),
        att(
            "/a/b/c",
            refs(&[blob(user(1), 3), blob(BlobDomain::Public, 1)]),
            5,
        ),
        StorageAttenuation {
            tree: Tree::SnapshotRo(SnapshotName::parse(b"nightly").unwrap()),
            ..att("/home", BlobScope::None, 1)
        },
    ];
    for a in samples {
        let mut out = [0u8; MAX_ENCODED_LEN];
        let n = a.encode(&mut out).unwrap();
        assert_eq!(n, a.encoded_len());
        assert_eq!(StorageAttenuation::decode(&out[..n]), Ok(a));
        assert_eq!(
            a.encode(&mut out[..n - 1]),
            Err(StorageError::BufferTooSmall)
        );
        // Every truncation and every extension is refused.
        for k in 0..n {
            assert!(StorageAttenuation::decode(&out[..k]).is_err());
        }
        let mut longer = [0u8; MAX_ENCODED_LEN + 1];
        longer[..n].copy_from_slice(&out[..n]);
        assert_eq!(
            StorageAttenuation::decode(&longer[..=n]),
            Err(StorageError::Trailing)
        );
    }
    // The pinned layout of one value.
    let a = att("/ab", BlobScope::Domain(user(0x0102)), 3);
    let mut out = [0u8; MAX_ENCODED_LEN];
    let n = a.encode(&mut out).unwrap();
    let mut want = [0u8; 1 + 3 + 3 + 24];
    want[..7].copy_from_slice(&[0, 2, b'a', b'b', 1, 0x02, 0x01]);
    want[7..15].copy_from_slice(&3u64.to_le_bytes());
    want[15..23].copy_from_slice(&64u64.to_le_bytes());
    want[23..31].copy_from_slice(&4096u64.to_le_bytes());
    assert_eq!(&out[..n], &want[..]);
    assert_eq!(KIND, 1);
}

/// The longest value at the production bounds encodes in exactly
/// `MAX_ENCODED_LEN` bytes, so `Attenuation::id_encoding`'s buffer always
/// suffices (its `encode` never fails).
#[test]
fn the_longest_value_encodes_in_max_encoded_len() {
    let mut rel = [b'a'; MAX_PATH_BYTES];
    for i in (1..MAX_PATH_BYTES).step_by(9) {
        rel[i] = b'/';
    }
    let refs: [BlobRef; MAX_REFS] =
        core::array::from_fn(|i| BlobRef::new(user(1), [i as u8; REF_HASH_LEN]));
    let a = StorageAttenuation {
        tree: Tree::SnapshotRo(SnapshotName::parse(&[b'n'; MAX_NAME]).unwrap()),
        prefix: StoragePath::from_relative(&rel).unwrap(),
        blobs: BlobScope::RefSet(RefSet::new(&refs).unwrap()),
        quota: Quota::UNLIMITED,
    };
    assert_eq!(a.encoded_len(), MAX_ENCODED_LEN);
    let mut out = [0u8; MAX_ENCODED_LEN];
    assert_eq!(a.encode(&mut out), Ok(MAX_ENCODED_LEN));
    assert_eq!(MAX_ENCODED_LEN, 245);
    assert_eq!(crate::cap::ATTENUATION_ENCODING_MAX, MAX_ENCODED_LEN);
}

#[test]
fn decode_refuses_non_canonical_bytes() {
    let a = att("/x", refs(&[blob(user(1), 1), blob(user(1), 2)]), 5);
    let mut out = [0u8; MAX_ENCODED_LEN];
    let n = a.encode(&mut out).unwrap();
    // Layout: [0]=tree, [1]=len 1, [2]='x', [3]=tag 2, [4]=count 2, refs...
    let r0 = 5;
    let r1 = r0 + 2 + REF_HASH_LEN;
    let mut swapped = out;
    swapped[r0..r1].copy_from_slice(&out[r1..r1 + 2 + REF_HASH_LEN]);
    swapped[r1..r1 + 2 + REF_HASH_LEN].copy_from_slice(&out[r0..r1]);
    assert_eq!(
        StorageAttenuation::decode(&swapped[..n]),
        Err(StorageError::NonCanonical)
    );
    let mut dup = out;
    dup[r1..r1 + 2 + REF_HASH_LEN].copy_from_slice(&out[r0..r1]);
    assert_eq!(
        StorageAttenuation::decode(&dup[..n]),
        Err(StorageError::DuplicateRef)
    );
    let mut tag = out;
    tag[0] = 2;
    assert_eq!(
        StorageAttenuation::decode(&tag[..n]),
        Err(StorageError::BadTag)
    );
    let mut blob_tag = out;
    blob_tag[3] = 3;
    assert_eq!(
        StorageAttenuation::decode(&blob_tag[..n]),
        Err(StorageError::BadTag)
    );
    let mut zero = out;
    zero[4] = 0;
    assert_eq!(
        StorageAttenuation::decode(&zero[..n]),
        Err(StorageError::RefCount)
    );
    let mut dot = out;
    dot[2] = b'.';
    assert_eq!(
        StorageAttenuation::decode(&dot[..n]),
        Err(StorageError::DotComponent)
    );
    let mut slash = out;
    slash[2] = b'/';
    assert_eq!(
        StorageAttenuation::decode(&slash[..n]),
        Err(StorageError::EmptyComponent)
    );
    // An empty snapshot name.
    assert_eq!(
        StorageAttenuation::decode(&[1, 0]),
        Err(StorageError::EmptyComponent)
    );
    assert_eq!(StorageAttenuation::decode(&[]), Err(StorageError::Short));
    let mut huge = [0u8; 4];
    huge[1] = (MAX_PATH_BYTES + 1) as u8;
    assert_eq!(
        StorageAttenuation::decode(&huge),
        Err(StorageError::TooLong)
    );
}

/// xorshift64* — deterministic, seeded.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// A small alphabet so random values collide often enough to be comparable.
fn rand_path(rng: &mut Rng) -> StoragePath {
    const COMPS: [&[u8]; 4] = [b"a", b"ab", b"b", b"a.b"];
    let depth = rng.below(4) as usize;
    let mut buf = [0u8; MAX_PATH_BYTES];
    let mut len = 0;
    for i in 0..depth {
        if i > 0 {
            buf[len] = b'/';
            len += 1;
        }
        let c = COMPS[rng.below(4) as usize];
        buf[len..len + c.len()].copy_from_slice(c);
        len += c.len();
    }
    StoragePath::from_relative(&buf[..len]).unwrap()
}

fn rand_domain(rng: &mut Rng) -> BlobDomain {
    BlobDomain::from_wire(rng.below(3) as u16)
}

fn rand_ref(rng: &mut Rng) -> BlobRef {
    // Every byte varies (few values each, so references still collide and
    // compare often): the order must use the whole hash.
    let mut hash = [0u8; REF_HASH_LEN];
    for b in hash.iter_mut() {
        *b = rng.below(2) as u8;
    }
    BlobRef::new(rand_domain(rng), hash)
}

fn rand_att(rng: &mut Rng) -> StorageAttenuation {
    let tree = match rng.below(3) {
        0 | 1 => Tree::Live,
        _ => Tree::SnapshotRo(
            SnapshotName::parse(if rng.below(2) == 0 { b"s" } else { b"t" }).unwrap(),
        ),
    };
    let blobs = match rng.below(3) {
        0 => BlobScope::None,
        1 => BlobScope::Domain(rand_domain(rng)),
        _ => {
            let n = 1 + rng.below(MAX_REFS as u64) as usize;
            let mut r = [rand_ref(rng); MAX_REFS];
            for x in r.iter_mut().take(n) {
                *x = rand_ref(rng);
            }
            match RefSet::new(&r[..n]) {
                Ok(s) => BlobScope::RefSet(s),
                Err(_) => BlobScope::None,
            }
        }
    };
    let q = |rng: &mut Rng| rng.below(4);
    StorageAttenuation {
        tree,
        prefix: rand_path(rng),
        blobs,
        quota: Quota {
            bytes: q(rng),
            inodes: q(rng),
            blob_bytes: q(rng),
        },
    }
}

fn rand_access(rng: &mut Rng) -> StorageAccess {
    let op = [
        Op::Read,
        Op::Write,
        Op::Snapshot,
        Op::Rollback,
        Op::Format,
        Op::Send,
    ][rng.below(6) as usize];
    let tree = if rng.below(4) == 0 {
        Tree::SnapshotRo(SnapshotName::parse(b"s").unwrap())
    } else {
        Tree::Live
    };
    StorageAccess {
        op,
        tree,
        object: if rng.below(2) == 0 {
            StorageObject::Path(rand_path(rng))
        } else {
            StorageObject::Blob(rand_ref(rng))
        },
        bytes: rng.below(5),
    }
}

/// Something usually (not always) below `x`: each field kept or narrowed.
fn narrow(rng: &mut Rng, x: &StorageAttenuation) -> StorageAttenuation {
    let mut y = *x;
    if rng.below(2) == 0 {
        let p = x.prefix.as_bytes();
        let mut buf = [0u8; MAX_PATH_BYTES + 2];
        let mut len = p.len();
        buf[..len].copy_from_slice(p);
        if len > 0 {
            buf[len] = b'/';
            len += 1;
        }
        buf[len] = b'a';
        len += 1;
        if let Ok(q) = StoragePath::from_relative(&buf[..len]) {
            y.prefix = q;
        }
    }
    y.blobs = match (rng.below(4), x.blobs) {
        (0, _) => BlobScope::None,
        (1, BlobScope::RefSet(s)) if s.as_slice().len() > 1 => {
            BlobScope::RefSet(RefSet::new(&s.as_slice()[1..]).unwrap())
        }
        (1, BlobScope::Domain(d)) => BlobScope::RefSet(
            RefSet::new(&[BlobRef::new(d, [rng.below(3) as u8; REF_HASH_LEN])]).unwrap(),
        ),
        (_, keep) => keep,
    };
    let mut cut = |v: u64| if v == 0 { 0 } else { rng.below(v + 1) };
    y.quota = Quota {
        bytes: cut(x.quota.bytes),
        inodes: cut(x.quota.inodes),
        blob_bytes: cut(x.quota.blob_bytes),
    };
    y
}

/// Property test (the Kani laws at the production bounds): partial order,
/// soundness against `admits`, and the canonical wire form.
#[test]
fn lattice_laws_hold_on_random_values() {
    let steps = if cfg!(miri) { 300 } else { 20_000 };
    let mut rng = Rng(0x5EED_F51C);
    let mut related = 0;
    for _ in 0..steps {
        // Independent values rarely compare: derive chains half the time.
        let c = rand_att(&mut rng);
        let b = if rng.below(2) == 0 {
            narrow(&mut rng, &c)
        } else {
            rand_att(&mut rng)
        };
        let a = if rng.below(2) == 0 {
            narrow(&mut rng, &b)
        } else {
            rand_att(&mut rng)
        };
        let x = rand_access(&mut rng);
        assert!(a.is_attenuation_of(&a));
        if a.is_attenuation_of(&b) {
            related += 1;
            if a.admits(&x) {
                assert!(b.admits(&x), "{a:?} ⊑ {b:?} admits {x:?}");
            }
            if b.is_attenuation_of(&c) {
                assert!(a.is_attenuation_of(&c));
            }
            if b.is_attenuation_of(&a) {
                assert_eq!(a, b);
            }
        }
        let mut out = [0u8; MAX_ENCODED_LEN];
        let n = a.encode(&mut out).unwrap();
        assert_eq!(StorageAttenuation::decode(&out[..n]), Ok(a));
    }
    assert!(
        related > steps / 8,
        "the generator relates values: {related}"
    );
}

#[test]
fn meet_is_the_greatest_lower_bound_on_examples() {
    let (h1, h2, h3) = (blob(user(1), 1), blob(user(1), 2), blob(user(2), 1));
    let a = att("/app", refs(&[h1, h2]), 100);
    let b = att("/app/foo", BlobScope::Domain(user(1)), 50);
    let m = a.meet(&b).unwrap();
    assert_eq!(m.prefix, path("/app/foo"), "the deeper prefix");
    assert_eq!(
        m.blobs,
        refs(&[h1, h2]),
        "RefSet ∧ Domain(d) keeps refs in d"
    );
    assert_eq!(m.quota.bytes, 50);
    assert!(m.is_attenuation_of(&a) && m.is_attenuation_of(&b));
    // Sibling prefixes and different trees share nothing.
    assert_eq!(a.meet(&att("/apps", BlobScope::None, 1)), None);
    assert_eq!(
        att("/app/foo", BlobScope::None, 1).meet(&att("/app/foobar", BlobScope::None, 1)),
        None
    );
    let snap = StorageAttenuation {
        tree: Tree::SnapshotRo(SnapshotName::parse(b"s").unwrap()),
        ..a
    };
    assert_eq!(a.meet(&snap), None);
    // Disjoint blob scopes meet at `None`, not at failure.
    assert_eq!(
        refs(&[h3]).meet(&BlobScope::Domain(user(1))),
        BlobScope::None
    );
    assert_eq!(
        BlobScope::Domain(user(1)).meet(&BlobScope::Domain(user(2))),
        BlobScope::None
    );
    assert_eq!(refs(&[h1, h3]).meet(&refs(&[h3, h2])), refs(&[h3]));
    // Through `Attenuation::meet`, as `grant` uses it.
    assert_eq!(
        Attenuation::Storage(a).meet(&Attenuation::Storage(b)),
        Some(Attenuation::Storage(m))
    );
    assert_eq!(
        Attenuation::Storage(a).meet(&Attenuation::UNRESTRICTED_MESSAGE),
        None
    );
}

/// Property test: the meet is below both arguments and above every common
/// lower bound; `None` only when there is no common lower bound.
#[test]
fn meet_laws_hold_on_random_values() {
    let steps = if cfg!(miri) { 300 } else { 20_000 };
    let mut rng = Rng(0x0BEE_F00D);
    let mut met = 0;
    for _ in 0..steps {
        let a = rand_att(&mut rng);
        let b = if rng.below(2) == 0 {
            narrow(&mut rng, &a)
        } else {
            rand_att(&mut rng)
        };
        let c = if rng.below(2) == 0 {
            narrow(&mut rng, &b)
        } else {
            rand_att(&mut rng)
        };
        let lower = c.is_attenuation_of(&a) && c.is_attenuation_of(&b);
        match a.meet(&b) {
            Some(m) => {
                met += 1;
                assert!(m.is_attenuation_of(&a) && m.is_attenuation_of(&b));
                if lower {
                    assert!(c.is_attenuation_of(&m), "{c:?} below {a:?} and {b:?}");
                }
                assert_eq!(b.meet(&a), Some(m), "commutative");
            }
            None => assert!(!lower),
        }
    }
    assert!(met > steps / 8, "the generator meets: {met}");
}

/// Byte fuzz: decode never panics, and whatever it accepts re-encodes to
/// exactly the input (no second encoding of anything).
#[test]
fn decode_is_total_and_canonical_on_random_bytes() {
    let steps = if cfg!(miri) { 300 } else { 50_000 };
    let mut rng = Rng(0xDEC0_DE00);
    let mut accepted = 0;
    for _ in 0..steps {
        let mut buf = [0u8; MAX_ENCODED_LEN];
        // Start from a valid encoding, then flip and cut: reaches deep.
        let a = rand_att(&mut rng);
        let n = a.encode(&mut buf).unwrap();
        for _ in 0..rng.below(3) {
            let i = rng.below(n as u64) as usize;
            buf[i] = rng.next() as u8;
        }
        let len = if rng.below(2) == 0 {
            n
        } else {
            rng.below(MAX_ENCODED_LEN as u64 + 1) as usize
        };
        if let Ok(d) = StorageAttenuation::decode(&buf[..len]) {
            accepted += 1;
            let mut out = [0u8; MAX_ENCODED_LEN];
            let m = d.encode(&mut out).unwrap();
            assert_eq!(&out[..m], &buf[..len]);
        }
    }
    assert!(accepted > 0);
}

// ── Through the capability tables (the wiring) ─────────────────────────────

const STORAGE: Target = Target::Service(ServiceId::Storage);

fn scap(ops: &[Op], a: StorageAttenuation, expires: Option<Tick>) -> Capability {
    Capability {
        target: STORAGE,
        ops: OpSet::of(ops),
        attenuation: Attenuation::Storage(a),
        expires,
    }
}

#[test]
fn storage_capabilities_are_well_formed_only_on_the_storage_service() {
    let a = att("/app", BlobScope::None, 1);
    assert!(scap(&[Op::Read, Op::Delegate], a, None).is_well_formed());
    assert!(
        !scap(&[Op::Send], a, None).is_well_formed(),
        "no bus ops on storage"
    );
    let on_instance = Capability {
        target: Target::Instance(crate::host::InstanceId(1)),
        ..scap(&[Op::Read], a, None)
    };
    assert!(
        !on_instance.is_well_formed(),
        "storage ops need the service"
    );
    let message_on_storage = Capability {
        attenuation: Attenuation::UNRESTRICTED_MESSAGE,
        ..scap(&[Op::Read], a, None)
    };
    assert!(!message_on_storage.is_well_formed());
    assert!(!STORAGE.names(crate::host::InstanceId(1)));
    assert_eq!(STORAGE_OPS.bits(), 0x1F00);
    assert_eq!(Op::Format.label(), "format");
    // Cross-kind never compares.
    assert!(!Attenuation::Storage(a).is_attenuation_of(&Attenuation::UNRESTRICTED_MESSAGE));
    assert!(!Attenuation::UNRESTRICTED_MESSAGE.is_attenuation_of(&Attenuation::Storage(a)));
    assert!(!Attenuation::UNRESTRICTED_MESSAGE.admits(&Access::Storage(read("/app"))));
}

#[test]
fn delegate_and_check_go_through_the_one_predicate() {
    let mut sp: CapSpace<2, 4> = CapSpace::new();
    let root = scap(
        &[Op::Read, Op::Write, Op::Delegate],
        att(
            "/app/foo",
            refs(&[blob(user(1), 1), blob(user(1), 2)]),
            1000,
        ),
        Some(500),
    );
    let p = sp.grant(0, &root, &root).unwrap();
    let narrow = scap(
        &[Op::Read],
        att("/app/foo/cache", refs(&[blob(user(1), 1)]), 10),
        Some(400),
    );
    let c = sp.delegate(0, p, 1, &narrow, 0).unwrap();
    assert!(sp
        .check(1, c, &Access::Storage(read("/app/foo/cache/x")), 0)
        .is_ok());
    assert_eq!(
        sp.check(1, c, &Access::Storage(read("/app/foobar")), 0),
        Err(DenyReason::Attenuation)
    );
    assert_eq!(
        sp.check(1, c, &Access::Storage(write("/app/foo/cache/x", 1)), 0),
        Err(DenyReason::OpNotAllowed)
    );
    assert_eq!(
        sp.check(1, c, &Access::Storage(read("/app/foo/cache")), 400),
        Err(DenyReason::Expired)
    );

    let base = att("/app/foo", refs(&[blob(user(1), 1)]), 10);
    let wider = scap(&[Op::Read], att("/app", BlobScope::None, 10), Some(400));
    let sibling = scap(
        &[Op::Read],
        att("/app/foobar", BlobScope::None, 10),
        Some(400),
    );
    let rollback = scap(&[Op::Write, Op::Rollback], base, Some(400));
    let domain = scap(
        &[Op::Read],
        att("/app/foo", BlobScope::Domain(user(1)), 10),
        Some(400),
    );
    let quota = scap(
        &[Op::Read],
        att("/app/foo", BlobScope::None, 1001),
        Some(400),
    );
    let later = scap(&[Op::Read], base, Some(501));
    let never = scap(&[Op::Read], base, None);
    for bad in [wider, sibling, rollback, domain, quota, later, never] {
        assert_eq!(
            sp.delegate(0, p, 1, &bad, 0),
            Err(crate::cap::CapError::Deny(DenyReason::Amplification)),
            "{bad:?}"
        );
    }
    // `grant` installs the meet: a request wider than the bound gets the
    // bound's prefix and expiry, the request's quota and blobs — below both.
    let above = scap(&[Op::Read], att("/app", BlobScope::None, 1), None);
    let g = sp.grant(1, &above, &root).unwrap();
    let got = sp.get(1, g).unwrap().cap;
    assert!(got.is_attenuation_of(&above) && got.is_attenuation_of(&root));
    assert_eq!(
        got.attenuation,
        Attenuation::Storage(att("/app/foo", BlobScope::None, 1))
    );
    assert_eq!(got.expires, Some(500));
    // Incomparable prefixes share nothing: not granted.
    let sibling = scap(&[Op::Read], att("/app/foobar", BlobScope::None, 1), None);
    assert!(sp.grant(1, &sibling, &root).is_err());
}

/// The lattice is stored inline in every slot of the static capability slab
/// (no heap): 16 × 16 slots × `Entry`. Pin the cost so growing a bound is a
/// visible decision. Since PR-2b (24-byte `Target`, 64-bit generations in
/// `CapRef`): 296-byte `Capability`, 328-byte `Entry`, so the 256-slot slab is
/// ≈ 86 KiB and the kernel-wide `kernel::bus::HOST` static is 136 464 bytes
/// of `.data` in the kernel image (measured with `nm`), at the production
/// bounds.
#[test]
fn the_slab_footprint_is_bounded() {
    assert!(core::mem::size_of::<StorageAttenuation>() <= 256);
    assert!(core::mem::size_of::<Capability>() <= 296);
    assert!(core::mem::size_of::<crate::cap::table::Entry>() <= 328);
    assert!(
        MAX_ENCODED_LEN <= usize::from(u16::MAX),
        "fits the le16 frame length"
    );
}
