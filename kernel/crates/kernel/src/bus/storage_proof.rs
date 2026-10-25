//! Boot proof for SentinelFS FS-1c (`docs/specs/2026-09-18-sentinelfs-design.md`
//! §11): the storage-capability lattice on the kernel-wide host.
//!
//! ```text
//! [sfs] cap: narrow=ok wider-prefix=refused sibling-prefix=refused rollback-from-write=refused blobs-widen=refused quota-raise=refused expiry-extend=refused tree-from-live=refused ok
//! ```
//!
//! Two first-party probe instances (`crate::host::probe`): **alice**, who
//! holds a `Send` capability over **bob** from her manifest, is granted a
//! storage capability by the kernel (the storage service's authority,
//! `Host::grant_service`): `{Read, Write, Delegate}` over the live tree under
//! `/app/foo`, two blobs of `User(1)`, a quota, and an expiry. She then
//! delegates over her capability to bob — through `Host::delegate_from`, the
//! exact host path `Ctx::delegate` runs, acting as alice (her kernel-stamped
//! identity is what the denial log records):
//!
//! - `narrow=ok` — a strictly narrower child (`Read` only, `/app/foo/cache`,
//!   one of the two blobs, a smaller quota, an earlier expiry) is installed in
//!   bob's table, bob is told by a kernel-stamped `Grant` notice from alice,
//!   and `CapSpace::check` on bob's index admits a read under the child's
//!   prefix and refuses `/app/foobar` (attenuation) and a write (op);
//! - each amplification is refused **and logged** — exactly one new denial,
//!   the newest record naming alice, `delegate` and `amplification`:
//!   `wider-prefix` (`/app`), `sibling-prefix` (`/app/foobar`),
//!   `rollback-from-write` (`{Write, Rollback}`), `blobs-widen` (`Domain(User(1))`
//!   from the parent's `RefSet`), `quota-raise` (one byte more),
//!   `expiry-extend` (a lifetime past the parent's expiry), and
//!   `tree-from-live` (read-only access to a snapshot from a live-tree
//!   parent: the trees are incomparable).
//!
//! `ok` additionally requires that both instances are terminated afterwards,
//! that no storage capability is left in any table, and that the instance
//! count is back where it started. Runs after `prove_caps` (same host, same
//! probes; it needs `clock::mono_ticks` for expiry) and before
//! `sfs::prove_mount` (it drives instances on this core and spawns nothing).

use super::{dispatch, instantiate, terminate, with_host, Delegation, HOST};
use crate::cap::deny::Action;
use crate::cap::storage::{
    BlobRef, BlobScope, Quota, RefSet, SnapshotName, StorageAccess, StorageAttenuation,
    StorageObject, StoragePath, Tree, REF_HASH_LEN,
};
use crate::cap::table::MAX_CAPS;
use crate::cap::{
    Access, Attenuation, CapIndex, Capability, DenyReason, Op, OpSet, ServiceId, Target, Tick,
};
use crate::host::codec::{Kind, Sender};
use crate::host::probe;
use crate::host::seen;
use crate::host::{InstanceId, MAX_INBOX, MAX_INSTANCES};
use crate::sfs::key::BlobDomain;
use core::num::NonZeroU16;
use hal::serial::write_str;

/// Lifetime of alice's storage capability (1000 s): never reached during the
/// proof, so only `expiry-extend` tests expiry.
const PARENT_TTL: Tick = 100_000;
/// Lifetime of the narrow child.
const CHILD_TTL: Tick = 1_000;

fn now() -> Tick {
    crate::clock::mono_ticks()
}

#[derive(Default)]
struct Verdict {
    narrow: bool,
    wider_prefix: bool,
    sibling_prefix: bool,
    rollback_from_write: bool,
    blobs_widen: bool,
    quota_raise: bool,
    expiry_extend: bool,
    tree_from_live: bool,
    torn_down: bool,
}

impl Verdict {
    fn ok(&self) -> bool {
        self.narrow
            && self.wider_prefix
            && self.sibling_prefix
            && self.rollback_from_write
            && self.blobs_widen
            && self.quota_raise
            && self.expiry_extend
            && self.tree_from_live
            && self.torn_down
    }
}

fn path(p: &[u8]) -> Option<StoragePath> {
    StoragePath::parse(p).ok()
}

fn user1() -> BlobDomain {
    BlobDomain::User(NonZeroU16::MIN)
}

fn blob(b: u8) -> BlobRef {
    BlobRef::new(user1(), [b; REF_HASH_LEN])
}

/// A live-tree attenuation over `prefix`, `blobs` and `quota`.
fn live(prefix: &[u8], blobs: BlobScope, quota: Quota) -> Option<StorageAttenuation> {
    Some(StorageAttenuation {
        tree: Tree::Live,
        prefix: path(prefix)?,
        blobs,
        quota,
    })
}

const PARENT_QUOTA: Quota = Quota {
    bytes: 1 << 20,
    inodes: 64,
    blob_bytes: 64 << 10,
};

const CHILD_QUOTA: Quota = Quota {
    bytes: 4096,
    inodes: 8,
    blob_bytes: 4096,
};

/// Everything the proof needs about alice and bob.
struct World {
    alice: Sender,
    bob: InstanceId,
    bob_slot: usize,
    a_bob: CapIndex,
}

/// The index of a capability in the table of host slot `holder` that targets
/// instance `to` and carries `Send` — found by what it designates, not by
/// manifest position (manifests change order; PR-2b).
fn send_cap_over(
    h: &crate::host::Host<crate::host::native::NativeRuntime>,
    holder: usize,
    to: InstanceId,
) -> Option<CapIndex> {
    (0..MAX_CAPS).find_map(|s| {
        let (e, gen) = h.caps().entry_at(holder, s)?;
        (e.cap.target == Target::Instance(to) && e.cap.ops.contains(Op::Send))
            .then(|| CapIndex::compose(holder, s, gen))
    })
}

/// Run the FS-1c storage-capability proof on the kernel-wide host and print
/// its line.
pub fn prove_storage_caps() {
    let base_count = with_host(|h| h.instance_count());
    seen::seen_reset();
    let mut v = Verdict::default();

    let bob = instantiate(&HOST, &probe::BOB_MANIFEST).ok();
    let alice = instantiate(&HOST, &probe::ALICE_MANIFEST).ok();
    if let (Some(a), Some(b)) = (alice, bob) {
        let world = with_host(|h| {
            Some(World {
                alice: h.sender_at(h.slot_of(a)?)?,
                bob: b,
                bob_slot: h.slot_of(b)?,
                a_bob: send_cap_over(h, h.slot_of(a)?, b)?,
            })
        });
        if let Some(w) = world {
            run(&w, &mut v);
        }
    }

    let mut torn = true;
    for inst in [alice, bob].into_iter().flatten() {
        torn &= terminate(&HOST, inst).is_ok();
    }
    let gone = [alice, bob];
    let clean = with_host(|h| {
        (0..MAX_INSTANCES).all(|t| {
            (0..MAX_CAPS).all(|s| {
                h.caps().entry_at(t, s).is_none_or(|(e, _)| {
                    !matches!(e.cap.target, Target::Service(_))
                        && gone.iter().flatten().all(|&i| !e.cap.target.names(i))
                })
            })
        })
    });
    v.torn_down = torn
        && alice.is_some()
        && bob.is_some()
        && clean
        && with_host(|h| h.instance_count()) == base_count;
    report(&v);
}

fn storage_cap(ops: &[Op], a: StorageAttenuation, expires: Option<Tick>) -> Capability {
    Capability {
        target: Target::Service(ServiceId::Storage),
        ops: OpSet::of(ops),
        attenuation: Attenuation::Storage(a),
        expires,
    }
}

fn run(w: &World, v: &mut Verdict) {
    let (Some(two_blobs), Some(one_blob)) = (
        RefSet::new(&[blob(1), blob(2)]).ok(),
        RefSet::new(&[blob(1)]).ok(),
    ) else {
        return;
    };
    let Some(parent_att) = live(b"/app/foo", BlobScope::RefSet(two_blobs), PARENT_QUOTA) else {
        return;
    };
    let me = w.alice.instance;
    let granted = with_host(|h| {
        let t = now();
        let parent = storage_cap(
            &[Op::Read, Op::Write, Op::Delegate],
            parent_att,
            Some(t.saturating_add(PARENT_TTL)),
        );
        h.grant_service(me, &parent, t)
    });
    let Ok(p) = granted else {
        return;
    };

    // ── Positive control: a strictly narrower child ──
    let Some(narrow_att) = live(b"/app/foo/cache", BlobScope::RefSet(one_blob), CHILD_QUOTA) else {
        return;
    };
    let narrow = Delegation {
        ops: OpSet::of(&[Op::Read]),
        attenuation: Attenuation::Storage(narrow_att),
        ttl: Some(CHILD_TTL),
    };
    let delegated = with_host(|h| h.delegate_from(me, p, w.a_bob, &narrow, now())).is_ok();
    let _ = dispatch(&HOST, w.bob, MAX_INBOX);
    let child = seen::seen_last_for(w.bob).and_then(|s| match s.kind {
        Kind::Grant { granted } if s.from == w.alice && s.cap == w.a_bob => Some(granted),
        _ => None,
    });
    v.narrow = delegated
        && child.is_some_and(|c| {
            let access = |op, p: &[u8], bytes| {
                path(p).map(|p| {
                    Access::Storage(StorageAccess {
                        op,
                        tree: Tree::Live,
                        object: StorageObject::Path(p),
                        bytes,
                    })
                })
            };
            let (Some(inside), Some(sibling), Some(write)) = (
                access(Op::Read, b"/app/foo/cache/model.bin", 0),
                access(Op::Read, b"/app/foobar", 0),
                access(Op::Write, b"/app/foo/cache/x", 1),
            ) else {
                return false;
            };
            with_host(|h| {
                let t = now();
                h.caps().check(w.bob_slot, c, &inside, t).is_ok()
                    && h.caps().check(w.bob_slot, c, &sibling, t) == Err(DenyReason::Attenuation)
                    && h.caps().check(w.bob_slot, c, &write, t) == Err(DenyReason::OpNotAllowed)
            })
        });

    // ── Every amplification refused, and logged ──
    let refused = |d: &Delegation| -> bool {
        let before = with_host(|h| h.deny_totals());
        let r = with_host(|h| h.delegate_from(me, p, w.a_bob, d, now()));
        with_host(|h| {
            let after = h.deny_totals();
            let logged = h
                .deny_len()
                .checked_sub(1)
                .and_then(|i| h.deny_record(i))
                .is_some_and(|rec| {
                    rec.seq + 1 == after.logged
                        && rec.holder == w.alice
                        && rec.index == p
                        && rec.action == Action::Delegate
                        && rec.reason == DenyReason::Amplification
                });
            r == Err(super::BusError::Denied)
                && after.total == before.total + 1
                && after.logged == before.logged + 1
                && logged
        })
    };
    let read_under = |prefix: &[u8], blobs, quota, ttl| {
        live(prefix, blobs, quota).map(|a| Delegation {
            ops: OpSet::of(&[Op::Read]),
            attenuation: Attenuation::Storage(a),
            ttl,
        })
    };
    let none = BlobScope::None;
    let check = |d: Option<Delegation>| d.is_some_and(|d| refused(&d));
    v.wider_prefix = check(read_under(b"/app", none, CHILD_QUOTA, Some(CHILD_TTL)));
    v.sibling_prefix = check(read_under(
        b"/app/foobar",
        none,
        CHILD_QUOTA,
        Some(CHILD_TTL),
    ));
    v.rollback_from_write = check(live(b"/app/foo", none, CHILD_QUOTA).map(|a| Delegation {
        ops: OpSet::of(&[Op::Write, Op::Rollback]),
        attenuation: Attenuation::Storage(a),
        ttl: Some(CHILD_TTL),
    }));
    v.blobs_widen = check(read_under(
        b"/app/foo",
        BlobScope::Domain(user1()),
        CHILD_QUOTA,
        Some(CHILD_TTL),
    ));
    let raised = Quota {
        bytes: PARENT_QUOTA.bytes + 1,
        ..PARENT_QUOTA
    };
    v.quota_raise = check(read_under(b"/app/foo", none, raised, Some(CHILD_TTL)));
    v.expiry_extend = check(read_under(
        b"/app/foo",
        none,
        CHILD_QUOTA,
        Some(2 * PARENT_TTL),
    ));
    v.tree_from_live = check(
        SnapshotName::parse(b"nightly")
            .ok()
            .zip(path(b"/app/foo"))
            .map(|(name, prefix)| Delegation {
                ops: OpSet::of(&[Op::Read]),
                attenuation: Attenuation::Storage(StorageAttenuation {
                    tree: Tree::SnapshotRo(name),
                    prefix,
                    blobs: BlobScope::None,
                    quota: CHILD_QUOTA,
                }),
                ttl: Some(CHILD_TTL),
            }),
    );
}

fn refused_or(b: bool) -> &'static str {
    if b {
        "refused"
    } else {
        "ACCEPTED"
    }
}

fn report(v: &Verdict) {
    write_str("[sfs] cap: narrow=");
    write_str(if v.narrow { "ok" } else { "FAIL" });
    write_str(" wider-prefix=");
    write_str(refused_or(v.wider_prefix));
    write_str(" sibling-prefix=");
    write_str(refused_or(v.sibling_prefix));
    write_str(" rollback-from-write=");
    write_str(refused_or(v.rollback_from_write));
    write_str(" blobs-widen=");
    write_str(refused_or(v.blobs_widen));
    write_str(" quota-raise=");
    write_str(refused_or(v.quota_raise));
    write_str(" expiry-extend=");
    write_str(refused_or(v.expiry_extend));
    write_str(" tree-from-live=");
    write_str(refused_or(v.tree_from_live));
    write_str(if v.ok() { " ok\n" } else { " FAIL\n" });
}
