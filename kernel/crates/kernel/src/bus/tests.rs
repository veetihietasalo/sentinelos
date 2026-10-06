//! Host tests for the bus (also run under Miri). Each builds its own host in a
//! local `SpinMutex` cell — never the kernel-wide [`super::HOST`] — so tests
//! running on parallel threads cannot see each other's instances.

use super::*;
use crate::cap::deny::{Action, DenyRecord};
use crate::cap::table::{GEN_MAX, MAX_CAPS};
use crate::cap::{
    Attenuation, CapIndex, CapNeed, CapRequest, Capability, DenyReason, Op, OpSet, Policy,
    PolicyRule, ReplyTag, Route, Target,
};
use crate::host::codec::{Envelope, Kind, Sender};
use crate::host::native::{NativeRuntime, BOOT_POLICY, REGISTRY};
use crate::host::probe::{self, Args, ALICE_ID, BOB_ID, CAROL_ID};
use crate::host::{Host, InstanceId, InstantiateError, Manifest, MAX_INBOX, MAX_INSTANCES};
use hal::sync::SpinMutex;

type Cell = SpinMutex<Host<NativeRuntime>>;

fn fresh() -> Cell {
    SpinMutex::new(Host::new(NativeRuntime::new(REGISTRY), BOOT_POLICY))
}

/// A host granting under `routes` and `rules`.
fn with_policy(routes: &'static [Route], rules: &'static [PolicyRule]) -> Cell {
    SpinMutex::new(Host::new(
        NativeRuntime::new(REGISTRY),
        Policy { routes, rules },
    ))
}

/// `m` with the id its code, params and declarations hash to.
fn honest(m: Manifest) -> Manifest {
    Manifest {
        id: m.derived_id(),
        ..m
    }
}

/// bob (no caps), carol (asked for bob, refused), alice (bob + carol).
struct World {
    cell: Cell,
    alice: InstanceId,
    bob: InstanceId,
    carol: InstanceId,
    a_bob: CapIndex,
    a_carol: CapIndex,
}

fn world() -> World {
    let cell = fresh();
    let bob = instantiate(&cell, &probe::BOB_MANIFEST).unwrap();
    let carol = instantiate(&cell, &probe::CAROL_MANIFEST).unwrap();
    let alice = instantiate(&cell, &probe::ALICE_MANIFEST).unwrap();
    let (a_bob, a_carol) = {
        let h = cell.lock();
        (h.granted(alice, 0).unwrap(), h.granted(alice, 1).unwrap())
    };
    World {
        cell,
        alice,
        bob,
        carol,
        a_bob,
        a_carol,
    }
}

/// Take the next envelope as `dispatch` would, and let its (absent) handler
/// return at once.
fn pop(h: &mut Host<NativeRuntime>, inst: InstanceId) -> Option<Envelope> {
    let next = h.pop_for_dispatch(inst).unwrap().map(|(_, e)| e);
    h.finish_run(inst);
    next
}

fn last_deny(h: &Host<NativeRuntime>) -> DenyRecord {
    h.deny_record(h.deny_len() - 1).unwrap()
}

fn who(inst: InstanceId, component: crate::host::ComponentId) -> Sender {
    Sender {
        instance: inst,
        component,
    }
}

fn slot(h: &Host<NativeRuntime>, inst: InstanceId) -> usize {
    h.slot_of(inst).unwrap()
}

const fn delegation(ops: &[Op], max_len: u16, ttl: Option<Tick>) -> Delegation {
    Delegation {
        ops: OpSet::of(ops),
        attenuation: Attenuation::Message { max_len },
        ttl,
    }
}

#[test]
fn grants_follow_manifest_and_policy() {
    let w = world();
    let h = w.cell.lock();
    assert_eq!(h.cap_count(w.alice), 2);
    assert_eq!(h.cap_count(w.bob), 0);
    assert_eq!(
        h.cap_count(w.carol),
        0,
        "carol asked; the policy has no rule"
    );
    assert_eq!(h.granted(w.carol, 0), None);
    let e = h.caps().get(slot(&h, w.alice), w.a_bob).unwrap();
    assert_eq!(e.cap.target, Target::Instance(w.bob));
    assert_eq!(e.cap.ops, OpSet::of(&[Op::Send, Op::Request, Op::Delegate]));
    // carol's refused request is logged, under her name, as a policy refusal.
    let r = last_deny(&h);
    assert_eq!(r.holder, who(w.carol, CAROL_ID));
    assert_eq!(
        (r.action, r.reason),
        (Action::Grant, DenyReason::PolicyRefused)
    );
}

#[test]
fn from_is_stamped_by_the_host_on_every_kind() {
    let w = world();
    let mut g = w.cell.lock();
    let h = &mut *g;
    let alice = who(w.alice, ALICE_ID);
    let bob = who(w.bob, BOB_ID);
    let carol = who(w.carol, CAROL_ID);

    // Event.
    h.send_from(w.alice, w.a_bob, b"hi", 0).unwrap();
    let e = pop(h, w.bob).unwrap();
    assert_eq!(
        (e.from, e.to, e.cap, e.kind),
        (alice, w.bob, w.a_bob, Kind::Event)
    );
    assert_eq!(e.payload.as_slice(), b"hi");

    // Request: bob is handed a reply right in HIS table as the reply_tag.
    let tag = h.request_from(w.alice, w.a_bob, b"ping", 50, 0).unwrap();
    let rq = pop(h, w.bob).unwrap();
    assert_eq!(rq.from, alice);
    let Kind::Request { reply } = rq.kind else {
        panic!("not a request: {:?}", rq.kind)
    };
    let right = h.caps().get(slot(h, w.bob), reply).unwrap();
    assert_eq!(right.cap.target, Target::Reply { to: w.alice, tag });
    assert_eq!(right.cap.expires, Some(50));

    // Reply: stamped from bob, carrying alice's own tag.
    h.reply_from(w.bob, reply, b"pong", 1).unwrap();
    let rp = pop(h, w.alice).unwrap();
    assert_eq!((rp.from, rp.kind), (bob, Kind::Reply { tag }));
    assert_eq!(rp.payload.as_slice(), b"pong");

    // Delegation notice: stamped from alice, the index is carol's own.
    h.delegate_from(
        w.alice,
        w.a_bob,
        w.a_carol,
        &delegation(&[Op::Send], 16, None),
        0,
    )
    .unwrap();
    let gn = pop(h, w.carol).unwrap();
    assert_eq!((gn.from, gn.cap), (alice, w.a_carol));
    let Kind::Grant { granted } = gn.kind else {
        panic!("not a grant: {:?}", gn.kind)
    };
    let c = h.caps().get(slot(h, w.carol), granted).unwrap();
    assert_eq!(c.cap.target, Target::Instance(w.bob));
    assert_eq!(c.cap.attenuation, Attenuation::Message { max_len: 16 });

    // carol now reaches bob — as carol.
    h.send_from(w.carol, granted, b"via alice", 0).unwrap();
    assert_eq!(pop(h, w.bob).unwrap().from, carol);
}

#[test]
fn deny_by_default_for_an_empty_table() {
    let w = world();
    let mut g = w.cell.lock();
    let h = &mut *g;
    let cs = slot(h, w.carol);
    let before = h.deny_totals().total;
    for idx in [
        CapIndex::KERNEL,
        CapIndex(1),
        CapIndex::compose(cs, 0, 1),
        CapIndex::compose(cs, 15, 99),
    ] {
        assert_eq!(h.send_from(w.carol, idx, b"x", 0), Err(BusError::Denied));
        assert_eq!(last_deny(h).reason, DenyReason::NotHeld);
        assert_eq!(
            h.request_from(w.carol, idx, b"x", 5, 0),
            Err(BusError::Denied)
        );
        assert_eq!(h.reply_from(w.carol, idx, b"x", 0), Err(BusError::Denied));
        assert_eq!(h.revoke_from(w.carol, idx, 0), Err(BusError::Denied));
        assert_eq!(h.release_from(w.carol, idx, 0), Err(BusError::Denied));
    }
    assert_eq!(
        h.deny_totals().total,
        before + 20,
        "every refusal is reported"
    );
    assert_eq!(h.inbox_len(w.bob), Some(0), "nothing was delivered");
    assert_eq!(h.inbox_len(w.alice), Some(0));
}

#[test]
fn forged_indices_are_refused_for_the_right_reason() {
    let w = world();
    let mut g = w.cell.lock();
    let h = &mut *g;
    let cs = slot(h, w.carol);
    // Another instance's index.
    assert_eq!(
        h.send_from(w.carol, w.a_bob, b"x", 0),
        Err(BusError::Denied)
    );
    assert_eq!(last_deny(h).reason, DenyReason::Foreign);
    assert_eq!(
        last_deny(h).index,
        w.a_bob,
        "the presented index is recorded verbatim"
    );

    // Revoked.
    h.delegate_from(
        w.alice,
        w.a_bob,
        w.a_carol,
        &delegation(&[Op::Send], 8, None),
        0,
    )
    .unwrap();
    let Kind::Grant { granted } = pop(h, w.carol).unwrap().kind else {
        panic!()
    };
    assert!(h.send_from(w.carol, granted, b"ok", 0).is_ok());
    assert_eq!(h.revoke_from(w.alice, w.a_bob, 0), Ok(1));
    assert_eq!(
        h.send_from(w.carol, granted, b"x", 0),
        Err(BusError::Denied)
    );
    assert_eq!(last_deny(h).reason, DenyReason::Stale);
    assert_eq!(h.caps().live_count(cs), 0);

    // Expired.
    h.delegate_from(
        w.alice,
        w.a_bob,
        w.a_carol,
        &delegation(&[Op::Send], 8, Some(5)),
        10,
    )
    .unwrap();
    let Kind::Grant { granted } = pop(h, w.carol).unwrap().kind else {
        panic!()
    };
    assert!(h.send_from(w.carol, granted, b"ok", 14).is_ok());
    assert_eq!(
        h.send_from(w.carol, granted, b"x", 15),
        Err(BusError::Denied)
    );
    assert_eq!(last_deny(h).reason, DenyReason::Expired);
    // The payload limit is part of the capability.
    let e2 = {
        h.delegate_from(
            w.alice,
            w.a_bob,
            w.a_carol,
            &delegation(&[Op::Send], 8, None),
            20,
        )
        .unwrap();
        let Kind::Grant { granted } = pop(h, w.carol).unwrap().kind else {
            panic!()
        };
        granted
    };
    assert_eq!(h.send_from(w.carol, e2, &[0; 9], 20), Err(BusError::Denied));
    assert_eq!(last_deny(h).reason, DenyReason::Attenuation);
    // A reply right cannot be used to send, nor an instance capability to reply.
    assert_eq!(
        h.reply_from(w.alice, w.a_bob, b"x", 20),
        Err(BusError::Denied)
    );
    assert_eq!(last_deny(h).reason, DenyReason::OpNotAllowed);
}

#[test]
fn unauthorised_sender_never_sees_busy_and_nothing_is_dropped() {
    let w = world();
    let mut g = w.cell.lock();
    let h = &mut *g;
    for i in 0..MAX_INBOX as u8 {
        h.send_from(w.alice, w.a_bob, &[i], 0).unwrap();
    }
    assert_eq!(
        h.send_from(w.alice, w.a_bob, b"one more", 0),
        Err(BusError::Busy)
    );
    let denials = h.deny_totals().total;
    assert_eq!(
        h.send_from(w.alice, w.a_bob, b"one more", 0),
        Err(BusError::Busy)
    );
    assert_eq!(
        h.deny_totals().total,
        denials,
        "Busy is backpressure, not a denial"
    );
    // carol learns nothing about bob's inbox.
    assert_eq!(
        h.send_from(w.carol, w.a_bob, b"x", 0),
        Err(BusError::Denied)
    );
    for i in 0..MAX_INBOX as u8 {
        assert_eq!(pop(h, w.bob).unwrap().payload.as_slice(), &[i]);
    }
    assert!(pop(h, w.bob).is_none());
}

#[test]
fn replies_are_one_shot_time_out_and_are_never_fabricated() {
    let w = world();
    let mut g = w.cell.lock();
    let h = &mut *g;
    let bs = slot(h, w.bob);

    h.request_from(w.alice, w.a_bob, b"q", 100, 0).unwrap();
    let Kind::Request { reply } = pop(h, w.bob).unwrap().kind else {
        panic!()
    };
    assert!(h.reply_from(w.bob, reply, b"a", 1).is_ok());
    assert_eq!(
        h.reply_from(w.bob, reply, b"again", 1),
        Err(BusError::Denied)
    );
    assert_eq!(last_deny(h).reason, DenyReason::Stale, "one shot");
    assert!(pop(h, w.alice).is_some());
    assert!(pop(h, w.alice).is_none(), "exactly one answer");

    // Timeout: the right expires at now + timeout; nothing arrives.
    h.request_from(w.alice, w.a_bob, b"q", 3, 100).unwrap();
    let Kind::Request { reply } = pop(h, w.bob).unwrap().kind else {
        panic!()
    };
    assert_eq!(
        h.reply_from(w.bob, reply, b"late", 103),
        Err(BusError::Denied)
    );
    assert_eq!(last_deny(h).reason, DenyReason::Expired);
    assert_eq!(
        h.caps().pending_replies(bs),
        0,
        "an expired right is reclaimed"
    );
    assert!(
        pop(h, w.alice).is_none(),
        "silence is denial: no fabricated reply"
    );

    // Timeouts are clamped to 1..=MAX_REPLY_TIMEOUT_TICKS.
    h.request_from(w.alice, w.a_bob, b"q", 0, 200).unwrap();
    let Kind::Request { reply } = pop(h, w.bob).unwrap().kind else {
        panic!()
    };
    let e = h.caps().get(bs, reply).unwrap();
    assert_eq!(e.cap.expires, Some(201));
    h.request_from(w.alice, w.a_bob, b"q", u64::MAX, 200)
        .unwrap();
    let Kind::Request { reply } = pop(h, w.bob).unwrap().kind else {
        panic!()
    };
    let e = h.caps().get(bs, reply).unwrap();
    assert_eq!(e.cap.expires, Some(200 + MAX_REPLY_TIMEOUT_TICKS));
}

#[test]
fn pending_replies_are_capped_per_responder() {
    let w = world();
    let mut g = w.cell.lock();
    let h = &mut *g;
    for _ in 0..MAX_PENDING_REPLIES {
        h.request_from(w.alice, w.a_bob, b"q", 100, 0).unwrap();
    }
    assert_eq!(
        h.request_from(w.alice, w.a_bob, b"q", 100, 0),
        Err(BusError::Busy),
        "the responder's table keeps room for real capabilities"
    );
    assert_eq!(h.inbox_len(w.bob), Some(MAX_PENDING_REPLIES));
    let bs = slot(h, w.bob);
    assert_eq!(h.caps().pending_replies(bs), MAX_PENDING_REPLIES);
    // Answering one frees its right, and the next request fits again.
    let Kind::Request { reply } = pop(h, w.bob).unwrap().kind else {
        panic!()
    };
    h.reply_from(w.bob, reply, b"a", 1).unwrap();
    assert!(h.request_from(w.alice, w.a_bob, b"q", 100, 1).is_ok());
}

#[test]
fn expired_reply_rights_never_lock_a_silent_responder_out() {
    let w = world();
    let mut g = w.cell.lock();
    let h = &mut *g;
    for _ in 0..MAX_PENDING_REPLIES {
        h.request_from(w.alice, w.a_bob, b"q", 1, 0).unwrap(); // bob stays silent
    }
    assert_eq!(
        h.request_from(w.alice, w.a_bob, b"q", 1, 0),
        Err(BusError::Busy)
    );
    assert!(
        h.request_from(w.alice, w.a_bob, b"q", 100, 1).is_ok(),
        "expired rights reclaimed"
    );
}

#[test]
fn an_expired_capability_offered_as_a_reply_right_is_refused_and_kept() {
    let w = world();
    let mut g = w.cell.lock();
    let h = &mut *g;
    let cs = slot(h, w.carol);
    h.delegate_from(
        w.alice,
        w.a_bob,
        w.a_carol,
        &delegation(&[Op::Send], 8, Some(5)),
        0,
    )
    .unwrap();
    let Kind::Grant { granted } = pop(h, w.carol).unwrap().kind else {
        panic!()
    };
    // Expired, and not a reply right: refused as expired, and left alone.
    assert_eq!(
        h.reply_from(w.carol, granted, b"x", 10),
        Err(BusError::Denied)
    );
    assert_eq!(last_deny(h).reason, DenyReason::Expired);
    assert!(
        h.caps().get(cs, granted).is_ok(),
        "only a reply right is reclaimed on use"
    );
    // An expired reply right, by contrast, is reclaimed by the late answer.
    h.request_from(w.alice, w.a_bob, b"q", 2, 0).unwrap();
    let Kind::Request { reply } = pop(h, w.bob).unwrap().kind else {
        panic!()
    };
    let bs = slot(h, w.bob);
    assert_eq!(
        h.reply_from(w.bob, reply, b"late", 2),
        Err(BusError::Denied)
    );
    assert!(h.caps().get(bs, reply).is_err());
}

#[test]
fn a_delegation_dead_on_arrival_is_refused() {
    let w = world();
    let mut g = w.cell.lock();
    let h = &mut *g;
    let cs = slot(h, w.carol);
    assert_eq!(
        h.delegate_from(
            w.alice,
            w.a_bob,
            w.a_carol,
            &delegation(&[Op::Send], 8, Some(0)),
            7
        ),
        Err(BusError::Denied)
    );
    let r = last_deny(h);
    assert_eq!(
        (r.holder, r.action, r.reason),
        (
            who(w.alice, ALICE_ID),
            Action::Delegate,
            DenyReason::Malformed
        )
    );
    assert_eq!(h.caps().live_count(cs), 0, "nothing installed");
    assert_eq!(h.inbox_len(w.carol), Some(0), "nobody notified");
    // Authority is judged first: a delegator without `Delegate` asking for a
    // dead-on-arrival child is logged as not delegable, not as malformed.
    h.delegate_from(
        w.alice,
        w.a_bob,
        w.a_carol,
        &delegation(&[Op::Send], 8, None),
        7,
    )
    .unwrap();
    let Kind::Grant { granted: c_bob } = pop(h, w.carol).unwrap().kind else {
        panic!()
    };
    assert_eq!(
        h.delegate_from(
            w.carol,
            c_bob,
            c_bob,
            &delegation(&[Op::Send], 8, Some(0)),
            7
        ),
        Err(BusError::Denied)
    );
    assert_eq!(last_deny(h).reason, DenyReason::NotDelegable);
    assert_eq!(h.inbox_len(w.bob), Some(0), "nobody notified");
}

#[test]
fn only_an_authorised_delegation_reclaims_a_full_recipient_table() {
    let w = world();
    let mut g = w.cell.lock();
    let h = &mut *g;
    let cs = slot(h, w.carol);
    // Fill carol's table with copies that expire at tick 5.
    for _ in 0..MAX_CAPS {
        h.delegate_from(
            w.alice,
            w.a_bob,
            w.a_carol,
            &delegation(&[Op::Send], 8, Some(5)),
            0,
        )
        .unwrap();
        assert!(pop(h, w.carol).is_some());
    }
    assert_eq!(h.caps().live_count(cs), MAX_CAPS);
    // Later, a refused delegation (a malformed child) changes nothing.
    assert_eq!(
        h.delegate_from(
            w.alice,
            w.a_bob,
            w.a_carol,
            &delegation(&[Op::Send, Op::Reply], 8, None),
            10
        ),
        Err(BusError::Denied)
    );
    assert_eq!(last_deny(h).reason, DenyReason::Malformed);
    assert_eq!(
        h.caps().live_count(cs),
        MAX_CAPS,
        "a refusal reclaims nothing"
    );
    // An authorised one finds the table full, reclaims the expired copies,
    // and is installed on the retry.
    h.delegate_from(
        w.alice,
        w.a_bob,
        w.a_carol,
        &delegation(&[Op::Send], 8, None),
        10,
    )
    .unwrap();
    assert_eq!(h.caps().live_count(cs), 1);
}

#[test]
fn a_delegation_into_a_full_inbox_spends_no_generation() {
    let w = world();
    let mut g = w.cell.lock();
    let h = &mut *g;
    let cs = slot(h, w.carol);
    // Fill carol's inbox with notices she has not read.
    for _ in 0..MAX_INBOX {
        h.delegate_from(
            w.alice,
            w.a_bob,
            w.a_carol,
            &delegation(&[Op::Send], 8, None),
            0,
        )
        .unwrap();
    }
    let gens = |h: &Host<NativeRuntime>| {
        let mut out = [0u64; MAX_CAPS];
        for (s, g) in out.iter_mut().enumerate() {
            *g = h.caps.gen_for_test(cs, s);
        }
        out
    };
    let before = gens(h);
    let live = h.caps().live_count(cs);
    for _ in 0..3 {
        assert_eq!(
            h.delegate_from(
                w.alice,
                w.a_bob,
                w.a_carol,
                &delegation(&[Op::Send], 8, None),
                0
            ),
            Err(BusError::Busy)
        );
    }
    assert_eq!(
        gens(h),
        before,
        "a Busy delegation installs and frees nothing"
    );
    assert_eq!(h.caps().live_count(cs), live);
    assert_eq!(h.inbox_len(w.carol), Some(MAX_INBOX));
    // Authority is still checked first: an amplifying request is refused,
    // not answered Busy.
    assert_eq!(
        h.delegate_from(
            w.alice,
            w.a_bob,
            w.a_carol,
            &delegation(&[Op::Send, Op::Reply], 8, None),
            0
        ),
        Err(BusError::Denied)
    );
    assert_eq!(gens(h), before);
}

#[test]
fn one_instance_never_runs_twice_at_once() {
    let w = world();
    {
        let mut g = w.cell.lock();
        let h = &mut *g;
        h.send_from(w.alice, w.a_bob, b"one", 0).unwrap();
        h.send_from(w.alice, w.a_bob, b"two", 0).unwrap();
        // A delivery in progress (on "another core")...
        assert!(h.pop_for_dispatch(w.bob).unwrap().is_some());
        // ...blocks a second delivery and a kernel call; nothing is taken.
        assert!(matches!(h.pop_for_dispatch(w.bob), Err(CallError::Busy)));
        assert!(matches!(h.prepare_kernel_call(w.bob), Err(CallError::Busy)));
        assert_eq!(h.inbox_len(w.bob), Some(1));
    }
    let mut out = [0u8; probe::ANSWER_LEN];
    assert_eq!(
        call(&w.cell, w.bob, "act", Args::granted(0).as_slice(), &mut out),
        Err(CallError::Busy)
    );
    assert_eq!(dispatch(&w.cell, w.bob, MAX_INBOX), Err(CallError::Busy));
    // Once it returns, both work again — and leave the flag clear.
    w.cell.lock().finish_run(w.bob);
    assert_eq!(dispatch(&w.cell, w.bob, MAX_INBOX), Ok(1));
    assert!(call(&w.cell, w.bob, "act", Args::granted(0).as_slice(), &mut out).is_ok());
    let mut g = w.cell.lock();
    assert!(g.prepare_kernel_call(w.bob).is_ok(), "the flag was cleared");
    // A kernel call in progress blocks a delivery the same way.
    g.send_from(w.alice, w.a_bob, b"three", 0).unwrap();
    assert!(matches!(g.pop_for_dispatch(w.bob), Err(CallError::Busy)));
    g.finish_run(w.bob);
    assert!(g.pop_for_dispatch(w.bob).unwrap().is_some());
    // Finishing for an instance that is gone is harmless.
    g.finish_run(InstanceId(4242));
}

/// Retire every slot of `table` but `keep` (each spent its last generation).
fn retire_all_but(h: &mut Host<NativeRuntime>, table: usize, keep: usize) {
    let c = Capability {
        target: Target::Instance(InstanceId(1)),
        ops: OpSet::of(&[Op::Send]),
        attenuation: Attenuation::Message { max_len: 8 },
        expires: None,
    };
    for s in keep..MAX_CAPS {
        h.caps.set_gen_for_test(table, s, GEN_MAX);
    }
    let mut held = [CapIndex::KERNEL; MAX_CAPS];
    for idx in held.iter_mut() {
        *idx = h.caps.grant(table, &c, &c).unwrap();
    }
    for idx in held {
        h.caps.release(table, idx).unwrap();
    }
    assert_eq!(h.caps.usable_slots(table), keep);
}

#[test]
fn grants_that_do_not_fit_are_refused_before_anything_changes() {
    let cell = fresh();
    let _bob = instantiate(&cell, &probe::BOB_MANIFEST).unwrap();
    let _carol = instantiate(&cell, &probe::CAROL_MANIFEST).unwrap();
    // alice will take host slot 2: no usable slot left in its table.
    retire_all_but(&mut cell.lock(), 2, 0);
    let before = cell.lock().instance_count();
    assert_eq!(
        instantiate(&cell, &probe::ALICE_MANIFEST),
        Err(InstantiateError::MissingRequiredCap)
    );
    {
        let h = cell.lock();
        assert_eq!(h.instance_count(), before);
        let r = last_deny(&h);
        assert_eq!(r.holder, who(InstanceId::KERNEL, ALICE_ID));
        assert_eq!(
            (r.action, r.reason),
            (Action::Grant, DenyReason::MissingRequired)
        );
    }
    // Nothing was claimed, not even an id: the next instance gets the id
    // the refused one would have had (bob is 1, carol 2).
    assert_eq!(
        instantiate(&cell, &probe::BOB_MANIFEST),
        Ok(InstanceId(3)),
        "the refused start consumed no InstanceId"
    );
}

#[test]
fn required_grants_get_the_room_before_optional_ones() {
    // alice's two requests, the optional one listed first. Since PR-2b the
    // order is part of the id: this is another component (its own honest
    // id), which the test policy allows what the boot policy allows alice.
    static OPTIONAL_FIRST: [CapRequest; 2] =
        [probe::ALICE_ASKS_FOR_CAROL, probe::ALICE_ASKS_FOR_BOB];
    const REORDERED_ID: crate::host::ComponentId = crate::host::native::id_literal(
        "4c9d65a46cfa156b65a74e212b93ffe2bf2a7e70ff6f40636b90894723847843",
    );
    static RULES: [PolicyRule; 2] = [
        PolicyRule {
            holder: REORDERED_ID,
            ..probe::POLICY_RULES[0]
        },
        PolicyRule {
            holder: REORDERED_ID,
            ..probe::POLICY_RULES[1]
        },
    ];
    let reordered = Manifest {
        caps: &OPTIONAL_FIRST,
        id: REORDERED_ID,
        ..probe::ALICE_MANIFEST
    };
    assert_eq!(
        honest(reordered).id,
        REORDERED_ID,
        "REORDERED_ID is stale: {:02x?}",
        honest(reordered).id.0
    );
    assert_ne!(reordered.id, ALICE_ID, "the order is in the id");
    let cell = with_policy(probe::POLICY_ROUTES, &RULES);
    let bob = instantiate(&cell, &probe::BOB_MANIFEST).unwrap();
    let _carol = instantiate(&cell, &probe::CAROL_MANIFEST).unwrap();
    // One usable slot: it goes to the required request, not the first one.
    retire_all_but(&mut cell.lock(), 2, 1);
    let alice = instantiate(&cell, &reordered).unwrap();
    let h = cell.lock();
    assert_eq!(h.cap_count(alice), 1);
    assert_eq!(
        h.granted(alice, 0),
        None,
        "the optional request got no room"
    );
    let to_bob = h
        .granted(alice, 1)
        .expect("the required request was granted");
    assert_eq!(
        h.caps().get(slot(&h, alice), to_bob).unwrap().cap.target,
        Target::Instance(bob)
    );
    let r = last_deny(&h);
    assert_eq!(r.holder, who(alice, reordered.id));
    assert_eq!((r.action, r.reason), (Action::Grant, DenyReason::TableFull));
}

#[test]
fn an_optional_grant_without_room_is_logged_as_table_full() {
    let cell = fresh();
    let _bob = instantiate(&cell, &probe::BOB_MANIFEST).unwrap();
    let _carol = instantiate(&cell, &probe::CAROL_MANIFEST).unwrap();
    // Room for alice's required grant, none for her optional one.
    retire_all_but(&mut cell.lock(), 2, 1);
    let alice = instantiate(&cell, &probe::ALICE_MANIFEST).unwrap();
    let h = cell.lock();
    assert_eq!(h.cap_count(alice), 1);
    assert!(h.granted(alice, 0).is_some());
    assert_eq!(h.granted(alice, 1), None);
    let r = last_deny(&h);
    assert_eq!(r.holder, who(alice, ALICE_ID));
    assert_eq!((r.action, r.reason), (Action::Grant, DenyReason::TableFull));
}

#[test]
fn delegation_through_the_bus_never_amplifies() {
    let w = world();
    let mut g = w.cell.lock();
    let h = &mut *g;
    h.delegate_from(
        w.alice,
        w.a_bob,
        w.a_carol,
        &delegation(&[Op::Send, Op::Delegate], 64, None),
        0,
    )
    .unwrap();
    let Kind::Grant { granted: c_bob } = pop(h, w.carol).unwrap().kind else {
        panic!()
    };
    // carol re-delegates via her own capability over bob.
    for (bad, why) in [
        (
            delegation(&[Op::Send, Op::Request], 32, None),
            DenyReason::Amplification,
        ),
        (delegation(&[Op::Send], 65, None), DenyReason::Amplification),
        (delegation(&[], 8, None), DenyReason::Malformed),
    ] {
        assert_eq!(
            h.delegate_from(w.carol, c_bob, c_bob, &bad, 0),
            Err(BusError::Denied)
        );
        assert_eq!(last_deny(h).reason, why);
    }
    assert_eq!(
        h.inbox_len(w.bob),
        Some(0),
        "a refused delegation notifies no one"
    );
    h.delegate_from(w.carol, c_bob, c_bob, &delegation(&[Op::Send], 32, None), 0)
        .unwrap();
    let Kind::Grant { granted: b_bob } = pop(h, w.bob).unwrap().kind else {
        panic!()
    };
    // bob's copy lacks Delegate.
    assert_eq!(
        h.delegate_from(w.bob, b_bob, b_bob, &delegation(&[Op::Send], 8, None), 0),
        Err(BusError::Denied)
    );
    assert_eq!(last_deny(h).reason, DenyReason::NotDelegable);
    // `via` must reach someone: a reply right is not a way in.
    h.request_from(w.alice, w.a_bob, b"q", 50, 0).unwrap();
    let Kind::Request { reply } = pop(h, w.bob).unwrap().kind else {
        panic!()
    };
    assert_eq!(
        h.delegate_from(w.bob, b_bob, reply, &delegation(&[Op::Send], 8, None), 0),
        Err(BusError::Denied)
    );
    assert_eq!(last_deny(h).reason, DenyReason::OpNotAllowed);
}

#[test]
fn revocation_cascades_through_the_bus() {
    let w = world();
    let mut g = w.cell.lock();
    let h = &mut *g;
    h.delegate_from(
        w.alice,
        w.a_bob,
        w.a_carol,
        &delegation(&[Op::Send, Op::Delegate], 64, None),
        0,
    )
    .unwrap();
    let Kind::Grant { granted: c_bob } = pop(h, w.carol).unwrap().kind else {
        panic!()
    };
    h.delegate_from(w.carol, c_bob, c_bob, &delegation(&[Op::Send], 32, None), 0)
        .unwrap();
    let Kind::Grant { granted: b_bob } = pop(h, w.bob).unwrap().kind else {
        panic!()
    };
    assert_eq!(h.revoke_from(w.alice, w.a_bob, 0), Ok(2));
    for (holder, idx) in [(w.carol, c_bob), (w.bob, b_bob)] {
        assert_eq!(h.send_from(holder, idx, b"x", 0), Err(BusError::Denied));
        assert_eq!(last_deny(h).reason, DenyReason::Stale);
    }
    assert!(h.send_from(w.alice, w.a_bob, b"root kept", 0).is_ok());
    assert_eq!(h.release_from(w.alice, w.a_bob, 0), Ok(()));
    assert_eq!(
        h.send_from(w.alice, w.a_bob, b"x", 0),
        Err(BusError::Denied)
    );
}

#[test]
fn terminate_frees_everything_naming_the_instance() {
    let w = world();
    let mut g = w.cell.lock();
    let h = &mut *g;
    h.delegate_from(
        w.alice,
        w.a_bob,
        w.a_carol,
        &delegation(&[Op::Send], 64, None),
        0,
    )
    .unwrap();
    let Kind::Grant { granted: c_bob } = pop(h, w.carol).unwrap().kind else {
        panic!()
    };
    h.request_from(w.alice, w.a_bob, b"q", 50, 0).unwrap();
    // alice goes: her table, carol's copy (a descendant) and the reply right
    // bob holds towards her are all freed.
    let freed = h.terminate(w.alice).unwrap();
    assert_eq!(freed, 2 + 1 + 1);
    assert_eq!(h.send_from(w.carol, c_bob, b"x", 0), Err(BusError::Denied));
    assert_eq!(last_deny(h).reason, DenyReason::Stale);
    assert_eq!(h.caps().pending_replies(slot(h, w.bob)), 0);
    // A context for the dead instance acts as no one.
    assert_eq!(
        h.send_from(w.alice, w.a_bob, b"x", 0),
        Err(BusError::Denied)
    );
    assert_eq!(last_deny(h).reason, DenyReason::NoSuchSender);
    // Nothing anywhere still names alice.
    for t in 0..MAX_INSTANCES {
        for s in 0..MAX_CAPS {
            if let Some((e, _)) = h.caps().entry_at(t, s) {
                assert!(!e.cap.target.names(w.alice));
            }
        }
    }
    assert_eq!(h.terminate(w.alice), Err(CallError::NoSuchInstance));
}

#[test]
fn required_caps_refuse_to_start_and_optional_refusals_are_logged() {
    // alice requires bob: with no bob alive she does not start.
    let cell = fresh();
    assert_eq!(
        instantiate(&cell, &probe::ALICE_MANIFEST),
        Err(InstantiateError::MissingRequiredCap)
    );
    {
        let h = cell.lock();
        assert_eq!(h.instance_count(), 0);
        let r = last_deny(&h);
        assert_eq!(r.holder, who(InstanceId::KERNEL, ALICE_ID));
        assert_eq!(
            (r.action, r.reason),
            (Action::Grant, DenyReason::MissingRequired)
        );
    }
    // With bob but no carol: the optional request is skipped and logged.
    let bob = instantiate(&cell, &probe::BOB_MANIFEST).unwrap();
    let alice = instantiate(&cell, &probe::ALICE_MANIFEST).unwrap();
    {
        let h = cell.lock();
        assert_eq!(h.cap_count(alice), 1);
        assert!(h.granted(alice, 0).is_some());
        assert_eq!(h.granted(alice, 1), None);
        assert_eq!(last_deny(&h).reason, DenyReason::NoProvider);
        assert_eq!(h.cap_count(bob), 0);
    }
    // carol marking her request required: refused, nothing instantiated.
    let n = cell.lock().instance_count();
    assert_eq!(
        instantiate(&cell, &probe::CAROL_STRICT_MANIFEST),
        Err(InstantiateError::MissingRequiredCap)
    );
    assert_eq!(cell.lock().instance_count(), n);
    assert_eq!(
        last_deny(&cell.lock()).holder,
        who(InstanceId::KERNEL, probe::CAROL_STRICT_ID)
    );
}

#[test]
fn the_denial_log_is_rate_limited_per_holder() {
    let w = world();
    let mut g = w.cell.lock();
    let h = &mut *g;
    let start = h.deny_totals();
    for _ in 0..20 {
        assert_eq!(
            h.send_from(w.carol, CapIndex(77), b"x", 0),
            Err(BusError::Denied)
        );
    }
    let t = h.deny_totals();
    assert_eq!(t.total - start.total, 20);
    assert_eq!(
        t.logged - start.logged,
        u64::from(crate::cap::deny::DENY_BURST)
    );
    assert_eq!(t.suppressed - start.suppressed, 12);
    // alice's budget is her own.
    assert_eq!(
        h.send_from(w.alice, CapIndex(77), b"x", 0),
        Err(BusError::Denied)
    );
    assert_eq!(last_deny(h).holder, who(w.alice, ALICE_ID));
    // One refill period later carol gets a record again, carrying the count.
    // (Buckets reset at instantiation, on the mono clock — 0 on the host.)
    let later = crate::clock::mono_ticks() + crate::cap::deny::DENY_REFILL_TICKS;
    assert_eq!(
        h.send_from(w.carol, CapIndex(77), b"x", later),
        Err(BusError::Denied)
    );
    let r = last_deny(h);
    assert_eq!(
        (r.holder, r.suppressed_before),
        (who(w.carol, CAROL_ID), 12)
    );
    let t = h.deny_totals();
    assert_eq!(t.logged + t.suppressed, t.total);
}

#[test]
fn handlers_and_exports_act_as_their_own_instance() {
    let w = world();
    // alice's own code sends through her Ctx.
    let mut out = [0u8; probe::ANSWER_LEN];
    let n = call(
        &w.cell,
        w.alice,
        "act",
        Args::send(w.a_bob, b"x").as_slice(),
        &mut out,
    )
    .unwrap();
    assert_eq!((n, out[0]), (1, probe::code::OK));
    // ...and bob's handler, dispatched with HIS Ctx, answers a request.
    let n = call(
        &w.cell,
        w.alice,
        "act",
        Args::request(w.a_bob, 10, b"ping").as_slice(),
        &mut out,
    )
    .unwrap();
    assert_eq!((n, out[0]), (probe::ANSWER_LEN, probe::code::OK));
    let mut le = [0u8; 8];
    le.copy_from_slice(&out[1..9]);
    let tag = ReplyTag(u64::from_le_bytes(le));
    assert_eq!(dispatch(&w.cell, w.bob, MAX_INBOX), Ok(2));
    assert_eq!(dispatch(&w.cell, w.bob, MAX_INBOX), Ok(0));
    let mut g = w.cell.lock();
    let reply = pop(&mut g, w.alice).unwrap();
    assert_eq!(reply.from, who(w.bob, BOB_ID));
    assert_eq!(reply.kind, Kind::Reply { tag });
    assert_eq!(reply.payload.as_slice(), b"ack");
    drop(g);
    // carol's code holds nothing and is refused as carol.
    call(
        &w.cell,
        w.carol,
        "act",
        Args::send(w.a_bob, b"x").as_slice(),
        &mut out,
    )
    .unwrap();
    assert_eq!(out[0], probe::code::DENIED);
    assert_eq!(last_deny(&w.cell.lock()).holder, who(w.carol, CAROL_ID));
    assert_eq!(
        dispatch(&w.cell, InstanceId(99), 1),
        Err(CallError::NoSuchInstance)
    );
}

#[test]
fn kernel_calls_are_not_starved_by_a_full_inbox() {
    let w = world();
    {
        let mut g = w.cell.lock();
        for _ in 0..MAX_INBOX {
            g.send_from(w.alice, w.a_bob, b"flood", 0).unwrap();
        }
    }
    let mut out = [0u8; probe::ANSWER_LEN];
    let n = call(&w.cell, w.bob, "act", Args::granted(0).as_slice(), &mut out).unwrap();
    assert_eq!(
        (n, out[0]),
        (probe::ANSWER_LEN, probe::code::NONE),
        "bob was granted nothing"
    );
    assert_eq!(w.cell.lock().inbox_len(w.bob), Some(MAX_INBOX), "untouched");
}

#[test]
fn ctx_operations_go_through_the_cell() {
    let w = world();
    let ctx = Ctx {
        cell: &w.cell,
        me: w.alice,
    };
    assert_eq!(ctx.me(), w.alice);
    assert_eq!(ctx.granted(0), Some(w.a_bob));
    assert!(ctx.send(w.a_bob, b"x").is_ok());
    let tag = ctx.request(w.a_bob, b"y", 10).unwrap();
    assert!(tag.0 >= 1);
    assert!(ctx
        .delegate(w.a_bob, w.a_carol, &delegation(&[Op::Send], 8, None))
        .is_ok());
    assert_eq!(ctx.revoke(w.a_bob), Ok(1));
    assert!(ctx.release(w.a_carol).is_ok());
    assert_eq!(ctx.send(w.a_carol, b"z"), Err(BusError::Denied));
    let ghost = Ctx {
        cell: &w.cell,
        me: InstanceId(4242),
    };
    assert_eq!(ghost.send(w.a_bob, b"x"), Err(BusError::Denied));
    assert_eq!(BusError::Busy.label(), "busy");
}

// ── Routing (PR-2b, A12): service → route → provider id → oldest instance ──

/// bob and carol live, then alice, on `cell`.
fn alice_under(cell: Cell) -> (Cell, InstanceId) {
    instantiate(&cell, &probe::BOB_MANIFEST).unwrap();
    instantiate(&cell, &probe::CAROL_MANIFEST).unwrap();
    let alice = instantiate(&cell, &probe::ALICE_MANIFEST).unwrap();
    (cell, alice)
}

#[test]
fn a_request_resolves_service_route_provider_and_oldest_instance() {
    let cell = fresh();
    let bob = instantiate(&cell, &probe::BOB_MANIFEST).unwrap();
    let _younger_bob = instantiate(&cell, &probe::BOB_MANIFEST).unwrap();
    instantiate(&cell, &probe::CAROL_MANIFEST).unwrap();
    let alice = instantiate(&cell, &probe::ALICE_MANIFEST).unwrap();
    let h = cell.lock();
    let to_bob = h.granted(alice, 0).unwrap();
    assert_eq!(
        h.caps().get(slot(&h, alice), to_bob).unwrap().cap.target,
        Target::Instance(bob),
        "the oldest live instance of the routed provider"
    );
}

#[test]
fn an_unrouted_service_is_refused_as_no_route() {
    // carol's code asking, optionally, for a service nothing routes.
    static ASKS: [CapRequest; 1] = [CapRequest {
        target: crate::cap::service_literal("sentinel.probe.nobody/1"),
        ..probe::ALICE_ASKS_FOR_CAROL
    }];
    let m = honest(Manifest {
        caps: &ASKS,
        ..probe::CAROL_MANIFEST
    });
    let cell = fresh();
    instantiate(&cell, &probe::BOB_MANIFEST).unwrap();
    let c = instantiate(&cell, &m).unwrap();
    let h = cell.lock();
    assert_eq!(h.cap_count(c), 0);
    let r = last_deny(&h);
    assert_eq!(r.holder, who(c, m.id));
    assert_eq!((r.action, r.reason), (Action::Grant, DenyReason::NoRoute));
}

#[test]
fn a_route_with_no_live_provider_is_refused_as_no_provider() {
    let cell = fresh();
    instantiate(&cell, &probe::BOB_MANIFEST).unwrap();
    let alice = instantiate(&cell, &probe::ALICE_MANIFEST).unwrap();
    let h = cell.lock();
    assert_eq!(h.granted(alice, 1), None, "carol is not running");
    let r = last_deny(&h);
    assert_eq!(r.holder, who(alice, ALICE_ID));
    assert_eq!(r.reason, DenyReason::NoProvider);
}

#[test]
fn a_route_to_a_provider_that_does_not_provide_the_service_is_not_honoured() {
    // Misrouted: carol's service to bob, whose id-bound manifest provides
    // only his own (threat T-ROUTE-1).
    static MISROUTED: [Route; 2] = [
        Route {
            service: probe::BOB_SERVICE,
            provider: BOB_ID,
        },
        Route {
            service: probe::CAROL_SERVICE,
            provider: BOB_ID,
        },
    ];
    let (cell, alice) = alice_under(with_policy(&MISROUTED, probe::POLICY_RULES));
    let h = cell.lock();
    assert!(
        h.granted(alice, 0).is_some(),
        "bob's own service still routes"
    );
    assert_eq!(h.granted(alice, 1), None);
    assert_eq!(h.cap_count(alice), 1);
    let r = last_deny(&h);
    assert_eq!(r.holder, who(alice, ALICE_ID));
    assert_eq!(r.reason, DenyReason::NotProvided);
}

#[test]
fn a_service_routed_twice_routes_nowhere() {
    static TWICE: [Route; 3] = [
        Route {
            service: probe::BOB_SERVICE,
            provider: BOB_ID,
        },
        Route {
            service: probe::CAROL_SERVICE,
            provider: CAROL_ID,
        },
        Route {
            service: probe::CAROL_SERVICE,
            provider: BOB_ID,
        },
    ];
    let (cell, alice) = alice_under(with_policy(&TWICE, probe::POLICY_RULES));
    let h = cell.lock();
    assert_eq!(h.granted(alice, 1), None);
    assert_eq!(last_deny(&h).reason, DenyReason::NoRoute);
}

#[test]
fn a_service_the_holders_rules_do_not_name_is_refused_as_policy_refused() {
    // Routed, provider live and providing — but alice's only rule is for bob.
    static ONLY_BOB: [PolicyRule; 1] = [probe::POLICY_RULES[0]];
    let (cell, alice) = alice_under(with_policy(probe::POLICY_ROUTES, &ONLY_BOB));
    let h = cell.lock();
    assert_eq!(h.granted(alice, 1), None);
    let r = last_deny(&h);
    assert_eq!(r.holder, who(alice, ALICE_ID));
    assert_eq!(r.reason, DenyReason::PolicyRefused);
}

#[test]
fn claiming_a_service_does_not_capture_its_route() {
    // bob's code, claiming carol's service as well: another id, and the route
    // names carol's id — so the squatter is never her service's provider.
    static SQUAT: [crate::cap::ServiceName; 2] = [probe::BOB_SERVICE, probe::CAROL_SERVICE];
    let squatter = honest(Manifest {
        provides: &SQUAT,
        ..probe::BOB_MANIFEST
    });
    assert_ne!(squatter.id, BOB_ID);
    let cell = fresh();
    instantiate(&cell, &probe::BOB_MANIFEST).unwrap();
    let sq = instantiate(&cell, &squatter).unwrap();
    let alice = instantiate(&cell, &probe::ALICE_MANIFEST).unwrap();
    let h = cell.lock();
    assert_eq!(h.granted(alice, 1), None);
    assert_eq!(last_deny(&h).reason, DenyReason::NoProvider);
    let a = slot(&h, alice);
    assert!(
        (0..MAX_CAPS).all(|s| h
            .caps()
            .entry_at(a, s)
            .is_none_or(|(e, _)| !e.cap.target.names(sq))),
        "nothing alice holds reaches the squatter"
    );
}

#[test]
fn an_edited_manifest_is_refused_before_anything_runs() {
    // alice's id with each declaration edit the boot proof makes.
    static STRIPPED: [CapRequest; 2] = [
        CapRequest {
            need: CapNeed::Optional,
            ..probe::ALICE_ASKS_FOR_BOB
        },
        probe::ALICE_ASKS_FOR_CAROL,
    ];
    static SWAPPED: [CapRequest; 2] = [probe::ALICE_ASKS_FOR_CAROL, probe::ALICE_ASKS_FOR_BOB];
    static OP_ADDED: [CapRequest; 2] = [
        probe::ALICE_ASKS_FOR_BOB,
        CapRequest {
            ops: OpSet::of(&[Op::Send, Op::Request]),
            ..probe::ALICE_ASKS_FOR_CAROL
        },
    ];
    static DROPPED: [CapRequest; 1] = [probe::ALICE_ASKS_FOR_BOB];
    let cell = fresh();
    instantiate(&cell, &probe::BOB_MANIFEST).unwrap();
    instantiate(&cell, &probe::CAROL_MANIFEST).unwrap();
    let before = {
        let h = cell.lock();
        (h.instance_count(), h.deny_totals().total)
    };
    for caps in [&STRIPPED[..], &SWAPPED[..], &OP_ADDED[..], &DROPPED[..]] {
        let m = Manifest {
            caps,
            ..probe::ALICE_MANIFEST
        };
        assert_eq!(m.verify().err(), Some(InstantiateError::IdMismatch));
        assert_eq!(instantiate(&cell, &m), Err(InstantiateError::IdMismatch));
    }
    let h = cell.lock();
    assert_eq!(
        (h.instance_count(), h.deny_totals().total),
        before,
        "no instance, and no grant was even planned"
    );
}

/// The record just before the newest.
fn second_last_deny(h: &Host<NativeRuntime>) -> DenyRecord {
    h.deny_record(h.deny_len() - 2).unwrap()
}

/// alice's required bob request refused for `cause`: no start, and the log
/// says why (the precise cause, then `missing-required`), both as alice.
fn assert_required_refused_for(cell: &Cell, cause: DenyReason) {
    let before = cell.lock().deny_totals().total;
    let n = cell.lock().instance_count();
    assert_eq!(
        instantiate(cell, &probe::ALICE_MANIFEST),
        Err(InstantiateError::MissingRequiredCap)
    );
    let h = cell.lock();
    assert_eq!(h.instance_count(), n, "nothing started");
    assert_eq!(
        h.deny_totals().total,
        before + 2,
        "cause and missing-required"
    );
    let unborn = who(InstanceId::KERNEL, ALICE_ID);
    let first = second_last_deny(&h);
    let last = last_deny(&h);
    assert_eq!(
        (first.holder, first.action, first.reason),
        (unborn, Action::Grant, cause)
    );
    assert_eq!(
        (last.holder, last.action, last.reason),
        (unborn, Action::Grant, DenyReason::MissingRequired)
    );
}

#[test]
fn a_required_request_refused_by_no_route_logs_the_cause() {
    // Only carol's service is routed; alice requires bob's.
    static ONLY_CAROL: [Route; 1] = [Route {
        service: probe::CAROL_SERVICE,
        provider: CAROL_ID,
    }];
    let cell = with_policy(&ONLY_CAROL, probe::POLICY_RULES);
    instantiate(&cell, &probe::BOB_MANIFEST).unwrap();
    instantiate(&cell, &probe::CAROL_MANIFEST).unwrap();
    assert_required_refused_for(&cell, DenyReason::NoRoute);
}

#[test]
fn a_required_request_refused_by_not_provided_logs_the_cause() {
    // bob's service misrouted to carol, whose id-bound manifest does not
    // provide it.
    static MISROUTED: [Route; 2] = [
        Route {
            service: probe::BOB_SERVICE,
            provider: CAROL_ID,
        },
        Route {
            service: probe::CAROL_SERVICE,
            provider: CAROL_ID,
        },
    ];
    let cell = with_policy(&MISROUTED, probe::POLICY_RULES);
    instantiate(&cell, &probe::BOB_MANIFEST).unwrap();
    instantiate(&cell, &probe::CAROL_MANIFEST).unwrap();
    assert_required_refused_for(&cell, DenyReason::NotProvided);
}

#[test]
fn a_required_request_refused_by_the_policy_logs_the_cause() {
    // Routed and provided, but the allow-list names only carol's service.
    static ONLY_CAROL_RULE: [PolicyRule; 1] = [probe::POLICY_RULES[1]];
    let cell = with_policy(probe::POLICY_ROUTES, &ONLY_CAROL_RULE);
    instantiate(&cell, &probe::BOB_MANIFEST).unwrap();
    instantiate(&cell, &probe::CAROL_MANIFEST).unwrap();
    assert_required_refused_for(&cell, DenyReason::PolicyRefused);
}

#[test]
fn a_restarted_provider_is_bound_by_a_new_holder() {
    let cell = fresh();
    let old_bob = instantiate(&cell, &probe::BOB_MANIFEST).unwrap();
    instantiate(&cell, &probe::CAROL_MANIFEST).unwrap();
    let old_alice = instantiate(&cell, &probe::ALICE_MANIFEST).unwrap();
    // bob restarts: everything naming the old instance goes with it.
    terminate(&cell, old_bob).unwrap();
    let new_bob = instantiate(&cell, &probe::BOB_MANIFEST).unwrap();
    assert_ne!(new_bob, old_bob);
    {
        let h = cell.lock();
        let stale = h.granted(old_alice, 0).unwrap();
        assert!(
            h.caps().get(slot(&h, old_alice), stale).is_err(),
            "the old alice's grant died with the old bob (no rebind, §18.7)"
        );
    }
    // A new alice resolves the same route to the same id — the new instance.
    terminate(&cell, old_alice).unwrap();
    let alice = instantiate(&cell, &probe::ALICE_MANIFEST).unwrap();
    let h = cell.lock();
    let to_bob = h.granted(alice, 0).expect("bound again");
    assert_eq!(
        h.caps().get(slot(&h, alice), to_bob).unwrap().cap.target,
        Target::Instance(new_bob)
    );
}

#[test]
fn a_meaningless_request_is_refused_before_hashing() {
    let bad_requests: [CapRequest; 4] = [
        // No operation.
        CapRequest {
            ops: OpSet::EMPTY,
            ..probe::ALICE_ASKS_FOR_BOB
        },
        // An undefined bit (FS-1c's reserved bit 8, not defined yet).
        CapRequest {
            ops: OpSet::from_bits(Op::Send.bit() | (1 << 8)),
            ..probe::ALICE_ASKS_FOR_BOB
        },
        // A bit far outside anything named.
        CapRequest {
            ops: OpSet::from_bits(1 << 31),
            ..probe::ALICE_ASKS_FOR_BOB
        },
        // An attenuation that never fits.
        CapRequest {
            attenuation: Attenuation::Message {
                max_len: (crate::host::codec::MAX_PAYLOAD + 1) as u16,
            },
            ..probe::ALICE_ASKS_FOR_BOB
        },
    ];
    for bad in bad_requests {
        assert!(!bad.is_meaningful());
    }
    assert!(probe::ALICE_ASKS_FOR_BOB.is_meaningful());
    static NO_OPS: [CapRequest; 1] = [CapRequest {
        ops: OpSet::EMPTY,
        ..probe::ALICE_ASKS_FOR_BOB
    }];
    static UNDEFINED_BIT: [CapRequest; 1] = [CapRequest {
        ops: OpSet::from_bits(1 << 8),
        ..probe::ALICE_ASKS_FOR_BOB
    }];
    static TOO_LONG: [CapRequest; 1] = [CapRequest {
        attenuation: Attenuation::Message { max_len: u16::MAX },
        ..probe::ALICE_ASKS_FOR_BOB
    }];
    let cell = fresh();
    for caps in [&NO_OPS[..], &UNDEFINED_BIT[..], &TOO_LONG[..]] {
        // Even with an honest id for exactly these declarations.
        let m = honest(Manifest {
            caps,
            ..probe::ALICE_MANIFEST
        });
        assert_eq!(m.verify().err(), Some(InstantiateError::MalformedRequest));
        assert_eq!(
            instantiate(&cell, &m),
            Err(InstantiateError::MalformedRequest)
        );
    }
    assert_eq!(cell.lock().instance_count(), 0);
    assert_eq!(
        InstantiateError::MalformedRequest.label(),
        "malformed-request"
    );
}
