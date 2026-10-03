//! Host tests for the bus (also run under Miri). Each builds its own host in a
//! local `SpinMutex` cell — never the kernel-wide [`super::HOST`] — so tests
//! running on parallel threads cannot see each other's instances.

use super::*;
use crate::cap::deny::{Action, DenyRecord};
use crate::cap::table::MAX_CAPS;
use crate::cap::{Attenuation, CapIndex, DenyReason, Op, OpSet, Target};
use crate::host::codec::{Envelope, Kind, Sender};
use crate::host::native::{NativeRuntime, BOOT_POLICY, REGISTRY};
use crate::host::probe::{self, Args, ALICE_ID, BOB_ID, CAROL_ID};
use crate::host::{Host, InstanceId, InstantiateError, MAX_INBOX, MAX_INSTANCES};
use hal::sync::SpinMutex;

type Cell = SpinMutex<Host<NativeRuntime>>;

fn fresh() -> Cell {
    SpinMutex::new(Host::new(NativeRuntime::new(REGISTRY), BOOT_POLICY))
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

fn pop(h: &mut Host<NativeRuntime>, inst: InstanceId) -> Option<Envelope> {
    h.pop_for_dispatch(inst).unwrap().map(|(_, e)| e)
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
    let Kind::Request { reply_tag } = rq.kind else {
        panic!("not a request: {:?}", rq.kind)
    };
    let right = h.caps().get(slot(h, w.bob), CapIndex(reply_tag)).unwrap();
    assert_eq!(right.cap.target, Target::Reply { to: w.alice, tag });
    assert_eq!(right.cap.expires, Some(50));

    // Reply: stamped from bob, carrying alice's own tag.
    h.reply_from(w.bob, CapIndex(reply_tag), b"pong", 1)
        .unwrap();
    let rp = pop(h, w.alice).unwrap();
    assert_eq!((rp.from, rp.kind), (bob, Kind::Reply { reply_tag: tag }));
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
    let Kind::Request { reply_tag } = pop(h, w.bob).unwrap().kind else {
        panic!()
    };
    assert!(h.reply_from(w.bob, CapIndex(reply_tag), b"a", 1).is_ok());
    assert_eq!(
        h.reply_from(w.bob, CapIndex(reply_tag), b"again", 1),
        Err(BusError::Denied)
    );
    assert_eq!(last_deny(h).reason, DenyReason::Stale, "one shot");
    assert!(pop(h, w.alice).is_some());
    assert!(pop(h, w.alice).is_none(), "exactly one answer");

    // Timeout: the right expires at now + timeout; nothing arrives.
    h.request_from(w.alice, w.a_bob, b"q", 3, 100).unwrap();
    let Kind::Request { reply_tag } = pop(h, w.bob).unwrap().kind else {
        panic!()
    };
    assert_eq!(
        h.reply_from(w.bob, CapIndex(reply_tag), b"late", 103),
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
    let Kind::Request { reply_tag } = pop(h, w.bob).unwrap().kind else {
        panic!()
    };
    let e = h.caps().get(bs, CapIndex(reply_tag)).unwrap();
    assert_eq!(e.cap.expires, Some(201));
    h.request_from(w.alice, w.a_bob, b"q", u64::MAX, 200)
        .unwrap();
    let Kind::Request { reply_tag } = pop(h, w.bob).unwrap().kind else {
        panic!()
    };
    let e = h.caps().get(bs, CapIndex(reply_tag)).unwrap();
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
    let Kind::Request { reply_tag } = pop(h, w.bob).unwrap().kind else {
        panic!()
    };
    h.reply_from(w.bob, CapIndex(reply_tag), b"a", 1).unwrap();
    assert!(h.request_from(w.alice, w.a_bob, b"q", 100, 1).is_ok());
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
    let Kind::Request { reply_tag } = pop(h, w.bob).unwrap().kind else {
        panic!()
    };
    assert_eq!(
        h.delegate_from(
            w.bob,
            b_bob,
            CapIndex(reply_tag),
            &delegation(&[Op::Send], 8, None),
            0
        ),
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
        assert_eq!(last_deny(&h).reason, DenyReason::TargetGone);
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
        who(InstanceId::KERNEL, CAROL_ID)
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
    let mut out = [0u8; 8];
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
    assert_eq!((n, out[0]), (5, probe::code::OK));
    let tag = u32::from_le_bytes([out[1], out[2], out[3], out[4]]);
    assert_eq!(dispatch(&w.cell, w.bob, MAX_INBOX), Ok(2));
    assert_eq!(dispatch(&w.cell, w.bob, MAX_INBOX), Ok(0));
    let mut g = w.cell.lock();
    let reply = pop(&mut g, w.alice).unwrap();
    assert_eq!(reply.from, who(w.bob, BOB_ID));
    assert_eq!(reply.kind, Kind::Reply { reply_tag: tag });
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
    let mut out = [0u8; 8];
    let n = call(&w.cell, w.bob, "act", Args::granted(0).as_slice(), &mut out).unwrap();
    assert_eq!(
        (n, out[0]),
        (5, probe::code::NONE),
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
    assert!(tag >= 1);
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
