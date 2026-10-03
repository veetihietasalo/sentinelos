//! Boot proof for component-model PR-2 (spec §14), on the kernel-wide host.
//!
//! Three first-party probe components (`crate::host::probe`): **alice** holds
//! a `Send`/`Request`/`Delegate` capability over **bob**; **carol** asked for
//! one and the policy refused, so she holds none. Every bus operation below is
//! performed by the component's **own code** through its own `Ctx` (the `act`
//! export); the kernel only drives, and then reads what the recipients saw and
//! what the denial log recorded.
//!
//! ```text
//! [cap] attested-from=yes deny-by-default=yes forge-attempt=refused denies-logged=N ok
//! ```
//!
//! - `attested-from` — every envelope a recipient was handed (an event, a
//!   request, a reply, three delegation notices, a delegated send) carries the
//!   `from` of the instance that acted — instance id **and** component id,
//!   from the host's record — and a one-shot reply right answers once.
//! - `deny-by-default` — carol, with an empty table, is refused `send` and
//!   `request`, nothing reaches anyone, and her refused grant was logged.
//! - `forge-attempt=refused` — an index never issued in your table, another
//!   instance's index, a revoked capability (and its grandchild in a third
//!   table: the cascade), an expired one, a payload beyond the capability's
//!   attenuation, two amplifying delegations, and an answer after the
//!   requester's timeout: each refused **for the right reason** (checked in
//!   the log), each after a positive control that the same path works with an
//!   honest capability. The late answer arrives nowhere: silence is denial.
//! - `denies-logged=N` — records written during the proof. The proof also
//!   requires the A8 rules: a required capability that cannot be granted
//!   refuses the start; every refusal is counted (`logged + suppressed ==
//!   total`, and the total is exactly the number of refusals provoked); a
//!   burst beyond carol's budget is suppressed, not lost.
//!
//! `ok` additionally requires that the three instances are terminated and
//! nothing names them afterwards. The `[cap] measure:` line (spec §18.4) is
//! informational and never asserted.

use super::{call, dispatch, instantiate, terminate, with_host, HOST};
use crate::cap::deny::{Action, DenyRecord, DenyTotals};
use crate::cap::table::{GEN_MAX, MAX_CAPS};
use crate::cap::{CapIndex, DenyReason, Op, OpSet, Tick};
use crate::host::codec::{Kind, Sender};
use crate::host::probe::{self, code, Args, ALICE_ID, BOB_ID, CAROL_ID, QUIET};
use crate::host::{InstanceId, InstantiateError, MAX_INBOX, MAX_INSTANCES};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use hal::serial::{write_dec, write_str};

/// Lifetime of the delegation the expiry probe uses (80 ms): long enough that
/// the in-time control send cannot miss it on a slow TCG host.
const EXPIRY_TTL: u32 = 8;
/// Timeout of the request bob leaves unanswered.
const REPLY_TTL: u32 = 4;
/// Upper bound on spin iterations while waiting for the clock (seconds even
/// under TCG): a broken clock fails the proof instead of hanging the boot.
const WAIT_SPIN_CAP: u64 = 200_000_000;
/// Refusals in the rate-limit burst.
const BURST: u32 = 6;
/// Window, in mono ticks, of each §18.4 measurement.
const MEASURE_TICKS: Tick = 5;
/// Iteration cap of each measurement loop.
const MEASURE_CAP: u64 = 1_000_000;

/// What a probe's `act` reported back.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Outcome {
    Done(u32),
    Denied,
    Busy,
    Nothing,
    Broken,
}

fn act(inst: InstanceId, args: &Args) -> Outcome {
    let mut out = [0u8; 8];
    match call(&HOST, inst, "act", args.as_slice(), &mut out) {
        Ok(n) if n >= 1 => {
            let v = if n >= 5 {
                u32::from_le_bytes([out[1], out[2], out[3], out[4]])
            } else {
                0
            };
            match out[0] {
                code::OK => Outcome::Done(v),
                code::DENIED => Outcome::Denied,
                code::BUSY => Outcome::Busy,
                code::NONE => Outcome::Nothing,
                _ => Outcome::Broken,
            }
        }
        _ => Outcome::Broken,
    }
}

fn done(o: Outcome) -> bool {
    matches!(o, Outcome::Done(_))
}

fn deliver(inst: InstanceId) {
    let _ = dispatch(&HOST, inst, MAX_INBOX);
}

fn totals() -> DenyTotals {
    with_host(|h| h.deny_totals())
}

fn newest_record() -> Option<DenyRecord> {
    with_host(|h| h.deny_len().checked_sub(1).and_then(|i| h.deny_record(i)))
}

/// Counts every refusal the proof provokes and checks each was logged.
struct DenyWatch {
    total: u64,
    expected: u64,
}

impl DenyWatch {
    fn new() -> Self {
        Self {
            total: totals().total,
            expected: 0,
        }
    }

    /// `o` was a refusal, reported exactly once, and the record just written
    /// names `who` (instance and component), `action` and `reason`.
    fn refused(&mut self, o: Outcome, who: Sender, action: Action, reason: DenyReason) -> bool {
        self.expected += 1;
        let t = totals();
        let one = t.total == self.total + 1;
        self.total = t.total;
        let logged = newest_record().is_some_and(|r| {
            r.seq + 1 == t.logged && r.holder == who && r.action == action && r.reason == reason
        });
        o == Outcome::Denied && one && logged
    }

    /// A refusal at instantiation (no `Outcome`): reported once, logged as
    /// `holder`/`reason`.
    fn refused_at_start(&mut self, holder: Sender, reason: DenyReason) -> bool {
        self.expected += 1;
        let t = totals();
        let one = t.total == self.total + 1;
        self.total = t.total;
        one && newest_record().is_some_and(|r| {
            r.seq + 1 == t.logged
                && r.holder == holder
                && r.action == Action::Grant
                && r.reason == reason
        })
    }

    /// `n` refusals the rate limit may suppress: counted, not checked per record.
    fn burst(&mut self, n: u64) {
        self.expected += n;
        self.total = totals().total;
    }
}

/// Spin, interrupts open, until the mono clock reaches `deadline`.
fn wait_until(deadline: Tick) -> bool {
    let were_enabled = hal::cpu::interrupts_enabled();
    hal::cpu::enable_interrupts();
    let mut spins: u64 = 0;
    while crate::clock::mono_ticks() < deadline && spins < WAIT_SPIN_CAP {
        core::hint::spin_loop();
        spins += 1;
    }
    if !were_enabled {
        hal::cpu::disable_interrupts();
    }
    crate::clock::mono_ticks() >= deadline
}

/// The index of the capability a kernel-stamped `Grant` notice handed `at`,
/// if the newest envelope it saw is one from `from` over `via`.
fn grant_notice(at: InstanceId, from: Sender, via: CapIndex) -> Option<CapIndex> {
    let s = probe::seen_last_for(at)?;
    match s.kind {
        Kind::Grant { granted } if s.from == from && s.cap == via => Some(granted),
        _ => None,
    }
}

/// The expiry of `idx` in the table of the instance in `slot`.
fn expiry_of(slot: usize, idx: CapIndex) -> Option<Tick> {
    with_host(|h| h.caps().get(slot, idx).ok()?.cap.expires)
}

#[derive(Default)]
struct Verdict {
    counts: (usize, usize, usize),
    grants: bool,
    strict_refused: bool,
    attested: bool,
    deny_by_default: bool,
    not_held: bool,
    foreign: bool,
    revoked: bool,
    cascade: bool,
    expired: bool,
    amplify: bool,
    attenuation: bool,
    reply_once: bool,
    reply_late: bool,
    silence: bool,
    rate_limited: bool,
    accounted: bool,
    torn_down: bool,
    actor_deliveries: u64,
    task_roundtrips: u64,
}

impl Verdict {
    fn forge_refused(&self) -> bool {
        self.not_held
            && self.foreign
            && self.revoked
            && self.cascade
            && self.expired
            && self.amplify
            && self.attenuation
            && self.reply_late
            && self.silence
    }

    fn ok(&self) -> bool {
        self.grants
            && self.strict_refused
            && self.attested
            && self.reply_once
            && self.deny_by_default
            && self.forge_refused()
            && self.rate_limited
            && self.accounted
            && self.torn_down
    }
}

struct World {
    alice: Sender,
    bob: Sender,
    carol: Sender,
    bob_slot: usize,
    carol_slot: usize,
    a_bob: CapIndex,
    a_carol: CapIndex,
}

/// Run the PR-2 capability proof on the kernel-wide host and print its lines.
pub fn prove_caps() {
    let base_count = with_host(|h| h.instance_count());
    let base = totals();
    probe::seen_reset();
    let mut watch = DenyWatch::new();
    let mut v = Verdict::default();

    let bob = instantiate(&HOST, &probe::BOB_MANIFEST).ok();
    let carol = instantiate(&HOST, &probe::CAROL_MANIFEST).ok();
    // carol asked for bob; the boot policy has no rule: logged as hers.
    let carol_refusal = carol.is_some_and(|c| {
        watch.refused_at_start(
            Sender {
                instance: c,
                component: CAROL_ID,
            },
            DenyReason::PolicyRefused,
        )
    });
    let alice = instantiate(&HOST, &probe::ALICE_MANIFEST).ok();

    if let (Some(a), Some(b), Some(c)) = (alice, bob, carol) {
        let world = with_host(|h| {
            Some(World {
                alice: h.sender_at(h.slot_of(a)?)?,
                bob: h.sender_at(h.slot_of(b)?)?,
                carol: h.sender_at(h.slot_of(c)?)?,
                bob_slot: h.slot_of(b)?,
                carol_slot: h.slot_of(c)?,
                a_bob: h.granted(a, 0)?,
                a_carol: h.granted(a, 1)?,
            })
        });
        if let Some(w) = world {
            run(&w, &mut watch, &mut v, carol_refusal);
        }
    }

    // Leave the kernel-wide host as we found it: nothing may name the three.
    let mut torn = true;
    for inst in [alice, bob, carol].into_iter().flatten() {
        torn &= terminate(&HOST, inst).is_ok();
    }
    let gone = [alice, bob, carol];
    let nothing_names_them = with_host(|h| {
        (0..MAX_INSTANCES).all(|t| {
            (0..MAX_CAPS).all(|s| {
                h.caps()
                    .entry_at(t, s)
                    .is_none_or(|(e, _)| gone.iter().flatten().all(|&i| !e.cap.target.names(i)))
            })
        })
    });
    v.torn_down = torn
        && alice.is_some()
        && nothing_names_them
        && with_host(|h| h.instance_count()) == base_count;

    let end = totals();
    v.accounted =
        end.total - base.total == watch.expected && end.logged + end.suppressed == end.total;
    report(&v, base, end);
}

fn run(w: &World, watch: &mut DenyWatch, v: &mut Verdict, carol_refusal: bool) {
    // ── Grants: manifest ∧ policy; a required cap missing refuses the start ──
    let counts = with_host(|h| {
        (
            h.cap_count(w.alice.instance),
            h.cap_count(w.bob.instance),
            h.cap_count(w.carol.instance),
        )
    });
    v.counts = counts;
    v.grants = counts == (2, 0, 0) && carol_refusal;
    let before = with_host(|h| h.instance_count());
    let strict = instantiate(&HOST, &probe::CAROL_STRICT_MANIFEST);
    v.strict_refused = strict == Err(InstantiateError::MissingRequiredCap)
        && with_host(|h| h.instance_count()) == before
        && watch.refused_at_start(
            Sender {
                instance: InstanceId::KERNEL,
                component: CAROL_ID,
            },
            DenyReason::MissingRequired,
        );

    // ── attested-from: each recipient sees who acted, as the host knows it ──
    let sent = done(act(w.alice.instance, &Args::send(w.a_bob, b"hello bob")));
    deliver(w.bob.instance);
    let event = probe::seen_last_for(w.bob.instance)
        .is_some_and(|s| s.from == w.alice && s.kind == Kind::Event && s.cap == w.a_bob);

    let tag = match act(w.alice.instance, &Args::request(w.a_bob, 100, b"ping")) {
        Outcome::Done(t) => Some(t),
        _ => None,
    };
    deliver(w.bob.instance);
    let at_bob = probe::seen_last_for(w.bob.instance);
    let request = at_bob.is_some_and(|s| s.from == w.alice && s.answered == Some(true));
    let reply_right = match at_bob.map(|s| s.kind) {
        Some(Kind::Request { reply_tag }) => Some(CapIndex(reply_tag)),
        _ => None,
    };
    deliver(w.alice.instance);
    let reply = tag.is_some_and(|t| {
        probe::seen_last_for(w.alice.instance)
            .is_some_and(|s| s.from == w.bob && s.kind == (Kind::Reply { reply_tag: t }))
    });
    // One shot: the same right a second time is stale.
    v.reply_once = reply_right.is_some_and(|r| {
        watch.refused(
            act(w.bob.instance, &Args::reply(r, b"again")),
            w.bob,
            Action::Reply,
            DenyReason::Stale,
        )
    });
    // The identities stamped are the ones the manifests claimed and the host
    // verified — not merely whatever the host's record says.
    let identities =
        w.alice.component == ALICE_ID && w.bob.component == BOB_ID && w.carol.component == CAROL_ID;
    let mut attested = identities && sent && event && tag.is_some() && request && reply;

    // ── deny-by-default: carol holds nothing ──
    let bob_queue = with_host(|h| h.inbox_len(w.bob.instance));
    // Well formed for her own table, never issued: a generation no slot has
    // reached, whatever the slot's history.
    let never_issued = CapIndex::compose(w.carol_slot, 0, GEN_MAX);
    let d_send = watch.refused(
        act(w.carol.instance, &Args::send(never_issued, b"let me in")),
        w.carol,
        Action::Send,
        DenyReason::NotHeld,
    );
    let d_request = watch.refused(
        act(w.carol.instance, &Args::request(CapIndex::KERNEL, 10, b"?")),
        w.carol,
        Action::Request,
        DenyReason::NotHeld,
    );
    let nothing_moved = with_host(|h| {
        h.inbox_len(w.bob.instance) == bob_queue
            && h.inbox_len(w.alice.instance) == Some(0)
            && h.cap_count(w.carol.instance) == 0
    });
    v.deny_by_default = d_send && d_request && nothing_moved && carol_refusal;
    // An index that is well formed for her own table but was never issued.
    v.not_held = d_send;

    // ── forge attempts ──
    // Another instance's index (an index is not a secret; it is just a number).
    v.foreign = watch.refused(
        act(w.carol.instance, &Args::send(w.a_bob, b"stolen")),
        w.carol,
        Action::Send,
        DenyReason::Foreign,
    );

    // Revocation and its cascade. alice → carol (send + delegate, ≤ 64 B);
    // carol uses it (control) and passes an attenuated copy to bob.
    let send_delegate = OpSet::of(&[Op::Send, Op::Delegate]);
    let send_only = OpSet::of(&[Op::Send]);
    let delegated = done(act(
        w.alice.instance,
        &Args::delegate(w.a_bob, w.a_carol, send_delegate, 64, 0),
    ));
    deliver(w.carol.instance);
    let c_bob = grant_notice(w.carol.instance, w.alice, w.a_carol);
    if let Some(c_bob) = c_bob {
        let control = done(act(w.carol.instance, &Args::send(c_bob, b"via alice")));
        deliver(w.bob.instance);
        let control_seen = probe::seen_last_for(w.bob.instance)
            .is_some_and(|s| s.from == w.carol && s.cap == c_bob);
        let redelegated = done(act(
            w.carol.instance,
            &Args::delegate(c_bob, c_bob, send_only, 32, 0),
        ));
        deliver(w.bob.instance);
        let b_bob = grant_notice(w.bob.instance, w.carol, c_bob);
        attested &= delegated && control && control_seen && redelegated && b_bob.is_some();

        // Never amplifies: more ops, a looser payload limit.
        let more_ops = watch.refused(
            act(
                w.carol.instance,
                &Args::delegate(c_bob, c_bob, OpSet::of(&[Op::Send, Op::Request]), 32, 0),
            ),
            w.carol,
            Action::Delegate,
            DenyReason::Amplification,
        );
        let looser = watch.refused(
            act(
                w.carol.instance,
                &Args::delegate(c_bob, c_bob, send_only, 128, 0),
            ),
            w.carol,
            Action::Delegate,
            DenyReason::Amplification,
        );
        v.amplify = more_ops && looser;
        v.attenuation = watch.refused(
            act(w.carol.instance, &Args::send(c_bob, &[0x55; 100])),
            w.carol,
            Action::Send,
            DenyReason::Attenuation,
        );

        let revoked = matches!(
            act(w.alice.instance, &Args::revoke(w.a_bob)),
            Outcome::Done(2)
        );
        v.revoked = revoked
            && watch.refused(
                act(w.carol.instance, &Args::send(c_bob, b"still?")),
                w.carol,
                Action::Send,
                DenyReason::Stale,
            );
        v.cascade = b_bob.is_some_and(|b| {
            watch.refused(
                act(w.bob.instance, &Args::send(b, b"me too?")),
                w.bob,
                Action::Send,
                DenyReason::Stale,
            )
        });
        // Revoke keeps the root: alice still reaches bob.
        v.revoked &= done(act(w.alice.instance, &Args::send(w.a_bob, b"root kept")));
        deliver(w.bob.instance);
    } else {
        attested = false;
    }

    // Expiry on the mono clock.
    let expiring = done(act(
        w.alice.instance,
        &Args::delegate(w.a_bob, w.a_carol, send_only, 64, EXPIRY_TTL),
    ));
    deliver(w.carol.instance);
    let e_bob = grant_notice(w.carol.instance, w.alice, w.a_carol);
    attested &= expiring && e_bob.is_some();
    if let Some(e) = e_bob {
        let in_time = done(act(w.carol.instance, &Args::send(e, b"in time")));
        deliver(w.bob.instance);
        let waited = expiry_of(w.carol_slot, e).is_some_and(wait_until);
        v.expired = in_time
            && waited
            && watch.refused(
                act(w.carol.instance, &Args::send(e, b"too late")),
                w.carol,
                Action::Send,
                DenyReason::Expired,
            );
    }

    // A request bob leaves unanswered: after the requester's timeout the
    // right is dead, and nothing ever reaches alice — silence is denial.
    let quiet = done(act(
        w.alice.instance,
        &Args::request(w.a_bob, REPLY_TTL, QUIET),
    ));
    deliver(w.bob.instance);
    let pending = probe::seen_last_for(w.bob.instance).and_then(|s| match s.kind {
        Kind::Request { reply_tag } if s.from == w.alice && s.answered.is_none() => {
            Some(CapIndex(reply_tag))
        }
        _ => None,
    });
    if let Some(r) = pending {
        let waited = expiry_of(w.bob_slot, r).is_some_and(wait_until);
        v.reply_late = quiet
            && waited
            && watch.refused(
                act(w.bob.instance, &Args::reply(r, b"late")),
                w.bob,
                Action::Reply,
                DenyReason::Expired,
            );
    }
    v.silence = with_host(|h| h.inbox_len(w.alice.instance) == Some(0));
    v.attested = attested;

    // ── Rate limit: carol's budget is spent; a burst is counted, not lost ──
    let before = totals();
    let mut all_denied = true;
    for i in 0..BURST {
        all_denied &= act(
            w.carol.instance,
            &Args::send(CapIndex(0xDEAD_0000 | i), b"flood"),
        ) == Outcome::Denied;
    }
    watch.burst(u64::from(BURST));
    let after = totals();
    v.rate_limited = all_denied
        && after.total - before.total == u64::from(BURST)
        && after.suppressed > before.suppressed;

    // ── §18.4 measurement (informational) ──
    v.actor_deliveries = measure_actor(w);
    v.task_roundtrips = measure_task_switch();
}

/// Run-to-completion delivery, end to end: one attested send exactly as
/// alice's code performs it (`Ctx::send`: lock, check, stamp, encode,
/// enqueue) and one dispatch (lock, pop, decode, unlock, bob's handler).
fn measure_actor(w: &World) -> u64 {
    let alice = super::Ctx {
        cell: &HOST,
        me: w.alice.instance,
    };
    let start = crate::clock::mono_ticks();
    let mut n: u64 = 0;
    while crate::clock::mono_ticks().wrapping_sub(start) < MEASURE_TICKS && n < MEASURE_CAP {
        if alice.send(w.a_bob, b"m").is_err() || dispatch(&HOST, w.bob.instance, 1) != Ok(1) {
            break;
        }
        n += 1;
    }
    n
}

static PONG_RUN: AtomicBool = AtomicBool::new(false);
static PONG_ITERS: AtomicU64 = AtomicU64::new(0);

/// The other half of a context-switch round trip: what instance = task would
/// add to every delivery (switch to the instance's task and back).
fn pong() {
    while PONG_RUN.load(Ordering::Acquire) {
        PONG_ITERS.fetch_add(1, Ordering::Relaxed);
        crate::sched::yield_now();
    }
}

/// Count kmain ↔ `cap-pong` yield round trips in a [`MEASURE_TICKS`] window
/// on the BSP. Assumes no other BSP task is runnable (it would only dilute the
/// count): run this proof before any always-runnable BSP task is started.
///
/// Never waits for the ready queue to drain: every loop is bounded by the
/// mono clock or an iteration cap. And no exited task outlives it: the last
/// loop yields until the scheduler no longer knows `cap-pong` — exited **and
/// reaped**, by this very task's yields (the pattern the cooperative and
/// preemptive proofs use), so no other BSP task is ever left to reap it.
fn measure_task_switch() -> u64 {
    PONG_ITERS.store(0, Ordering::Relaxed);
    PONG_RUN.store(true, Ordering::Release);
    let pong_id = crate::sched::spawn("cap-pong", pong);
    let start = crate::clock::mono_ticks();
    let mut spins: u64 = 0;
    while crate::clock::mono_ticks().wrapping_sub(start) < MEASURE_TICKS && spins < MEASURE_CAP {
        crate::sched::yield_now();
        spins += 1;
    }
    let n = PONG_ITERS.load(Ordering::Relaxed);
    PONG_RUN.store(false, Ordering::Release);
    let mut guard: u32 = 0;
    while crate::sched::task_name(pong_id).is_some() && guard < 10_000 {
        crate::sched::yield_now();
        guard += 1;
    }
    n
}

// ── Output (fmt-free) ───────────────────────────────────────────────────────

fn yes_no(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

fn write_hex32(v: u32) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut b = *b"0x00000000";
    for i in 0..8 {
        b[2 + i] = HEX[((v >> (28 - 4 * i)) & 0xF) as usize];
    }
    if let Ok(s) = core::str::from_utf8(&b) {
        write_str(s);
    }
}

fn write_short_id(component: &crate::host::ComponentId) {
    let hex = component.short_hex();
    if let Ok(s) = core::str::from_utf8(&hex) {
        write_str(s);
    }
}

fn report(v: &Verdict, base: DenyTotals, end: DenyTotals) {
    write_str("[cap] grants: alice=");
    write_dec(v.counts.0 as u64);
    write_str("/2 bob=");
    write_dec(v.counts.1 as u64);
    write_str("/0 carol=");
    write_dec(v.counts.2 as u64);
    write_str("/1 policy-refused-logged=");
    write_str(yes_no(v.grants));
    write_str(" carol-required=");
    write_str(if v.strict_refused {
        "refused-to-start"
    } else {
        "STARTED"
    });
    write_str("\n");

    write_str("[cap] forge: not-held=");
    write_str(yes_no(v.not_held));
    write_str(" foreign=");
    write_str(yes_no(v.foreign));
    write_str(" revoked=");
    write_str(yes_no(v.revoked));
    write_str(" cascade=");
    write_str(yes_no(v.cascade));
    write_str(" expired=");
    write_str(yes_no(v.expired));
    write_str(" amplify=");
    write_str(yes_no(v.amplify));
    write_str(" attenuation=");
    write_str(yes_no(v.attenuation));
    write_str(" reply-once=");
    write_str(yes_no(v.reply_once));
    write_str(" reply-late=");
    write_str(yes_no(v.reply_late));
    write_str(" silence=");
    write_str(yes_no(v.silence));
    write_str("\n");

    write_str("[cap] deny-log: total=");
    write_dec(end.total - base.total);
    write_str(" logged=");
    write_dec(end.logged - base.logged);
    write_str(" suppressed=");
    write_dec(end.suppressed - base.suppressed);
    write_str(" overwritten=");
    write_dec(end.overwritten - base.overwritten);
    write_str(" rate-limited=");
    write_str(yes_no(v.rate_limited));
    write_str(" accounted=");
    write_str(yes_no(v.accounted));
    write_str("\n");
    let records = with_host(|h| h.deny_len());
    for i in 0..records {
        let Some(r) = with_host(|h| h.deny_record(i)) else {
            continue;
        };
        if r.seq < base.logged {
            continue;
        }
        write_str("[cap] deny: #");
        write_dec(r.seq);
        write_str(" t=");
        write_dec(r.tick);
        write_str(" inst=");
        write_dec(r.holder.instance.0);
        write_str(" comp=");
        write_short_id(&r.holder.component);
        write_str(" did=");
        write_str(r.action.label());
        write_str(" idx=");
        write_hex32(r.index.0);
        write_str(" why=");
        write_str(r.reason.label());
        if r.suppressed_before > 0 {
            write_str(" suppressed-before=");
            write_dec(u64::from(r.suppressed_before));
        }
        write_str("\n");
    }

    write_str("[cap] measure: model=actor actor-deliveries=");
    write_dec(v.actor_deliveries);
    write_str(" task-switch-roundtrips=");
    write_dec(v.task_roundtrips);
    write_str(" window-ticks=");
    write_dec(MEASURE_TICKS);
    write_str("\n");

    write_str("[cap] attested-from=");
    write_str(yes_no(v.attested));
    write_str(" deny-by-default=");
    write_str(yes_no(v.deny_by_default));
    write_str(" forge-attempt=");
    write_str(if v.forge_refused() {
        "refused"
    } else {
        "ACCEPTED"
    });
    write_str(" denies-logged=");
    write_dec(end.logged - base.logged);
    write_str(if v.ok() { " ok\n" } else { " FAIL\n" });
}
