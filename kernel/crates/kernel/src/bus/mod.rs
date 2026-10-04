//! The bus — the only code that moves a message between components (spec
//! `docs/specs/2026-09-18-component-model-design.md` §5, §7; PR-2 of §14;
//! threat entries T-ATT-1, T-CAP-1, T-REP-1, T-DOS-*, T-CON-* in
//! `docs/security/threat-model.md`).
//!
//! # The kernel-wide host
//!
//! `HOST` is the one `Host` the kernel runs components on (spec §13: the
//! PR-1 host becomes kernel-wide in PR-2). Every instance's inbox arena, every
//! capability table and the denial log are part of that fixed value, sized at
//! build time: **nothing on the bus allocates, ever** (threat T-DOS-4).
//!
//! # Component code acts only as itself: [`Ctx`]
//!
//! Component code runs in exactly two places, both here: `dispatch` (one
//! delivered envelope → the instance's message handler) and `call` (a
//! kernel-originated call into one of its exports). Each hands the code a
//! [`Ctx`] minted for **that** instance; `Ctx` cannot be constructed anywhere
//! else, and none of its operations takes a sender or a target. Everything
//! else here is `pub(crate)`, and `cargo xtask check-component-imports` keeps
//! component modules from naming it (threat T-NAT-1):
//!
//! - [`Ctx::send`] = spec §7's `bus::send(cap, payload)`. The host looks `cap`
//!   up in the *sender's own* table, checks `Send` and the attenuation,
//!   resolves the target from the capability, stamps `from = {instance,
//!   component}` from the running instance's record (A2), and enqueues. A full
//!   inbox is `Busy`; nothing is dropped, nothing grows.
//! - [`Ctx::request`] does the same with `Request`, and mints the target a
//!   **one-shot reply capability** in *its* table, expiring at the requester's
//!   timeout; the target sees that capability's index as the request's
//!   `reply_tag`. [`Ctx::reply`] spends it. The host never fabricates a reply:
//!   **silence is denial**.
//! - [`Ctx::delegate`] passes an attenuated (or equal) copy of a capability to
//!   the instance another capability (`via`, holding `Send`) reaches — you can
//!   hand authority only to someone you can already reach. The recipient is
//!   told by a kernel-stamped `Grant` envelope carrying its new index.
//! - [`Ctx::revoke`] / [`Ctx::release`] cascade through the delegation tree.
//!
//! Authority is checked **before** capacity: an unauthorised sender gets
//! `Denied`, never `Busy`, so it learns nothing about the target. Every denial
//! is logged (rate-limited, `crate::cap::deny`); components see only `Denied`.
//!
//! # Locking — one leaf lock
//!
//! `HOST` is the only bus lock. It is taken by `locked` with interrupts
//! **masked** on the local core, held only for bounded, allocation-free table
//! and ring operations, **never across a context switch**, never around an
//! allocation or a console write, and **nothing else is acquired while it is
//! held** (a leaf in the kernel's lock order: never nested inside or outside
//! `sched`'s queue → table locks, the console lock or the heap lock).
//! Component code always runs with no host lock held — dispatch copies the
//! envelope out, drops the lock, then runs the handler; a handler that sends
//! takes the lock again briefly. Check, target resolution, reply-capability
//! mint and enqueue happen in one critical section (no check-then-use race),
//! and the mono clock is read **inside** it: a tick read before waiting for the
//! lock would be stale by the wait, and a stale tick fails open for expiry.
//!
//! One instance's code never runs twice at once: `dispatch` and `call` set
//! the instance's `running` flag under the lock before running its code and
//! clear it after; while it is set, both refuse with `CallError::Busy`. Two
//! cores therefore never run the same handler concurrently (`dispatch` +
//! `dispatch`, `call` + `dispatch`, or `call` + `call`).
//!
//! Against the kernel's lock/interrupt rule (`kernel/docs/hal-tcb.md` §5e:
//! locks reachable from IRQ context are taken only with `IF = 0`; locks never
//! taken from IRQ context may be held with `IF = 1` provided no same-core
//! waiter spins): `HOST` — and the boot proof's `SEEN` recorder (`host::seen`), the only
//! other lock this PR adds — are **never taken from IRQ context** (no
//! interrupt handler touches the bus). They are held with `IF = 0` all the
//! same, by choice: the holder can then never be preempted, so a same-core
//! waiter can never exist, and the hold time is bounded by table/ring work.
//! `kernel::cap` itself holds no lock (pure functions over `&mut`).
//!
//! # Delivery model (spec §18.4, decided at PR-2)
//!
//! **Run-to-completion dispatch**, not one task per instance: an inbox is
//! drained by whoever calls `dispatch` (the boot proof today), each envelope
//! running the instance's handler to completion with no lock held. Instance =
//! task would cost each instance a 16 KiB guard-paged stack, an `XsaveArea`
//! and one of the scheduler's 64 task slots, and needs a block-on-inbox
//! primitive the scheduler does not have; the measurement and the decision are
//! in spec §18.4. The `Ctx` design is model-independent: a future
//! per-instance task would mint its `Ctx` the same way.

#![deny(missing_docs)]

pub mod proof;

use crate::cap::deny::Action;
use crate::cap::table::MAX_PENDING_REPLIES;
use crate::cap::{
    Access, Attenuation, CapError, CapIndex, Capability, DenyReason, Op, OpSet, Target, Tick,
};
use crate::host::codec::{Envelope, Kind, Payload, Sender, Wire, MAX_PAYLOAD};
use crate::host::native::{self, NativeRuntime};
use crate::host::{
    CallError, ComponentId, ComponentRuntime, Host, InstanceId, InstantiateError, Manifest,
    UNBOUND_BUCKET,
};
use hal::sync::SpinMutex;

/// Longest reply timeout a requester may ask for: 10 s at 100 Hz. Bounds how
/// long an unanswered request occupies the responder's table (T-DOS-2).
pub const MAX_REPLY_TIMEOUT_TICKS: Tick = 1000;

/// The kernel-wide host: the native runtime over [`native::REGISTRY`],
/// granting under [`native::BOOT_POLICY`]. See the module docs for its lock.
pub(crate) static HOST: SpinMutex<Host<NativeRuntime>> = SpinMutex::new(Host::new(
    NativeRuntime::new(native::REGISTRY),
    native::BOOT_POLICY,
));

/// Run `f` with maskable interrupts disabled on this core, restoring the
/// previous state after — the pattern `sched` uses for its own locks
/// (`hal::sync::SpinMutex` does not mask interrupts itself). A no-op stub on
/// host builds.
pub(crate) fn irq_masked<T>(f: impl FnOnce() -> T) -> T {
    let were_enabled = hal::cpu::interrupts_enabled();
    hal::cpu::disable_interrupts();
    let out = f();
    if were_enabled {
        hal::cpu::enable_interrupts();
    }
    out
}

/// Run `f` on the host in `cell` under its lock, interrupts masked. The guard
/// is dropped before interrupts are restored. Never call component code, the
/// scheduler, the console or the allocator from `f`.
pub(crate) fn locked<R: ComponentRuntime, T>(
    cell: &SpinMutex<Host<R>>,
    f: impl FnOnce(&mut Host<R>) -> T,
) -> T {
    irq_masked(|| f(&mut cell.lock()))
}

/// `locked` on the kernel-wide `HOST`.
pub(crate) fn with_host<T>(f: impl FnOnce(&mut Host<NativeRuntime>) -> T) -> T {
    locked(&HOST, f)
}

fn now() -> Tick {
    crate::clock::mono_ticks()
}

/// Why a bus operation did not happen, as the component sees it. The precise
/// reason for a denial is in the denial log only (threat T-INFO-1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BusError {
    /// Refused: no such capability in your table, or it does not allow this.
    Denied,
    /// Authorised, but the target cannot take it now (inbox or table full).
    Busy,
}

impl BusError {
    /// Fixed label for `fmt`-free console output.
    pub const fn label(self) -> &'static str {
        match self {
            BusError::Denied => "denied",
            BusError::Busy => "busy",
        }
    }
}

/// What a delegator asks its child capability to be. The target is always the
/// parent's; the host refuses anything that is not `⊑` the parent.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Delegation {
    /// Operations, `⊆` the parent's.
    pub ops: OpSet,
    /// Attenuation, `⊑` the parent's.
    pub attenuation: Attenuation,
    /// Lifetime in ticks from now; `None` inherits the parent's expiry.
    /// `Some(0)` would be dead on arrival and is refused (`Malformed`).
    pub ttl: Option<Tick>,
}

/// A running instance's handle on the kernel: the only way component code
/// reaches the bus, and it acts as that instance and nothing else. Minted by
/// `dispatch` and `call` for the instance they run; it cannot be built
/// outside this module and carries no target. Every operation reads the mono
/// clock inside the host lock (module docs).
pub struct Ctx<'h, R: ComponentRuntime> {
    cell: &'h SpinMutex<Host<R>>,
    me: InstanceId,
}

impl<'h, R: ComponentRuntime> Ctx<'h, R> {
    /// The instance this context acts as.
    pub fn me(&self) -> InstanceId {
        self.me
    }

    /// Post an `Event` over capability `cap` (spec §7 `bus::send(cap, payload)`).
    pub fn send(&self, cap: CapIndex, payload: &[u8]) -> Result<(), BusError> {
        locked(self.cell, |h| h.send_from(self.me, cap, payload, now()))
    }

    /// Post a `Request` over `cap`; the answer, if any, arrives in this
    /// instance's inbox as `Reply { reply_tag }` with the returned tag. The
    /// responder's right to answer expires after `timeout` ticks (clamped to
    /// `1..=MAX_REPLY_TIMEOUT_TICKS`).
    pub fn request(&self, cap: CapIndex, payload: &[u8], timeout: Tick) -> Result<u32, BusError> {
        locked(self.cell, |h| {
            h.request_from(self.me, cap, payload, timeout, now())
        })
    }

    /// Answer the request whose `reply_tag` was `reply` — once.
    pub fn reply(&self, reply: CapIndex, payload: &[u8]) -> Result<(), BusError> {
        locked(self.cell, |h| h.reply_from(self.me, reply, payload, now()))
    }

    /// Give the instance `via` reaches an attenuated copy of `cap`.
    pub fn delegate(&self, cap: CapIndex, via: CapIndex, d: &Delegation) -> Result<(), BusError> {
        locked(self.cell, |h| h.delegate_from(self.me, cap, via, d, now()))
    }

    /// Revoke everything delegated from `cap`, at any depth; keep `cap`.
    /// Returns how many capabilities were freed.
    pub fn revoke(&self, cap: CapIndex) -> Result<usize, BusError> {
        locked(self.cell, |h| h.revoke_from(self.me, cap, now()))
    }

    /// Drop `cap` and everything delegated from it (for a reply capability:
    /// decline to answer).
    pub fn release(&self, cap: CapIndex) -> Result<(), BusError> {
        locked(self.cell, |h| h.release_from(self.me, cap, now()))
    }

    /// The index granted for this instance's manifest request `i`, if any.
    pub fn granted(&self, i: usize) -> Option<CapIndex> {
        locked(self.cell, |h| h.granted(self.me, i))
    }
}

// ── The host side of every bus operation (under the HOST lock) ─────────────

impl<R: ComponentRuntime> Host<R> {
    /// The acting instance's slot and kernel-stamped identity; a dead or
    /// unknown instance is refused (and logged).
    fn acting(
        &mut self,
        me: InstanceId,
        idx: CapIndex,
        action: Action,
        now: Tick,
    ) -> Result<(usize, Sender), BusError> {
        if let Some(slot) = self.slot_of(me) {
            if let Some(who) = self.sender_at(slot) {
                return Ok((slot, who));
            }
        }
        self.deny.record(
            now,
            UNBOUND_BUCKET,
            Sender {
                instance: me,
                component: ComponentId::KERNEL,
            },
            idx,
            action,
            DenyReason::NoSuchSender,
        );
        Err(BusError::Denied)
    }

    /// Log a refusal by `who` and return the component-visible error.
    fn refuse(
        &mut self,
        now: Tick,
        slot: usize,
        who: Sender,
        idx: CapIndex,
        action: Action,
        reason: DenyReason,
    ) -> BusError {
        self.deny.record(now, slot, who, idx, action, reason);
        BusError::Denied
    }

    /// The live instance a checked capability designates, or a logged refusal.
    fn target_slot(
        &mut self,
        now: Tick,
        (slot, who): (usize, Sender),
        idx: CapIndex,
        action: Action,
        target: Target,
    ) -> Result<(InstanceId, usize), BusError> {
        let Target::Instance(to) = target else {
            return Err(self.refuse(now, slot, who, idx, action, DenyReason::WrongTarget));
        };
        match self.slot_of(to) {
            Some(t) => Ok((to, t)),
            None => Err(self.refuse(now, slot, who, idx, action, DenyReason::TargetGone)),
        }
    }

    fn inbox_full(&self, slot: usize) -> bool {
        self.instances
            .get(slot)
            .and_then(Option::as_ref)
            .is_none_or(|i| i.inbox.is_full())
    }

    /// Encode `env` into the inbox of the instance in `slot`.
    fn enqueue(&mut self, slot: usize, env: &Envelope) -> Result<(), BusError> {
        match self.instances.get_mut(slot).and_then(Option::as_mut) {
            Some(i) => i.inbox.push(Wire::encode(env)).map_err(|_| BusError::Busy),
            // Unreachable: callers resolved `slot` under this same lock.
            None => Err(BusError::Busy),
        }
    }

    fn next_reply_tag(&mut self, slot: usize) -> u32 {
        match self.instances.get_mut(slot).and_then(Option::as_mut) {
            Some(i) => {
                let tag = i.next_reply_tag;
                i.next_reply_tag = tag.wrapping_add(1).max(1);
                tag
            }
            None => 0,
        }
    }

    /// Check `cap` in the acting instance's table for `access`, or refuse.
    fn authorise(
        &mut self,
        now: Tick,
        (slot, who): (usize, Sender),
        cap: CapIndex,
        action: Action,
        access: &Access,
    ) -> Result<crate::cap::Capability, BusError> {
        match self.caps.check(slot, cap, access, now) {
            Ok(c) => Ok(c),
            Err(reason) => Err(self.refuse(now, slot, who, cap, action, reason)),
        }
    }

    /// `send` on behalf of instance `me` (what [`Ctx::send`] runs).
    pub(crate) fn send_from(
        &mut self,
        me: InstanceId,
        cap: CapIndex,
        payload: &[u8],
        now: Tick,
    ) -> Result<(), BusError> {
        let actor = self.acting(me, cap, Action::Send, now)?;
        let access = Access::Message {
            op: Op::Send,
            len: payload.len(),
        };
        let c = self.authorise(now, actor, cap, Action::Send, &access)?;
        let (to, t) = self.target_slot(now, actor, cap, Action::Send, c.target)?;
        let Ok(payload) = Payload::new(payload) else {
            // Unreachable: the attenuation admitted `len <= MAX_PAYLOAD`.
            return Err(self.refuse(
                now,
                actor.0,
                actor.1,
                cap,
                Action::Send,
                DenyReason::Attenuation,
            ));
        };
        self.enqueue(
            t,
            &Envelope {
                from: actor.1,
                to,
                cap,
                kind: Kind::Event,
                payload,
            },
        )
    }

    /// `request` on behalf of instance `me` (what [`Ctx::request`] runs).
    pub(crate) fn request_from(
        &mut self,
        me: InstanceId,
        cap: CapIndex,
        payload: &[u8],
        timeout: Tick,
        now: Tick,
    ) -> Result<u32, BusError> {
        let actor = self.acting(me, cap, Action::Request, now)?;
        let access = Access::Message {
            op: Op::Request,
            len: payload.len(),
        };
        let c = self.authorise(now, actor, cap, Action::Request, &access)?;
        let (to, t) = self.target_slot(now, actor, cap, Action::Request, c.target)?;
        let Ok(payload) = Payload::new(payload) else {
            return Err(self.refuse(
                now,
                actor.0,
                actor.1,
                cap,
                Action::Request,
                DenyReason::Attenuation,
            ));
        };
        // Authorised. Now capacity — room for the envelope and the reply
        // right, checked before anything changes. Expired capabilities still
        // occupy their slots, and expired reply rights still count against
        // MAX_PENDING_REPLIES, until reclaimed: reclaim the responder's
        // whenever either limit is reached, or requests a responder left
        // unanswered (silence is denial) would lock it out for good.
        if !self.caps.has_room(t) || self.caps.pending_replies(t) >= MAX_PENDING_REPLIES {
            self.caps.reap_expired_in(t, now);
        }
        if self.inbox_full(t)
            || !self.caps.has_room(t)
            || self.caps.pending_replies(t) >= MAX_PENDING_REPLIES
        {
            return Err(BusError::Busy);
        }
        let tag = self.next_reply_tag(actor.0);
        let expires = now.saturating_add(timeout.clamp(1, MAX_REPLY_TIMEOUT_TICKS));
        let reply = self
            .caps
            .mint_reply(t, Capability::reply_right(me, tag, expires))
            .map_err(|_| BusError::Busy)?;
        let env = Envelope {
            from: actor.1,
            to,
            cap,
            kind: Kind::Request { reply_tag: reply.0 },
            payload,
        };
        if let Err(e) = self.enqueue(t, &env) {
            // Unreachable (room checked above); undo the mint regardless.
            let _ = self.caps.release(t, reply);
            return Err(e);
        }
        Ok(tag)
    }

    /// `reply` on behalf of instance `me` (what [`Ctx::reply`] runs).
    pub(crate) fn reply_from(
        &mut self,
        me: InstanceId,
        reply: CapIndex,
        payload: &[u8],
        now: Tick,
    ) -> Result<(), BusError> {
        let actor = self.acting(me, reply, Action::Reply, now)?;
        let access = Access::Message {
            op: Op::Reply,
            len: payload.len(),
        };
        let c = match self.caps.check(actor.0, reply, &access, now) {
            Ok(c) => c,
            Err(reason) => {
                // The requester's timeout passed: a reply right is dead for
                // good, so reclaim its slot now. Only a reply right — any
                // other capability presented here is refused and left alone.
                let reply_right = self
                    .caps
                    .get(actor.0, reply)
                    .is_ok_and(|e| matches!(e.cap.target, Target::Reply { .. }));
                if reason == DenyReason::Expired && reply_right {
                    let _ = self.caps.release(actor.0, reply);
                }
                return Err(self.refuse(now, actor.0, actor.1, reply, Action::Reply, reason));
            }
        };
        let Target::Reply { to, tag } = c.target else {
            return Err(self.refuse(
                now,
                actor.0,
                actor.1,
                reply,
                Action::Reply,
                DenyReason::WrongTarget,
            ));
        };
        let Some(r) = self.slot_of(to) else {
            let _ = self.caps.release(actor.0, reply);
            return Err(self.refuse(
                now,
                actor.0,
                actor.1,
                reply,
                Action::Reply,
                DenyReason::TargetGone,
            ));
        };
        let Ok(payload) = Payload::new(payload) else {
            return Err(self.refuse(
                now,
                actor.0,
                actor.1,
                reply,
                Action::Reply,
                DenyReason::Attenuation,
            ));
        };
        self.enqueue(
            r,
            &Envelope {
                from: actor.1,
                to,
                cap: reply,
                kind: Kind::Reply { reply_tag: tag },
                payload,
            },
        )?;
        // One shot: the right is spent the moment the answer is enqueued.
        let _ = self.caps.release(actor.0, reply);
        Ok(())
    }

    /// `delegate` on behalf of instance `me` (what [`Ctx::delegate`] runs).
    pub(crate) fn delegate_from(
        &mut self,
        me: InstanceId,
        cap: CapIndex,
        via: CapIndex,
        d: &Delegation,
        now: Tick,
    ) -> Result<(), BusError> {
        let actor = self.acting(me, cap, Action::Delegate, now)?;
        // The recipient is whoever `via` reaches: authority goes only to an
        // instance the delegator can already reach.
        let reach = Access::Message {
            op: Op::Send,
            len: 0,
        };
        let v = self.authorise(now, actor, via, Action::Delegate, &reach)?;
        let (to, r) = self.target_slot(now, actor, via, Action::Delegate, v.target)?;
        let parent = match self.caps.get(actor.0, cap) {
            Ok(e) => e.cap,
            Err(reason) => {
                return Err(self.refuse(now, actor.0, actor.1, cap, Action::Delegate, reason));
            }
        };
        let expires = match d.ttl {
            None => parent.expires,
            Some(t) => Some(now.saturating_add(t)),
        };
        // The child is over the parent's target; anything else would fail `⊑`.
        let child = Capability {
            target: parent.target,
            ops: d.ops,
            attenuation: d.attenuation,
            expires,
        };
        // Authority first — everything `delegate` checks (live, `Delegate`,
        // well formed, `⊑`), changing nothing. Then capacity, still changing
        // nothing: the notice must fit the recipient's inbox, so a `Busy`
        // never spends a generation of the recipient's table. Only then
        // install; an authorised delegation that finds the recipient's table
        // full reclaims that table's expired capabilities and is tried once
        // more. A refused call changes nothing.
        let deny = |e: CapError| match e {
            CapError::Deny(reason) => Some(reason),
            CapError::TableFull | CapError::NoSuchTable => None,
        };
        if let Err(e) = self.caps.check_delegate(actor.0, cap, r, &child, now) {
            return Err(match deny(e) {
                Some(reason) => self.refuse(now, actor.0, actor.1, cap, Action::Delegate, reason),
                None => BusError::Busy,
            });
        }
        // Dead on arrival (`ttl = 0`): refuse it rather than install it and
        // notify — after the authority checks, so a delegator refused for
        // authority is logged with that reason, and before any state change.
        if d.ttl == Some(0) {
            return Err(self.refuse(
                now,
                actor.0,
                actor.1,
                cap,
                Action::Delegate,
                DenyReason::Malformed,
            ));
        }
        if self.inbox_full(r) {
            return Err(BusError::Busy);
        }
        let mut attempt = self.caps.delegate(actor.0, cap, r, &child, now);
        if matches!(attempt, Err(CapError::TableFull)) {
            self.caps.reap_expired_in(r, now);
            attempt = self.caps.delegate(actor.0, cap, r, &child, now);
        }
        let granted = match attempt {
            Ok(i) => i,
            Err(e) => {
                return Err(match deny(e) {
                    // Unreachable: checked above, under this same lock.
                    Some(reason) => {
                        self.refuse(now, actor.0, actor.1, cap, Action::Delegate, reason)
                    }
                    None => BusError::Busy,
                });
            }
        };
        let notice = Envelope {
            from: actor.1,
            to,
            cap: via,
            kind: Kind::Grant { granted },
            payload: Payload::EMPTY,
        };
        if let Err(e) = self.enqueue(r, &notice) {
            // Unreachable: room was checked above, under this same lock.
            let _ = self.caps.release(r, granted);
            return Err(e);
        }
        Ok(())
    }

    /// `revoke` on behalf of instance `me` (what [`Ctx::revoke`] runs).
    pub(crate) fn revoke_from(
        &mut self,
        me: InstanceId,
        cap: CapIndex,
        now: Tick,
    ) -> Result<usize, BusError> {
        let (slot, who) = self.acting(me, cap, Action::Revoke, now)?;
        match self.caps.revoke(slot, cap) {
            Ok(n) => Ok(n),
            Err(CapError::Deny(reason)) => {
                Err(self.refuse(now, slot, who, cap, Action::Revoke, reason))
            }
            Err(_) => Err(self.refuse(now, slot, who, cap, Action::Revoke, DenyReason::NotHeld)),
        }
    }

    /// `release` on behalf of instance `me` (what [`Ctx::release`] runs).
    pub(crate) fn release_from(
        &mut self,
        me: InstanceId,
        cap: CapIndex,
        now: Tick,
    ) -> Result<(), BusError> {
        let (slot, who) = self.acting(me, cap, Action::Release, now)?;
        match self.caps.release(slot, cap) {
            Ok(_) => Ok(()),
            Err(CapError::Deny(reason)) => {
                Err(self.refuse(now, slot, who, cap, Action::Release, reason))
            }
            Err(_) => Err(self.refuse(now, slot, who, cap, Action::Release, DenyReason::NotHeld)),
        }
    }

    /// Take the oldest envelope from `inst`'s inbox, with the runtime entry
    /// to deliver it to, and mark the instance running (cleared by
    /// [`Self::finish_run`]). `Ok(None)` when the inbox is empty;
    /// `Err(CallError::Busy)`, taking nothing, while its code already runs.
    pub(crate) fn pop_for_dispatch(
        &mut self,
        inst: InstanceId,
    ) -> Result<Option<(R::Entry, Envelope)>, CallError> {
        let slot = self.slot_of(inst).ok_or(CallError::NoSuchInstance)?;
        let i = self.instances[slot]
            .as_mut()
            .ok_or(CallError::NoSuchInstance)?;
        if i.running {
            return Err(CallError::Busy);
        }
        let handle = i.handle;
        let Some(wire) = i.inbox.pop() else {
            return Ok(None);
        };
        let env = wire.decode().map_err(CallError::Wire)?;
        let entry = self
            .runtime
            .entry(handle)
            .ok_or(CallError::NoSuchInstance)?;
        i.running = true;
        Ok(Some((entry, env)))
    }

    /// The code `inst` was running (a handler or an export) has returned. A
    /// no-op if the instance has gone meanwhile; its id is never reused.
    pub(crate) fn finish_run(&mut self, inst: InstanceId) {
        if let Some(i) = self
            .slot_of(inst)
            .and_then(|s| self.instances.get_mut(s))
            .and_then(Option::as_mut)
        {
            i.running = false;
        }
    }

    /// Resolve a kernel call into `inst`: its runtime entry, its component,
    /// and a fresh kernel tag; mark the instance running (cleared by
    /// [`Self::finish_run`]). `Err(CallError::Busy)` while its code already
    /// runs.
    pub(crate) fn prepare_kernel_call(
        &mut self,
        inst: InstanceId,
    ) -> Result<(R::Entry, ComponentId, u32), CallError> {
        let slot = self.slot_of(inst).ok_or(CallError::NoSuchInstance)?;
        let i = self.instances[slot]
            .as_mut()
            .ok_or(CallError::NoSuchInstance)?;
        if i.running {
            return Err(CallError::Busy);
        }
        let tag = i.next_kernel_tag;
        i.next_kernel_tag = tag.wrapping_add(1);
        let (handle, component) = (i.handle, i.component);
        let entry = self
            .runtime
            .entry(handle)
            .ok_or(CallError::NoSuchInstance)?;
        i.running = true;
        Ok((entry, component, tag))
    }
}

// ── Cell-level operations: the lock dance around component code ────────────

/// Verify `manifest` (hash, **no lock held**), then instantiate it on the host
/// in `cell` and grant its capabilities.
pub(crate) fn instantiate<R: ComponentRuntime>(
    cell: &SpinMutex<Host<R>>,
    manifest: &Manifest,
) -> Result<InstanceId, InstantiateError> {
    let verified = manifest.verify()?;
    locked(cell, |h| h.instantiate_verified(verified, now()))
}

/// End instance `inst` on the host in `cell` (see `Host::terminate`).
pub(crate) fn terminate<R: ComponentRuntime>(
    cell: &SpinMutex<Host<R>>,
    inst: InstanceId,
) -> Result<usize, CallError> {
    locked(cell, |h| h.terminate(inst))
}

/// Deliver up to `max` envelopes from `inst`'s inbox, oldest first, each to
/// the instance's message handler, run to completion **with no lock held**.
/// Returns how many were delivered. `Err(CallError::Busy)` if the instance's
/// code is already running elsewhere before anything was delivered; after
/// that, the count so far.
pub(crate) fn dispatch<R: ComponentRuntime>(
    cell: &SpinMutex<Host<R>>,
    inst: InstanceId,
    max: usize,
) -> Result<usize, CallError> {
    let mut delivered = 0;
    while delivered < max {
        let (entry, env) = match locked(cell, |h| h.pop_for_dispatch(inst)) {
            Ok(Some(next)) => next,
            Ok(None) => break,
            Err(CallError::Busy) if delivered > 0 => break,
            Err(e) => return Err(e),
        };
        let ctx = Ctx { cell, me: inst };
        let ran = R::deliver(entry, &ctx, &env);
        locked(cell, |h| h.finish_run(inst));
        ran?;
        delivered += 1;
    }
    Ok(delivered)
}

/// A kernel-originated call into `inst`'s `export`, answered as a reply
/// envelope stamped with the instance's identity (spec §7, PR-1's path).
///
/// The kernel needs no capability to address an instance it hosts, and its
/// calls travel on a control channel of their own — they never enter the
/// instance's inbox, so component traffic can neither delay nor displace
/// them. The request is built and stamped by the kernel, encoded and decoded
/// through the envelope codec (what the component is handed), the export runs
/// with **no lock held** and a [`Ctx`] for `inst`, and the reply is stamped
/// `from = {inst, its component}` and round-tripped through the codec again.
pub(crate) fn call_envelope<R: ComponentRuntime>(
    cell: &SpinMutex<Host<R>>,
    inst: InstanceId,
    export: &str,
    args: &[u8],
) -> Result<Envelope, CallError> {
    let payload = Payload::new(args).map_err(|_| CallError::PayloadTooLong)?;
    let (entry, component, tag) = locked(cell, |h| h.prepare_kernel_call(inst))?;
    let out = run_export(cell, inst, (entry, component, tag), export, payload);
    locked(cell, |h| h.finish_run(inst));
    out
}

/// The body of [`call_envelope`] once the instance is marked running: build,
/// round-trip and run the request, then stamp and round-trip the reply.
fn run_export<R: ComponentRuntime>(
    cell: &SpinMutex<Host<R>>,
    inst: InstanceId,
    (entry, component, tag): (R::Entry, ComponentId, u32),
    export: &str,
    payload: Payload,
) -> Result<Envelope, CallError> {
    let request = Envelope {
        from: Sender::KERNEL,
        to: inst,
        cap: CapIndex::KERNEL,
        kind: Kind::Request { reply_tag: tag },
        payload,
    };
    let delivered = Wire::encode(&request).decode().map_err(CallError::Wire)?;
    let Kind::Request { reply_tag } = delivered.kind else {
        return Err(CallError::ReplyMismatch);
    };

    let ctx = Ctx { cell, me: inst };
    let mut buf = [0u8; MAX_PAYLOAD];
    let n = R::call(entry, &ctx, export, delivered.payload.as_slice(), &mut buf)?;
    let reply_payload = Payload::new(buf.get(..n).ok_or(CallError::ReplyTooLong)?)
        .map_err(|_| CallError::ReplyTooLong)?;

    // The kernel stamps the reply with the INSTANCE's identity and routes it
    // back to whoever asked; the component wrote none of this.
    let reply = Envelope {
        from: Sender {
            instance: inst,
            component,
        },
        to: delivered.from.instance,
        cap: delivered.cap,
        kind: Kind::Reply { reply_tag },
        payload: reply_payload,
    };
    let back = Wire::encode(&reply).decode().map_err(CallError::Wire)?;
    if back.kind != (Kind::Reply { reply_tag: tag })
        || back.to != InstanceId::KERNEL
        || back.from.instance != inst
    {
        return Err(CallError::ReplyMismatch);
    }
    Ok(back)
}

/// `call_envelope`, copying the reply payload into `reply_out`.
pub(crate) fn call<R: ComponentRuntime>(
    cell: &SpinMutex<Host<R>>,
    inst: InstanceId,
    export: &str,
    args: &[u8],
    reply_out: &mut [u8],
) -> Result<usize, CallError> {
    let reply = call_envelope(cell, inst, export, args)?;
    let bytes = reply.payload.as_slice();
    let out = reply_out
        .get_mut(..bytes.len())
        .ok_or(CallError::ReplyTooLong)?;
    out.copy_from_slice(bytes);
    Ok(bytes.len())
}

#[cfg(test)]
mod tests;
