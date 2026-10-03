//! Capabilities — unforgeable, attenuable, revocable authority (component-model
//! spec `docs/specs/2026-09-18-component-model-design.md` §8; PR-2 of §14;
//! threat entries T-CAP-* in `docs/security/threat-model.md`).
//!
//! A capability is a kernel-held value `(target, ops, attenuation, expires)`.
//! Components never hold one: they hold a [`CapIndex`], an opaque `u32` that
//! is meaningful only in **their own** table, which lives here, in the kernel.
//! Absence of a capability is denial; nothing is granted implicitly.
//!
//! # One order, one predicate
//!
//! Every comparison between two capabilities goes through
//! [`Capability::is_attenuation_of`] (written `⊑`): same target, `ops' ⊆ ops`,
//! `attenuation' ⊑ attenuation`, `expires' ≤ expires`. It is total and
//! decidable, and the only thing [`table::CapSpace::delegate`] consults before
//! installing a derived capability. What a capability *permits* is
//! [`Capability::permits`]; the Kani harnesses prove the two agree — whatever
//! a child permits, at any tick, its parent permits
//! (`proofs::attenuation_order_is_sound_and_transitive`,
//! `table::proofs::delegate_never_amplifies`).
//!
//! # Extension point (SentinelFS FS-1c)
//!
//! Storage arrives as a purely additive change, written against the same
//! predicate (spec §8 "extension point"):
//!
//! 1. a [`Target`] variant (`Target::Storage(..)`) and its [`Target::allowed_ops`]
//!    arm, using new [`Op`] bits (`Read`, `Write`, `Snapshot`, `Rollback`,
//!    `Format`) — existing bits never move;
//! 2. an [`Attenuation`] variant carrying the storage lattice (tree, path
//!    prefix by components, blob set, quota) with its arms of
//!    [`Attenuation::is_attenuation_of`], [`Attenuation::admits`] and
//!    [`Attenuation::fits`];
//! 3. an [`Access`] variant (`Access::Storage { op, path, bytes }`).
//!
//! [`Attenuation::meet`] (used by `grant`), `delegate`, `revoke`, the tables
//! and every Kani harness are written against `⊑`/`admits` only, so none of
//! them changes; FS-1c extends the harnesses' symbolic generators
//! (`any_capability`, `any_access`) with the new variants and re-runs them.
//!
//! # Layout
//!
//! - this module: the lattice ([`Op`], [`OpSet`], [`Target`], [`Attenuation`],
//!   [`Access`], [`Capability`]), denial reasons, and manifest/policy types;
//! - [`table`]: the fixed slab of per-instance tables — `grant`, `delegate`,
//!   `revoke`, `release`, `check`, reply minting, reclamation;
//! - [`deny`]: the fixed-size, rate-limited denial log (amendment A8).
//!
//! Everything here is pure: no clock reads (the caller passes `now`), no
//! locks, no allocation. `kernel::bus` adds the lock and the clock.

#![deny(missing_docs)]

pub mod deny;
pub mod table;

use crate::host::codec::MAX_PAYLOAD;
use crate::host::{ComponentId, InstanceId};

/// A component's name for one of **its own** capabilities: an opaque `u32`
/// that means something only in the holder's table, where the kernel checks
/// it on every use ([`table`] documents the encoding). A component can write
/// any number here; the number confers nothing — forging one is refused for
/// the same reason a stolen one is (threat T-CAP-2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CapIndex(pub u32);

impl CapIndex {
    /// The kernel needs no capability to address an instance it hosts; this
    /// index (generation 0) is never issued in any table.
    pub const KERNEL: CapIndex = CapIndex(0);
}

/// A tick of `crate::clock::mono_ticks()` — the only clock authority decisions
/// use (spec §14 PR-1b: never a counter one core can stall).
pub type Tick = u64;

/// One operation a capability may authorise.
///
/// Each is one bit of an [`OpSet`]. Bit positions are stable — they appear in
/// audit records — and new operations take new bits, so adding one never
/// changes what an existing set means. Bits 8..=12 are reserved for storage
/// (FS-1c: `Read`, `Write`, `Snapshot`, `Rollback`, `Format`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum Op {
    /// Post an `Event` envelope to the target instance.
    Send = 1 << 0,
    /// Post a `Request`; the host mints the target a one-shot reply capability.
    Request = 1 << 1,
    /// Answer one request, once. Only reply capabilities carry it.
    Reply = 1 << 2,
    /// Derive an attenuated (or equal) copy for another instance.
    Delegate = 1 << 3,
}

impl Op {
    /// This operation's bit.
    pub const fn bit(self) -> u32 {
        self as u32
    }

    /// Fixed label for `fmt`-free console output.
    pub const fn label(self) -> &'static str {
        match self {
            Op::Send => "send",
            Op::Request => "request",
            Op::Reply => "reply",
            Op::Delegate => "delegate",
        }
    }
}

/// A set of [`Op`]s. `⊆` is bitwise, so it is decidable for any bits —
/// including bits no [`Op`] names yet, which [`Capability::is_well_formed`]
/// refuses.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct OpSet(u32);

impl OpSet {
    /// No operations.
    pub const EMPTY: OpSet = OpSet(0);

    /// The set holding exactly `ops`.
    pub const fn of(ops: &[Op]) -> OpSet {
        let mut bits = 0;
        let mut i = 0;
        while i < ops.len() {
            bits |= ops[i].bit();
            i += 1;
        }
        OpSet(bits)
    }

    /// A set from raw bits (audit records, the probe protocol, Kani).
    pub const fn from_bits(bits: u32) -> OpSet {
        OpSet(bits)
    }

    /// The raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// `op ∈ self`.
    pub const fn contains(self, op: Op) -> bool {
        self.0 & op.bit() != 0
    }

    /// `self ⊆ other`.
    pub const fn is_subset_of(self, other: OpSet) -> bool {
        self.0 & !other.0 == 0
    }

    /// `self ∩ other`.
    pub const fn intersect(self, other: OpSet) -> OpSet {
        OpSet(self.0 & other.0)
    }

    /// `self == ∅`.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// What a capability designates.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Target {
    /// A live component instance, reached over the bus.
    Instance(InstanceId),
    /// The right to answer request `tag` of instance `to`, once. Minted by the
    /// host per request (spec §7); never granted, never delegable.
    Reply {
        /// The requester the answer goes to.
        to: InstanceId,
        /// The requester's own correlation tag, restored on the answer.
        tag: u32,
    },
}

impl Target {
    /// Every operation a capability on this kind of target may ever carry.
    /// Well-formedness requires `ops ⊆ allowed_ops()`.
    pub const fn allowed_ops(&self) -> OpSet {
        match self {
            Target::Instance(_) => OpSet::of(&[Op::Send, Op::Request, Op::Delegate]),
            Target::Reply { .. } => OpSet::of(&[Op::Reply]),
        }
    }

    /// Whether this target designates instance `inst` in any role — what
    /// `terminate` revokes so nothing outlives the instance it names.
    pub fn names(&self, inst: InstanceId) -> bool {
        match *self {
            Target::Instance(i) => i == inst,
            Target::Reply { to, .. } => to == inst,
        }
    }
}

/// How a capability is narrowed beyond its target and ops.
///
/// Each variant is one lattice; variants never compare (cross-kind `⊑` is
/// `false`), so a new variant cannot weaken an existing one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Attenuation {
    /// Bus traffic carrying at most `max_len` payload bytes. Totally ordered:
    /// a smaller limit is a stronger restriction. `MAX_PAYLOAD` is no
    /// restriction beyond the envelope's own.
    Message {
        /// Largest payload this capability carries, `<= MAX_PAYLOAD`.
        max_len: u16,
    },
}

impl Attenuation {
    /// The top of the message lattice: any payload the envelope can carry.
    pub const UNRESTRICTED_MESSAGE: Attenuation = Attenuation::Message {
        max_len: MAX_PAYLOAD as u16,
    };

    /// `self ⊑ parent`: every access `self` admits, `parent` admits. Total and
    /// decidable; cross-kind is `false`.
    pub fn is_attenuation_of(&self, parent: &Attenuation) -> bool {
        match (self, parent) {
            (Attenuation::Message { max_len: a }, Attenuation::Message { max_len: b }) => a <= b,
        }
    }

    /// Whether this attenuation lets `access` through. Cross-kind is `false`.
    pub fn admits(&self, access: &Access) -> bool {
        match (self, access) {
            (Attenuation::Message { max_len }, Access::Message { len, .. }) => {
                *len <= usize::from(*max_len)
            }
        }
    }

    /// Whether this attenuation is well formed for `target`: the right kind,
    /// and within that kind's bounds.
    pub fn fits(&self, target: &Target) -> bool {
        match (self, target) {
            (Attenuation::Message { max_len }, Target::Instance(_) | Target::Reply { .. }) => {
                usize::from(*max_len) <= MAX_PAYLOAD
            }
        }
    }

    /// The greatest lower bound by `⊑` where the two are comparable, else
    /// `None` (no grant). Written against [`Self::is_attenuation_of`] only, so
    /// a new variant needs no meet of its own: incomparable values simply do
    /// not grant. For `Message` (a total order) this is the exact meet.
    pub fn meet(&self, other: &Attenuation) -> Option<Attenuation> {
        if self.is_attenuation_of(other) {
            Some(*self)
        } else if other.is_attenuation_of(self) {
            Some(*other)
        } else {
            None
        }
    }
}

/// One concrete use of a capability — what a check is asked to allow.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Access {
    /// A bus operation carrying `len` payload bytes.
    Message {
        /// The operation attempted.
        op: Op,
        /// Payload bytes it carries.
        len: usize,
    },
}

impl Access {
    /// The operation this access needs.
    pub const fn op(&self) -> Op {
        match self {
            Access::Message { op, .. } => *op,
        }
    }
}

/// `a ≤ b` on expiries, where `None` is "never" (the top).
pub const fn expiry_le(a: Option<Tick>, b: Option<Tick>) -> bool {
    match (a, b) {
        (_, None) => true,
        (None, Some(_)) => false,
        (Some(x), Some(y)) => x <= y,
    }
}

/// The earlier of two expiries (`None` is "never").
pub const fn expiry_min(a: Option<Tick>, b: Option<Tick>) -> Option<Tick> {
    match (a, b) {
        (None, x) | (x, None) => x,
        (Some(x), Some(y)) => Some(if x <= y { x } else { y }),
    }
}

/// A capability: what it designates, which operations it carries, how it is
/// narrowed, and when it stops.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Capability {
    /// What it designates.
    pub target: Target,
    /// Operations it carries; `⊆ target.allowed_ops()` when well formed.
    pub ops: OpSet,
    /// How it is narrowed.
    pub attenuation: Attenuation,
    /// Last tick it is valid is `expires - 1`; `None` never expires.
    pub expires: Option<Tick>,
}

impl Capability {
    /// Whether this value may be installed in a table at all: at least one
    /// operation, only operations its target allows, and an attenuation of
    /// the right kind within bounds. The tables hold nothing else.
    pub fn is_well_formed(&self) -> bool {
        !self.ops.is_empty()
            && self.ops.is_subset_of(self.target.allowed_ops())
            && self.attenuation.fits(&self.target)
    }

    /// Valid at tick `now`.
    pub const fn is_live(&self, now: Tick) -> bool {
        match self.expires {
            None => true,
            Some(e) => now < e,
        }
    }

    /// Whether this capability allows `access` at tick `now`. The single
    /// decision every check reduces to.
    pub fn permits(&self, access: &Access, now: Tick) -> bool {
        self.is_live(now) && self.ops.contains(access.op()) && self.attenuation.admits(access)
    }

    /// `self ⊑ parent`: the one predicate delegation is checked against.
    /// Same target; `ops ⊆`; `attenuation ⊑`; `expires ≤`.
    pub fn is_attenuation_of(&self, parent: &Capability) -> bool {
        self.target == parent.target
            && self.ops.is_subset_of(parent.ops)
            && self.attenuation.is_attenuation_of(&parent.attenuation)
            && expiry_le(self.expires, parent.expires)
    }

    /// The greatest capability below both (`grant`: manifest ∧ policy), or
    /// `None` when they share no target, no operation, or no attenuation.
    pub fn meet(&self, other: &Capability) -> Option<Capability> {
        if self.target != other.target {
            return None;
        }
        let ops = self.ops.intersect(other.ops);
        if ops.is_empty() {
            return None;
        }
        Some(Capability {
            target: self.target,
            ops,
            attenuation: self.attenuation.meet(&other.attenuation)?,
            expires: expiry_min(self.expires, other.expires),
        })
    }
}

impl Capability {
    /// The one-shot right to answer request `tag` of instance `to`, valid
    /// until `expires` — what the bus mints per request (spec §7).
    pub fn reply_right(to: InstanceId, tag: u32, expires: Tick) -> Capability {
        Capability {
            target: Target::Reply { to, tag },
            ops: OpSet::of(&[Op::Reply]),
            attenuation: Attenuation::UNRESTRICTED_MESSAGE,
            expires: Some(expires),
        }
    }
}

/// What a capability table stores. The tables never look inside a value
/// except through this trait, so their structural guarantees — only the
/// three producers write an entry, a delegated entry stays `⊑` a live
/// parent, revocation removes exactly the descendants — hold for **every**
/// implementation. Kani proves those over a small value type whose `⊑` is an
/// arbitrary symbolic relation (`table::proofs`), and proves the lattice laws
/// on [`Capability`] itself (`proofs::attenuation_order_is_sound_and_transitive`):
/// together, the guarantees for the tables the kernel actually runs.
pub trait Authority: Copy + PartialEq + core::fmt::Debug {
    /// May be installed in a table at all.
    fn is_well_formed(&self) -> bool;
    /// Valid at tick `now`.
    fn is_live(&self, now: Tick) -> bool;
    /// Carries the right to derive children (`Delegate`).
    fn may_delegate(&self) -> bool;
    /// `self ⊑ parent` — the one predicate delegation is checked against.
    fn is_attenuation_of(&self, parent: &Self) -> bool;
    /// The greatest value below both, if any — what `grant` installs.
    fn meet(&self, other: &Self) -> Option<Self>;
}

impl Authority for Capability {
    fn is_well_formed(&self) -> bool {
        Capability::is_well_formed(self)
    }

    fn is_live(&self, now: Tick) -> bool {
        Capability::is_live(self, now)
    }

    fn may_delegate(&self) -> bool {
        self.ops.contains(Op::Delegate)
    }

    fn is_attenuation_of(&self, parent: &Self) -> bool {
        Capability::is_attenuation_of(self, parent)
    }

    fn meet(&self, other: &Self) -> Option<Self> {
        Capability::meet(self, other)
    }
}

/// Why the kernel refused an operation. Recorded in the denial log; the
/// component itself only ever sees "denied" (threat T-INFO-1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DenyReason {
    /// The index was never issued in the holder's table (or is malformed).
    NotHeld,
    /// The index was minted for another instance's table.
    Foreign,
    /// The capability it named was revoked, released, used up or reclaimed.
    Stale,
    /// The capability is past its expiry tick.
    Expired,
    /// The capability does not carry the operation.
    OpNotAllowed,
    /// The access exceeds the capability's attenuation (e.g. payload length).
    Attenuation,
    /// The capability designates the wrong kind of target for the operation.
    WrongTarget,
    /// The target instance no longer exists.
    TargetGone,
    /// The parent capability does not carry `Delegate`.
    NotDelegable,
    /// The requested child is not an attenuation of its parent.
    Amplification,
    /// The value would not be well formed (no ops, foreign ops, bad bounds).
    Malformed,
    /// The manifest asked; the policy has no rule for it, or the rule and the
    /// request share nothing.
    PolicyRefused,
    /// A required manifest capability could not be granted: refused to start.
    MissingRequired,
    /// The acting instance is not live.
    NoSuchSender,
}

impl DenyReason {
    /// Fixed label for `fmt`-free console output.
    pub const fn label(self) -> &'static str {
        match self {
            DenyReason::NotHeld => "not-held",
            DenyReason::Foreign => "foreign",
            DenyReason::Stale => "stale",
            DenyReason::Expired => "expired",
            DenyReason::OpNotAllowed => "op-not-allowed",
            DenyReason::Attenuation => "attenuation",
            DenyReason::WrongTarget => "wrong-target",
            DenyReason::TargetGone => "target-gone",
            DenyReason::NotDelegable => "not-delegable",
            DenyReason::Amplification => "amplification",
            DenyReason::Malformed => "malformed",
            DenyReason::PolicyRefused => "policy-refused",
            DenyReason::MissingRequired => "missing-required",
            DenyReason::NoSuchSender => "no-such-sender",
        }
    }
}

/// Why a table operation did not happen.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CapError {
    /// An authority decision: refused, and logged by the caller.
    Deny(DenyReason),
    /// No free slot in the destination table (a resource limit, not a denial).
    TableFull,
    /// The destination table number is out of range (internal).
    NoSuchTable,
}

/// Whether a manifest capability is needed to run (amendment A8).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CapNeed {
    /// Refuse to start without it, rather than run degraded.
    Required,
    /// Run without it; the component copes with denial (principle 2).
    Optional,
}

/// One capability a manifest asks for: authority over a live instance of
/// component `target` (the host binds the id to an instance, spec §6).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CapRequest {
    /// The component whose instance it designates.
    pub target: ComponentId,
    /// Operations asked for.
    pub ops: OpSet,
    /// Attenuation asked for (the top of its lattice for "no restriction").
    pub attenuation: Attenuation,
    /// Refuse to start without it, or not.
    pub need: CapNeed,
}

/// One allow-list entry: instances of component `holder` may hold up to
/// `(ops, attenuation, ttl)` over instances of component `target`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PolicyRule {
    /// Who may hold it.
    pub holder: ComponentId,
    /// Over what.
    pub target: ComponentId,
    /// The most operations granted.
    pub ops: OpSet,
    /// The loosest attenuation granted.
    pub attenuation: Attenuation,
    /// Longest lifetime granted, in ticks from instantiation; `None` = no expiry.
    pub ttl: Option<Tick>,
}

/// The grant policy: an allow-list, **deny by default** — no rule, no grant.
/// A static first-party table until the PolicyAgent delegate (spec §9, PR-5).
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    /// The allow-list. The first rule matching `(holder, target)` applies.
    pub rules: &'static [PolicyRule],
}

impl Policy {
    /// The empty policy: nothing is ever granted.
    pub const DENY_ALL: Policy = Policy { rules: &[] };

    /// The rule for `(holder, target)`, if any.
    pub fn rule(&self, holder: &ComponentId, target: &ComponentId) -> Option<&PolicyRule> {
        self.rules
            .iter()
            .find(|r| r.holder == *holder && r.target == *target)
    }

    /// The bound the policy places on `holder`'s capability over instance
    /// `target_inst` of `target`, at tick `now`; `None` = deny.
    pub fn bound(
        &self,
        holder: &ComponentId,
        target: &ComponentId,
        target_inst: InstanceId,
        now: Tick,
    ) -> Option<Capability> {
        let rule = self.rule(holder, target)?;
        Some(Capability {
            target: Target::Instance(target_inst),
            ops: rule.ops,
            attenuation: rule.attenuation,
            expires: rule.ttl.map(|t| now.saturating_add(t)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inst(n: u64) -> Target {
        Target::Instance(InstanceId(n))
    }

    fn cap(target: Target, ops: &[Op], max_len: u16, expires: Option<Tick>) -> Capability {
        Capability {
            target,
            ops: OpSet::of(ops),
            attenuation: Attenuation::Message { max_len },
            expires,
        }
    }

    #[test]
    fn opset_algebra() {
        let sr = OpSet::of(&[Op::Send, Op::Request]);
        assert!(sr.contains(Op::Send) && sr.contains(Op::Request));
        assert!(!sr.contains(Op::Delegate));
        assert!(OpSet::of(&[Op::Send]).is_subset_of(sr));
        assert!(!sr.is_subset_of(OpSet::of(&[Op::Send])));
        assert!(OpSet::EMPTY.is_subset_of(OpSet::EMPTY));
        assert_eq!(
            sr.intersect(OpSet::of(&[Op::Request, Op::Delegate])),
            OpSet::of(&[Op::Request])
        );
        // Unknown bits are never a subset of a named set.
        assert!(!OpSet::from_bits(1 << 20).is_subset_of(sr));
        assert_eq!(Op::Delegate.bit(), 8);
        assert_eq!(Op::Reply.label(), "reply");
    }

    #[test]
    fn expiry_order_treats_none_as_never() {
        assert!(expiry_le(Some(5), None));
        assert!(expiry_le(None, None));
        assert!(!expiry_le(None, Some(5)));
        assert!(expiry_le(Some(4), Some(5)));
        assert!(!expiry_le(Some(6), Some(5)));
        assert_eq!(expiry_min(None, Some(3)), Some(3));
        assert_eq!(expiry_min(Some(9), Some(3)), Some(3));
        assert_eq!(expiry_min(None, None), None);
    }

    #[test]
    fn well_formedness_ties_ops_and_attenuation_to_the_target() {
        assert!(cap(inst(1), &[Op::Send], 16, None).is_well_formed());
        assert!(!cap(inst(1), &[], 16, None).is_well_formed(), "no ops");
        assert!(
            !cap(inst(1), &[Op::Reply], 16, None).is_well_formed(),
            "an instance capability never carries Reply"
        );
        let reply = Target::Reply {
            to: InstanceId(2),
            tag: 7,
        };
        assert!(cap(reply, &[Op::Reply], 16, Some(9)).is_well_formed());
        assert!(
            !cap(reply, &[Op::Reply, Op::Delegate], 16, None).is_well_formed(),
            "reply capabilities are never delegable"
        );
        assert!(!cap(inst(1), &[Op::Send], (MAX_PAYLOAD + 1) as u16, None).is_well_formed());
        let unknown = Capability {
            ops: OpSet::from_bits(1 << 20),
            ..cap(inst(1), &[Op::Send], 1, None)
        };
        assert!(!unknown.is_well_formed());
    }

    #[test]
    fn permits_checks_expiry_op_and_attenuation() {
        let c = cap(inst(1), &[Op::Send], 4, Some(10));
        let send = |len| Access::Message { op: Op::Send, len };
        assert!(c.permits(&send(4), 9));
        assert!(!c.permits(&send(4), 10), "expiry is exclusive");
        assert!(!c.permits(&send(5), 0), "longer than the attenuation");
        assert!(!c.permits(
            &Access::Message {
                op: Op::Request,
                len: 0
            },
            0
        ));
    }

    #[test]
    fn attenuation_predicate_and_meet() {
        let parent = cap(inst(1), &[Op::Send, Op::Delegate], 64, Some(100));
        assert!(parent.is_attenuation_of(&parent), "equal is allowed");
        assert!(cap(inst(1), &[Op::Send], 32, Some(50)).is_attenuation_of(&parent));
        assert!(!cap(inst(1), &[Op::Request], 32, Some(50)).is_attenuation_of(&parent));
        assert!(!cap(inst(1), &[Op::Send], 65, Some(50)).is_attenuation_of(&parent));
        assert!(!cap(inst(1), &[Op::Send], 32, Some(101)).is_attenuation_of(&parent));
        assert!(!cap(inst(1), &[Op::Send], 32, None).is_attenuation_of(&parent));
        assert!(!cap(inst(2), &[Op::Send], 32, Some(50)).is_attenuation_of(&parent));

        let asked = cap(inst(1), &[Op::Send, Op::Request], 256, None);
        let rule = cap(inst(1), &[Op::Send, Op::Delegate], 64, Some(100));
        let m = asked.meet(&rule).unwrap();
        assert_eq!(m, cap(inst(1), &[Op::Send], 64, Some(100)));
        assert!(m.is_attenuation_of(&asked) && m.is_attenuation_of(&rule));
        assert_eq!(
            asked.meet(&cap(inst(1), &[Op::Delegate], 8, None)),
            None,
            "no shared op"
        );
        assert_eq!(asked.meet(&cap(inst(2), &[Op::Send], 8, None)), None);
    }

    #[test]
    fn policy_is_deny_by_default() {
        let a = ComponentId([1; 32]);
        let b = ComponentId([2; 32]);
        static RULES: [PolicyRule; 1] = [PolicyRule {
            holder: ComponentId([1; 32]),
            target: ComponentId([2; 32]),
            ops: OpSet::of(&[Op::Send]),
            attenuation: Attenuation::Message { max_len: 8 },
            ttl: Some(5),
        }];
        let p = Policy { rules: &RULES };
        assert!(Policy::DENY_ALL.bound(&a, &b, InstanceId(3), 0).is_none());
        assert!(
            p.bound(&b, &a, InstanceId(3), 0).is_none(),
            "rules are directional"
        );
        let bound = p.bound(&a, &b, InstanceId(3), 10).unwrap();
        assert_eq!(bound.target, Target::Instance(InstanceId(3)));
        assert_eq!(bound.expires, Some(15));
        assert_eq!(
            p.bound(&a, &b, InstanceId(3), u64::MAX).unwrap().expires,
            Some(u64::MAX),
            "ttl saturates"
        );
    }

    #[test]
    fn reasons_have_stable_labels() {
        assert_eq!(DenyReason::Foreign.label(), "foreign");
        assert_eq!(DenyReason::MissingRequired.label(), "missing-required");
    }
}

/// Kani harnesses for the lattice. Compiled only under `cargo kani`.
#[cfg(kani)]
pub(crate) mod proofs {
    use super::*;

    /// A symbolic target of every kind. FS-1c adds its variant here.
    pub(crate) fn any_target() -> Target {
        if kani::any() {
            Target::Instance(InstanceId(kani::any()))
        } else {
            Target::Reply {
                to: InstanceId(kani::any()),
                tag: kani::any(),
            }
        }
    }

    /// A symbolic attenuation of every kind. FS-1c adds its variant here.
    pub(crate) fn any_attenuation() -> Attenuation {
        Attenuation::Message {
            max_len: kani::any(),
        }
    }

    /// A symbolic capability — any bits, any bounds, well formed or not.
    pub(crate) fn any_capability() -> Capability {
        Capability {
            target: any_target(),
            ops: OpSet::from_bits(kani::any()),
            attenuation: any_attenuation(),
            expires: if kani::any() { Some(kani::any()) } else { None },
        }
    }

    /// A symbolic access of every kind. FS-1c adds its variant here.
    pub(crate) fn any_access() -> Access {
        let op = match kani::any::<u8>() % 4 {
            0 => Op::Send,
            1 => Op::Request,
            2 => Op::Reply,
            _ => Op::Delegate,
        };
        Access::Message {
            op,
            len: kani::any(),
        }
    }

    /// `⊑` is **sound** with respect to what capabilities permit — if
    /// `child ⊑ parent`, every access the child permits at any tick, the parent
    /// permits — and it is a preorder (reflexive, transitive), so a chain of
    /// delegations never amplifies either. The meet `grant` uses lies below
    /// both of its arguments. A well-formed capability on a reply target is
    /// exactly `{Reply}` — never delegable, never a send right — and the
    /// tables hold only well-formed capabilities (`table::proofs`). All over
    /// fully symbolic capabilities, accesses and ticks; no loops.
    #[kani::proof]
    fn attenuation_order_is_sound_and_transitive() {
        let a = any_capability();
        let b = any_capability();
        let c = any_capability();
        let access = any_access();
        let now: Tick = kani::any();

        if a.is_attenuation_of(&b) && a.permits(&access, now) {
            assert!(b.permits(&access, now));
        }
        assert!(a.is_attenuation_of(&a));
        if a.is_attenuation_of(&b) && b.is_attenuation_of(&c) {
            assert!(a.is_attenuation_of(&c));
        }
        if let Some(m) = a.meet(&b) {
            assert!(m.is_attenuation_of(&a));
            assert!(m.is_attenuation_of(&b));
        }
        if a.is_well_formed() && matches!(a.target, Target::Reply { .. }) {
            assert!(a.ops == OpSet::of(&[Op::Reply]));
        }
    }
}
