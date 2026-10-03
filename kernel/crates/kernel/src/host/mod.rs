//! Component host — the only code that turns component bytes into a running
//! instance (spec `docs/specs/2026-09-18-component-model-design.md`, §5–§8,
//! §12–§14; PR-1 and PR-2 of the staging in §14).
//!
//! All safe Rust, zero `hal` delta.
//!
//! - **Identity** ([`ComponentId`], §6): `SHA-256(TAG ‖ le64(|code|) ‖ code ‖
//!   le64(|params|) ‖ params)`. The framing is *injective* (Kani:
//!   `proofs::framing_is_injective_bounded`), which unframed `H(code ‖ params)`
//!   is not (amendment A1). [`InstanceId`] is per boot, per instantiation, and
//!   never reused.
//! - **The runtime seam** ([`ComponentRuntime`]): the only thing the host sees
//!   of whatever executes a component. [`native::NativeRuntime`] is the first
//!   implementation; the memory-boundary gate (spec §12) adds the second before
//!   the trait freezes.
//! - **Verify before run** ([`Manifest::verify`]): the requester names an id in
//!   a [`Manifest`]; the host hashes the bytes it is about to run and refuses on
//!   mismatch *before* the runtime sees them. Instantiation takes the
//!   [`Verified`] token only `verify` mints, so the order is a type, not a
//!   convention.
//! - **Grants** (PR-2, spec §8, amendment A8): a manifest lists the
//!   capabilities it asks for, each `Required` or `Optional`. Each is bound to
//!   the oldest live instance of the named component and granted as
//!   `request ∧ policy` ([`crate::cap::Policy`], deny by default). Every request
//!   is resolved **before** anything changes; a required one that cannot be
//!   granted refuses the instantiation ([`InstantiateError::MissingRequiredCap`]),
//!   an optional one is skipped and the refusal logged.
//! - **Kernel-wide** (PR-2): the host lives in `crate::bus::HOST`, behind one
//!   lock; component code never runs while it is held. Every instance's inbox
//!   arena, every capability table and the denial log are part of this fixed
//!   value — the host allocates nothing, ever (threat T-DOS-4). Moving messages
//!   is `crate::bus`'s job.
//!
//! A `Host` is ~60 KiB: it lives in a `static` in the kernel and on the (8 MiB)
//! test-thread stacks in host tests — never on a 16 KiB kernel stack.
//!
//! Boot proofs: [`prove_hello`] (PR-1, still asserted) and
//! `crate::bus::proof::prove_caps` (PR-2).

pub mod codec;
pub mod inbox;
pub mod native;
pub mod probe;
pub mod seen;

use crate::cap::deny::{Action, DenyLog, DenyRecord, DenyTotals, DENY_LOG_LEN};
use crate::cap::table::{CapSpace, MAX_CAPS};
use crate::cap::{CapIndex, CapNeed, CapRequest, Capability, DenyReason, Policy, Target, Tick};
use crate::hash::{Digest, Sha256};
use codec::{DecodeError, Envelope, Sender, Wire};
use inbox::InboxRing;

/// Live instances the host can track. Fixed slab: no growth, no allocation
/// under any lock (the same discipline as `sched::TaskTable`). Instance slot
/// `i` owns capability table `i`.
pub const MAX_INSTANCES: usize = 16;
/// Envelopes one instance's inbox holds before senders see `Busy`.
pub const MAX_INBOX: usize = 8;
/// Capability requests one manifest may carry.
pub const MAX_MANIFEST_CAPS: usize = 8;
/// Denial-log rate-limit buckets: one per instance slot, plus one for
/// refusals with no instance (a manifest refused before it started).
pub const DENY_BUCKETS: usize = MAX_INSTANCES + 1;
/// The bucket for refusals with no instance.
pub const UNBOUND_BUCKET: usize = MAX_INSTANCES;
/// Domain-separation tag that opens every framed id input (spec §6).
pub const ID_DOMAIN_TAG: &[u8] = b"sentinelos:component:v1";

/// *What* a component is: the framed hash of its code and parameters.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ComponentId(pub Digest);

impl ComponentId {
    /// Reserved for the kernel itself as a message sender. Not a hash of
    /// anything (no preimage is expected to reach it).
    pub const KERNEL: ComponentId = ComponentId([0; 32]);

    /// `SHA-256(frame(code, params))` — see [`frame_into`].
    pub fn derive(code: &[u8], params: &[u8]) -> ComponentId {
        let mut h = Sha256::new();
        frame_into(code, params, &mut h);
        ComponentId(h.finalize())
    }

    /// The first four bytes as eight lowercase hex characters — the short form
    /// the boot line prints.
    pub fn short_hex(&self) -> [u8; 8] {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = [0u8; 8];
        for (i, b) in self.0[..4].iter().enumerate() {
            out[2 * i] = HEX[usize::from(b >> 4)];
            out[2 * i + 1] = HEX[usize::from(b & 0xF)];
        }
        out
    }
}

/// *Which* running instance: per boot, per instantiation, never reused.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct InstanceId(pub u64);

impl InstanceId {
    /// The kernel as a message endpoint.
    pub const KERNEL: InstanceId = InstanceId(0);
}

/// A runtime's own name for an instance it hosts. Opaque to the host.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RuntimeHandle(pub u32);

/// Anything that absorbs the framed id input byte-for-byte: the hasher in
/// production, a byte buffer in the tests and the Kani harness. One
/// [`frame_into`] serves both, so what is proven injective is what is hashed.
pub trait FrameSink {
    /// Absorb the next bytes of the framed input.
    fn absorb(&mut self, bytes: &[u8]);
}

impl FrameSink for Sha256 {
    fn absorb(&mut self, bytes: &[u8]) {
        self.update(bytes);
    }
}

/// Feed `TAG ‖ le64(|code|) ‖ code ‖ le64(|params|) ‖ params` to `sink`.
///
/// Length prefixes bind the split: `("a", "bc")` and `("ab", "c")` frame to
/// different byte strings, so they get different ids. The tag separates this
/// hash from every other use of SHA-256 in the kernel.
pub fn frame_into(code: &[u8], params: &[u8], sink: &mut impl FrameSink) {
    sink.absorb(ID_DOMAIN_TAG);
    sink.absorb(&(code.len() as u64).to_le_bytes());
    sink.absorb(code);
    sink.absorb(&(params.len() as u64).to_le_bytes());
    sink.absorb(params);
}

/// What a requester hands the host: the bytes, the parameters, the id it
/// *claims* they hash to, and the capabilities the component asks for. The
/// host checks the claim; it never trusts it. The requests bound nothing by
/// themselves — the policy does (`grant = request ∧ policy`).
///
/// The capability requests are not part of the id yet (threat T-MAN-1: today
/// every manifest is compiled into the image and only the kernel
/// instantiates). Decided as component amendment A12, landing in PR-2b before
/// PR-3: the v2 framing binds them into the id, and they name services.
#[derive(Clone, Copy, Debug)]
pub struct Manifest {
    /// The component's code (for a native component, its descriptor).
    pub code: &'static [u8],
    /// Its instantiation parameters.
    pub params: &'static [u8],
    /// The id the requester claims `(code, params)` hash to.
    pub id: ComponentId,
    /// Capabilities it asks for, each required or optional (A8).
    pub caps: &'static [CapRequest],
}

impl Manifest {
    /// Hash what would run and compare with the claimed id. The only way to
    /// obtain a [`Verified`] token, which instantiation requires.
    pub fn verify(&self) -> Result<Verified<'_>, InstantiateError> {
        if ComponentId::derive(self.code, self.params) == self.id {
            Ok(Verified { manifest: self })
        } else {
            Err(InstantiateError::IdMismatch)
        }
    }
}

/// Proof that a manifest's id matched the hash of its bytes. Only
/// [`Manifest::verify`] constructs one, so the hash cannot be skipped — and it
/// can be computed with no lock held.
#[derive(Clone, Copy, Debug)]
pub struct Verified<'m> {
    manifest: &'m Manifest,
}

/// Why the host refused to instantiate.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InstantiateError {
    /// `derive(code, params) != manifest.id`. Nothing ran.
    IdMismatch,
    /// The runtime has no component for these bytes.
    UnknownCode,
    /// The host's or the runtime's instance table is full.
    TooManyInstances,
    /// The runtime rejected the bytes for a reason of its own.
    RuntimeRejected,
    /// A capability the manifest marks required could not be granted:
    /// refused to start rather than run degraded (amendment A8).
    MissingRequiredCap,
    /// The manifest asks for more than [`MAX_MANIFEST_CAPS`] capabilities.
    TooManyCaps,
}

impl InstantiateError {
    /// Fixed label for `fmt`-free console output.
    pub fn label(self) -> &'static str {
        match self {
            InstantiateError::IdMismatch => "id-mismatch",
            InstantiateError::UnknownCode => "unknown-code",
            InstantiateError::TooManyInstances => "too-many-instances",
            InstantiateError::RuntimeRejected => "runtime-rejected",
            InstantiateError::MissingRequiredCap => "missing-required-cap",
            InstantiateError::TooManyCaps => "too-many-caps",
        }
    }
}

/// Why a call or a delivery did not happen. **Silence is denial** (spec §7):
/// none of these fabricate a reply.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CallError {
    /// No live instance by that id.
    NoSuchInstance,
    /// The instance is already running a message handler or an export (on
    /// another core); nothing ran. One instance's code never runs twice at
    /// once.
    Busy,
    /// The request payload exceeds `codec::MAX_PAYLOAD`.
    PayloadTooLong,
    /// The component has no export by that name.
    NoSuchExport,
    /// The export ran and refused.
    Export(native::ExportError),
    /// A wire envelope on the delivery path failed to decode.
    Wire(DecodeError),
    /// The reply did not fit the caller's buffer.
    ReplyTooLong,
    /// The stamped reply did not answer this request (internal consistency).
    ReplyMismatch,
}

impl CallError {
    /// Fixed label for `fmt`-free console output.
    pub fn label(self) -> &'static str {
        match self {
            CallError::NoSuchInstance => "no-such-instance",
            CallError::Busy => "busy",
            CallError::PayloadTooLong => "payload-too-long",
            CallError::NoSuchExport => "no-such-export",
            CallError::Export(e) => e.label(),
            CallError::Wire(e) => e.label(),
            CallError::ReplyTooLong => "reply-too-long",
            CallError::ReplyMismatch => "reply-mismatch",
        }
    }
}

/// The seam between the host and whatever executes a component. PR-1/PR-2:
/// the native runtime. The gate before PR-3 adds the second implementation
/// (`wasmi` under the §12 conditions, or ring-3) behind this same trait.
///
/// Component code runs through [`ComponentRuntime::call`] and
/// [`ComponentRuntime::deliver`] — associated functions over a `Copy`
/// [`ComponentRuntime::Entry`], so the host can invoke them with **no lock
/// held** (`crate::bus` takes the entry under the lock, drops it, then runs).
/// The code reaches the kernel only through the `crate::bus::Ctx` it is
/// handed, which acts as that instance and nothing else.
pub trait ComponentRuntime: Sized {
    /// What the host needs to run an instance's code without the runtime
    /// borrowed (for the native runtime, the component's static descriptor).
    type Entry: Copy;
    /// `"native"`, `"wasm"`, … — printed in the boot line.
    fn name(&self) -> &'static str;
    /// Prepare `code` with `params`. The host has already verified the id.
    fn instantiate(
        &mut self,
        code: &[u8],
        params: &[u8],
    ) -> Result<RuntimeHandle, InstantiateError>;
    /// Forget an instance (its slot may be reused; its handle is dead).
    fn release(&mut self, handle: RuntimeHandle);
    /// The runnable entry for a live instance.
    fn entry(&self, handle: RuntimeHandle) -> Option<Self::Entry>;
    /// Fuel consumed so far, or `None` when this runtime cannot meter.
    fn fuel_used(&self, handle: RuntimeHandle) -> Option<u64>;
    /// Run `export` (a kernel-originated call) with request payload `args`;
    /// write the reply payload into `reply` and return its length.
    fn call(
        entry: Self::Entry,
        ctx: &crate::bus::Ctx<'_, Self>,
        export: &str,
        args: &[u8],
        reply: &mut [u8],
    ) -> Result<usize, CallError>;
    /// Hand one delivered envelope to the instance's message handler.
    fn deliver(
        entry: Self::Entry,
        ctx: &crate::bus::Ctx<'_, Self>,
        env: &Envelope,
    ) -> Result<(), CallError>;
}

/// One live instance. Its inbox *is* its pre-sized payload arena: a fixed
/// ring of encoded envelopes, part of the host value itself.
pub(crate) struct Instance {
    /// Which instance.
    pub(crate) id: InstanceId,
    /// What it runs.
    pub(crate) component: ComponentId,
    /// The runtime's name for it.
    pub(crate) handle: RuntimeHandle,
    /// Its inbox.
    pub(crate) inbox: InboxRing<Wire, MAX_INBOX>,
    /// Next correlation tag for its own requests (never 0).
    pub(crate) next_reply_tag: u32,
    /// Next tag for kernel calls into it.
    pub(crate) next_kernel_tag: u32,
    /// The index granted for each manifest request, in manifest order.
    pub(crate) grants: [Option<CapIndex>; MAX_MANIFEST_CAPS],
    /// Its code is running now (a delivered envelope's handler or a kernel
    /// call into an export), on some core. Set and cleared under the host
    /// lock by `crate::bus`; while set, neither `dispatch` nor `call` starts
    /// its code again, so a handler never runs concurrently with itself.
    pub(crate) running: bool,
}

/// The host: a runtime, a fixed table of instances, their capability tables,
/// the grant policy, and the denial log.
pub struct Host<R: ComponentRuntime> {
    pub(crate) runtime: R,
    pub(crate) policy: Policy,
    pub(crate) instances: [Option<Instance>; MAX_INSTANCES],
    pub(crate) caps: CapSpace<MAX_INSTANCES, MAX_CAPS>,
    pub(crate) deny: DenyLog<DENY_BUCKETS, DENY_LOG_LEN>,
    pub(crate) next_instance: u64,
}

impl<R: ComponentRuntime> Host<R> {
    /// A host with no instances, granting under `policy`.
    pub const fn new(runtime: R, policy: Policy) -> Self {
        Self {
            runtime,
            policy,
            instances: [const { None }; MAX_INSTANCES],
            caps: CapSpace::new(),
            deny: DenyLog::new(),
            // 0 is the kernel.
            next_instance: 1,
        }
    }

    /// The runtime's name.
    pub fn runtime_name(&self) -> &'static str {
        self.runtime.name()
    }

    /// Live instances.
    pub fn instance_count(&self) -> usize {
        self.instances.iter().filter(|s| s.is_some()).count()
    }

    /// The component an instance runs, if it exists.
    pub fn component_of(&self, inst: InstanceId) -> Option<ComponentId> {
        Some(self.instance(inst)?.component)
    }

    /// Fuel the runtime reports for `inst`, if it meters.
    pub fn fuel_used(&self, inst: InstanceId) -> Option<u64> {
        self.runtime.fuel_used(self.instance(inst)?.handle)
    }

    /// The index granted for `inst`'s manifest request `i`, if it was granted.
    /// (It may since have been released; the index then refuses as stale.)
    pub fn granted(&self, inst: InstanceId, i: usize) -> Option<CapIndex> {
        *self.instance(inst)?.grants.get(i)?
    }

    /// Capabilities `inst` currently holds.
    pub fn cap_count(&self, inst: InstanceId) -> usize {
        self.slot_of(inst).map_or(0, |s| self.caps.live_count(s))
    }

    /// Envelopes waiting in `inst`'s inbox.
    pub fn inbox_len(&self, inst: InstanceId) -> Option<usize> {
        Some(self.instance(inst)?.inbox.len())
    }

    /// The denial log's counters.
    pub fn deny_totals(&self) -> DenyTotals {
        self.deny.totals()
    }

    /// Denial records currently held.
    pub fn deny_len(&self) -> usize {
        self.deny.len()
    }

    /// The `i`-th oldest denial record held.
    pub fn deny_record(&self, i: usize) -> Option<DenyRecord> {
        self.deny.get(i)
    }

    /// Read-only view of the capability tables (audit, tests).
    pub fn caps(&self) -> &CapSpace<MAX_INSTANCES, MAX_CAPS> {
        &self.caps
    }

    fn instance(&self, inst: InstanceId) -> Option<&Instance> {
        self.instances[self.slot_of(inst)?].as_ref()
    }

    /// The slot (= capability table) of a live instance.
    pub(crate) fn slot_of(&self, inst: InstanceId) -> Option<usize> {
        if inst == InstanceId::KERNEL {
            return None;
        }
        self.instances
            .iter()
            .position(|s| s.as_ref().is_some_and(|x| x.id == inst))
    }

    /// The kernel-stamped identity of the instance in `slot` (spec §7, A2).
    pub(crate) fn sender_at(&self, slot: usize) -> Option<Sender> {
        let i = self.instances.get(slot)?.as_ref()?;
        Some(Sender {
            instance: i.id,
            component: i.component,
        })
    }

    /// The oldest live instance of `component` — how a manifest's request,
    /// which names an id, is bound to an instance (spec §6).
    fn oldest_instance_of(&self, component: &ComponentId) -> Option<InstanceId> {
        self.instances
            .iter()
            .flatten()
            .filter(|i| i.component == *component)
            .map(|i| i.id)
            .min()
    }

    /// What `holder` would be granted for `req` now: `(request, bound)`, whose
    /// meet `grant` installs; or why not.
    fn plan_grant(
        &self,
        holder: &ComponentId,
        req: &CapRequest,
        now: Tick,
    ) -> Result<(Capability, Capability), DenyReason> {
        let target = self
            .oldest_instance_of(&req.target)
            .ok_or(DenyReason::TargetGone)?;
        let bound = self
            .policy
            .bound(holder, &req.target, target, now)
            .ok_or(DenyReason::PolicyRefused)?;
        let requested = Capability {
            target: Target::Instance(target),
            ops: req.ops,
            attenuation: req.attenuation,
            expires: None,
        };
        let granted = requested.meet(&bound).ok_or(DenyReason::PolicyRefused)?;
        if !granted.is_well_formed() {
            return Err(DenyReason::Malformed);
        }
        Ok((requested, bound))
    }

    /// Verify, then instantiate — [`Self::instantiate_verified`] after
    /// [`Manifest::verify`]. Tests only: it hashes inside whatever lock the
    /// caller holds, which must never be the kernel-wide host's (the kernel
    /// path, `crate::bus::instantiate`, hashes before taking the lock).
    #[cfg(test)]
    pub fn instantiate(
        &mut self,
        manifest: &Manifest,
        now: Tick,
    ) -> Result<InstanceId, InstantiateError> {
        let verified = manifest.verify()?;
        self.instantiate_verified(verified, now)
    }

    /// Instantiate a verified manifest and grant its capabilities.
    ///
    /// Order matters, and nothing changes until every check has passed:
    /// 1. a free instance slot is found (not yet claimed);
    /// 2. every capability request is resolved against the live instances,
    ///    the policy **and the room in that slot's table** — retired slots
    ///    never come back (threat T-DOS-5) — the `Required` ones first, so an
    ///    `Optional` one can never take the room a `Required` one needs; a
    ///    `Required` one that cannot be granted refuses here (logged,
    ///    amendment A8);
    /// 3. the slot and the runtime are claimed;
    /// 4. the grants are installed (`request ∧ policy`) in the instance's own
    ///    table and their indices recorded in manifest order; refused
    ///    `Optional` requests are logged against the new instance, with the
    ///    reason (`TableFull` when there was no room).
    pub fn instantiate_verified(
        &mut self,
        verified: Verified<'_>,
        now: Tick,
    ) -> Result<InstanceId, InstantiateError> {
        let m = verified.manifest;
        if m.caps.len() > MAX_MANIFEST_CAPS {
            return Err(InstantiateError::TooManyCaps);
        }
        let slot = self
            .instances
            .iter()
            .position(Option::is_none)
            .ok_or(InstantiateError::TooManyInstances)?;
        // Refusals before the instance exists are the kernel's, under the
        // component's name.
        let unborn = Sender {
            instance: InstanceId::KERNEL,
            component: m.id,
        };
        // Every planned grant takes one usable slot. The room is handed out
        // to the `Required` requests first, then the `Optional` ones; the
        // grants still install in manifest order (`granted(i)` is by it), and
        // all of them fit, whatever that order, since none was planned
        // without a slot.
        let mut room = self.caps.usable_slots(slot);
        let mut plan: [Result<(Capability, Capability), DenyReason>; MAX_MANIFEST_CAPS] =
            [Err(DenyReason::NotHeld); MAX_MANIFEST_CAPS];
        for need in [CapNeed::Required, CapNeed::Optional] {
            for (i, req) in m.caps.iter().enumerate() {
                if req.need != need {
                    continue;
                }
                let mut planned = self.plan_grant(&m.id, req, now);
                if planned.is_ok() {
                    if room == 0 {
                        planned = Err(DenyReason::TableFull);
                    } else {
                        room -= 1;
                    }
                }
                if planned.is_err() && need == CapNeed::Required {
                    self.deny.record(
                        now,
                        UNBOUND_BUCKET,
                        unborn,
                        CapIndex::KERNEL,
                        Action::Grant,
                        DenyReason::MissingRequired,
                    );
                    return Err(InstantiateError::MissingRequiredCap);
                }
                plan[i] = planned;
            }
        }

        let handle = self.runtime.instantiate(m.code, m.params)?;
        let id = InstanceId(self.next_instance);
        self.next_instance += 1;
        // Nothing of a previous occupant survives: its table was cleared at
        // `terminate`; clearing again is a no-op that keeps this local.
        self.caps.clear_table(slot);
        self.deny.reset_bucket(slot, now);
        let me = Sender {
            instance: id,
            component: m.id,
        };

        let mut grants = [None; MAX_MANIFEST_CAPS];
        for (i, req) in m.caps.iter().enumerate() {
            let outcome = match plan[i] {
                Ok((requested, bound)) => {
                    self.caps
                        .grant(slot, &requested, &bound)
                        .map_err(|e| match e {
                            crate::cap::CapError::Deny(r) => r,
                            crate::cap::CapError::TableFull | crate::cap::CapError::NoSuchTable => {
                                DenyReason::TableFull
                            }
                        })
                }
                Err(r) => Err(r),
            };
            match outcome {
                Ok(idx) => grants[i] = Some(idx),
                Err(reason) => {
                    if req.need == CapNeed::Required {
                        // Unreachable: every required grant was planned
                        // above against this table's usable slots (retired
                        // ones excluded). Never run degraded regardless:
                        // undo everything, and log it as a refused start.
                        self.caps.clear_table(slot);
                        self.runtime.release(handle);
                        self.deny.record(
                            now,
                            UNBOUND_BUCKET,
                            unborn,
                            CapIndex::KERNEL,
                            Action::Grant,
                            DenyReason::MissingRequired,
                        );
                        return Err(InstantiateError::MissingRequiredCap);
                    }
                    // Instantiation is the kernel's act: rate-limited in the
                    // kernel's bucket, so the new instance starts with its
                    // full budget — but recorded under the instance's name.
                    self.deny.record(
                        now,
                        UNBOUND_BUCKET,
                        me,
                        CapIndex::KERNEL,
                        Action::Grant,
                        reason,
                    );
                }
            }
        }

        self.instances[slot] = Some(Instance {
            id,
            component: m.id,
            handle,
            inbox: InboxRing::new(),
            next_reply_tag: 1,
            next_kernel_tag: 1,
            grants,
            running: false,
        });
        Ok(id)
    }

    /// End an instance: free every capability it holds, and every capability
    /// anywhere that names it (descendants included), release its runtime
    /// slot and its inbox. Returns how many capabilities were freed. Its
    /// `InstanceId` is never reused, so nothing can address the next occupant
    /// of the slot by the old id (threat T-ID-1).
    pub fn terminate(&mut self, inst: InstanceId) -> Result<usize, CallError> {
        let slot = self.slot_of(inst).ok_or(CallError::NoSuchInstance)?;
        let mut freed = self.caps.clear_table(slot);
        freed += self.caps.free_where(|e| e.cap.target.names(inst));
        if let Some(i) = self.instances[slot].take() {
            self.runtime.release(i.handle);
        }
        Ok(freed)
    }
}

/// Boot proof for PR-1 (spec §14): the `hello` component, native runtime, on
/// the kernel-wide host since PR-2.
///
/// 1. A manifest with one bit of the id flipped is **refused** and nothing is
///    instantiated (`wrong-id=refused`).
/// 2. The real manifest verifies and instantiates (`verified=yes`).
/// 3. `greet("sentinelos")` answers `hello, sentinelos` through the envelope
///    codec, stamped by the kernel both ways (`reply=ok`).
/// 4. The instance is terminated: the kernel-wide host is left as found.
///
/// Prints one line, `fmt`-free (the target's `{}` formatting faults — see
/// `hal::serial::write_str`); `cargo xtask test` asserts every field.
pub fn prove_hello() {
    use crate::bus;
    use hal::serial::write_str;

    let before = bus::with_host(|h| h.instance_count());

    // Negative first: the requester lies about the id by one bit.
    let mut wrong = native::HELLO_MANIFEST;
    wrong.id.0[0] ^= 0x01;
    let wrong_refused = matches!(
        bus::instantiate(&bus::HOST, &wrong),
        Err(InstantiateError::IdMismatch)
    ) && bus::with_host(|h| h.instance_count()) == before;

    let instantiated = bus::instantiate(&bus::HOST, &native::HELLO_MANIFEST);
    let verified = instantiated.is_ok();

    let mut reply = [0u8; 64];
    let reply_result: Result<bool, CallError> = match instantiated {
        Ok(inst) => bus::call(&bus::HOST, inst, "greet", b"sentinelos", &mut reply)
            .map(|n| &reply[..n] == b"hello, sentinelos"),
        Err(_) => Ok(false),
    };
    let reply_ok = matches!(reply_result, Ok(true));
    let cleaned = match instantiated {
        Ok(inst) => bus::terminate(&bus::HOST, inst).is_ok(),
        Err(_) => true,
    };
    let ok = wrong_refused && verified && reply_ok && cleaned;

    write_str("[comp] hello: id=");
    let hex = native::HELLO_MANIFEST.id.short_hex();
    if let Ok(s) = core::str::from_utf8(&hex) {
        write_str(s);
    }
    write_str(" verified=");
    write_str(match instantiated {
        Ok(_) => "yes",
        Err(e) => e.label(),
    });
    write_str(" wrong-id=");
    write_str(if wrong_refused { "refused" } else { "ACCEPTED" });
    write_str(" runtime=");
    write_str(bus::with_host(|h| h.runtime_name()));
    write_str(" reply=");
    match reply_result {
        Ok(true) => write_str("ok"),
        Ok(false) => write_str("WRONG"),
        Err(e) => {
            write_str("FAIL(");
            write_str(e.label());
            write_str(")");
        }
    }
    write_str(if ok { " ok\n" } else { " FAIL\n" });
}

#[cfg(test)]
mod tests {
    use super::codec::{Kind, Sender};
    use super::native::{NativeRuntime, BOOT_POLICY, HELLO_DESCRIPTOR, HELLO_MANIFEST, REGISTRY};
    use super::*;
    use crate::bus;
    use crate::cap::{Attenuation, Op, OpSet};
    use alloc::vec::Vec;
    use hal::sync::SpinMutex;

    struct VecSink(Vec<u8>);
    impl FrameSink for VecSink {
        fn absorb(&mut self, bytes: &[u8]) {
            self.0.extend_from_slice(bytes);
        }
    }

    fn framed(code: &[u8], params: &[u8]) -> Vec<u8> {
        let mut s = VecSink(Vec::new());
        frame_into(code, params, &mut s);
        s.0
    }

    fn hello_host() -> SpinMutex<Host<NativeRuntime>> {
        SpinMutex::new(Host::new(NativeRuntime::new(REGISTRY), BOOT_POLICY))
    }

    #[test]
    fn framing_binds_the_split_and_the_tag() {
        // The classic collision unframed concatenation allows.
        assert_ne!(framed(b"a", b"bc"), framed(b"ab", b"c"));
        assert_ne!(
            ComponentId::derive(b"a", b"bc"),
            ComponentId::derive(b"ab", b"c")
        );
        assert_ne!(framed(b"", b""), Vec::<u8>::new());
        assert!(framed(b"x", b"y").starts_with(ID_DOMAIN_TAG));
        let f = framed(b"abc", b"de");
        assert_eq!(f.len(), ID_DOMAIN_TAG.len() + 8 + 3 + 8 + 2);
        assert_eq!(
            &f[ID_DOMAIN_TAG.len()..ID_DOMAIN_TAG.len() + 8],
            &3u64.to_le_bytes()
        );
    }

    #[test]
    fn derive_is_deterministic_and_short_hex_is_lowercase() {
        let a = ComponentId::derive(HELLO_DESCRIPTOR, b"");
        assert_eq!(a, ComponentId::derive(HELLO_DESCRIPTOR, b""));
        assert_ne!(a, ComponentId::KERNEL);
        let hex = ComponentId([
            0xAB, 0xCD, 0x01, 0x2F, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0,
        ])
        .short_hex();
        assert_eq!(&hex, b"abcd012f");
    }

    #[test]
    fn wrong_id_is_refused_before_anything_runs() {
        let cell = hello_host();
        let mut wrong = HELLO_MANIFEST;
        wrong.id.0[31] ^= 0x80;
        assert_eq!(wrong.verify().err(), Some(InstantiateError::IdMismatch));
        assert_eq!(
            bus::instantiate(&cell, &wrong),
            Err(InstantiateError::IdMismatch)
        );
        assert_eq!(cell.lock().instance_count(), 0);
        // A manifest that lies about the *code* fails the same way: the id
        // was computed for other bytes.
        let lying = Manifest {
            code: b"something else",
            ..HELLO_MANIFEST
        };
        assert_eq!(
            cell.lock().instantiate(&lying, 0),
            Err(InstantiateError::IdMismatch)
        );
        assert_eq!(cell.lock().instance_count(), 0);
    }

    #[test]
    fn unknown_code_with_an_honest_id_is_refused_by_the_runtime() {
        let cell = hello_host();
        let code: &'static [u8] = b"honest but unregistered";
        let m = Manifest {
            code,
            params: b"",
            id: ComponentId::derive(code, b""),
            caps: &[],
        };
        assert_eq!(
            bus::instantiate(&cell, &m),
            Err(InstantiateError::UnknownCode)
        );
        assert_eq!(cell.lock().instance_count(), 0);
    }

    #[test]
    fn instantiate_call_and_kernel_stamping() {
        let cell = hello_host();
        let inst = bus::instantiate(&cell, &HELLO_MANIFEST).unwrap();
        assert_eq!(inst, InstanceId(1));
        {
            let h = cell.lock();
            assert_eq!(h.component_of(inst), Some(HELLO_MANIFEST.id));
            assert_eq!(h.fuel_used(inst), None);
            assert_eq!(h.runtime_name(), "native");
            assert_eq!(h.cap_count(inst), 0);
        }

        let reply = bus::call_envelope(&cell, inst, "greet", b"sentinelos").unwrap();
        assert_eq!(reply.payload.as_slice(), b"hello, sentinelos");
        // Stamped by the kernel with the INSTANCE's identity, routed to the kernel.
        assert_eq!(
            reply.from,
            Sender {
                instance: inst,
                component: HELLO_MANIFEST.id
            }
        );
        assert_eq!(reply.to, InstanceId::KERNEL);
        assert_eq!(reply.kind, Kind::Reply { reply_tag: 1 });
        // Reply tags advance per request.
        let again = bus::call_envelope(&cell, inst, "greet", b"x").unwrap();
        assert_eq!(again.kind, Kind::Reply { reply_tag: 2 });

        let mut out = [0u8; 64];
        let n = bus::call(&cell, inst, "greet", b"world", &mut out).unwrap();
        assert_eq!(&out[..n], b"hello, world");
        // The kernel's calls never touch the component's inbox.
        assert_eq!(cell.lock().inbox_len(inst), Some(0));
    }

    #[test]
    fn call_errors_are_refusals_not_replies() {
        let cell = hello_host();
        let mut out = [0u8; 8];
        assert_eq!(
            bus::call(&cell, InstanceId(42), "greet", b"", &mut out),
            Err(CallError::NoSuchInstance)
        );
        let inst = bus::instantiate(&cell, &HELLO_MANIFEST).unwrap();
        assert_eq!(
            bus::call(&cell, inst, "shout", b"", &mut out),
            Err(CallError::NoSuchExport)
        );
        assert_eq!(
            bus::call(&cell, inst, "greet", b"a long name", &mut out),
            Err(CallError::ReplyTooLong)
        );
        let too_long = [0u8; codec::MAX_PAYLOAD + 1];
        assert_eq!(
            bus::call(&cell, inst, "greet", &too_long, &mut out),
            Err(CallError::PayloadTooLong)
        );
        // A reply that would overflow the payload is refused by the export.
        let near = [b'z'; codec::MAX_PAYLOAD - 3];
        let mut big = [0u8; codec::MAX_PAYLOAD];
        assert_eq!(
            bus::call(&cell, inst, "greet", &near, &mut big),
            Err(CallError::Export(native::ExportError::ReplyTooLong))
        );
    }

    #[test]
    fn instance_table_is_bounded_and_ids_never_repeat() {
        let cell = hello_host();
        let mut last = InstanceId::KERNEL;
        for _ in 0..MAX_INSTANCES {
            let id = bus::instantiate(&cell, &HELLO_MANIFEST).unwrap();
            assert!(id > last);
            last = id;
        }
        assert_eq!(
            bus::instantiate(&cell, &HELLO_MANIFEST),
            Err(InstantiateError::TooManyInstances)
        );
        assert_eq!(cell.lock().instance_count(), MAX_INSTANCES);
        // A freed slot is reused, its id is not.
        assert!(bus::terminate(&cell, InstanceId(3)).is_ok());
        let next = bus::instantiate(&cell, &HELLO_MANIFEST).unwrap();
        assert_eq!(next, InstanceId(MAX_INSTANCES as u64 + 1));
        assert_eq!(
            bus::terminate(&cell, InstanceId(3)),
            Err(CallError::NoSuchInstance)
        );
    }

    #[test]
    fn manifest_caps_are_bounded() {
        static MANY: [CapRequest; MAX_MANIFEST_CAPS + 1] = [CapRequest {
            target: ComponentId([9; 32]),
            ops: OpSet::of(&[Op::Send]),
            attenuation: Attenuation::UNRESTRICTED_MESSAGE,
            need: CapNeed::Optional,
        }; MAX_MANIFEST_CAPS + 1];
        let m = Manifest {
            caps: &MANY,
            ..HELLO_MANIFEST
        };
        assert_eq!(
            bus::instantiate(&hello_host(), &m),
            Err(InstantiateError::TooManyCaps)
        );
    }

    #[test]
    fn labels_are_stable() {
        assert_eq!(InstantiateError::IdMismatch.label(), "id-mismatch");
        assert_eq!(
            InstantiateError::MissingRequiredCap.label(),
            "missing-required-cap"
        );
        assert_eq!(CallError::Busy.label(), "busy");
        assert_eq!(CallError::Wire(DecodeError::Short).label(), "short");
    }
}

/// Kani proof harnesses. Compiled only under `cargo kani`.
#[cfg(kani)]
mod proofs {
    use super::{frame_into, FrameSink, ID_DOMAIN_TAG};

    /// A fixed byte buffer that absorbs framed input (never more than `N`).
    struct ByteSink<const N: usize> {
        buf: [u8; N],
        len: usize,
    }

    impl<const N: usize> FrameSink for ByteSink<N> {
        fn absorb(&mut self, bytes: &[u8]) {
            let n = bytes.len().min(N - self.len);
            self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
            self.len += n;
        }
    }

    /// The framing is injective on bounded inputs: if two `(code, params)`
    /// pairs frame to the same bytes, they are the same pair — lengths and
    /// contents. This is the property unframed `H(code ‖ params)` lacks
    /// (spec §6, amendment A1) and the one the hash's collision resistance
    /// then lifts to `ComponentId`.
    #[kani::proof]
    fn framing_is_injective_bounded() {
        const MAX: usize = 3;
        const CAP: usize = 23 + 8 + MAX + 8 + MAX;
        assert!(ID_DOMAIN_TAG.len() == 23);

        let la: usize = kani::any();
        kani::assume(la <= MAX);
        let a: [u8; MAX] = kani::any();
        let pa: usize = kani::any();
        kani::assume(pa <= MAX);
        let ap: [u8; MAX] = kani::any();

        let lb: usize = kani::any();
        kani::assume(lb <= MAX);
        let b: [u8; MAX] = kani::any();
        let pb: usize = kani::any();
        kani::assume(pb <= MAX);
        let bp: [u8; MAX] = kani::any();

        let mut sa = ByteSink::<CAP> {
            buf: [0; CAP],
            len: 0,
        };
        frame_into(&a[..la], &ap[..pa], &mut sa);
        let mut sb = ByteSink::<CAP> {
            buf: [0; CAP],
            len: 0,
        };
        frame_into(&b[..lb], &bp[..pb], &mut sb);

        assert!(sa.len == 23 + 8 + la + 8 + pa);
        if sa.len == sb.len && sa.buf == sb.buf {
            assert!(la == lb);
            assert!(pa == pb);
            for i in 0..MAX {
                if i < la {
                    assert!(a[i] == b[i]);
                }
                if i < pa {
                    assert!(ap[i] == bp[i]);
                }
            }
        }
    }
}
