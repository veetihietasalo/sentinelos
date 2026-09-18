//! Component host — the only code that turns component bytes into a running
//! instance (spec `docs/specs/2026-09-18-component-model-design.md`, §5–§7,
//! §12–§14; PR-1 of the staging in §14).
//!
//! What lands here in PR-1, all safe Rust, zero `hal` delta:
//!
//! - **Identity** ([`ComponentId`], §6): `SHA-256(TAG ‖ le64(|code|) ‖ code ‖
//!   le64(|params|) ‖ params)`. The framing is *injective* (Kani:
//!   `proofs::framing_is_injective_bounded`), which unframed `H(code ‖ params)`
//!   is not (amendment A1). [`InstanceId`] is per boot, per instantiation.
//! - **The runtime seam** ([`ComponentRuntime`]): the only thing the host sees
//!   of whatever executes a component. PR-1 ships [`native::NativeRuntime`];
//!   the memory-boundary gate (spec §12) adds the second implementation before
//!   the trait freezes.
//! - **Verify before run** ([`Host::instantiate`]): the requester names an id in
//!   a [`Manifest`]; the host hashes the bytes it is about to run and refuses on
//!   mismatch *before* the runtime sees them. Nothing is instantiated on refusal.
//! - **Attested delivery** ([`Host::call`]): the kernel builds the request
//!   envelope and stamps `from` itself, encodes it into the instance's fixed
//!   [`inbox::InboxRing`], delivers it, runs the export, and stamps the reply
//!   with the *instance's* identity. The component writes neither `from`.
//!   Full → `Err(Busy)` to the sender; nothing grows, nothing allocates on the
//!   delivery path.
//!
//! **Zero time-dependent semantics** (spec §19 consensus): no expiry, no
//! timeouts, no clock reads. Budgets, when they arrive in PR-2, are by count.
//!
//! Boot proof: [`prove_hello`] prints
//! `[comp] hello: id=<8 hex> verified=yes wrong-id=refused runtime=native reply=ok ok`
//! and `cargo xtask test` asserts every field.

pub mod codec;
pub mod inbox;
pub mod native;

use crate::hash::{Digest, Sha256};
use alloc::boxed::Box;
use codec::{CapIndex, DecodeError, Envelope, Kind, Payload, Sender, Wire};
use inbox::InboxRing;

/// Live instances the host can track. Fixed slab: no growth, no allocation
/// under any lock (the same discipline as `sched::TaskTable`).
pub const MAX_INSTANCES: usize = 16;
/// Envelopes one instance's inbox holds before senders see `Busy`.
pub const MAX_INBOX: usize = 8;
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

/// What a requester hands the host: the bytes, the parameters, and the id it
/// *claims* they hash to. The host checks the claim; it never trusts it.
#[derive(Clone, Copy, Debug)]
pub struct Manifest {
    pub code: &'static [u8],
    pub params: &'static [u8],
    pub id: ComponentId,
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
}

impl InstantiateError {
    /// Fixed label for `fmt`-free console output.
    pub fn label(self) -> &'static str {
        match self {
            InstantiateError::IdMismatch => "id-mismatch",
            InstantiateError::UnknownCode => "unknown-code",
            InstantiateError::TooManyInstances => "too-many-instances",
            InstantiateError::RuntimeRejected => "runtime-rejected",
        }
    }
}

/// Why a call did not produce a reply. **Silence is denial** (spec §7): none of
/// these fabricate one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CallError {
    NoSuchInstance,
    /// The target's inbox ring is full; the request was not enqueued.
    InboxFull,
    PayloadTooLong,
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
            CallError::InboxFull => "inbox-full",
            CallError::PayloadTooLong => "payload-too-long",
            CallError::NoSuchExport => "no-such-export",
            CallError::Export(e) => e.label(),
            CallError::Wire(e) => e.label(),
            CallError::ReplyTooLong => "reply-too-long",
            CallError::ReplyMismatch => "reply-mismatch",
        }
    }
}

/// The seam between the host and whatever executes a component. PR-1: the
/// native runtime. The gate before PR-3 adds the second implementation
/// (`wasmi` under the §12 conditions, or ring-3) behind this same trait.
pub trait ComponentRuntime {
    /// `"native"`, `"wasm"`, … — printed in the boot line.
    fn name(&self) -> &'static str;
    /// Prepare `code` with `params`. The host has already verified the id.
    fn instantiate(
        &mut self,
        code: &[u8],
        params: &[u8],
    ) -> Result<RuntimeHandle, InstantiateError>;
    /// Run `export` on the instance with the request payload `args`; write the
    /// reply payload into `reply` and return its length.
    fn call(
        &mut self,
        handle: RuntimeHandle,
        export: &str,
        args: &[u8],
        reply: &mut [u8],
    ) -> Result<usize, CallError>;
    /// Fuel consumed so far, or `None` when this runtime cannot meter.
    fn fuel_used(&self, handle: RuntimeHandle) -> Option<u64>;
}

/// One live instance.
struct Instance {
    id: InstanceId,
    component: ComponentId,
    handle: RuntimeHandle,
    inbox: InboxRing<Wire, MAX_INBOX>,
    next_reply_tag: u32,
}

/// The host: a runtime plus a fixed table of instances.
pub struct Host<R: ComponentRuntime> {
    runtime: R,
    instances: [Option<Box<Instance>>; MAX_INSTANCES],
    next_instance: u64,
}

impl<R: ComponentRuntime> Host<R> {
    /// A host with no instances.
    pub fn new(runtime: R) -> Self {
        Self {
            runtime,
            instances: [const { None }; MAX_INSTANCES],
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
        self.slot_of(inst)
            .map(|i| self.instances[i].as_ref().map(|x| x.component))?
    }

    /// Fuel the runtime reports for `inst`, if it meters.
    pub fn fuel_used(&self, inst: InstanceId) -> Option<u64> {
        let i = self.slot_of(inst)?;
        let handle = self.instances[i].as_ref()?.handle;
        self.runtime.fuel_used(handle)
    }

    fn slot_of(&self, inst: InstanceId) -> Option<usize> {
        self.instances
            .iter()
            .position(|s| s.as_ref().is_some_and(|x| x.id == inst))
    }

    /// Verify, then instantiate. Order matters: the hash of what is about to
    /// run is compared with the manifest's claim **before** the runtime sees
    /// the bytes, and a mismatch leaves the table untouched.
    pub fn instantiate(&mut self, manifest: &Manifest) -> Result<InstanceId, InstantiateError> {
        let actual = ComponentId::derive(manifest.code, manifest.params);
        if actual != manifest.id {
            return Err(InstantiateError::IdMismatch);
        }
        let slot = self
            .instances
            .iter()
            .position(Option::is_none)
            .ok_or(InstantiateError::TooManyInstances)?;
        let handle = self.runtime.instantiate(manifest.code, manifest.params)?;
        let id = InstanceId(self.next_instance);
        self.next_instance += 1;
        self.instances[slot] = Some(Box::new(Instance {
            id,
            component: actual,
            handle,
            inbox: InboxRing::new(),
            next_reply_tag: 1,
        }));
        Ok(id)
    }

    /// A kernel-originated request to `inst`'s `export`, answered as a reply
    /// envelope stamped with the instance's identity.
    ///
    /// The path is the real one, not a shortcut: request envelope built and
    /// stamped by the kernel → encoded into the instance's inbox ring →
    /// popped and decoded (what the component sees) → export run → reply
    /// envelope stamped `from = {inst, its component}` → encoded and decoded
    /// again on the way back. The codec and the ring are load-bearing.
    pub fn call_envelope(
        &mut self,
        inst: InstanceId,
        export: &str,
        args: &[u8],
    ) -> Result<Envelope, CallError> {
        let slot = self.slot_of(inst).ok_or(CallError::NoSuchInstance)?;
        // Disjoint borrows: the runtime and one instance.
        let runtime = &mut self.runtime;
        let instance = self.instances[slot]
            .as_mut()
            .ok_or(CallError::NoSuchInstance)?;

        let payload = Payload::new(args).map_err(|_| CallError::PayloadTooLong)?;
        let reply_tag = instance.next_reply_tag;
        instance.next_reply_tag = instance.next_reply_tag.wrapping_add(1);
        let request = Envelope {
            from: Sender::KERNEL,
            to: inst,
            cap: CapIndex::KERNEL,
            kind: Kind::Request { reply_tag },
            payload,
        };
        instance
            .inbox
            .push(Wire::encode(&request))
            .map_err(|_| CallError::InboxFull)?;

        // The instance's turn: take the oldest envelope exactly as it would.
        let delivered = instance
            .inbox
            .pop()
            .ok_or(CallError::ReplyMismatch)?
            .decode()
            .map_err(CallError::Wire)?;
        let Kind::Request { reply_tag: tag } = delivered.kind else {
            return Err(CallError::ReplyMismatch);
        };
        let mut reply_buf = [0u8; codec::MAX_PAYLOAD];
        let n = runtime.call(
            instance.handle,
            export,
            delivered.payload.as_slice(),
            &mut reply_buf,
        )?;
        let reply_payload = Payload::new(reply_buf.get(..n).ok_or(CallError::ReplyTooLong)?)
            .map_err(|_| CallError::ReplyTooLong)?;

        // The kernel stamps the reply with the INSTANCE's identity and routes
        // it back to whoever asked; the component wrote none of this.
        let reply = Envelope {
            from: Sender {
                instance: instance.id,
                component: instance.component,
            },
            to: delivered.from.instance,
            cap: delivered.cap,
            kind: Kind::Reply { reply_tag: tag },
            payload: reply_payload,
        };
        let back = Wire::encode(&reply).decode().map_err(CallError::Wire)?;
        if back.kind != (Kind::Reply { reply_tag })
            || back.to != InstanceId::KERNEL
            || back.from.instance != inst
        {
            return Err(CallError::ReplyMismatch);
        }
        Ok(back)
    }

    /// [`Self::call_envelope`], copying the reply payload into `reply_out`.
    pub fn call(
        &mut self,
        inst: InstanceId,
        export: &str,
        args: &[u8],
        reply_out: &mut [u8],
    ) -> Result<usize, CallError> {
        let reply = self.call_envelope(inst, export, args)?;
        let bytes = reply.payload.as_slice();
        let out = reply_out
            .get_mut(..bytes.len())
            .ok_or(CallError::ReplyTooLong)?;
        out.copy_from_slice(bytes);
        Ok(bytes.len())
    }
}

/// Boot proof for PR-1 (spec §14): the `hello` component, native runtime.
///
/// 1. A manifest with one bit of the id flipped is **refused** and nothing is
///    instantiated (`wrong-id=refused`).
/// 2. The real manifest verifies and instantiates (`verified=yes`).
/// 3. `greet("sentinelos")` answers `hello, sentinelos` through the inbox
///    ring and the envelope codec, stamped by the kernel (`reply=ok`).
///
/// Prints one line, `fmt`-free (the target's `{}` formatting faults — see
/// `hal::serial::write_str`); `cargo xtask test` asserts every field.
pub fn prove_hello() {
    use hal::serial::write_str;

    let mut host = Host::new(native::NativeRuntime::new(native::REGISTRY));

    // Negative first: the requester lies about the id by one bit.
    let mut wrong = native::HELLO_MANIFEST;
    wrong.id.0[0] ^= 0x01;
    let wrong_refused = matches!(host.instantiate(&wrong), Err(InstantiateError::IdMismatch))
        && host.instance_count() == 0;

    let instantiated = host.instantiate(&native::HELLO_MANIFEST);
    let verified = instantiated.is_ok();

    let mut reply = [0u8; 64];
    let reply_result: Result<bool, CallError> = match instantiated {
        Ok(inst) => host
            .call(inst, "greet", b"sentinelos", &mut reply)
            .map(|n| &reply[..n] == b"hello, sentinelos"),
        Err(_) => Ok(false),
    };
    let reply_ok = matches!(reply_result, Ok(true));
    let ok = wrong_refused && verified && reply_ok;

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
    write_str(host.runtime_name());
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
    use super::native::{NativeRuntime, HELLO_DESCRIPTOR, HELLO_MANIFEST, REGISTRY};
    use super::*;
    use alloc::vec::Vec;

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

    fn hello_host() -> Host<NativeRuntime> {
        Host::new(NativeRuntime::new(REGISTRY))
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
        let mut host = hello_host();
        let mut wrong = HELLO_MANIFEST;
        wrong.id.0[31] ^= 0x80;
        assert_eq!(host.instantiate(&wrong), Err(InstantiateError::IdMismatch));
        assert_eq!(host.instance_count(), 0);
        // A manifest that lies about the *code* fails the same way: the id
        // was computed for other bytes.
        let lying = Manifest {
            code: b"something else",
            ..HELLO_MANIFEST
        };
        assert_eq!(host.instantiate(&lying), Err(InstantiateError::IdMismatch));
        assert_eq!(host.instance_count(), 0);
    }

    #[test]
    fn unknown_code_with_an_honest_id_is_refused_by_the_runtime() {
        let mut host = hello_host();
        let code: &'static [u8] = b"honest but unregistered";
        let m = Manifest {
            code,
            params: b"",
            id: ComponentId::derive(code, b""),
        };
        assert_eq!(host.instantiate(&m), Err(InstantiateError::UnknownCode));
        assert_eq!(host.instance_count(), 0);
    }

    #[test]
    fn instantiate_call_and_kernel_stamping() {
        let mut host = hello_host();
        let inst = host.instantiate(&HELLO_MANIFEST).unwrap();
        assert_eq!(inst, InstanceId(1));
        assert_eq!(host.component_of(inst), Some(HELLO_MANIFEST.id));
        assert_eq!(host.fuel_used(inst), None);
        assert_eq!(host.runtime_name(), "native");

        let reply = host.call_envelope(inst, "greet", b"sentinelos").unwrap();
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
        let again = host.call_envelope(inst, "greet", b"x").unwrap();
        assert_eq!(again.kind, Kind::Reply { reply_tag: 2 });

        let mut out = [0u8; 64];
        let n = host.call(inst, "greet", b"world", &mut out).unwrap();
        assert_eq!(&out[..n], b"hello, world");
    }

    #[test]
    fn call_errors_are_refusals_not_replies() {
        let mut host = hello_host();
        let mut out = [0u8; 8];
        assert_eq!(
            host.call(InstanceId(42), "greet", b"", &mut out),
            Err(CallError::NoSuchInstance)
        );
        let inst = host.instantiate(&HELLO_MANIFEST).unwrap();
        assert_eq!(
            host.call(inst, "shout", b"", &mut out),
            Err(CallError::NoSuchExport)
        );
        assert_eq!(
            host.call(inst, "greet", b"a long name", &mut out),
            Err(CallError::ReplyTooLong)
        );
        let too_long = [0u8; codec::MAX_PAYLOAD + 1];
        assert_eq!(
            host.call(inst, "greet", &too_long, &mut out),
            Err(CallError::PayloadTooLong)
        );
        // A reply that would overflow the payload is refused by the export.
        let near = [b'z'; codec::MAX_PAYLOAD - 3];
        let mut big = [0u8; codec::MAX_PAYLOAD];
        assert_eq!(
            host.call(inst, "greet", &near, &mut big),
            Err(CallError::Export(native::ExportError::ReplyTooLong))
        );
    }

    #[test]
    fn instance_table_is_bounded_and_ids_never_repeat() {
        let mut host = hello_host();
        let mut last = InstanceId::KERNEL;
        for _ in 0..MAX_INSTANCES {
            let id = host.instantiate(&HELLO_MANIFEST).unwrap();
            assert!(id > last);
            last = id;
        }
        assert_eq!(
            host.instantiate(&HELLO_MANIFEST),
            Err(InstantiateError::TooManyInstances)
        );
        assert_eq!(host.instance_count(), MAX_INSTANCES);
    }

    #[test]
    fn labels_are_stable() {
        assert_eq!(InstantiateError::IdMismatch.label(), "id-mismatch");
        assert_eq!(CallError::InboxFull.label(), "inbox-full");
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
