//! The native [`ComponentRuntime`] and the embedded first-party components.
//!
//! Spec §12 (revised 2026-09-18): components are native first. A native
//! component is Rust compiled into the kernel image and registered by a
//! **descriptor** — the bytes the host hashes as the component's `code`
//! (spec §6). The runtime maps a descriptor to its exports and its message
//! handler; the host has already verified that the v2 id of `(descriptor,
//! params, declarations)` is the id the requester asked for before this
//! runtime ever sees the bytes.
//!
//! What this boundary is and is not (spec §16 → `docs/security/threat-model.md`
//! §2, amendment A4): a native component runs in ring 0 in the kernel address
//! space. It is confined by what it can *name* and *reach* through the host —
//! authority, not memory. That stops a confused component, not a malicious
//! one; no non-first-party component is instantiated on this runtime. The
//! memory boundary (wasm under the §12 conditions, or ring-3) is the gate
//! before PR-3.
//!
//! Component code reaches the kernel only through the `crate::bus::Ctx` it is
//! handed: [`ExportFn`] for kernel-originated calls, [`MessageFn`] for bus
//! traffic. Both run with no host lock held (spec §18.4 as decided at PR-2:
//! run-to-completion delivery).
//!
//! Fuel: native code cannot be metered, so [`ComponentRuntime::fuel_used`] is
//! `None` here and the boot line says `runtime=native` instead of `fuel-used=`.

use super::codec::{Envelope, Kind};
use super::probe;
use super::{
    CallError, ComponentId, ComponentRuntime, InstantiateError, Manifest, RuntimeHandle,
    MAX_INSTANCES,
};
use crate::bus::Ctx;
use crate::cap::{service_literal, Policy, ServiceName};
use crate::hash::digest_from_hex;

/// A native export, called by the kernel: `(ctx, request payload, reply
/// buffer) -> reply length`.
pub type ExportFn =
    fn(ctx: &Ctx<'_, NativeRuntime>, args: &[u8], reply: &mut [u8]) -> Result<usize, ExportError>;

/// A native message handler: one delivered envelope, run to completion.
pub type MessageFn = fn(ctx: &Ctx<'_, NativeRuntime>, env: &Envelope);

/// Why an export refused to answer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ExportError {
    /// The reply would not fit the caller's buffer.
    ReplyTooLong,
    /// The request payload was not what this export accepts.
    BadArguments,
}

impl ExportError {
    /// Fixed label for `fmt`-free console output.
    pub fn label(self) -> &'static str {
        match self {
            ExportError::ReplyTooLong => "reply-too-long",
            ExportError::BadArguments => "bad-arguments",
        }
    }
}

/// One named export.
pub struct NativeExport {
    /// Its name.
    pub name: &'static str,
    /// Its body.
    pub func: ExportFn,
}

/// A component compiled into the kernel: its hashed descriptor, its exports,
/// and its message handler.
pub struct NativeComponent {
    /// The `code` bytes of spec §6 for this component. Hashed (framed with the
    /// params and the declarations) into its [`ComponentId`]; matched
    /// byte-for-byte at instantiation.
    pub descriptor: &'static [u8],
    /// Kernel-callable exports.
    pub exports: &'static [NativeExport],
    /// What runs for each envelope delivered from its inbox.
    pub on_message: MessageFn,
}

impl NativeComponent {
    fn export(&self, name: &str) -> Option<ExportFn> {
        self.exports.iter().find(|e| e.name == name).map(|e| e.func)
    }
}

/// The native runtime: a registry of embeddable components and a fixed table
/// of live instances.
pub struct NativeRuntime {
    registry: &'static [&'static NativeComponent],
    slots: [Option<&'static NativeComponent>; MAX_INSTANCES],
}

impl NativeRuntime {
    /// A runtime that can instantiate exactly the components in `registry`.
    pub const fn new(registry: &'static [&'static NativeComponent]) -> Self {
        Self {
            registry,
            slots: [None; MAX_INSTANCES],
        }
    }
}

impl ComponentRuntime for NativeRuntime {
    type Entry = &'static NativeComponent;

    fn name(&self) -> &'static str {
        "native"
    }

    fn instantiate(
        &mut self,
        code: &[u8],
        _params: &[u8],
    ) -> Result<RuntimeHandle, InstantiateError> {
        let component = self
            .registry
            .iter()
            .copied()
            .find(|c| c.descriptor == code)
            .ok_or(InstantiateError::UnknownCode)?;
        let slot = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(InstantiateError::TooManyInstances)?;
        self.slots[slot] = Some(component);
        Ok(RuntimeHandle(slot as u32))
    }

    fn release(&mut self, handle: RuntimeHandle) {
        if let Some(s) = self.slots.get_mut(handle.0 as usize) {
            *s = None;
        }
    }

    fn entry(&self, handle: RuntimeHandle) -> Option<Self::Entry> {
        *self.slots.get(handle.0 as usize)?
    }

    fn fuel_used(&self, _handle: RuntimeHandle) -> Option<u64> {
        None
    }

    fn call(
        entry: Self::Entry,
        ctx: &Ctx<'_, Self>,
        export: &str,
        args: &[u8],
        reply: &mut [u8],
    ) -> Result<usize, CallError> {
        let func = entry.export(export).ok_or(CallError::NoSuchExport)?;
        func(ctx, args, reply).map_err(CallError::Export)
    }

    fn deliver(entry: Self::Entry, ctx: &Ctx<'_, Self>, env: &Envelope) -> Result<(), CallError> {
        (entry.on_message)(ctx, env);
        Ok(())
    }
}

/// The `hello` component's descriptor — its `code` bytes for hashing.
pub const HELLO_DESCRIPTOR: &[u8] =
    b"sentinelos/native-component\nname: hello\nversion: 1\nexports: greet\n";

/// The embedded `hello` component: one export, `greet`, which answers
/// `hello, <request payload>`; on the bus it answers requests the same way.
pub static HELLO: NativeComponent = NativeComponent {
    descriptor: HELLO_DESCRIPTOR,
    exports: &[NativeExport {
        name: "greet",
        func: greet,
    }],
    on_message: hello_on_message,
};

/// Everything the native runtime may instantiate at boot: `hello` (PR-1) and
/// the three first-party probe components of the PR-2 capability proof.
pub const REGISTRY: &[&NativeComponent] = &[&HELLO, &probe::ALICE, &probe::BOB, &probe::CAROL];

/// The kernel-wide grant policy until the PolicyAgent (spec §9, PR-5): routes
/// (service → provider id) and an allow-list, deny by default. `hello` holds
/// nothing and nothing is routed to it.
pub const BOOT_POLICY: Policy = Policy {
    routes: probe::POLICY_ROUTES,
    rules: probe::POLICY_RULES,
};

// One provider per service: a duplicated route does not build (and would
// route nowhere at run time anyway — `Policy::route` fails closed).
const _: () = assert!(BOOT_POLICY.routes_are_unique());

/// The service `hello` answers on the bus (`hello, <payload>`).
pub const HELLO_SERVICE: ServiceName = service_literal("sentinel.hello/1");

/// The id `kmain` asks the host for. A **literal**, not a value computed from
/// the embedded bytes at boot: the requester names what it wants, the host
/// hashes what it is about to run, and only equality lets it run. The host test
/// `hello_manifest_id_matches_the_framed_hash` keeps the literal honest.
pub const HELLO_MANIFEST: Manifest = Manifest {
    code: HELLO_DESCRIPTOR,
    params: b"",
    id: id_literal(HELLO_ID_HEX),
    caps: &[],
    provides: &[HELLO_SERVICE],
};

/// `ComponentId::derive(HELLO_DESCRIPTOR, b"", &[], &[HELLO_SERVICE])` (v2)
/// as hex.
const HELLO_ID_HEX: &str = "f8ca98cb0c5ddbcef4c17eaf20e4df3ea6c6ca02974fc659ace182352501e97f";

/// A [`ComponentId`] from a 64-digit hex literal, checked at compile time.
pub(crate) const fn id_literal(hex: &str) -> ComponentId {
    ComponentId(match digest_from_hex(hex) {
        Some(d) => d,
        None => panic!("component id literal is not 64 hex digits"),
    })
}

/// `greet`'s logic: `hello, <args>` into `reply`.
fn greet_into(args: &[u8], reply: &mut [u8]) -> Result<usize, ExportError> {
    const PREFIX: &[u8] = b"hello, ";
    let n = PREFIX.len() + args.len();
    let out = reply.get_mut(..n).ok_or(ExportError::ReplyTooLong)?;
    out[..PREFIX.len()].copy_from_slice(PREFIX);
    out[PREFIX.len()..].copy_from_slice(args);
    Ok(n)
}

fn greet(
    _ctx: &Ctx<'_, NativeRuntime>,
    args: &[u8],
    reply: &mut [u8],
) -> Result<usize, ExportError> {
    greet_into(args, reply)
}

/// `hello` on the bus: answer each request with the greeting (if it fits);
/// events are delivered and ignored.
fn hello_on_message(ctx: &Ctx<'_, NativeRuntime>, env: &Envelope) {
    if let Kind::Request { reply } = env.kind {
        let mut buf = [0u8; super::codec::MAX_PAYLOAD];
        if let Ok(n) = greet_into(env.payload.as_slice(), &mut buf) {
            let _ = ctx.reply(reply, &buf[..n]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(id: &ComponentId) -> alloc::string::String {
        id.0.iter().map(|b| alloc::format!("{b:02x}")).collect()
    }

    /// Every manifest the image carries: `hello` and each of
    /// [`probe::MANIFESTS`]. A manifest added to the image without a place
    /// here fails `every_registered_component_has_a_checked_manifest`.
    fn all_manifests() -> alloc::vec::Vec<(&'static str, Manifest)> {
        let mut v = alloc::vec![("hello", HELLO_MANIFEST)];
        v.extend_from_slice(probe::MANIFESTS);
        v
    }

    #[test]
    fn manifest_id_literals_match_the_framed_hash() {
        for (name, m) in all_manifests() {
            let derived = m.derived_id();
            assert_eq!(
                derived,
                m.id,
                "{name}: id literal is stale; the v2 id is {}",
                hex(&derived)
            );
            assert!(m.verify().is_ok(), "{name} verifies");
        }
    }

    #[test]
    fn every_registered_component_has_a_checked_manifest() {
        let all = all_manifests();
        for c in REGISTRY {
            assert!(
                all.iter().any(|(_, m)| m.code == c.descriptor),
                "a registered component has no manifest in the literal test"
            );
        }
        // Distinct declarations, distinct ids.
        for (i, (a, ma)) in all.iter().enumerate() {
            for (b, mb) in &all[i + 1..] {
                assert_ne!(ma.id, mb.id, "{a} and {b} share an id");
            }
        }
    }

    #[test]
    fn hello_manifest_id_matches_the_framed_hash() {
        let derived = ComponentId::derive(HELLO_DESCRIPTOR, b"", &[], &[HELLO_SERVICE]);
        assert_eq!(
            derived,
            HELLO_MANIFEST.id,
            "HELLO_ID_HEX is stale; the v2 id is {}",
            hex(&derived)
        );
    }

    #[test]
    fn greet_prefixes_and_bounds() {
        let mut out = [0u8; 32];
        let n = greet_into(b"world", &mut out).unwrap();
        assert_eq!(&out[..n], b"hello, world");
        let mut tiny = [0u8; 4];
        assert_eq!(
            greet_into(b"world", &mut tiny),
            Err(ExportError::ReplyTooLong)
        );
    }

    #[test]
    fn runtime_rejects_unknown_code_and_releases_slots() {
        let mut rt = NativeRuntime::new(REGISTRY);
        assert_eq!(
            rt.instantiate(b"not-a-descriptor", b"").err(),
            Some(InstantiateError::UnknownCode)
        );
        let h = rt.instantiate(HELLO_DESCRIPTOR, b"").unwrap();
        assert!(rt
            .entry(h)
            .is_some_and(|c| c.descriptor == HELLO_DESCRIPTOR));
        assert!(rt.entry(h).is_some_and(|c| c.export("greet").is_some()));
        assert!(rt.entry(h).is_some_and(|c| c.export("nope").is_none()));
        assert!(rt.entry(RuntimeHandle(99)).is_none());
        assert_eq!(rt.fuel_used(h), None);
        assert_eq!(rt.name(), "native");
        rt.release(h);
        assert!(rt.entry(h).is_none());
        rt.release(RuntimeHandle(99)); // out of range: no effect, no panic
    }

    #[test]
    fn runtime_table_is_bounded() {
        let mut rt = NativeRuntime::new(REGISTRY);
        for _ in 0..MAX_INSTANCES {
            rt.instantiate(HELLO_DESCRIPTOR, b"").unwrap();
        }
        assert_eq!(
            rt.instantiate(HELLO_DESCRIPTOR, b"").err(),
            Some(InstantiateError::TooManyInstances)
        );
    }

    #[test]
    fn every_registered_descriptor_is_distinct() {
        for (i, a) in REGISTRY.iter().enumerate() {
            for b in &REGISTRY[i + 1..] {
                assert_ne!(a.descriptor, b.descriptor);
            }
        }
    }
}
