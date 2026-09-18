//! The native [`ComponentRuntime`] and the embedded `hello` component.
//!
//! Spec §12 (revised 2026-09-18): PR-1 is native-first. A native component is
//! Rust compiled into the kernel image and registered by a **descriptor** — the
//! bytes the host hashes as the component's `code` (spec §6). The runtime maps a
//! descriptor to its export table; the host has already verified that
//! `ComponentId::derive(descriptor, params)` is the id the requester asked for
//! before this runtime ever sees the bytes.
//!
//! What this boundary is and is not (spec §16, amendment A4): a native
//! component runs in ring 0 in the kernel address space. It is confined by what
//! it can *name* and *reach* through the host — authority, not memory. That
//! stops a confused component, not a malicious one; no non-first-party
//! component is instantiated on this runtime. The memory boundary (wasm under
//! the §12 conditions, or ring-3) is the gate before PR-3.
//!
//! Fuel: native code cannot be metered, so [`ComponentRuntime::fuel_used`] is
//! `None` here and the boot line says `runtime=native` instead of `fuel-used=`.

use super::{
    CallError, ComponentId, ComponentRuntime, InstantiateError, Manifest, RuntimeHandle,
    MAX_INSTANCES,
};
use crate::hash::digest_from_hex;

/// A native export: `(request payload, reply buffer) -> reply length`.
pub type ExportFn = fn(args: &[u8], reply: &mut [u8]) -> Result<usize, ExportError>;

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
    pub name: &'static str,
    pub func: ExportFn,
}

/// A component compiled into the kernel: its hashed descriptor and exports.
pub struct NativeComponent {
    /// The `code` bytes of spec §6 for this component. Hashed (framed with the
    /// params) into its [`ComponentId`]; matched byte-for-byte at instantiation.
    pub descriptor: &'static [u8],
    pub exports: &'static [NativeExport],
}

impl NativeComponent {
    fn export(&self, name: &str) -> Option<ExportFn> {
        self.exports.iter().find(|e| e.name == name).map(|e| e.func)
    }
}

#[derive(Clone, Copy)]
struct Slot {
    component: &'static NativeComponent,
}

/// The native runtime: a registry of embeddable components and a fixed table
/// of live instances.
pub struct NativeRuntime {
    registry: &'static [&'static NativeComponent],
    slots: [Option<Slot>; MAX_INSTANCES],
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
        self.slots[slot] = Some(Slot { component });
        Ok(RuntimeHandle(slot as u32))
    }

    fn call(
        &mut self,
        handle: RuntimeHandle,
        export: &str,
        args: &[u8],
        reply: &mut [u8],
    ) -> Result<usize, CallError> {
        let slot = self
            .slots
            .get(handle.0 as usize)
            .and_then(|s| s.as_ref())
            .ok_or(CallError::NoSuchInstance)?;
        let func = slot
            .component
            .export(export)
            .ok_or(CallError::NoSuchExport)?;
        func(args, reply).map_err(CallError::Export)
    }

    fn fuel_used(&self, _handle: RuntimeHandle) -> Option<u64> {
        None
    }
}

/// The `hello` component's descriptor — its `code` bytes for hashing.
pub const HELLO_DESCRIPTOR: &[u8] =
    b"sentinelos/native-component\nname: hello\nversion: 1\nexports: greet\n";

/// The embedded `hello` component: one export, `greet`, which answers
/// `hello, <request payload>`.
pub static HELLO: NativeComponent = NativeComponent {
    descriptor: HELLO_DESCRIPTOR,
    exports: &[NativeExport {
        name: "greet",
        func: greet,
    }],
};

/// Everything the native runtime may instantiate at boot. PR-2 adds the
/// second and third components the capability proof needs.
pub static REGISTRY: &[&NativeComponent] = &[&HELLO];

/// The id `kmain` asks the host for. A **literal**, not a value computed from
/// the embedded bytes at boot: the requester names what it wants, the host
/// hashes what it is about to run, and only equality lets it run. The host test
/// `hello_manifest_id_matches_the_framed_hash` keeps the literal honest.
pub const HELLO_MANIFEST: Manifest = Manifest {
    code: HELLO_DESCRIPTOR,
    params: b"",
    id: ComponentId(match digest_from_hex(HELLO_ID_HEX) {
        Some(d) => d,
        None => panic!("HELLO_ID_HEX is not 64 hex digits"),
    }),
};

/// `ComponentId::derive(HELLO_DESCRIPTOR, b"")` as hex.
const HELLO_ID_HEX: &str = "9c1877d2681476cc7bc48e716d7f38d88d3f2db3fcbba868fc924018595ab7fa";

fn greet(args: &[u8], reply: &mut [u8]) -> Result<usize, ExportError> {
    const PREFIX: &[u8] = b"hello, ";
    let n = PREFIX.len() + args.len();
    let out = reply.get_mut(..n).ok_or(ExportError::ReplyTooLong)?;
    out[..PREFIX.len()].copy_from_slice(PREFIX);
    out[PREFIX.len()..].copy_from_slice(args);
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_manifest_id_matches_the_framed_hash() {
        let derived = ComponentId::derive(HELLO_DESCRIPTOR, b"");
        assert_eq!(
            derived, HELLO_MANIFEST.id,
            "HELLO_ID_HEX is stale; derived id is {:02x?}",
            derived.0
        );
    }

    #[test]
    fn greet_prefixes_and_bounds() {
        let mut out = [0u8; 32];
        let n = greet(b"world", &mut out).unwrap();
        assert_eq!(&out[..n], b"hello, world");
        let mut tiny = [0u8; 4];
        assert_eq!(greet(b"world", &mut tiny), Err(ExportError::ReplyTooLong));
    }

    #[test]
    fn runtime_rejects_unknown_code_and_unknown_export() {
        let mut rt = NativeRuntime::new(REGISTRY);
        assert_eq!(
            rt.instantiate(b"not-a-descriptor", b"").err(),
            Some(InstantiateError::UnknownCode)
        );
        let h = rt.instantiate(HELLO_DESCRIPTOR, b"").unwrap();
        let mut out = [0u8; 8];
        assert_eq!(
            rt.call(h, "nope", b"", &mut out).err(),
            Some(CallError::NoSuchExport)
        );
        assert_eq!(
            rt.call(RuntimeHandle(99), "greet", b"", &mut out).err(),
            Some(CallError::NoSuchInstance)
        );
        assert_eq!(rt.fuel_used(h), None);
        assert_eq!(rt.name(), "native");
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
}
