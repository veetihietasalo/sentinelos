//! First-party **probe components** for the PR-2 capability boot proof
//! (spec §15: "every 'cannot' in §16 is a probe component in the boot test
//! that tries it and is refused"; threat register in
//! `docs/security/threat-model.md` §5).
//!
//! - **alice** holds a `Send`/`Request`/`Delegate` capability over bob
//!   (required) and a `Send` capability over carol (optional, to hand her
//!   delegations).
//! - **bob** holds nothing; he records what he receives and answers requests
//!   with `ack` — except a request whose payload is [`QUIET`], which he leaves
//!   unanswered (silence is denial).
//! - **carol** asks for a `Send` capability over bob (optional); the boot
//!   policy has no rule for it, so she starts with an empty table.
//!
//! Since PR-2b (component A12) requests name **services**, never component
//! ids: bob provides [`BOB_SERVICE`], carol [`CAROL_SERVICE`], and the boot
//! policy routes each to its provider's id ([`POLICY_ROUTES`]). Each id is the
//! v2 hash of the component's code, params *and* declarations, so
//! carol-strict — carol's code with her request marked required — is a
//! component of its own ([`CAROL_STRICT_ID`]).
//!
//! Each exports one function, `act`: a tiny command protocol that makes the
//! component's **own code** perform a bus operation through its own
//! `bus::Ctx`, with whatever index the proof hands it — including indices it
//! does not hold. The kernel drives; the component acts as itself; the kernel
//! judges. Every envelope a probe's handler is handed goes to the proof's
//! recorder, `super::seen`, so the proof can check `from` as the recipient
//! saw it.
//!
//! This is a **component module**: of the kernel's bus it names only `Ctx`,
//! `BusError` and `Delegation`, never the host or the capability tables —
//! `cargo xtask check-component-imports` enforces it (threat T-NAT-1). Its
//! one other kernel call is that recorder.

use super::codec::{Envelope, Kind, MAX_PAYLOAD};
use super::native::{id_literal, ExportError, NativeComponent, NativeExport, NativeRuntime};
use super::seen::record;
use super::{ComponentId, Manifest};
use crate::bus::{BusError, Ctx, Delegation};
use crate::cap::{
    service_literal, Attenuation, CapIndex, CapNeed, CapRequest, Op, OpSet, PolicyRule, Route,
    ServiceName, Tick,
};

/// alice's descriptor — her `code` bytes for hashing.
pub const ALICE_DESCRIPTOR: &[u8] =
    b"sentinelos/native-component\nname: alice\nversion: 1\nexports: act\nrole: cap-proof holder\n";
/// bob's descriptor.
pub const BOB_DESCRIPTOR: &[u8] =
    b"sentinelos/native-component\nname: bob\nversion: 1\nexports: act\nrole: cap-proof receiver\n";
/// carol's descriptor.
pub const CAROL_DESCRIPTOR: &[u8] =
    b"sentinelos/native-component\nname: carol\nversion: 1\nexports: act\nrole: cap-proof probe\n";

/// The service bob answers.
pub const BOB_SERVICE: ServiceName = service_literal("sentinel.probe.bob/1");
/// The service carol answers (alice reaches her over it to hand her
/// delegations).
pub const CAROL_SERVICE: ServiceName = service_literal("sentinel.probe.carol/1");

/// alice's v2 id — `ALICE_MANIFEST.derived_id()` — a literal, kept honest by
/// `native::tests::manifest_id_literals_match_the_framed_hash`.
pub const ALICE_ID: ComponentId =
    id_literal("a03a9c974cacfbf1b6da70b57bf9a268b9862446b30baefd5c1dbce3b6e78942");
/// bob's v2 id.
pub const BOB_ID: ComponentId =
    id_literal("d921f1d5dd440c5e7fccd5c5f67be0a061ecf8d393e7c29190876f004a6661d3");
/// carol's v2 id.
pub const CAROL_ID: ComponentId =
    id_literal("9fca63b0806a6fd6fe4f350b5858b618ae12957c4ad91f501f7cc7f4b55a42dc");
/// carol-strict's v2 id: carol's code with her one request marked
/// `Required` — another component, so another id (threat T-MAN-1).
pub const CAROL_STRICT_ID: ComponentId =
    id_literal("4425fca7aef5e1c0ab5d919f1a1e7ed17972b7358bf2c5fd785f5bbdd61e3e77");

/// The payload bob leaves unanswered.
pub const QUIET: &[u8] = b"quiet";

const ACT: &[NativeExport] = &[NativeExport {
    name: "act",
    func: act,
}];

/// alice: records what she receives.
pub static ALICE: NativeComponent = NativeComponent {
    descriptor: ALICE_DESCRIPTOR,
    exports: ACT,
    on_message: observe,
};
/// bob: records and answers requests.
pub static BOB: NativeComponent = NativeComponent {
    descriptor: BOB_DESCRIPTOR,
    exports: ACT,
    on_message: bob_on_message,
};
/// carol: records what she receives.
pub static CAROL: NativeComponent = NativeComponent {
    descriptor: CAROL_DESCRIPTOR,
    exports: ACT,
    on_message: observe,
};

const SEND_REQUEST_DELEGATE: OpSet = OpSet::of(&[Op::Send, Op::Request, Op::Delegate]);
const SEND: OpSet = OpSet::of(&[Op::Send]);

/// alice asks for bob's service (required) and carol's (optional); she
/// provides nothing.
pub const ALICE_MANIFEST: Manifest = Manifest {
    code: ALICE_DESCRIPTOR,
    params: b"",
    id: ALICE_ID,
    caps: &[ALICE_ASKS_FOR_BOB, ALICE_ASKS_FOR_CAROL],
    provides: &[],
};

/// alice's request 0: `Send`/`Request`/`Delegate` over bob, required.
pub const ALICE_ASKS_FOR_BOB: CapRequest = CapRequest {
    target: BOB_SERVICE,
    ops: SEND_REQUEST_DELEGATE,
    attenuation: Attenuation::UNRESTRICTED_MESSAGE,
    need: CapNeed::Required,
};

/// alice's request 1: `Send` over carol, optional.
pub const ALICE_ASKS_FOR_CAROL: CapRequest = CapRequest {
    target: CAROL_SERVICE,
    ops: SEND,
    attenuation: Attenuation::UNRESTRICTED_MESSAGE,
    need: CapNeed::Optional,
};

/// bob asks for nothing and provides his service.
pub const BOB_MANIFEST: Manifest = Manifest {
    code: BOB_DESCRIPTOR,
    params: b"",
    id: BOB_ID,
    caps: &[],
    provides: &[BOB_SERVICE],
};

const CAROL_ASKS_FOR_BOB: CapRequest = CapRequest {
    target: BOB_SERVICE,
    ops: SEND,
    attenuation: Attenuation::UNRESTRICTED_MESSAGE,
    need: CapNeed::Optional,
};

/// carol asks for `Send` over bob's service, optionally — routed, but the
/// policy has no rule for her — and provides her own.
pub const CAROL_MANIFEST: Manifest = Manifest {
    code: CAROL_DESCRIPTOR,
    params: b"",
    id: CAROL_ID,
    caps: &[CAROL_ASKS_FOR_BOB],
    provides: &[CAROL_SERVICE],
};

/// The same request marked **required**: refused to start (amendment A8).
/// Since PR-2b the mark is part of the id, so this is a component of its
/// own, with its own id ([`CAROL_STRICT_ID`]).
pub const CAROL_STRICT_MANIFEST: Manifest = Manifest {
    id: CAROL_STRICT_ID,
    caps: &[CapRequest {
        need: CapNeed::Required,
        ..CAROL_ASKS_FOR_BOB
    }],
    ..CAROL_MANIFEST
};

/// Every probe manifest, named — what the id-literal test walks.
pub const MANIFESTS: &[(&str, Manifest)] = &[
    ("alice", ALICE_MANIFEST),
    ("bob", BOB_MANIFEST),
    ("carol", CAROL_MANIFEST),
    ("carol-strict", CAROL_STRICT_MANIFEST),
];

/// The boot policy's routes: each probe service to the component that
/// provides it (and whose id-bound manifest says so).
pub const POLICY_ROUTES: &[Route] = &[
    Route {
        service: BOB_SERVICE,
        provider: BOB_ID,
    },
    Route {
        service: CAROL_SERVICE,
        provider: CAROL_ID,
    },
];

/// The boot policy's rules: alice may reach bob (send, request, delegate) and
/// carol (send). Nothing else — in particular nothing for carol or bob.
pub const POLICY_RULES: &[PolicyRule] = &[
    PolicyRule {
        holder: ALICE_ID,
        service: BOB_SERVICE,
        ops: SEND_REQUEST_DELEGATE,
        attenuation: Attenuation::UNRESTRICTED_MESSAGE,
        ttl: None,
    },
    PolicyRule {
        holder: ALICE_ID,
        service: CAROL_SERVICE,
        ops: SEND,
        attenuation: Attenuation::UNRESTRICTED_MESSAGE,
        ttl: None,
    },
];

// ── The `act` protocol ──────────────────────────────────────────────────────

/// Command bytes (first byte of `act`'s arguments; integers little-endian).
/// Capability indices and reply tags are `u64` since PR-2b (A13).
pub mod cmd {
    /// `[idx u64][payload…]` → `[code]`.
    pub const SEND: u8 = 1;
    /// `[idx u64][timeout u32][payload…]` → `[code][tag u64]`.
    pub const REQUEST: u8 = 2;
    /// `[reply-idx u64][payload…]` → `[code]`.
    pub const REPLY: u8 = 3;
    /// `[idx u64][via u64][ops u32][max_len u16][ttl u32, 0 = inherit]` → `[code]`.
    pub const DELEGATE: u8 = 4;
    /// `[idx u64]` → `[code][freed u64]`.
    pub const REVOKE: u8 = 5;
    /// `[idx u64]` → `[code]`.
    pub const RELEASE: u8 = 6;
    /// `[i u8]` → `[code][idx u64]`: the index granted for manifest request `i`.
    pub const GRANTED: u8 = 7;
}

/// Bytes of a value-carrying `act` reply: `[code][value u64]`.
pub const ANSWER_LEN: usize = 9;

/// Result codes (first byte of `act`'s reply).
pub mod code {
    /// Done.
    pub const OK: u8 = 0;
    /// The kernel refused.
    pub const DENIED: u8 = 1;
    /// The target could not take it now.
    pub const BUSY: u8 = 2;
    /// Nothing to report (e.g. no grant for that request).
    pub const NONE: u8 = 3;
}

/// Encoder for `act` arguments — a fixed buffer, no allocation.
pub struct Args {
    buf: [u8; MAX_PAYLOAD],
    len: usize,
}

impl Args {
    fn start(cmd: u8) -> Args {
        let mut a = Args {
            buf: [0; MAX_PAYLOAD],
            len: 0,
        };
        a.put(&[cmd]);
        a
    }

    fn put(&mut self, bytes: &[u8]) {
        let end = (self.len + bytes.len()).min(MAX_PAYLOAD);
        let n = end - self.len;
        self.buf[self.len..end].copy_from_slice(&bytes[..n]);
        self.len = end;
    }

    /// `send(idx, payload)`.
    pub fn send(idx: CapIndex, payload: &[u8]) -> Args {
        let mut a = Args::start(cmd::SEND);
        a.put(&idx.0.to_le_bytes());
        a.put(payload);
        a
    }

    /// `request(idx, payload, timeout)`.
    pub fn request(idx: CapIndex, timeout: u32, payload: &[u8]) -> Args {
        let mut a = Args::start(cmd::REQUEST);
        a.put(&idx.0.to_le_bytes());
        a.put(&timeout.to_le_bytes());
        a.put(payload);
        a
    }

    /// `reply(reply_idx, payload)`.
    pub fn reply(idx: CapIndex, payload: &[u8]) -> Args {
        let mut a = Args::start(cmd::REPLY);
        a.put(&idx.0.to_le_bytes());
        a.put(payload);
        a
    }

    /// `delegate(idx, via, Delegation { ops, Message { max_len }, ttl })`;
    /// `ttl == 0` inherits the parent's expiry.
    pub fn delegate(idx: CapIndex, via: CapIndex, ops: OpSet, max_len: u16, ttl: u32) -> Args {
        let mut a = Args::start(cmd::DELEGATE);
        a.put(&idx.0.to_le_bytes());
        a.put(&via.0.to_le_bytes());
        a.put(&ops.bits().to_le_bytes());
        a.put(&max_len.to_le_bytes());
        a.put(&ttl.to_le_bytes());
        a
    }

    /// `revoke(idx)`.
    pub fn revoke(idx: CapIndex) -> Args {
        let mut a = Args::start(cmd::REVOKE);
        a.put(&idx.0.to_le_bytes());
        a
    }

    /// `release(idx)`.
    pub fn release(idx: CapIndex) -> Args {
        let mut a = Args::start(cmd::RELEASE);
        a.put(&idx.0.to_le_bytes());
        a
    }

    /// `granted(i)`.
    pub fn granted(i: u8) -> Args {
        let mut a = Args::start(cmd::GRANTED);
        a.put(&[i]);
        a
    }

    /// The encoded arguments.
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

fn u64_at(b: &[u8], off: usize) -> Result<u64, ExportError> {
    b.get(off..off + 8)
        .and_then(|s| s.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(ExportError::BadArguments)
}

fn u32_at(b: &[u8], off: usize) -> Result<u32, ExportError> {
    b.get(off..off + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(ExportError::BadArguments)
}

fn u16_at(b: &[u8], off: usize) -> Result<u16, ExportError> {
    b.get(off..off + 2)
        .and_then(|s| s.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(ExportError::BadArguments)
}

fn code_of<T>(r: &Result<T, BusError>) -> u8 {
    match r {
        Ok(_) => code::OK,
        Err(BusError::Denied) => code::DENIED,
        Err(BusError::Busy) => code::BUSY,
    }
}

/// Write `[code][value u64]` (or just `[code]`) into `reply`.
fn answer(reply: &mut [u8], code: u8, value: Option<u64>) -> Result<usize, ExportError> {
    let n = if value.is_some() { ANSWER_LEN } else { 1 };
    let out = reply.get_mut(..n).ok_or(ExportError::ReplyTooLong)?;
    out[0] = code;
    if let Some(v) = value {
        out[1..ANSWER_LEN].copy_from_slice(&v.to_le_bytes());
    }
    Ok(n)
}

/// The probes' one export: perform one bus operation as this instance.
fn act(ctx: &Ctx<'_, NativeRuntime>, args: &[u8], reply: &mut [u8]) -> Result<usize, ExportError> {
    let (&op, rest) = args.split_first().ok_or(ExportError::BadArguments)?;
    match op {
        cmd::SEND => {
            let idx = CapIndex(u64_at(rest, 0)?);
            let r = ctx.send(idx, rest.get(8..).unwrap_or(&[]));
            answer(reply, code_of(&r), None)
        }
        cmd::REQUEST => {
            let idx = CapIndex(u64_at(rest, 0)?);
            let timeout = Tick::from(u32_at(rest, 8)?);
            let r = ctx.request(idx, rest.get(12..).unwrap_or(&[]), timeout);
            answer(reply, code_of(&r), Some(r.map_or(0, |t| t.0)))
        }
        cmd::REPLY => {
            let idx = CapIndex(u64_at(rest, 0)?);
            let r = ctx.reply(idx, rest.get(8..).unwrap_or(&[]));
            answer(reply, code_of(&r), None)
        }
        cmd::DELEGATE => {
            let idx = CapIndex(u64_at(rest, 0)?);
            let via = CapIndex(u64_at(rest, 8)?);
            let ops = OpSet::from_bits(u32_at(rest, 16)?);
            let max_len = u16_at(rest, 20)?;
            let ttl = u32_at(rest, 22)?;
            let d = Delegation {
                ops,
                attenuation: Attenuation::Message { max_len },
                ttl: if ttl == 0 {
                    None
                } else {
                    Some(Tick::from(ttl))
                },
            };
            let r = ctx.delegate(idx, via, &d);
            answer(reply, code_of(&r), None)
        }
        cmd::REVOKE => {
            let r = ctx.revoke(CapIndex(u64_at(rest, 0)?));
            let freed = r.map_or(0, |n| u64::try_from(n).unwrap_or(u64::MAX));
            answer(reply, code_of(&r), Some(freed))
        }
        cmd::RELEASE => {
            let r = ctx.release(CapIndex(u64_at(rest, 0)?));
            answer(reply, code_of(&r), None)
        }
        cmd::GRANTED => {
            let i = *rest.first().ok_or(ExportError::BadArguments)?;
            match ctx.granted(usize::from(i)) {
                Some(idx) => answer(reply, code::OK, Some(idx.0)),
                None => answer(reply, code::NONE, Some(0)),
            }
        }
        _ => Err(ExportError::BadArguments),
    }
}

// ── The handlers ─────────────────────────────────────────────────────────────

fn observe(ctx: &Ctx<'_, NativeRuntime>, env: &Envelope) {
    record(ctx.me(), env, None);
}

fn bob_on_message(ctx: &Ctx<'_, NativeRuntime>, env: &Envelope) {
    let mut answered = None;
    if let Kind::Request { reply } = env.kind {
        if env.payload.as_slice() != QUIET {
            answered = Some(ctx.reply(reply, b"ack").is_ok());
        }
    }
    record(ctx.me(), env, answered);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_encode_what_act_decodes() {
        let a = Args::delegate(CapIndex(0x0102_0304_0506_0708), CapIndex(9), SEND, 64, 0);
        let s = a.as_slice();
        assert_eq!(s[0], cmd::DELEGATE);
        assert_eq!(u64_at(&s[1..], 0), Ok(0x0102_0304_0506_0708));
        assert_eq!(u64_at(&s[1..], 8), Ok(9));
        assert_eq!(u32_at(&s[1..], 16), Ok(SEND.bits()));
        assert_eq!(u16_at(&s[1..], 20), Ok(64));
        assert_eq!(u32_at(&s[1..], 22), Ok(0));
        assert_eq!(s.len(), 1 + 26);
        assert_eq!(u32_at(&s[1..], 23), Err(ExportError::BadArguments));
        let r = Args::request(CapIndex(5), 7, b"hi");
        assert_eq!(u32_at(&r.as_slice()[1..], 8), Ok(7));
        assert_eq!(&r.as_slice()[13..], b"hi");
        // The encoder never overruns its buffer.
        let big = [1u8; MAX_PAYLOAD + 10];
        assert_eq!(Args::send(CapIndex(1), &big).as_slice().len(), MAX_PAYLOAD);
        // Value-carrying answers are `[code][u64]`.
        let mut out = [0u8; ANSWER_LEN];
        assert_eq!(answer(&mut out, code::OK, Some(u64::MAX)), Ok(ANSWER_LEN));
        assert_eq!(&out[1..], &u64::MAX.to_le_bytes());
        assert_eq!(
            answer(&mut out[..4], code::OK, Some(1)),
            Err(ExportError::ReplyTooLong)
        );
    }

    #[test]
    fn the_policy_names_only_alice() {
        assert!(POLICY_RULES.iter().all(|r| r.holder == ALICE_ID));
        // carol-strict is not carol: the `Required` mark is in the id.
        assert_ne!(CAROL_STRICT_MANIFEST.id, CAROL_ID);
        assert_eq!(CAROL_STRICT_MANIFEST.id, CAROL_STRICT_ID);
        assert_eq!(CAROL_STRICT_MANIFEST.code, CAROL_MANIFEST.code);
        assert_eq!(CAROL_STRICT_MANIFEST.caps[0].need, CapNeed::Required);
        assert!(POLICY_RULES
            .iter()
            .all(|r| r.holder != CAROL_ID && r.holder != CAROL_STRICT_ID));
    }

    #[test]
    fn every_route_names_a_provider_whose_manifest_provides_it() {
        for r in POLICY_ROUTES {
            let m = MANIFESTS
                .iter()
                .map(|(_, m)| m)
                .find(|m| m.id == r.provider)
                .expect("the routed provider is a probe");
            assert!(m.provides.contains(&r.service));
        }
    }
}
