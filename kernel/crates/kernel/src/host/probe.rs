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
use crate::cap::{Attenuation, CapIndex, CapNeed, CapRequest, Op, OpSet, PolicyRule, Tick};

/// alice's descriptor — her `code` bytes for hashing.
pub const ALICE_DESCRIPTOR: &[u8] =
    b"sentinelos/native-component\nname: alice\nversion: 1\nexports: act\nrole: cap-proof holder\n";
/// bob's descriptor.
pub const BOB_DESCRIPTOR: &[u8] =
    b"sentinelos/native-component\nname: bob\nversion: 1\nexports: act\nrole: cap-proof receiver\n";
/// carol's descriptor.
pub const CAROL_DESCRIPTOR: &[u8] =
    b"sentinelos/native-component\nname: carol\nversion: 1\nexports: act\nrole: cap-proof probe\n";

/// `ComponentId::derive(ALICE_DESCRIPTOR, b"")` — a literal, kept honest by
/// `native::tests::manifest_id_literals_match_the_framed_hash`.
pub const ALICE_ID: ComponentId =
    id_literal("7d2ebb834a7d23e075177b86478592f0d566da0771b21fd77812333f79c66cc7");
/// `ComponentId::derive(BOB_DESCRIPTOR, b"")`.
pub const BOB_ID: ComponentId =
    id_literal("aa724c93db1344380645099121dc560b9bf8a66d84fc9946160b9f865fe079fc");
/// `ComponentId::derive(CAROL_DESCRIPTOR, b"")`.
pub const CAROL_ID: ComponentId =
    id_literal("d59f88594b41cc38b5d0791d01079a6cf57d742fc5e919fce6def5ccfe842f91");

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

/// alice asks for bob (required) and carol (optional).
pub const ALICE_MANIFEST: Manifest = Manifest {
    code: ALICE_DESCRIPTOR,
    params: b"",
    id: ALICE_ID,
    caps: &[
        CapRequest {
            target: BOB_ID,
            ops: SEND_REQUEST_DELEGATE,
            attenuation: Attenuation::UNRESTRICTED_MESSAGE,
            need: CapNeed::Required,
        },
        CapRequest {
            target: CAROL_ID,
            ops: SEND,
            attenuation: Attenuation::UNRESTRICTED_MESSAGE,
            need: CapNeed::Optional,
        },
    ],
};

/// bob asks for nothing.
pub const BOB_MANIFEST: Manifest = Manifest {
    code: BOB_DESCRIPTOR,
    params: b"",
    id: BOB_ID,
    caps: &[],
};

const CAROL_ASKS_FOR_BOB: CapRequest = CapRequest {
    target: BOB_ID,
    ops: SEND,
    attenuation: Attenuation::UNRESTRICTED_MESSAGE,
    need: CapNeed::Optional,
};

/// carol asks for `Send` over bob, optionally; the policy has no rule for it.
pub const CAROL_MANIFEST: Manifest = Manifest {
    code: CAROL_DESCRIPTOR,
    params: b"",
    id: CAROL_ID,
    caps: &[CAROL_ASKS_FOR_BOB],
};

/// The same request marked **required**: refused to start (amendment A8).
pub const CAROL_STRICT_MANIFEST: Manifest = Manifest {
    caps: &[CapRequest {
        need: CapNeed::Required,
        ..CAROL_ASKS_FOR_BOB
    }],
    ..CAROL_MANIFEST
};

/// The boot policy's rules: alice may reach bob (send, request, delegate) and
/// carol (send). Nothing else — in particular nothing for carol or bob.
pub const POLICY_RULES: &[PolicyRule] = &[
    PolicyRule {
        holder: ALICE_ID,
        target: BOB_ID,
        ops: SEND_REQUEST_DELEGATE,
        attenuation: Attenuation::UNRESTRICTED_MESSAGE,
        ttl: None,
    },
    PolicyRule {
        holder: ALICE_ID,
        target: CAROL_ID,
        ops: SEND,
        attenuation: Attenuation::UNRESTRICTED_MESSAGE,
        ttl: None,
    },
];

// ── The `act` protocol ──────────────────────────────────────────────────────

/// Command bytes (first byte of `act`'s arguments; integers little-endian).
pub mod cmd {
    /// `[idx u32][payload…]` → `[code]`.
    pub const SEND: u8 = 1;
    /// `[idx u32][timeout u32][payload…]` → `[code][tag u32]`.
    pub const REQUEST: u8 = 2;
    /// `[reply-idx u32][payload…]` → `[code]`.
    pub const REPLY: u8 = 3;
    /// `[idx u32][via u32][ops u32][max_len u16][ttl u32, 0 = inherit]` → `[code]`.
    pub const DELEGATE: u8 = 4;
    /// `[idx u32]` → `[code][freed u32]`.
    pub const REVOKE: u8 = 5;
    /// `[idx u32]` → `[code]`.
    pub const RELEASE: u8 = 6;
    /// `[i u8]` → `[code][idx u32]`: the index granted for manifest request `i`.
    pub const GRANTED: u8 = 7;
}

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

/// Write `[code][value u32]` (or just `[code]`) into `reply`.
fn answer(reply: &mut [u8], code: u8, value: Option<u32>) -> Result<usize, ExportError> {
    let n = if value.is_some() { 5 } else { 1 };
    let out = reply.get_mut(..n).ok_or(ExportError::ReplyTooLong)?;
    out[0] = code;
    if let Some(v) = value {
        out[1..5].copy_from_slice(&v.to_le_bytes());
    }
    Ok(n)
}

/// The probes' one export: perform one bus operation as this instance.
fn act(ctx: &Ctx<'_, NativeRuntime>, args: &[u8], reply: &mut [u8]) -> Result<usize, ExportError> {
    let (&op, rest) = args.split_first().ok_or(ExportError::BadArguments)?;
    match op {
        cmd::SEND => {
            let idx = CapIndex(u32_at(rest, 0)?);
            let r = ctx.send(idx, rest.get(4..).unwrap_or(&[]));
            answer(reply, code_of(&r), None)
        }
        cmd::REQUEST => {
            let idx = CapIndex(u32_at(rest, 0)?);
            let timeout = Tick::from(u32_at(rest, 4)?);
            let r = ctx.request(idx, rest.get(8..).unwrap_or(&[]), timeout);
            answer(reply, code_of(&r), Some(r.unwrap_or(0)))
        }
        cmd::REPLY => {
            let idx = CapIndex(u32_at(rest, 0)?);
            let r = ctx.reply(idx, rest.get(4..).unwrap_or(&[]));
            answer(reply, code_of(&r), None)
        }
        cmd::DELEGATE => {
            let idx = CapIndex(u32_at(rest, 0)?);
            let via = CapIndex(u32_at(rest, 4)?);
            let ops = OpSet::from_bits(u32_at(rest, 8)?);
            let max_len = u16_at(rest, 12)?;
            let ttl = u32_at(rest, 14)?;
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
            let r = ctx.revoke(CapIndex(u32_at(rest, 0)?));
            let freed = r.map_or(0, |n| u32::try_from(n).unwrap_or(u32::MAX));
            answer(reply, code_of(&r), Some(freed))
        }
        cmd::RELEASE => {
            let r = ctx.release(CapIndex(u32_at(rest, 0)?));
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
    if let Kind::Request { reply_tag } = env.kind {
        if env.payload.as_slice() != QUIET {
            answered = Some(ctx.reply(CapIndex(reply_tag), b"ack").is_ok());
        }
    }
    record(ctx.me(), env, answered);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_encode_what_act_decodes() {
        let a = Args::delegate(CapIndex(0x0102_0304), CapIndex(9), SEND, 64, 0);
        let s = a.as_slice();
        assert_eq!(s[0], cmd::DELEGATE);
        assert_eq!(u32_at(&s[1..], 0), Ok(0x0102_0304));
        assert_eq!(u32_at(&s[1..], 4), Ok(9));
        assert_eq!(u32_at(&s[1..], 8), Ok(SEND.bits()));
        assert_eq!(u16_at(&s[1..], 12), Ok(64));
        assert_eq!(u32_at(&s[1..], 14), Ok(0));
        assert_eq!(u32_at(&s[1..], 15), Err(ExportError::BadArguments));
        let r = Args::request(CapIndex(5), 7, b"hi");
        assert_eq!(&r.as_slice()[9..], b"hi");
        // The encoder never overruns its buffer.
        let big = [1u8; MAX_PAYLOAD + 10];
        assert_eq!(Args::send(CapIndex(1), &big).as_slice().len(), MAX_PAYLOAD);
    }

    #[test]
    fn the_policy_names_only_alice() {
        assert!(POLICY_RULES.iter().all(|r| r.holder == ALICE_ID));
        assert_eq!(CAROL_STRICT_MANIFEST.id, CAROL_ID);
        assert_eq!(CAROL_STRICT_MANIFEST.caps[0].need, CapNeed::Required);
    }
}
