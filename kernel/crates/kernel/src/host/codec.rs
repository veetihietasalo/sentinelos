//! Envelope wire codec — the bytes a component actually receives.
//!
//! Spec §7: every message between the kernel and a component, or between two
//! components, is an [`Envelope`] whose `from` field is written by the kernel
//! and never by the sender. On the wire an envelope is a fixed 68-byte header
//! followed by at most [`MAX_PAYLOAD`] payload bytes, little-endian throughout
//! (version 2, PR-2b: the tag and index fields widened to `u64` with the
//! capability index, amendment A13):
//!
//! ```text
//! off  len  field
//!  0    1   WIRE_VERSION (= 2)
//!  1    1   kind          0 = Event, 1 = Request, 2 = Reply, 3 = Grant
//!  2    8   reply_tag     u64; MUST be 0 for Event (canonical form);
//!                         Request: the responder's reply CapIndex;
//!                         Reply: the requester's ReplyTag;
//!                         Grant: the granted CapIndex
//! 10    8   from.instance u64
//! 18   32   from.component (ComponentId)
//! 50    8   to            u64 (InstanceId)
//! 58    8   cap           u64 (CapIndex the sender used)
//! 66    2   payload_len   u16 ≤ MAX_PAYLOAD
//! 68    n   payload
//! ```
//!
//! Version 1 (60-byte header, `u32` tag and index) is refused
//! ([`DecodeError::Version`]): nothing persists an envelope, so there is
//! nothing to migrate.
//!
//! [`decode`] is total (a `Result`, never a panic) and accepts exactly the
//! canonical encodings, so `decode(encode(e)) == e` for every envelope and
//! `encode(decode(b)) == b` for every accepted byte string. Both are proven
//! bounded by Kani (`proofs`). Every bus delivery is encoded into the
//! recipient's inbox ring and decoded on dispatch (`crate::bus`), and the
//! kernel's own calls round-trip request and reply through it
//! (`crate::bus::call`); both boot proofs exercise both paths.
//!
//! Sizes are fixed on purpose: an inbox ring holds [`Wire`] values, so nothing
//! grows and nothing allocates on the delivery path (spec §7, "nothing grows").

use super::{ComponentId, InstanceId};

/// Wire format version byte.
pub const WIRE_VERSION: u8 = 2;
/// Largest payload one envelope carries. Larger transfers go through a
/// shared-buffer capability (later PR).
pub const MAX_PAYLOAD: usize = 256;
/// Fixed header length.
pub const HEADER_LEN: usize = 68;
/// Largest encoded envelope.
pub const MAX_ENVELOPE: usize = HEADER_LEN + MAX_PAYLOAD;

const OFF_VERSION: usize = 0;
const OFF_KIND: usize = 1;
const OFF_REPLY_TAG: usize = 2;
const OFF_FROM_INSTANCE: usize = 10;
const OFF_FROM_COMPONENT: usize = 18;
const OFF_TO: usize = 50;
const OFF_CAP: usize = 58;
const OFF_PAYLOAD_LEN: usize = 66;

/// Index into the sender's capability table that authorised a send — defined
/// with its meaning in `kernel::cap` (PR-2), carried verbatim on the wire.
pub use crate::cap::CapIndex;
/// A requester's correlation tag — defined in `kernel::cap` (PR-2b, R10),
/// carried verbatim on the wire.
pub use crate::cap::ReplyTag;

/// Who sent an envelope — both the *which* (instance) and the *what*
/// (component), stamped by the kernel (spec §7, amendment A2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Sender {
    /// *Which* instance sent it.
    pub instance: InstanceId,
    /// *What* sent it: the component id the host verified.
    pub component: ComponentId,
}

impl Sender {
    /// The kernel itself.
    pub const KERNEL: Sender = Sender {
        instance: InstanceId::KERNEL,
        component: ComponentId::KERNEL,
    };
}

/// Message kind.
///
/// The two ends of a request see different values, both chosen by the kernel
/// and, since PR-2b (spec §19 R10), of different types: the responder's
/// `Request { reply }` is the [`CapIndex`] of the one-shot reply capability
/// the host minted in **its** table for this request (it answers with
/// `bus::Ctx::reply(reply, …)`); the requester's `Reply { tag }` is the
/// [`ReplyTag`] its own `bus::Ctx::request` returned. Both travel in the
/// wire's `reply_tag` field.
///
/// A kernel call (`bus::call`) is answered by the export's return value, not
/// over a capability: its `Request` carries [`CapIndex::KERNEL`], valid in no
/// table, and its `Reply` the kernel's own tag.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// One-way message.
    Event,
    /// A request expecting at most one answer.
    Request {
        /// The responder's one-shot right to answer it (see the type docs).
        reply: CapIndex,
    },
    /// The answer to a request.
    Reply {
        /// The requester's correlation tag (see the type docs).
        tag: ReplyTag,
    },
    /// A delegation notice: the sender delegated a capability to the
    /// recipient, now installed at `granted` in the recipient's own table.
    /// The kernel writes it, so the recipient learns the index from the
    /// kernel, never from the delegator's payload (no confused deputy).
    Grant {
        /// The new capability's index in the recipient's table.
        granted: CapIndex,
    },
}

impl Kind {
    const EVENT: u8 = 0;
    const REQUEST: u8 = 1;
    const REPLY: u8 = 2;
    const GRANT: u8 = 3;

    fn to_wire(self) -> (u8, u64) {
        match self {
            Kind::Event => (Self::EVENT, 0),
            Kind::Request { reply } => (Self::REQUEST, reply.0),
            Kind::Reply { tag } => (Self::REPLY, tag.0),
            Kind::Grant { granted } => (Self::GRANT, granted.0),
        }
    }

    fn from_wire(code: u8, reply_tag: u64) -> Result<Kind, DecodeError> {
        match (code, reply_tag) {
            (Self::EVENT, 0) => Ok(Kind::Event),
            (Self::EVENT, _) => Err(DecodeError::Kind),
            (Self::REQUEST, idx) => Ok(Kind::Request {
                reply: CapIndex(idx),
            }),
            (Self::REPLY, tag) => Ok(Kind::Reply { tag: ReplyTag(tag) }),
            (Self::GRANT, idx) => Ok(Kind::Grant {
                granted: CapIndex(idx),
            }),
            _ => Err(DecodeError::Kind),
        }
    }
}

/// An inline payload of at most [`MAX_PAYLOAD`] bytes. Unused tail bytes are
/// always zero, so two payloads with equal contents compare equal.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Payload {
    bytes: [u8; MAX_PAYLOAD],
    len: u16,
}

/// `Payload::new` was handed more than [`MAX_PAYLOAD`] bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PayloadTooLong;

impl Payload {
    /// The empty payload.
    pub const EMPTY: Payload = Payload {
        bytes: [0; MAX_PAYLOAD],
        len: 0,
    };

    /// Copy `data` into a payload; `Err` if it does not fit.
    pub fn new(data: &[u8]) -> Result<Payload, PayloadTooLong> {
        if data.len() > MAX_PAYLOAD {
            return Err(PayloadTooLong);
        }
        let mut p = Payload::EMPTY;
        p.bytes[..data.len()].copy_from_slice(data);
        p.len = data.len() as u16;
        Ok(p)
    }

    /// The live bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    /// Number of live bytes.
    pub fn len(&self) -> usize {
        usize::from(self.len)
    }

    /// `true` when there are no live bytes.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl core::fmt::Debug for Payload {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Payload").field(&self.as_slice()).finish()
    }
}

/// One message. See the module docs for the wire layout.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Envelope {
    /// Stamped by the kernel from the running instance; never by the sender.
    pub from: Sender,
    /// Resolved by the kernel from the capability used to send.
    pub to: InstanceId,
    /// The sender's capability that authorised this send.
    pub cap: CapIndex,
    /// Event, request, reply, or delegation notice.
    pub kind: Kind,
    /// The message body (at most [`MAX_PAYLOAD`] bytes).
    pub payload: Payload,
}

/// Why a byte string is not a canonical envelope.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DecodeError {
    /// Fewer bytes than the header, or than `payload_len` promises.
    Short,
    /// Unknown `WIRE_VERSION`.
    Version,
    /// Unknown kind code, or an `Event` with a non-zero `reply_tag`.
    Kind,
    /// `payload_len` exceeds [`MAX_PAYLOAD`].
    PayloadLength,
    /// Bytes after the payload.
    Trailing,
}

impl DecodeError {
    /// Fixed label for `fmt`-free console output.
    pub fn label(self) -> &'static str {
        match self {
            DecodeError::Short => "short",
            DecodeError::Version => "version",
            DecodeError::Kind => "kind",
            DecodeError::PayloadLength => "payload-length",
            DecodeError::Trailing => "trailing",
        }
    }
}

/// `encode` was handed an output buffer smaller than the encoding.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BufferTooSmall;

/// Bytes `encode` will produce for `env`.
pub fn encoded_len(env: &Envelope) -> usize {
    HEADER_LEN + env.payload.len()
}

/// Write the canonical encoding of `env` into `out`; returns the byte count.
pub fn encode(env: &Envelope, out: &mut [u8]) -> Result<usize, BufferTooSmall> {
    let total = encoded_len(env);
    let out = out.get_mut(..total).ok_or(BufferTooSmall)?;
    let (kind, reply_tag) = env.kind.to_wire();
    out[OFF_VERSION] = WIRE_VERSION;
    out[OFF_KIND] = kind;
    out[OFF_REPLY_TAG..OFF_REPLY_TAG + 8].copy_from_slice(&reply_tag.to_le_bytes());
    out[OFF_FROM_INSTANCE..OFF_FROM_INSTANCE + 8]
        .copy_from_slice(&env.from.instance.0.to_le_bytes());
    out[OFF_FROM_COMPONENT..OFF_FROM_COMPONENT + 32].copy_from_slice(&env.from.component.0);
    out[OFF_TO..OFF_TO + 8].copy_from_slice(&env.to.0.to_le_bytes());
    out[OFF_CAP..OFF_CAP + 8].copy_from_slice(&env.cap.0.to_le_bytes());
    out[OFF_PAYLOAD_LEN..OFF_PAYLOAD_LEN + 2]
        .copy_from_slice(&(env.payload.len() as u16).to_le_bytes());
    out[HEADER_LEN..total].copy_from_slice(env.payload.as_slice());
    Ok(total)
}

/// Parse exactly one canonical envelope from `bytes`. Total: never panics.
pub fn decode(bytes: &[u8]) -> Result<Envelope, DecodeError> {
    let header: &[u8; HEADER_LEN] = bytes
        .get(..HEADER_LEN)
        .and_then(|h| h.try_into().ok())
        .ok_or(DecodeError::Short)?;
    if header[OFF_VERSION] != WIRE_VERSION {
        return Err(DecodeError::Version);
    }
    let kind = Kind::from_wire(header[OFF_KIND], u64_at(header, OFF_REPLY_TAG))?;
    let payload_len = usize::from(u16::from_le_bytes([
        header[OFF_PAYLOAD_LEN],
        header[OFF_PAYLOAD_LEN + 1],
    ]));
    if payload_len > MAX_PAYLOAD {
        return Err(DecodeError::PayloadLength);
    }
    let payload_bytes = bytes
        .get(HEADER_LEN..HEADER_LEN + payload_len)
        .ok_or(DecodeError::Short)?;
    if bytes.len() != HEADER_LEN + payload_len {
        return Err(DecodeError::Trailing);
    }
    let mut component = [0u8; 32];
    component.copy_from_slice(&header[OFF_FROM_COMPONENT..OFF_FROM_COMPONENT + 32]);
    Ok(Envelope {
        from: Sender {
            instance: InstanceId(u64_at(header, OFF_FROM_INSTANCE)),
            component: ComponentId(component),
        },
        to: InstanceId(u64_at(header, OFF_TO)),
        cap: CapIndex(u64_at(header, OFF_CAP)),
        kind,
        // Cannot fail: `payload_len <= MAX_PAYLOAD` was checked above.
        payload: Payload::new(payload_bytes).map_err(|_| DecodeError::PayloadLength)?,
    })
}

fn u64_at(h: &[u8; HEADER_LEN], off: usize) -> u64 {
    u64::from_le_bytes([
        h[off],
        h[off + 1],
        h[off + 2],
        h[off + 3],
        h[off + 4],
        h[off + 5],
        h[off + 6],
        h[off + 7],
    ])
}

/// An encoded envelope in a fixed buffer — what an inbox ring stores and what a
/// component reads. `Copy` so rings can be built with `[None; N]`.
#[derive(Clone, Copy)]
pub struct Wire {
    bytes: [u8; MAX_ENVELOPE],
    len: u16,
}

impl Wire {
    /// Encode `env`. Infallible: every envelope fits in [`MAX_ENVELOPE`].
    pub fn encode(env: &Envelope) -> Wire {
        let mut w = Wire {
            bytes: [0; MAX_ENVELOPE],
            len: 0,
        };
        // `encoded_len(env) <= MAX_ENVELOPE` by construction of `Payload`, so
        // this cannot fail; a zero-length wire is the visible fallback.
        w.len = encode(env, &mut w.bytes).unwrap_or(0) as u16;
        w
    }

    /// The encoded bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    /// Parse back into an envelope.
    pub fn decode(&self) -> Result<Envelope, DecodeError> {
        decode(self.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(kind: Kind, payload: &[u8]) -> Envelope {
        Envelope {
            from: Sender {
                instance: InstanceId(7),
                component: ComponentId([0xAB; 32]),
            },
            to: InstanceId(9),
            cap: CapIndex(3),
            kind,
            payload: Payload::new(payload).unwrap(),
        }
    }

    #[test]
    fn round_trips_every_kind() {
        for kind in [
            Kind::Event,
            Kind::Request {
                reply: CapIndex(0xDEAD_BEEF_0BAD_F00D),
            },
            Kind::Reply { tag: ReplyTag(1) },
            Kind::Reply {
                tag: ReplyTag(u64::MAX),
            },
            Kind::Grant {
                granted: CapIndex(0x0102_0304_0506_0708),
            },
        ] {
            let env = sample(kind, b"hello");
            let mut buf = [0u8; MAX_ENVELOPE];
            let n = encode(&env, &mut buf).unwrap();
            assert_eq!(n, HEADER_LEN + 5);
            assert_eq!(decode(&buf[..n]).unwrap(), env);
            let wire = Wire::encode(&env);
            assert_eq!(wire.as_slice(), &buf[..n]);
            assert_eq!(wire.decode().unwrap(), env);
        }
    }

    #[test]
    fn round_trips_the_largest_payload() {
        let big = [0x5A; MAX_PAYLOAD];
        let env = sample(Kind::Event, &big);
        let wire = Wire::encode(&env);
        assert_eq!(wire.as_slice().len(), MAX_ENVELOPE);
        assert_eq!(wire.decode().unwrap(), env);
    }

    #[test]
    fn rejects_short_wrong_version_trailing_and_bad_kind() {
        let env = sample(Kind::Request { reply: CapIndex(4) }, b"xy");
        let mut buf = [0u8; MAX_ENVELOPE];
        let n = encode(&env, &mut buf).unwrap();
        assert_eq!(decode(&buf[..HEADER_LEN - 1]), Err(DecodeError::Short));
        assert_eq!(decode(&buf[..n - 1]), Err(DecodeError::Short));
        assert_eq!(decode(&buf[..n + 1]), Err(DecodeError::Trailing));
        let mut bad = buf;
        bad[OFF_VERSION] = 1;
        assert_eq!(
            decode(&bad[..n]),
            Err(DecodeError::Version),
            "the v1 (u32) format is refused"
        );
        let mut bad = buf;
        bad[OFF_VERSION] = 3;
        assert_eq!(decode(&bad[..n]), Err(DecodeError::Version));
        let mut bad = buf;
        bad[OFF_KIND] = 9;
        assert_eq!(decode(&bad[..n]), Err(DecodeError::Kind));
        // An Event must carry reply_tag 0: the non-canonical form is refused,
        // which is what makes encode∘decode the identity on accepted input.
        let mut bad = buf;
        bad[OFF_KIND] = 0;
        assert_eq!(decode(&bad[..n]), Err(DecodeError::Kind));
        let mut bad = buf;
        bad[OFF_PAYLOAD_LEN..OFF_PAYLOAD_LEN + 2].copy_from_slice(&300u16.to_le_bytes());
        assert_eq!(decode(&bad[..n]), Err(DecodeError::PayloadLength));
    }

    #[test]
    fn payload_bounds_and_equality() {
        assert!(Payload::new(&[0; MAX_PAYLOAD]).is_ok());
        assert_eq!(Payload::new(&[0; MAX_PAYLOAD + 1]), Err(PayloadTooLong));
        assert_eq!(Payload::new(b"a").unwrap(), Payload::new(b"a").unwrap());
        assert_ne!(Payload::new(b"a").unwrap(), Payload::new(b"b").unwrap());
        assert!(Payload::EMPTY.is_empty());
    }

    #[test]
    fn the_v2_header_layout_is_exact() {
        assert_eq!(WIRE_VERSION, 2);
        assert_eq!(HEADER_LEN, 68);
        let env = Envelope {
            from: Sender {
                instance: InstanceId(0x1111_2222_3333_4444),
                component: ComponentId([0xC0; 32]),
            },
            to: InstanceId(0x5555_6666_7777_8888),
            cap: CapIndex(0x0102_0304_0506_0708),
            kind: Kind::Reply {
                tag: ReplyTag(0x99AA_BBCC_DDEE_FF00),
            },
            payload: Payload::new(b"z").unwrap(),
        };
        let mut buf = [0u8; MAX_ENVELOPE];
        let n = encode(&env, &mut buf).unwrap();
        assert_eq!(n, 69);
        assert_eq!(buf[0], 2);
        assert_eq!(buf[1], 2, "reply");
        assert_eq!(&buf[2..10], &0x99AA_BBCC_DDEE_FF00u64.to_le_bytes());
        assert_eq!(&buf[10..18], &0x1111_2222_3333_4444u64.to_le_bytes());
        assert_eq!(&buf[18..50], &[0xC0; 32]);
        assert_eq!(&buf[50..58], &0x5555_6666_7777_8888u64.to_le_bytes());
        assert_eq!(&buf[58..66], &0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(&buf[66..68], &1u16.to_le_bytes());
        assert_eq!(buf[68], b'z');
    }

    #[test]
    fn encode_reports_a_small_buffer() {
        let env = sample(Kind::Event, b"abc");
        let mut buf = [0u8; HEADER_LEN + 2];
        assert_eq!(encode(&env, &mut buf), Err(BufferTooSmall));
    }
}

/// Kani proof harnesses for the codec. Compiled only under `cargo kani`.
#[cfg(kani)]
mod proofs {
    use super::*;

    /// `decode(encode(e)) == e` for a symbolic header and a bounded symbolic
    /// payload — every field, every kind, every payload length up to the bound.
    ///
    /// Solver: minisat (PR-2b). The v2 header's wider tag and index fields
    /// took this harness from ~82 s to 113 s locally under the default
    /// (cadical), unchanged with the payload bound cut to 3; minisat discharges
    /// it in ~35 s at the original bound of 4 (spec §19 R16).
    #[kani::proof]
    #[kani::solver(minisat)]
    fn envelope_codec_round_trips_bounded() {
        const MAX: usize = 4;
        let code: u8 = kani::any();
        kani::assume(code <= 3);
        let reply_tag: u64 = kani::any();
        let kind = match code {
            0 => Kind::Event,
            1 => Kind::Request {
                reply: CapIndex(reply_tag),
            },
            2 => Kind::Reply {
                tag: ReplyTag(reply_tag),
            },
            _ => Kind::Grant {
                granted: CapIndex(reply_tag),
            },
        };
        let len: usize = kani::any();
        kani::assume(len <= MAX);
        let raw: [u8; MAX] = kani::any();
        let env = Envelope {
            from: Sender {
                instance: InstanceId(kani::any()),
                component: ComponentId(kani::any()),
            },
            to: InstanceId(kani::any()),
            cap: CapIndex(kani::any()),
            kind,
            payload: Payload::new(&raw[..len]).unwrap(),
        };
        let mut buf = [0u8; MAX_ENVELOPE];
        let n = encode(&env, &mut buf).unwrap();
        assert!(n == HEADER_LEN + len);
        let back = decode(&buf[..n]).unwrap();
        assert!(back == env);
    }

    /// `decode` never panics on any byte string up to a header plus a little
    /// payload: every rejection is a `Result`, never an index out of bounds.
    #[kani::proof]
    fn envelope_decode_is_total_bounded() {
        const N: usize = HEADER_LEN + 2;
        let bytes: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        let _ = decode(&bytes[..len]);
    }
}
