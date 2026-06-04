//! ICMP echo (ping) — request + reply — pure safe logic.
//!
//! An ICMP message header is `[type(1)][code(1)][checksum(2)]` followed by
//! type-specific data. For echo request (type 8) / echo reply (type 0) the next
//! four bytes are `[identifier(2)][sequence(2)]`, then an arbitrary payload that
//! a reply echoes back verbatim. The checksum covers the whole ICMP message
//! (header + data) using the internet checksum ([`super::ipv4::checksum`]).
//!
//! All byte arithmetic over slices — no `unsafe`, no allocation.

use super::ipv4::checksum;

/// ICMP type: echo reply.
pub const TYPE_ECHO_REPLY: u8 = 0;
/// ICMP type: echo request.
pub const TYPE_ECHO_REQUEST: u8 = 8;

/// The fixed ICMP echo header length (`type`+`code`+`checksum`+`id`+`seq`).
pub const ECHO_HEADER_LEN: usize = 8;

/// A parsed ICMP echo message (request or reply): the identifier/sequence plus
/// a borrow of the echo payload.
#[derive(Clone, Copy, Debug)]
pub struct EchoMessage<'a> {
    /// Message type ([`TYPE_ECHO_REQUEST`] or [`TYPE_ECHO_REPLY`]).
    pub msg_type: u8,
    /// Echo identifier.
    pub ident: u16,
    /// Echo sequence number.
    pub seq: u16,
    /// The echo payload (after the 8-byte header).
    pub payload: &'a [u8],
}

impl<'a> EchoMessage<'a> {
    /// Parse an ICMP echo message from `buf`, or `None` if too short or not an
    /// echo request/reply.
    #[must_use]
    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < ECHO_HEADER_LEN {
            return None;
        }
        let msg_type = buf[0];
        if msg_type != TYPE_ECHO_REQUEST && msg_type != TYPE_ECHO_REPLY {
            return None;
        }
        let ident = u16::from_be_bytes([buf[4], buf[5]]);
        let seq = u16::from_be_bytes([buf[6], buf[7]]);
        Some(Self {
            msg_type,
            ident,
            seq,
            payload: &buf[ECHO_HEADER_LEN..],
        })
    }
}

/// Write an ICMP echo message of `msg_type` (request or reply) into the front of
/// `out`, with the given identifier/sequence and `payload`, computing the ICMP
/// checksum over the whole message. Returns the total ICMP message length
/// (`8 + payload.len()`), or `None` if `out` is too small.
#[must_use]
pub fn write_echo(
    out: &mut [u8],
    msg_type: u8,
    ident: u16,
    seq: u16,
    payload: &[u8],
) -> Option<usize> {
    let total = ECHO_HEADER_LEN + payload.len();
    if out.len() < total {
        return None;
    }
    out[0] = msg_type;
    out[1] = 0; // code
    out[2..4].copy_from_slice(&[0, 0]); // checksum placeholder
    out[4..6].copy_from_slice(&ident.to_be_bytes());
    out[6..8].copy_from_slice(&seq.to_be_bytes());
    out[ECHO_HEADER_LEN..total].copy_from_slice(payload);
    let csum = checksum(&out[0..total]);
    out[2..4].copy_from_slice(&csum.to_be_bytes());
    Some(total)
}

/// Build an echo **reply** to a parsed echo `request`, into `out`. Mirrors the
/// identifier, sequence, and payload (as a real ping reply does). Returns the
/// ICMP message length or `None` if `out` is too small.
#[must_use]
pub fn reply_to(out: &mut [u8], request: &EchoMessage<'_>) -> Option<usize> {
    write_echo(
        out,
        TYPE_ECHO_REPLY,
        request.ident,
        request.seq,
        request.payload,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_roundtrip_and_checksum() {
        let payload = b"sentinelos-ping";
        let mut buf = [0u8; 64];
        let n = write_echo(&mut buf, TYPE_ECHO_REQUEST, 0xABCD, 1, payload).unwrap();
        assert_eq!(n, ECHO_HEADER_LEN + payload.len());
        // A correct ICMP message checksums to zero over its bytes.
        assert_eq!(checksum(&buf[0..n]), 0);
        let m = EchoMessage::parse(&buf[0..n]).unwrap();
        assert_eq!(m.msg_type, TYPE_ECHO_REQUEST);
        assert_eq!(m.ident, 0xABCD);
        assert_eq!(m.seq, 1);
        assert_eq!(m.payload, payload);
    }

    #[test]
    fn reply_mirrors_request() {
        let payload = b"abc";
        let mut req = [0u8; 32];
        let n = write_echo(&mut req, TYPE_ECHO_REQUEST, 7, 42, payload).unwrap();
        let parsed = EchoMessage::parse(&req[0..n]).unwrap();
        let mut rep = [0u8; 32];
        let rn = reply_to(&mut rep, &parsed).unwrap();
        let prep = EchoMessage::parse(&rep[0..rn]).unwrap();
        assert_eq!(prep.msg_type, TYPE_ECHO_REPLY);
        assert_eq!(prep.ident, 7);
        assert_eq!(prep.seq, 42);
        assert_eq!(prep.payload, payload);
        assert_eq!(checksum(&rep[0..rn]), 0);
    }
}
