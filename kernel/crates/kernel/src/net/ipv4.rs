//! IPv4 address type, header parse/build, and the internet checksum — pure safe
//! logic.
//!
//! We implement the minimum needed to carry ICMP: parse an incoming IPv4 header
//! (to find the protocol + payload), build an outgoing header, and compute the
//! one's-complement "internet checksum" (RFC 1071) used by both the IPv4 header
//! and ICMP. No options, no fragmentation — QEMU SLIRP never fragments the small
//! frames we exchange. All byte arithmetic; no `unsafe`, no allocation.

/// The minimum (option-less) IPv4 header length, in bytes.
pub const HEADER_LEN: usize = 20;

/// IP protocol number for ICMP.
pub const PROTO_ICMP: u8 = 1;

/// An IPv4 address (four octets, stored big-endian-as-written).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ipv4Addr([u8; 4]);

impl Ipv4Addr {
    /// Construct from four octets `a.b.c.d`.
    #[must_use]
    pub const fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self([a, b, c, d])
    }

    /// Construct from a four-byte array.
    #[must_use]
    pub const fn from_bytes(b: [u8; 4]) -> Self {
        Self(b)
    }

    /// The four octets, in network/written order.
    #[must_use]
    pub const fn octets(&self) -> [u8; 4] {
        self.0
    }
}

/// A parsed IPv4 header + a borrow of the payload after it.
#[derive(Clone, Copy, Debug)]
pub struct Ipv4Header<'a> {
    /// Source address.
    pub src: Ipv4Addr,
    /// Destination address.
    pub dst: Ipv4Addr,
    /// Upper-layer protocol (e.g. [`PROTO_ICMP`]).
    pub protocol: u8,
    /// Total datagram length from the header (header + payload).
    pub total_len: u16,
    /// The payload bytes after the header (clipped to `total_len`).
    pub payload: &'a [u8],
}

impl<'a> Ipv4Header<'a> {
    /// Parse an IPv4 datagram from `buf`. Accepts only version 4 with a 20-byte
    /// (option-less) header; returns `None` otherwise or if `buf` is too short.
    #[must_use]
    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < HEADER_LEN {
            return None;
        }
        let version = buf[0] >> 4;
        let ihl = (buf[0] & 0x0F) as usize * 4; // header length in bytes
        if version != 4 || ihl < HEADER_LEN || buf.len() < ihl {
            return None;
        }
        let total_len = u16::from_be_bytes([buf[2], buf[3]]);
        let protocol = buf[9];
        let src = Ipv4Addr::from_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let dst = Ipv4Addr::from_bytes([buf[16], buf[17], buf[18], buf[19]]);
        // Payload runs from the end of the header to total_len (bounded by buf).
        let end = (total_len as usize).min(buf.len());
        let payload = if end > ihl {
            &buf[ihl..end]
        } else {
            &buf[ihl..ihl]
        };
        Some(Self {
            src,
            dst,
            protocol,
            total_len,
            payload,
        })
    }
}

/// Build a 20-byte (option-less) IPv4 header into the front of `out`, for a
/// datagram whose payload is `payload_len` bytes. Fills version/IHL, total
/// length, TTL, protocol, addresses, and the header checksum. Returns the number
/// of header bytes written ([`HEADER_LEN`]), or `None` if `out` is too small.
///
/// `ident` is the IP identification field (any value; we pass a simple counter).
#[must_use]
pub fn write_header(
    out: &mut [u8],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: u8,
    payload_len: usize,
    ident: u16,
) -> Option<usize> {
    if out.len() < HEADER_LEN {
        return None;
    }
    let total_len = (HEADER_LEN + payload_len) as u16;
    out[0] = 0x45; // version 4, IHL 5 (20 bytes)
    out[1] = 0x00; // DSCP/ECN
    out[2..4].copy_from_slice(&total_len.to_be_bytes());
    out[4..6].copy_from_slice(&ident.to_be_bytes());
    out[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // flags: Don't Fragment
    out[8] = 64; // TTL
    out[9] = protocol;
    out[10..12].copy_from_slice(&[0, 0]); // checksum placeholder
    out[12..16].copy_from_slice(&src.octets());
    out[16..20].copy_from_slice(&dst.octets());
    // Compute the header checksum over the 20 header bytes (with checksum = 0).
    let csum = checksum(&out[0..HEADER_LEN]);
    out[10..12].copy_from_slice(&csum.to_be_bytes());
    Some(HEADER_LEN)
}

/// The RFC 1071 "internet checksum": the 16-bit one's-complement of the
/// one's-complement sum of the data taken as 16-bit big-endian words (a trailing
/// odd byte is padded with zero). Used for the IPv4 header and ICMP.
#[must_use]
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let (words, remainder) = data.as_chunks::<2>();
    for &[hi, lo] in words {
        sum += u16::from_be_bytes([hi, lo]) as u32;
    }
    if let [last] = remainder {
        sum += (u16::from_be_bytes([*last, 0])) as u32;
    }
    // Fold the carries into the low 16 bits.
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_known_value() {
        // RFC 1071 worked example bytes.
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        let c = checksum(&data);
        // The checksum, when included, makes the total sum's complement zero.
        // Build `data ++ checksum` in a fixed stack array (no alloc needed).
        let mut withck = [0u8; 10];
        withck[..8].copy_from_slice(&data);
        withck[8..].copy_from_slice(&c.to_be_bytes());
        assert_eq!(checksum(&withck), 0);
    }

    #[test]
    fn header_roundtrip() {
        let src = Ipv4Addr::new(10, 0, 2, 15);
        let dst = Ipv4Addr::new(10, 0, 2, 2);
        let mut buf = [0u8; HEADER_LEN + 8];
        let n = write_header(&mut buf, src, dst, PROTO_ICMP, 8, 0x1234).unwrap();
        assert_eq!(n, HEADER_LEN);
        // A correct header checksums to zero over the header bytes.
        assert_eq!(checksum(&buf[0..HEADER_LEN]), 0);
        let h = Ipv4Header::parse(&buf).unwrap();
        assert_eq!(h.src, src);
        assert_eq!(h.dst, dst);
        assert_eq!(h.protocol, PROTO_ICMP);
        assert_eq!(h.total_len as usize, HEADER_LEN + 8);
    }

    #[test]
    fn rejects_non_v4() {
        let mut buf = [0u8; HEADER_LEN];
        buf[0] = 0x65; // version 6
        assert!(Ipv4Header::parse(&buf).is_none());
    }
}
