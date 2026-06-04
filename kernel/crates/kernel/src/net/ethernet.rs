//! Ethernet II frame parsing and building — pure safe logic.
//!
//! An Ethernet II frame is `[dst MAC (6)][src MAC (6)][ethertype (2)][payload…]`.
//! This module parses an incoming frame into its header fields + payload slice,
//! and builds an outgoing frame into a caller-provided buffer. No hardware, no
//! allocation, no `unsafe` — it is all byte arithmetic over slices, so it is a
//! prime candidate for `forbid(unsafe_code)` and unit testing on the host.

/// A six-byte Ethernet MAC address.
pub type MacAddr = [u8; 6];

/// The broadcast MAC address (`ff:ff:ff:ff:ff:ff`).
pub const BROADCAST: MacAddr = [0xFF; 6];

/// EtherType for ARP (`0x0806`).
pub const ETHERTYPE_ARP: u16 = 0x0806;
/// EtherType for IPv4 (`0x0800`).
pub const ETHERTYPE_IPV4: u16 = 0x0800;

/// Length of the Ethernet II header (dst + src + ethertype).
pub const HEADER_LEN: usize = 14;

/// A parsed view of an incoming Ethernet frame: the header fields plus a borrow
/// of the payload bytes (everything after the 14-byte header).
#[derive(Clone, Copy, Debug)]
pub struct EthFrame<'a> {
    /// Destination MAC.
    pub dst: MacAddr,
    /// Source MAC.
    pub src: MacAddr,
    /// EtherType (host byte order).
    pub ethertype: u16,
    /// The payload (after the header), borrowed from the input buffer.
    pub payload: &'a [u8],
}

impl<'a> EthFrame<'a> {
    /// Parse `buf` as an Ethernet II frame, or `None` if it is too short to hold
    /// even a header.
    #[must_use]
    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        if buf.len() < HEADER_LEN {
            return None;
        }
        let mut dst = [0u8; 6];
        let mut src = [0u8; 6];
        dst.copy_from_slice(&buf[0..6]);
        src.copy_from_slice(&buf[6..12]);
        let ethertype = u16::from_be_bytes([buf[12], buf[13]]);
        Some(Self {
            dst,
            src,
            ethertype,
            payload: &buf[HEADER_LEN..],
        })
    }
}

/// Write an Ethernet II header (`dst`, `src`, `ethertype`) into the front of
/// `out`, returning the number of header bytes written (`HEADER_LEN`), or `None`
/// if `out` is too small.
///
/// The caller then writes the payload starting at `out[HEADER_LEN..]` and
/// transmits `out[..HEADER_LEN + payload_len]`.
#[must_use]
pub fn write_header(out: &mut [u8], dst: MacAddr, src: MacAddr, ethertype: u16) -> Option<usize> {
    if out.len() < HEADER_LEN {
        return None;
    }
    out[0..6].copy_from_slice(&dst);
    out[6..12].copy_from_slice(&src);
    out[12..14].copy_from_slice(&ethertype.to_be_bytes());
    Some(HEADER_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_roundtrip() {
        let mut buf = [0u8; 64];
        let dst = [1, 2, 3, 4, 5, 6];
        let src = [7, 8, 9, 10, 11, 12];
        let n = write_header(&mut buf, dst, src, ETHERTYPE_IPV4).unwrap();
        assert_eq!(n, HEADER_LEN);
        buf[HEADER_LEN] = 0xAB; // one payload byte
        let f = EthFrame::parse(&buf[..HEADER_LEN + 1]).unwrap();
        assert_eq!(f.dst, dst);
        assert_eq!(f.src, src);
        assert_eq!(f.ethertype, ETHERTYPE_IPV4);
        assert_eq!(f.payload, &[0xAB]);
    }

    #[test]
    fn too_short_is_none() {
        assert!(EthFrame::parse(&[0u8; 10]).is_none());
        assert!(write_header(&mut [0u8; 8], BROADCAST, BROADCAST, 0).is_none());
    }
}
