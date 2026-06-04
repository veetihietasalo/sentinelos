//! ARP (Address Resolution Protocol) for IPv4-over-Ethernet — pure safe logic.
//!
//! ARP maps an IPv4 address to a MAC address. An ARP packet (for Ethernet/IPv4)
//! is 28 bytes:
//!
//! ```text
//! htype(2) ptype(2) hlen(1) plen(1) oper(2)
//! sender_mac(6) sender_ip(4) target_mac(6) target_ip(4)
//! ```
//!
//! We handle exactly the Ethernet/IPv4 case: reply to requests for our IP, and
//! build requests to resolve a gateway. All byte arithmetic over slices — no
//! `unsafe`, no allocation.

use super::ethernet::MacAddr;
use super::ipv4::Ipv4Addr;

/// ARP packet length for Ethernet/IPv4.
pub const PACKET_LEN: usize = 28;

/// Hardware type: Ethernet (`1`).
const HTYPE_ETHERNET: u16 = 1;
/// Protocol type: IPv4 (`0x0800`).
const PTYPE_IPV4: u16 = 0x0800;
/// Hardware address length (MAC = 6).
const HLEN_MAC: u8 = 6;
/// Protocol address length (IPv4 = 4).
const PLEN_IPV4: u8 = 4;

/// ARP operation: request (`1`).
pub const OPER_REQUEST: u16 = 1;
/// ARP operation: reply (`2`).
pub const OPER_REPLY: u16 = 2;

/// A parsed ARP packet (Ethernet/IPv4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArpPacket {
    /// Operation: [`OPER_REQUEST`] or [`OPER_REPLY`].
    pub oper: u16,
    /// Sender's MAC.
    pub sender_mac: MacAddr,
    /// Sender's IPv4.
    pub sender_ip: Ipv4Addr,
    /// Target's MAC (zero in a request).
    pub target_mac: MacAddr,
    /// Target's IPv4.
    pub target_ip: Ipv4Addr,
}

impl ArpPacket {
    /// Parse an ARP packet from `buf`, accepting only the Ethernet/IPv4 form.
    ///
    /// Returns `None` if the buffer is too short or the hardware/protocol types
    /// are not Ethernet/IPv4 (we do not handle other ARP variants).
    #[must_use]
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < PACKET_LEN {
            return None;
        }
        let htype = u16::from_be_bytes([buf[0], buf[1]]);
        let ptype = u16::from_be_bytes([buf[2], buf[3]]);
        let hlen = buf[4];
        let plen = buf[5];
        if htype != HTYPE_ETHERNET || ptype != PTYPE_IPV4 || hlen != HLEN_MAC || plen != PLEN_IPV4 {
            return None;
        }
        let oper = u16::from_be_bytes([buf[6], buf[7]]);
        let mut sender_mac = [0u8; 6];
        let mut target_mac = [0u8; 6];
        sender_mac.copy_from_slice(&buf[8..14]);
        let sender_ip = Ipv4Addr::from_bytes([buf[14], buf[15], buf[16], buf[17]]);
        target_mac.copy_from_slice(&buf[18..24]);
        let target_ip = Ipv4Addr::from_bytes([buf[24], buf[25], buf[26], buf[27]]);
        Some(Self {
            oper,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        })
    }

    /// Write this packet into the front of `out` as an Ethernet/IPv4 ARP packet,
    /// returning the number of bytes written ([`PACKET_LEN`]), or `None` if `out`
    /// is too small.
    #[must_use]
    pub fn write(&self, out: &mut [u8]) -> Option<usize> {
        if out.len() < PACKET_LEN {
            return None;
        }
        out[0..2].copy_from_slice(&HTYPE_ETHERNET.to_be_bytes());
        out[2..4].copy_from_slice(&PTYPE_IPV4.to_be_bytes());
        out[4] = HLEN_MAC;
        out[5] = PLEN_IPV4;
        out[6..8].copy_from_slice(&self.oper.to_be_bytes());
        out[8..14].copy_from_slice(&self.sender_mac);
        out[14..18].copy_from_slice(&self.sender_ip.octets());
        out[18..24].copy_from_slice(&self.target_mac);
        out[24..28].copy_from_slice(&self.target_ip.octets());
        Some(PACKET_LEN)
    }
}

/// Build an ARP **request** packet ("who has `target_ip`? tell `sender_ip`").
#[must_use]
pub fn request(sender_mac: MacAddr, sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> ArpPacket {
    ArpPacket {
        oper: OPER_REQUEST,
        sender_mac,
        sender_ip,
        target_mac: [0; 6],
        target_ip,
    }
}

/// Build an ARP **reply** to `req`, asserting that `our_mac` owns `our_ip`.
#[must_use]
pub fn reply(req: &ArpPacket, our_mac: MacAddr, our_ip: Ipv4Addr) -> ArpPacket {
    ArpPacket {
        oper: OPER_REPLY,
        sender_mac: our_mac,
        sender_ip: our_ip,
        target_mac: req.sender_mac,
        target_ip: req.sender_ip,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrip() {
        let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        let me = Ipv4Addr::new(10, 0, 2, 15);
        let gw = Ipv4Addr::new(10, 0, 2, 2);
        let req = request(mac, me, gw);
        let mut buf = [0u8; PACKET_LEN];
        assert_eq!(req.write(&mut buf), Some(PACKET_LEN));
        let parsed = ArpPacket::parse(&buf).unwrap();
        assert_eq!(parsed, req);
        assert_eq!(parsed.oper, OPER_REQUEST);
        assert_eq!(parsed.target_ip, gw);
    }

    #[test]
    fn reply_targets_requester() {
        let our_mac = [1, 2, 3, 4, 5, 6];
        let our_ip = Ipv4Addr::new(10, 0, 2, 15);
        let their_mac = [9, 9, 9, 9, 9, 9];
        let their_ip = Ipv4Addr::new(10, 0, 2, 2);
        let req = ArpPacket {
            oper: OPER_REQUEST,
            sender_mac: their_mac,
            sender_ip: their_ip,
            target_mac: [0; 6],
            target_ip: our_ip,
        };
        let rep = reply(&req, our_mac, our_ip);
        assert_eq!(rep.oper, OPER_REPLY);
        assert_eq!(rep.sender_mac, our_mac);
        assert_eq!(rep.target_mac, their_mac);
        assert_eq!(rep.target_ip, their_ip);
    }

    #[test]
    fn rejects_non_ethernet() {
        let mut buf = [0u8; PACKET_LEN];
        buf[0..2].copy_from_slice(&99u16.to_be_bytes()); // bogus htype
        assert!(ArpPacket::parse(&buf).is_none());
    }
}
