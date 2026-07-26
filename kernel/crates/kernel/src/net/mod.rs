//! The SentinelOS minimal network stack — safe (`#![forbid(unsafe_code)]`).
//!
//! This module is the safe protocol stack that sits on top of the `hal::e1000`
//! NIC driver (the TCB owns the privileged MMIO/DMA; this module is pure byte
//! logic). It implements just enough of the classic LAN stack to demonstrate a
//! working NIC:
//!
//! - **Ethernet II** ([`ethernet`]) — frame parse/build.
//! - **ARP** ([`arp`]) — reply to "who has 10.0.2.15?" and resolve the gateway.
//! - **IPv4** ([`ipv4`]) — option-less header + the internet checksum.
//! - **ICMP echo** ([`icmp`]) — reply to pings and send echo requests.
//!
//! # Configuration
//!
//! A static IP of `10.0.2.15`, gateway `10.0.2.2` — the QEMU user-mode (SLIRP)
//! defaults, so the guest is reachable from the host gateway without DHCP. The
//! MAC comes from the NIC at init.
//!
//! # Flow
//!
//! [`init`] brings up the NIC, logs the MAC, and (if the link is up) fires an
//! ARP request + an ICMP echo at the gateway to prove TX works. [`poll`] is
//! called from the kernel idle loop: it drains received frames and dispatches
//! them — answering ARP requests for our IP, recording ARP replies, and
//! answering / logging ICMP echoes. All logging uses the `fmt`-free serial
//! helpers (`core::fmt`'s integer path faults on this target).

pub mod arp;
pub mod ethernet;
pub mod icmp;
pub mod ipv4;

use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};

use ethernet::{EthFrame, MacAddr, ETHERTYPE_ARP, ETHERTYPE_IPV4};
use ipv4::Ipv4Addr;

/// Our static IPv4 address (QEMU SLIRP default guest address).
pub const OUR_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);
/// The gateway IPv4 address (QEMU SLIRP default gateway).
pub const GATEWAY_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);

/// Maximum Ethernet frame we build/receive (1500 MTU + 14-byte header, rounded).
const FRAME_BUF: usize = 1536;

/// Whether the NIC + stack are up.
static UP: AtomicBool = AtomicBool::new(false);
/// A simple monotonically-increasing IP identification / ICMP sequence counter.
static SEQ: AtomicU16 = AtomicU16::new(1);

/// The last ICMP echo *reply* we received, encoded so a single relaxed
/// `AtomicU32` load gives the whole status to a reader (the Net app) without a
/// lock: the low 16 bits hold the answered sequence number, and the next bit
/// (`0x0001_0000`) is a "we have seen at least one reply" flag. Zero means "no
/// reply yet". Recorded by [`handle_icmp`] on an echo reply and read by
/// [`status`].
static LAST_PING_REPLY: AtomicU32 = AtomicU32::new(0);

/// Bit set in [`LAST_PING_REPLY`] once at least one echo reply has arrived.
const PING_SEEN_BIT: u32 = 0x0001_0000;

/// Has the stack come up (NIC initialised)?
#[must_use]
pub fn is_up() -> bool {
    UP.load(Ordering::Acquire)
}

/// The result of the most recent outgoing ping (ICMP echo), as observed by the
/// stack, for the Net status app to display.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PingResult {
    /// No echo reply has been received yet (stack down, or still waiting).
    Pending,
    /// An echo reply arrived; the field is the answered sequence number.
    Replied(u16),
}

/// A read-only snapshot of the network stack's status, for the Net app.
///
/// Built by [`status`] from the NIC ([`hal::e1000::mac`]/[`hal::e1000::link_up`])
/// and the stack's static configuration + last-ping state. Plain `Copy` data, so
/// the caller owns it with no borrow of the live stack.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetStatus {
    /// `true` once the NIC + stack have initialised (see [`is_up`]).
    pub up: bool,
    /// The NIC's MAC address (`00:00:00:00:00:00` if the stack is down).
    pub mac: MacAddr,
    /// Our static IPv4 address ([`OUR_IP`]).
    pub ip: Ipv4Addr,
    /// The gateway IPv4 address ([`GATEWAY_IP`]).
    pub gateway: Ipv4Addr,
    /// Whether the NIC reports the physical link as up.
    pub link_up: bool,
    /// The result of the most recent ICMP echo (ping).
    pub last_ping: PingResult,
}

/// A read-only snapshot of the current network status, for the Net status app.
///
/// Reads the live MAC/link from the NIC ([`hal::e1000`]) and the last observed
/// ICMP echo reply from the stack. Cheap and lock-free: a couple of atomic loads
/// plus a NIC register read. Safe to call from app render/tick.
#[must_use]
pub fn status() -> NetStatus {
    let up = is_up();
    // The NIC only has a valid MAC once it's initialised; report zeros otherwise.
    let mac = if up { hal::e1000::mac() } else { [0u8; 6] };
    let link_up = up && hal::e1000::link_up();
    let raw = LAST_PING_REPLY.load(Ordering::Relaxed);
    let last_ping = if raw & PING_SEEN_BIT != 0 {
        PingResult::Replied((raw & 0xFFFF) as u16)
    } else {
        PingResult::Pending
    };
    NetStatus {
        up,
        mac,
        ip: OUR_IP,
        gateway: GATEWAY_IP,
        link_up,
        last_ping,
    }
}

/// Bring up the NIC and the stack, log the MAC, and (if the link is up) send an
/// ARP request + ICMP echo to the gateway as a TX proof.
///
/// Degrades gracefully: if no NIC is present (`hal::e1000::init` returns
/// `NotFound`) it logs that and leaves the stack down, so the boot path is never
/// broken by a missing NIC.
pub fn init() {
    match hal::e1000::init() {
        Ok(info) => {
            hal::serial::write_str("[net] e1000 up; MAC=");
            log_mac(&info.mac);
            hal::serial::write_str(" IRQ=");
            hal::serial::write_dec(info.irq as u64);
            hal::serial::write_str("\n");

            UP.store(true, Ordering::Release);

            log_ip("[net] our IP: ", &OUR_IP);
            hal::serial::write_str("\n");
            log_ip("[net] gateway: ", &GATEWAY_IP);
            hal::serial::write_str("\n");

            let link = hal::e1000::link_up();
            hal::serial::write_str(if link {
                "[net] link: UP\n"
            } else {
                "[net] link: down (will still attempt TX)\n"
            });

            // Proof of TX: ARP-request the gateway, then send an ICMP echo to it.
            send_arp_request(GATEWAY_IP);
            send_ping(GATEWAY_IP);

            // Drain any replies the gateway sends back, bounded so a quiet link
            // can never hang boot. This captures the gateway's ARP/ICMP replies
            // into the boot log without depending on the idle loop (owned by
            // another track). The idle loop should also call `poll()` to keep
            // servicing frames after boot, but this gives immediate RX evidence.
            drain_replies();
        }
        Err(e) => {
            let reason = match e {
                hal::e1000::InitError::NotFound => "no e1000 NIC found",
                hal::e1000::InitError::NoMmio => "BAR0 not memory-mapped",
                hal::e1000::InitError::MapFailed => "MMIO map failed",
                hal::e1000::InitError::OutOfMemory => "DMA alloc failed",
            };
            hal::serial::write_str("[net] NIC init skipped: ");
            hal::serial::write_str(reason);
            hal::serial::write_str("\n");
        }
    }
}

/// Spin (bounded) draining received frames, to capture the gateway's immediate
/// replies during boot without depending on the idle loop.
///
/// QEMU's SLIRP answers ARP/ICMP synchronously, but the round trip still takes a
/// little wall-clock time, so we poll in a bounded busy loop. The bound (a large
/// iteration count, not a real timer) guarantees boot cannot hang on a quiet
/// link. Each iteration drains all pending frames via [`poll`].
fn drain_replies() {
    // Poll until the gateway's echo reply lands, then stop. The ICMP reply is
    // the LAST of the two replies we expect (the ARP reply necessarily precedes
    // it — the gateway must resolve us before it can answer the ping), so
    // seeing it means the RX evidence this loop exists to capture is already in
    // the boot log and every further spin is dead time.
    //
    // The iteration count is now a CEILING, not a duration. It used to be run
    // to completion unconditionally, which cost 13.2 s of a 16.5 s TCG boot —
    // 80% of it — while the replies had actually arrived ~1 s in (measured
    // 2026-07-26). A quiet or absent link still cannot wedge boot: it simply
    // exhausts the ceiling exactly as before.
    //
    // `poll()` runs at least once regardless, so a reply that is already
    // pending when we arrive is still drained into the log.
    for _ in 0..8_000_000u64 {
        poll();
        if LAST_PING_REPLY.load(Ordering::Relaxed) & PING_SEEN_BIT != 0 {
            break;
        }
        core::hint::spin_loop();
    }
}

/// Drain and dispatch all currently-available received frames. Called from the
/// kernel idle loop. A no-op if the stack is down.
pub fn poll() {
    if !is_up() {
        return;
    }
    let mut buf = [0u8; FRAME_BUF];
    // Bound the work per poll so a flood cannot starve the idle loop.
    for _ in 0..16 {
        match hal::e1000::poll_frame(&mut buf) {
            Some(len) => handle_frame(&buf[..len]),
            None => break,
        }
    }
}

/// Dispatch one received Ethernet frame.
fn handle_frame(frame: &[u8]) {
    let Some(eth) = EthFrame::parse(frame) else {
        return;
    };
    match eth.ethertype {
        ETHERTYPE_ARP => handle_arp(&eth),
        ETHERTYPE_IPV4 => handle_ipv4(&eth),
        _ => {} // ignore other ethertypes
    }
}

/// Handle an ARP packet: reply to requests for our IP; log replies.
fn handle_arp(eth: &EthFrame<'_>) {
    let Some(pkt) = arp::ArpPacket::parse(eth.payload) else {
        return;
    };
    match pkt.oper {
        arp::OPER_REQUEST if pkt.target_ip == OUR_IP => {
            // Someone is asking for our MAC — reply.
            let our_mac = hal::e1000::mac();
            let rep = arp::reply(&pkt, our_mac, OUR_IP);
            let mut out = [0u8; FRAME_BUF];
            if let Some(eth_len) =
                ethernet::write_header(&mut out, pkt.sender_mac, our_mac, ETHERTYPE_ARP)
            {
                if let Some(arp_len) = rep.write(&mut out[eth_len..]) {
                    hal::serial::write_str("[net] ARP request for us -> replying\n");
                    let _ = hal::e1000::send_frame(&out[..eth_len + arp_len]);
                }
            }
        }
        arp::OPER_REPLY => {
            hal::serial::write_str("[net] ARP reply: ");
            log_ip("", &pkt.sender_ip);
            hal::serial::write_str(" is-at ");
            log_mac(&pkt.sender_mac);
            hal::serial::write_str("\n");
        }
        _ => {}
    }
}

/// Handle an IPv4 datagram: currently just ICMP echo.
fn handle_ipv4(eth: &EthFrame<'_>) {
    let Some(ip) = ipv4::Ipv4Header::parse(eth.payload) else {
        return;
    };
    if ip.dst != OUR_IP {
        return; // not for us
    }
    if ip.protocol == ipv4::PROTO_ICMP {
        handle_icmp(eth.src, &ip);
    }
}

/// Handle an ICMP message inside an IPv4 datagram: reply to echo requests, log
/// echo replies (so an outgoing ping we sent is visibly answered).
fn handle_icmp(src_mac: MacAddr, ip: &ipv4::Ipv4Header<'_>) {
    let Some(echo) = icmp::EchoMessage::parse(ip.payload) else {
        return;
    };
    match echo.msg_type {
        icmp::TYPE_ECHO_REQUEST => {
            hal::serial::write_str("[net] ICMP echo request from ");
            log_ip("", &ip.src);
            hal::serial::write_str(" -> replying\n");
            // Build reply: Ethernet -> IPv4 -> ICMP echo reply.
            let mut out = [0u8; FRAME_BUF];
            let our_mac = hal::e1000::mac();
            let Some(eth_len) = ethernet::write_header(&mut out, src_mac, our_mac, ETHERTYPE_IPV4)
            else {
                return;
            };
            // ICMP reply first (we need its length for the IP header).
            let icmp_off = eth_len + ipv4::HEADER_LEN;
            let Some(icmp_len) = icmp::reply_to(&mut out[icmp_off..], &echo) else {
                return;
            };
            let ident = SEQ.fetch_add(1, Ordering::Relaxed);
            // IPv4 header (src = us, dst = original sender), then patch nothing —
            // write_header computes the checksum over the just-written header.
            if ipv4::write_header(
                &mut out[eth_len..icmp_off + icmp_len],
                OUR_IP,
                ip.src,
                ipv4::PROTO_ICMP,
                icmp_len,
                ident,
            )
            .is_some()
            {
                let total = icmp_off + icmp_len;
                let _ = hal::e1000::send_frame(&out[..total]);
            }
        }
        icmp::TYPE_ECHO_REPLY => {
            hal::serial::write_str("[net] ICMP echo REPLY from ");
            log_ip("", &ip.src);
            hal::serial::write_str(" (ping answered!) seq=");
            hal::serial::write_dec(echo.seq as u64);
            hal::serial::write_str("\n");
            // Record the answered sequence for the Net status app: low 16 bits =
            // seq, plus the "seen a reply" flag. A single relaxed store keeps the
            // status readable lock-free by `status()`.
            LAST_PING_REPLY.store(PING_SEEN_BIT | echo.seq as u32, Ordering::Relaxed);
        }
        _ => {}
    }
}

/// Broadcast an ARP request resolving `target_ip` (e.g. the gateway).
pub fn send_arp_request(target_ip: Ipv4Addr) {
    if !is_up() {
        return;
    }
    let our_mac = hal::e1000::mac();
    let req = arp::request(our_mac, OUR_IP, target_ip);
    let mut out = [0u8; FRAME_BUF];
    if let Some(eth_len) =
        ethernet::write_header(&mut out, ethernet::BROADCAST, our_mac, ETHERTYPE_ARP)
    {
        if let Some(arp_len) = req.write(&mut out[eth_len..]) {
            hal::serial::write_str("[net] sending ARP request for ");
            log_ip("", &target_ip);
            hal::serial::write_str("\n");
            let ok = hal::e1000::send_frame(&out[..eth_len + arp_len]);
            hal::serial::write_str(if ok {
                "[net]   ARP TX confirmed (descriptor done)\n"
            } else {
                "[net]   ARP TX not confirmed\n"
            });
        }
    }
}

/// Send an ICMP echo (ping) to `target_ip`. The destination MAC is the gateway's
/// — but before ARP resolves we do not know it, so we send to broadcast for the
/// demo (QEMU SLIRP still routes a unicast IP correctly; the gateway answers).
///
/// In a fuller stack this would wait for the ARP reply and use the resolved MAC;
/// for the bring-up proof, broadcasting the first echo is enough to demonstrate
/// an IP/ICMP frame leaving the NIC (visible in the pcap), and the gateway's
/// echo reply is logged by [`handle_icmp`].
pub fn send_ping(target_ip: Ipv4Addr) {
    if !is_up() {
        return;
    }
    let our_mac = hal::e1000::mac();
    let payload = b"sentinelos\0\0\0\0\0\0"; // 16-byte echo payload
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);

    let mut out = [0u8; FRAME_BUF];
    // Destination MAC: broadcast (pre-ARP). Ethertype IPv4.
    let Some(eth_len) =
        ethernet::write_header(&mut out, ethernet::BROADCAST, our_mac, ETHERTYPE_IPV4)
    else {
        return;
    };
    let icmp_off = eth_len + ipv4::HEADER_LEN;
    let Some(icmp_len) = icmp::write_echo(
        &mut out[icmp_off..],
        icmp::TYPE_ECHO_REQUEST,
        0x5E05,
        seq,
        payload,
    ) else {
        return;
    };
    if ipv4::write_header(
        &mut out[eth_len..icmp_off + icmp_len],
        OUR_IP,
        target_ip,
        ipv4::PROTO_ICMP,
        icmp_len,
        seq,
    )
    .is_some()
    {
        let total = icmp_off + icmp_len;
        hal::serial::write_str("[net] sending ICMP echo to ");
        log_ip("", &target_ip);
        hal::serial::write_str("\n");
        let ok = hal::e1000::send_frame(&out[..total]);
        hal::serial::write_str(if ok {
            "[net]   ICMP TX confirmed (descriptor done)\n"
        } else {
            "[net]   ICMP TX not confirmed\n"
        });
    }
}

// ── fmt-free logging helpers (core::fmt int path faults on this target) ────────

/// Log a MAC as `aa:bb:cc:dd:ee:ff` using only the `fmt`-free serial helpers.
fn log_mac(mac: &MacAddr) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, &b) in mac.iter().enumerate() {
        if i != 0 {
            hal::serial::write_str(":");
        }
        let hi = HEX[(b >> 4) as usize];
        let lo = HEX[(b & 0xF) as usize];
        // Two-char hex via tiny stack strings.
        let pair = [hi, lo];
        // `write_str` takes &str; build it from the two ASCII bytes (always valid).
        if let Ok(s) = core::str::from_utf8(&pair) {
            hal::serial::write_str(s);
        }
    }
}

/// Log an IPv4 address as `a.b.c.d` with an optional label, fmt-free.
fn log_ip(label: &str, ip: &Ipv4Addr) {
    if !label.is_empty() {
        hal::serial::write_str(label);
    }
    let o = ip.octets();
    for (i, &part) in o.iter().enumerate() {
        if i != 0 {
            hal::serial::write_str(".");
        }
        hal::serial::write_dec(part as u64);
    }
}
