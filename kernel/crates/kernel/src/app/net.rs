//! The **Net** app — a small, live, read-only panel showing the network stack's
//! status: the NIC MAC, our IPv4 address, the gateway, the physical link state,
//! and the result of the most recent ICMP echo (ping).
//!
//! It reads everything through the safe [`net::status`](crate::net::status)
//! accessor (which itself reads the NIC's MAC/link and the stack's last-ping
//! state), formats the rows with a hand-rolled hex/decimal builder (no
//! `core::fmt`, which faults on this target), and draws them via the safe
//! `ui::font::draw_text` plotter. Like the system panel, it refreshes once a whole
//! second from its [`App::tick`] so a link change or a freshly-answered ping shows
//! up without any keystrokes.

use alloc::string::String;
use alloc::vec::Vec;

use ui::Rect;

use crate::input::KeyEvent;
use crate::net::{self, PingResult};

use super::App;

/// Text scale of the panel rows (matches the console/system-panel body scale).
const ROW_SCALE: usize = 2;
/// Vertical leading between rows, in source pixels.
const ROW_LEADING: usize = 6;

/// Near-white primary text (matches the system panel's primary).
const PRIMARY_RGB: (u8, u8, u8) = (0xe8, 0xf6, 0xff);
/// Muted cyan-grey label text for the stat rows.
const LABEL_RGB: (u8, u8, u8) = (0x9a, 0xb6, 0xd6);

/// Lowercase hex digits — the font has `0-9` and lowercase `a-f`, so a MAC reads
/// correctly as `aa:bb:cc:dd:ee:ff`.
const HEX: &[u8; 16] = b"0123456789abcdef";

/// Append the base-10 ASCII digits of `value` to `out` (no `core::fmt`). Zero
/// renders as `"0"`.
fn push_dec(out: &mut String, value: u64) {
    if value == 0 {
        out.push('0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut n = value;
    let mut i = buf.len();
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    for &b in &buf[i..] {
        out.push(b as char);
    }
}

/// Append `byte` as two lowercase hex digits to `out`.
fn push_hex2(out: &mut String, byte: u8) {
    out.push(HEX[(byte >> 4) as usize] as char);
    out.push(HEX[(byte & 0x0F) as usize] as char);
}

/// Append a MAC as `aa:bb:cc:dd:ee:ff`.
fn push_mac(out: &mut String, mac: &[u8; 6]) {
    for (i, &b) in mac.iter().enumerate() {
        if i != 0 {
            out.push(':');
        }
        push_hex2(out, b);
    }
}

/// Append an IPv4 address as `a.b.c.d`.
fn push_ip(out: &mut String, octets: [u8; 4]) {
    for (i, &part) in octets.iter().enumerate() {
        if i != 0 {
            out.push('.');
        }
        push_dec(out, part as u64);
    }
}

/// The Net panel: live network status, refreshed once a second.
pub struct Net {
    /// The rendered status rows (label-prefixed), rebuilt on each whole-second
    /// tick. Held so `render` (which is `&self`) can draw the memoised strings.
    rows: Vec<String>,
    /// The last whole-second value we rebuilt `rows` at, so `tick` only refreshes
    /// (and reports dirty) when the second changes.
    last_secs: u64,
}

impl Net {
    /// Create a fresh Net panel and populate its first status snapshot. Allocates
    /// on the kernel heap.
    #[must_use]
    pub fn new() -> Self {
        let mut panel = Self {
            rows: Vec::new(),
            last_secs: u64::MAX,
        };
        panel.refresh();
        panel
    }

    /// Rebuild the status rows from the current [`net::status`] snapshot.
    fn refresh(&mut self) {
        let st = net::status();
        self.rows.clear();

        // "stack: up" / "stack: down"
        let mut stack = String::from("stack: ");
        stack.push_str(if st.up { "up" } else { "down" });
        self.rows.push(stack);

        // "mac: aa:bb:cc:dd:ee:ff"
        let mut mac = String::from("mac: ");
        push_mac(&mut mac, &st.mac);
        self.rows.push(mac);

        // "ip: 10.0.2.15"
        let mut ip = String::from("ip: ");
        push_ip(&mut ip, st.ip.octets());
        self.rows.push(ip);

        // "gw: 10.0.2.2"
        let mut gw = String::from("gw: ");
        push_ip(&mut gw, st.gateway.octets());
        self.rows.push(gw);

        // "link: up" / "link: down"
        let mut link = String::from("link: ");
        link.push_str(if st.link_up { "up" } else { "down" });
        self.rows.push(link);

        // "ping: reply seq N" / "ping: pending"
        let mut ping = String::from("ping: ");
        match st.last_ping {
            PingResult::Replied(seq) => {
                ping.push_str("reply seq ");
                push_dec(&mut ping, seq as u64);
            }
            PingResult::Pending => ping.push_str("pending"),
        }
        self.rows.push(ping);
    }
}

impl Default for Net {
    fn default() -> Self {
        Self::new()
    }
}

impl App for Net {
    fn title(&self) -> &str {
        "Net"
    }

    fn render(&self, fb: &hal::framebuffer::Framebuffer, area: Rect) {
        // Pack against the framebuffer's native pixel format (RGB *and* BGR safe).
        let primary = fb.pack_rgb(PRIMARY_RGB.0, PRIMARY_RGB.1, PRIMARY_RGB.2);
        let label = fb.pack_rgb(LABEL_RGB.0, LABEL_RGB.1, LABEL_RGB.2);

        let inset = ui::font::GLYPH_SIZE * ROW_SCALE / 2;
        let x0 = area.x + inset;
        let mut y = area.y + inset;
        let row_pitch = ui::font::GLYPH_SIZE * ROW_SCALE + ROW_LEADING;

        ui::font::draw_text(fb, x0, y, "NET", ROW_SCALE, primary);
        y += row_pitch + ROW_LEADING;

        for row in &self.rows {
            if y + ui::font::GLYPH_SIZE * ROW_SCALE > area.bottom() {
                break; // ran out of content rect (the framebuffer also clips)
            }
            ui::font::draw_text(fb, x0, y, row, ROW_SCALE, label);
            y += row_pitch;
        }
    }

    fn on_key(&mut self, _event: KeyEvent) -> bool {
        // Read-only panel: it ignores input and never dirties from a keystroke.
        false
    }

    fn tick(&mut self, now_ticks: u64) -> bool {
        let secs = now_ticks / hal::pit::TICK_HZ;
        if secs != self.last_secs {
            self.last_secs = secs;
            self.refresh();
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_dec_formats_decimal() {
        let mut s = String::new();
        push_dec(&mut s, 0);
        push_dec(&mut s, 255);
        assert_eq!(s, "0255");
    }

    #[test]
    fn push_hex2_is_two_lowercase_digits() {
        let mut s = String::new();
        push_hex2(&mut s, 0x0a);
        push_hex2(&mut s, 0xff);
        assert_eq!(s, "0aff");
    }

    #[test]
    fn push_mac_formats_colon_separated() {
        let mut s = String::new();
        push_mac(&mut s, &[0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        assert_eq!(s, "52:54:00:12:34:56");
    }

    #[test]
    fn push_ip_formats_dotted_quad() {
        let mut s = String::new();
        push_ip(&mut s, [10, 0, 2, 15]);
        assert_eq!(s, "10.0.2.15");
    }

    /// A fresh Net panel populates the expected rows; with the stack down (the
    /// default in a host test) the IP/gateway still read the static config.
    #[test]
    fn new_populates_rows() {
        let net = Net::new();
        // Header is drawn separately; rows are: stack, mac, ip, gw, link, ping.
        assert_eq!(net.rows.len(), 6);
        assert!(net.rows[2].starts_with("ip: "));
        assert!(net.rows[2].contains("10.0.2.15"));
        assert!(net.rows[3].contains("10.0.2.2"));
        assert!(net.rows[5].starts_with("ping: "));
    }
}
