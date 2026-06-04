//! PCI configuration-space access (legacy `0xCF8`/`0xCFC` mechanism) — part of
//! the TCB.
//!
//! The PCI configuration space is the standardised register window every PCI
//! device exposes (vendor/device id, class, the Base Address Registers that
//! locate its MMIO/IO windows, and the interrupt line). On a PC it is reached
//! through the legacy *configuration access mechanism #1*: write a 32-bit
//! address (bus/device/function/offset + the enable bit) to the **address
//! port** `0xCF8`, then read/write the **data port** `0xCFC`.
//!
//! This module does raw x86 port I/O (`in`/`out` of 32-bit words) through two
//! private primitives, each documented with a `# Safety` rustdoc section; see
//! `kernel/docs/hal-tcb.md` (§6a). The public surface is **safe**:
//!
//! - [`scan_for`] — enumerate bus 0 (and, via the bridge, beyond is **not**
//!   needed on QEMU q35 where the e1000 sits on bus 0) looking for a device
//!   matching a `(vendor, device)` id, returning a [`PciDevice`] handle.
//! - [`PciDevice`] — a located device: its address, plus safe readers for the
//!   BARs, the interrupt line, and command-register bits (bus-master enable).
//!
//! # Concurrency model
//!
//! Identical to the other port-I/O drivers: single-core at bring-up,
//! enumeration runs once during init with no concurrent PCI access. The
//! address/data port pair is **not** internally serialised by the hardware, so a
//! config read is a write-then-read pair that must not be interleaved — which is
//! guaranteed here by the single-threaded init path.

use core::arch::asm;

/// PCI configuration **address** port (write the target register address here).
const CONFIG_ADDRESS: u16 = 0xCF8;
/// PCI configuration **data** port (read/write the selected register here).
const CONFIG_DATA: u16 = 0xCFC;

/// Enable bit (bit 31) of the configuration address word; must be set for the
/// host bridge to forward the access to configuration space.
const CONFIG_ENABLE: u32 = 1 << 31;

// ── Configuration-space register offsets (within a function's 256-byte space) ──

/// Offset 0x00: vendor id (low 16 bits) + device id (high 16 bits).
const OFF_VENDOR_DEVICE: u8 = 0x00;
/// Offset 0x04: command (low 16) + status (high 16) register.
const OFF_COMMAND: u8 = 0x04;
/// Offset 0x08: revision/class-code word.
const OFF_CLASS: u8 = 0x08;
/// Offset 0x0C: cache-line/latency/**header-type**/BIST word (header type =
/// byte 2).
const OFF_HEADER_TYPE: u8 = 0x0C;
/// Offset 0x10: the first Base Address Register (BAR0). BAR_n is at `0x10 + 4n`.
const OFF_BAR0: u8 = 0x10;
/// Offset 0x3C: interrupt-line (byte 0) + interrupt-pin (byte 1) word.
const OFF_INTERRUPT_LINE: u8 = 0x3C;

/// Command-register bit 2: **bus master enable** — the device may initiate DMA.
pub const CMD_BUS_MASTER: u16 = 1 << 2;
/// Command-register bit 1: memory-space enable — respond to MMIO accesses.
pub const CMD_MEMORY_SPACE: u16 = 1 << 1;

/// "No vendor" sentinel: a vendor id of `0xFFFF` means the function is absent.
const VENDOR_NONE: u16 = 0xFFFF;

/// Write a 32-bit word to an x86 I/O port.
///
/// # Safety
///
/// The caller must ensure `port` names a register safe to write with `value`.
/// All call sites write only the PCI configuration address/data ports
/// (`0xCF8`/`0xCFC`).
#[inline]
unsafe fn outl(port: u16, value: u32) {
    // SAFETY: `out dx, eax` writes the 32-bit `eax` to the I/O port in `dx`. The
    // contract that `port`/`value` are a valid, write-safe PCI config port pair
    // is delegated to this function's `# Safety` section and upheld by every
    // caller (only `0xCF8`/`0xCFC`). No memory (`nomem`) / stack (`nostack`).
    unsafe {
        asm!("out dx, eax", in("dx") port, in("eax") value, options(nomem, nostack));
    }
}

/// Read a 32-bit word from an x86 I/O port.
///
/// # Safety
///
/// The caller must ensure `port` names a register safe to read. All call sites
/// read only the PCI configuration data port (`0xCFC`).
#[inline]
unsafe fn inl(port: u16) -> u32 {
    let value: u32;
    // SAFETY: `in eax, dx` reads a 32-bit word from the I/O port in `dx` into
    // `eax`. The contract that `port` is a valid, read-safe PCI config port is
    // delegated to this `# Safety` section and upheld by every caller (only
    // `0xCFC`). Pure device read; no memory (`nomem`) / stack (`nostack`).
    unsafe {
        asm!("in eax, dx", out("eax") value, in("dx") port, options(nomem, nostack));
    }
    value
}

/// Build the 32-bit configuration address word for a (bus, device, function,
/// offset) target. `offset` is forced to a 32-bit-aligned dword boundary (the
/// low two bits are part of the address but config reads are dword-granular).
const fn config_address(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    CONFIG_ENABLE
        | ((bus as u32) << 16)
        | ((device as u32 & 0x1F) << 11)
        | ((function as u32 & 0x07) << 8)
        | (offset as u32 & 0xFC)
}

/// Read a 32-bit configuration-space register at `offset` of (bus, dev, func).
///
/// Safe wrapper: it performs the address-port write + data-port read pair, which
/// only touches the PCI config ports. Single-core init ⇒ the pair is never
/// interleaved with another config access.
fn read_config(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    let addr = config_address(bus, device, function, offset);
    // SAFETY: writes the enable-bit-set address word to the config **address**
    // port (`0xCF8`) then reads the selected register from the config **data**
    // port (`0xCFC`). Both are the documented PCI mechanism-#1 ports; the write
    // only selects which config register the next data-port access targets and
    // the read returns that register — a device-only effect that cannot alias or
    // corrupt Rust memory. `outl`/`inl` contracts (valid config ports) hold, and
    // the write+read pair is not interleaved (single-core init).
    unsafe {
        outl(CONFIG_ADDRESS, addr);
        inl(CONFIG_DATA)
    }
}

/// Write a 32-bit configuration-space register at `offset` of (bus, dev, func).
fn write_config(bus: u8, device: u8, function: u8, offset: u8, value: u32) {
    let addr = config_address(bus, device, function, offset);
    // SAFETY: as in `read_config`, selects the register via the address port,
    // then writes `value` to it via the data port. Used only to set the command
    // register's bus-master / memory-space bits (a device-only effect). `outl`'s
    // contract holds and the pair is not interleaved (single-core init).
    unsafe {
        outl(CONFIG_ADDRESS, addr);
        outl(CONFIG_DATA, value);
    }
}

/// A located PCI device (a specific bus/device/function on the host bridge).
///
/// Returned by [`scan_for`]. All of its methods are **safe** wrappers over
/// dword config reads/writes of the located function.
#[derive(Clone, Copy, Debug)]
pub struct PciDevice {
    bus: u8,
    device: u8,
    function: u8,
    /// Vendor id read at discovery (cached).
    vendor: u16,
    /// Device id read at discovery (cached).
    dev_id: u16,
}

impl PciDevice {
    /// The cached `(vendor, device)` id pair.
    #[must_use]
    pub const fn id(&self) -> (u16, u16) {
        (self.vendor, self.dev_id)
    }

    /// The device's `(bus, device, function)` location.
    #[must_use]
    pub const fn location(&self) -> (u8, u8, u8) {
        (self.bus, self.device, self.function)
    }

    /// Read Base Address Register `n` (0..=5) as a raw 32-bit value.
    ///
    /// For a 32-bit memory BAR, masking off the low 4 flag bits yields the
    /// MMIO base. (The e1000's BAR0 is a 32-bit, non-prefetchable memory BAR.)
    #[must_use]
    pub fn bar(&self, n: u8) -> u32 {
        read_config(self.bus, self.device, self.function, OFF_BAR0 + n * 4)
    }

    /// The MMIO base physical address from BAR0 (low 4 flag bits masked off).
    ///
    /// Returns `0` if BAR0 is an I/O-space BAR (bit 0 set) rather than memory —
    /// which never happens for the e1000's BAR0 on QEMU, but is checked so a
    /// misconfiguration degrades to a recognisable zero rather than a bogus
    /// address.
    #[must_use]
    pub fn mmio_base(&self) -> u64 {
        let bar0 = self.bar(0);
        if bar0 & 0x1 != 0 {
            return 0; // I/O-space BAR, not memory — unexpected for the e1000.
        }
        // Bits [2:1] == 0b10 would mark a 64-bit BAR (base spans BAR0+BAR1);
        // the e1000's BAR0 is 32-bit, so the base is simply BAR0 & !0xF.
        (bar0 & 0xFFFF_FFF0) as u64
    }

    /// The interrupt-line byte (the legacy PIC IRQ the device is wired to).
    #[must_use]
    pub fn interrupt_line(&self) -> u8 {
        (read_config(self.bus, self.device, self.function, OFF_INTERRUPT_LINE) & 0xFF) as u8
    }

    /// Enable bus mastering (DMA) and memory-space response in the command
    /// register, so the NIC can DMA to/from our descriptor rings and we can
    /// reach its MMIO. Reads the current command word, ORs in the bits, writes
    /// it back (preserving the status half, which is read-only/`write-1-to-clear`
    /// and unaffected by writing back what we read).
    pub fn enable_bus_master(&self) {
        let cmd_status = read_config(self.bus, self.device, self.function, OFF_COMMAND);
        let new = cmd_status | (CMD_BUS_MASTER as u32) | (CMD_MEMORY_SPACE as u32);
        write_config(self.bus, self.device, self.function, OFF_COMMAND, new);
    }
}

/// Read the `(vendor, device)` id pair of a function, or `None` if absent.
fn probe(bus: u8, device: u8, function: u8) -> Option<(u16, u16)> {
    let id = read_config(bus, device, function, OFF_VENDOR_DEVICE);
    let vendor = (id & 0xFFFF) as u16;
    if vendor == VENDOR_NONE {
        return None; // No device responds at this function.
    }
    let dev_id = (id >> 16) as u16;
    Some((vendor, dev_id))
}

/// Whether function 0 of a device is multi-function (header-type bit 7 set), so
/// we should probe functions 1..8 as well.
fn is_multifunction(bus: u8, device: u8) -> bool {
    let word = read_config(bus, device, 0, OFF_HEADER_TYPE);
    let header_type = ((word >> 16) & 0xFF) as u8;
    header_type & 0x80 != 0
}

/// Scan the PCI bus(es) for the first device matching `(vendor, device)`.
///
/// Enumerates every device/function on buses `0..=max_bus`. On QEMU's q35 the
/// e1000 sits on bus 0, so a small `max_bus` (e.g. 0 or 1) suffices, but the
/// scan is cheap and bounded. Returns the first match as a [`PciDevice`], or
/// `None` if no such device is present — letting the caller degrade gracefully
/// (e.g. boot headless networking) when the NIC was not attached.
#[must_use]
pub fn scan_for(target_vendor: u16, target_device: u16, max_bus: u8) -> Option<PciDevice> {
    for bus in 0..=max_bus {
        for device in 0u8..32 {
            // Probe function 0 first; if absent, the whole device slot is empty.
            let Some((vendor, dev_id)) = probe(bus, device, 0) else {
                continue;
            };
            if vendor == target_vendor && dev_id == target_device {
                return Some(PciDevice {
                    bus,
                    device,
                    function: 0,
                    vendor,
                    dev_id,
                });
            }
            // If multi-function, probe the remaining functions too.
            if is_multifunction(bus, device) {
                for function in 1u8..8 {
                    if let Some((vendor, dev_id)) = probe(bus, device, function) {
                        if vendor == target_vendor && dev_id == target_device {
                            return Some(PciDevice {
                                bus,
                                device,
                                function,
                                vendor,
                                dev_id,
                            });
                        }
                    }
                }
            }
        }
    }
    None
}

/// Read the class-code byte (high byte of the class word at offset 0x08) of a
/// located device — exposed for diagnostics/logging.
#[must_use]
pub fn class_code(dev: &PciDevice) -> u8 {
    ((read_config(dev.bus, dev.device, dev.function, OFF_CLASS) >> 24) & 0xFF) as u8
}
