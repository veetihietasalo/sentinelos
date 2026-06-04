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
//! - [`list_devices`] — enumerate **all** functions on the bus into a
//!   fixed-capacity [`PciDeviceList`] of [`PciDeviceInfo`] (location, id,
//!   class/subclass, and a human name) for the shell's `devices` command.
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

// ── Device enumeration (for the shell's `devices` command) ──────────────────
//
// `scan_for` answers "is *this* device present?". The `devices` command needs
// the *whole* list, so the accessors below walk every bus/slot/function once and
// collect a small fixed-capacity inventory. `hal` does not depend on `alloc`, so
// the list is returned in a stack array ([`PciDeviceList`]) the kernel formats —
// no heap, no `unsafe` beyond the already-documented config-read ports.

/// Maximum number of PCI functions [`list_devices`] records. q35/QEMU exposes a
/// handful; 32 is comfortably more than any board we boot and bounds the scan's
/// memory. Devices past the limit are dropped (the count is still capped here).
pub const MAX_DEVICES: usize = 32;

/// A summary of one enumerated PCI function, for diagnostics / the `devices`
/// command. Carries the location, the `(vendor, device)` id pair, the
/// class/subclass/prog-IF bytes, and a best-effort human name for recognised
/// devices (otherwise an empty name — the kernel falls back to the class).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PciDeviceInfo {
    /// Bus number the function sits on.
    pub bus: u8,
    /// Device (slot) number within the bus.
    pub device: u8,
    /// Function number within the device.
    pub function: u8,
    /// PCI vendor id (e.g. `0x8086` for Intel, `0x1234` for QEMU's stdvga).
    pub vendor: u16,
    /// PCI device id.
    pub dev_id: u16,
    /// Class code (high byte of the class word) — broad device category.
    pub class: u8,
    /// Subclass code (second byte) — finer category within the class.
    pub subclass: u8,
    /// Programming-interface byte (third byte) — register-level interface.
    pub prog_if: u8,
    /// Best-effort human name for a recognised `(vendor, device)`/class, or `""`.
    pub name: &'static str,
}

/// A fixed-capacity list of enumerated PCI functions (no heap).
///
/// Returned by [`list_devices`]. Iterate the populated prefix with
/// [`as_slice`](PciDeviceList::as_slice); [`len`](PciDeviceList::len) reports how
/// many functions were found (capped at [`MAX_DEVICES`]).
#[derive(Clone, Copy, Debug)]
pub struct PciDeviceList {
    devices: [PciDeviceInfo; MAX_DEVICES],
    len: usize,
}

impl PciDeviceList {
    /// Number of devices recorded (`<= MAX_DEVICES`).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether no PCI device was found at all.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The populated prefix of the device array.
    #[must_use]
    pub fn as_slice(&self) -> &[PciDeviceInfo] {
        &self.devices[..self.len]
    }
}

/// A best-effort human name for a `(vendor, device)` pair, or for a device class
/// when the exact id is unknown.
///
/// Covers the handful of devices QEMU's q35 machine exposes (so the `devices`
/// command reads meaningfully on our boot target); anything else falls back to a
/// broad class name, and finally to `""` (the kernel then prints the raw class).
fn human_name(vendor: u16, dev_id: u16, class: u8, subclass: u8) -> &'static str {
    match (vendor, dev_id) {
        (0x8086, 0x100E) => "Intel e1000 (82540EM) NIC",
        (0x8086, 0x1237) => "Intel 440FX host bridge",
        (0x8086, 0x7000) => "Intel PIIX3 ISA bridge",
        (0x8086, 0x7010) => "Intel PIIX3 IDE",
        (0x8086, 0x7113) => "Intel PIIX4 ACPI",
        (0x8086, 0x2918) => "Intel ICH9 LPC bridge",
        (0x8086, 0x2922) => "Intel ICH9 SATA (AHCI)",
        (0x8086, 0x2930) => "Intel ICH9 SMBus",
        (0x8086, 0x29C0) => "Intel Q35 MCH host bridge",
        (0x1234, 0x1111) => "QEMU stdvga / bochs-display",
        (0x1B36, 0x000D) => "QEMU XHCI USB controller",
        (0x1AF4, _) => "VirtIO device",
        _ => class_name(class, subclass),
    }
}

/// A broad human name for a PCI device *class* (used when the exact id is not in
/// the table above), or `""` for an unrecognised class.
fn class_name(class: u8, subclass: u8) -> &'static str {
    match (class, subclass) {
        (0x00, _) => "legacy device",
        (0x01, 0x01) => "IDE controller",
        (0x01, 0x06) => "SATA controller",
        (0x01, _) => "mass-storage controller",
        (0x02, _) => "network controller",
        (0x03, _) => "display controller",
        (0x04, _) => "multimedia controller",
        (0x06, 0x00) => "host bridge",
        (0x06, 0x01) => "ISA bridge",
        (0x06, 0x04) => "PCI-to-PCI bridge",
        (0x06, _) => "bridge",
        (0x0C, 0x03) => "USB controller",
        (0x0C, 0x05) => "SMBus controller",
        (0x0C, _) => "serial-bus controller",
        _ => "",
    }
}

/// Read the full class word (class/subclass/prog-IF) of a located function.
///
/// Returns `(class, subclass, prog_if)`. The class word at offset `0x08` is
/// `[revision][prog-if][subclass][class]` low→high, so the three category bytes
/// are bits 8..32.
fn class_triplet(bus: u8, device: u8, function: u8) -> (u8, u8, u8) {
    let word = read_config(bus, device, function, OFF_CLASS);
    let class = ((word >> 24) & 0xFF) as u8;
    let subclass = ((word >> 16) & 0xFF) as u8;
    let prog_if = ((word >> 8) & 0xFF) as u8;
    (class, subclass, prog_if)
}

/// Build the [`PciDeviceInfo`] for a function already known to be present.
fn describe(bus: u8, device: u8, function: u8, vendor: u16, dev_id: u16) -> PciDeviceInfo {
    let (class, subclass, prog_if) = class_triplet(bus, device, function);
    PciDeviceInfo {
        bus,
        device,
        function,
        vendor,
        dev_id,
        class,
        subclass,
        prog_if,
        name: human_name(vendor, dev_id, class, subclass),
    }
}

/// Enumerate every PCI function on buses `0..=max_bus` into a fixed-capacity list.
///
/// This is the **safe** general accessor behind the shell's `devices` command: it
/// probes each device slot's function 0, descends into the remaining functions of
/// multi-function devices, and records up to [`MAX_DEVICES`] entries (location,
/// id, class/subclass/prog-IF, and a human name). The scan is identical in spirit
/// to [`scan_for`] but collects the whole inventory instead of stopping at the
/// first match. On QEMU's q35 a small `max_bus` (0 or 1) covers everything.
#[must_use]
pub fn list_devices(max_bus: u8) -> PciDeviceList {
    let empty = PciDeviceInfo {
        bus: 0,
        device: 0,
        function: 0,
        vendor: 0,
        dev_id: 0,
        class: 0,
        subclass: 0,
        prog_if: 0,
        name: "",
    };
    let mut list = PciDeviceList {
        devices: [empty; MAX_DEVICES],
        len: 0,
    };

    'scan: for bus in 0..=max_bus {
        for device in 0u8..32 {
            // Probe function 0 first; if absent, the whole device slot is empty.
            let Some((vendor, dev_id)) = probe(bus, device, 0) else {
                continue;
            };
            if list.len >= MAX_DEVICES {
                break 'scan;
            }
            list.devices[list.len] = describe(bus, device, 0, vendor, dev_id);
            list.len += 1;

            // If multi-function, record the remaining present functions too.
            if is_multifunction(bus, device) {
                for function in 1u8..8 {
                    if let Some((vendor, dev_id)) = probe(bus, device, function) {
                        if list.len >= MAX_DEVICES {
                            break 'scan;
                        }
                        list.devices[list.len] = describe(bus, device, function, vendor, dev_id);
                        list.len += 1;
                    }
                }
            }
        }
    }

    list
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_address_sets_enable_and_packs_fields() {
        // bus 1, device 3, function 2, offset 0x10 (BAR0).
        let addr = config_address(1, 3, 2, 0x10);
        assert_eq!(addr & CONFIG_ENABLE, CONFIG_ENABLE);
        assert_eq!((addr >> 16) & 0xFF, 1); // bus
        assert_eq!((addr >> 11) & 0x1F, 3); // device
        assert_eq!((addr >> 8) & 0x07, 2); // function
        assert_eq!(addr & 0xFC, 0x10); // dword-aligned offset
    }

    #[test]
    fn known_device_names_resolve() {
        assert_eq!(
            human_name(0x8086, 0x100E, 0x02, 0x00),
            "Intel e1000 (82540EM) NIC"
        );
        // Unknown id but known class → class fallback.
        assert_eq!(human_name(0xDEAD, 0xBEEF, 0x03, 0x00), "display controller");
        // Unknown id and unknown class → empty.
        assert_eq!(human_name(0xDEAD, 0xBEEF, 0xFF, 0xFF), "");
    }

    #[test]
    fn empty_device_list_reports_empty() {
        let list = PciDeviceList {
            devices: [PciDeviceInfo {
                bus: 0,
                device: 0,
                function: 0,
                vendor: 0,
                dev_id: 0,
                class: 0,
                subclass: 0,
                prog_if: 0,
                name: "",
            }; MAX_DEVICES],
            len: 0,
        };
        assert!(list.is_empty());
        assert_eq!(list.len(), 0);
        assert!(list.as_slice().is_empty());
    }
}
