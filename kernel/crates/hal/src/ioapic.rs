//! I/O APIC register access + device-IRQ EOI routing (SMP phase 3b-ii) — part
//! of the TCB.
//!
//! An IOAPIC turns device interrupt pins (global system interrupts, GSIs) into
//! LAPIC messages: each pin has a 64-bit **redirection entry** naming a vector, a
//! delivery mode, a destination APIC ID, polarity, trigger mode and a mask bit.
//! Its registers are reached **indirectly** through a two-word MMIO window:
//! write a register index to `IOREGSEL` (+0x00), then read/write `IOWIN` (+0x10).
//!
//! `hal` provides the mechanism only; *which* IRQ goes to which GSI, vector and
//! CPU is policy in the safe kernel (`kernel::ioapic`), from the MADT the kernel
//! parsed itself (`kernel::acpi`). The public surface is safe:
//!
//! - [`RedirectionEntry`] — the entry as a value type, with pure, Kani-proved
//!   [`RedirectionEntry::to_raw`] / [`RedirectionEntry::from_raw`] packing.
//! - [`IoApic::map`] — validate and map one IOAPIC's register window (IO1), read
//!   its ID and version register (IO2). The handle is sealed: only `map` makes
//!   one, so a kernel-held `IoApic` always names a mapped, version-checked window.
//! - [`IoApic::write_entry`] / [`IoApic::read_entry`] / [`IoApic::mask_pin`] —
//!   program a pin (IO3). Refuses pins past the version register's maximum and
//!   any fixed/lowest-priority vector below `0x20` (an exception vector: its ISR
//!   stub's error-code expectation would not match a device delivery).
//! - [`device_eoi`] — the one EOI every device IRQ handler (PIT, keyboard, mouse,
//!   NIC) calls. It EOIs the **LAPIC** when the LAPIC has the vector in service —
//!   i.e. the interrupt arrived as a LAPIC message, which once the PIC is masked
//!   means the IOAPIC — and the 8259 only otherwise (the legacy virtual-wire
//!   path, where ExtINT delivery never sets a LAPIC ISR bit). The decision is
//!   made per interrupt from the hardware's own record, so there is no software
//!   flag that could disagree with the path an interrupt actually took, during
//!   the switch-over or after a rollback.
//!
//! # Concurrency
//!
//! One global [`SpinMutex`] serialises every `IOREGSEL`/`IOWIN` pair across all
//! IOAPICs and cores, so a select can never be separated from its window access.
//! It is **never** taken from interrupt context ([`device_eoi`] touches only the
//! LAPIC), so it needs no interrupt masking to be deadlock-free.
//!
//! Registry: `kernel/docs/hal-tcb.md` §2m (IO1–IO4) and invariant 17.

use crate::mm::{self, PhysAddr};
use crate::sync::{SpinGuard, SpinMutex};

/// `IOREGSEL` offset in the window.
const IOREGSEL: u64 = 0x00;
/// `IOWIN` offset in the window.
const IOWIN: u64 = 0x10;
/// Bytes of the register window `hal` maps (IOREGSEL..IOWIN+4).
const WINDOW_LEN: usize = 0x20;

/// IOAPIC ID register index.
const REG_ID: u32 = 0x00;
/// IOAPIC version register index (`[7:0]` version, `[23:16]` max redirection entry).
const REG_VER: u32 = 0x01;
/// First redirection-table register (pin `n` low dword = `0x10 + 2n`, high = `+1`).
const REG_REDTBL: u32 = 0x10;

/// Lowest vector a device may be routed to with fixed / lowest-priority
/// delivery: `0..0x20` are CPU exception vectors.
pub const MIN_DEVICE_VECTOR: u8 = 0x20;

/// Serialises every select/window pair (see the module docs).
static IOAPIC_LOCK: SpinMutex<()> = SpinMutex::new(());

// ── Pure redirection-entry packing (Kani: `proofs`) ──────────────────────────

/// Delivery mode, bits `[10:8]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryMode {
    /// `000` — deliver `vector` to the destination.
    Fixed,
    /// `001` — deliver to the lowest-priority CPU of a logical destination.
    LowestPriority,
    /// `010` — SMI.
    Smi,
    /// `100` — NMI (vector ignored).
    Nmi,
    /// `101` — INIT.
    Init,
    /// `111` — ExtINT (8259-compatible).
    ExtInt,
}

impl DeliveryMode {
    const fn bits(self) -> u64 {
        match self {
            DeliveryMode::Fixed => 0b000,
            DeliveryMode::LowestPriority => 0b001,
            DeliveryMode::Smi => 0b010,
            DeliveryMode::Nmi => 0b100,
            DeliveryMode::Init => 0b101,
            DeliveryMode::ExtInt => 0b111,
        }
    }
    const fn from_bits(b: u64) -> Option<Self> {
        match b & 0b111 {
            0b000 => Some(DeliveryMode::Fixed),
            0b001 => Some(DeliveryMode::LowestPriority),
            0b010 => Some(DeliveryMode::Smi),
            0b100 => Some(DeliveryMode::Nmi),
            0b101 => Some(DeliveryMode::Init),
            0b111 => Some(DeliveryMode::ExtInt),
            _ => None,
        }
    }
}

/// One IOAPIC redirection entry, **physical** destination mode only (the kernel
/// names one APIC ID per IRQ; logical/cluster modes are not exposed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RedirectionEntry {
    /// Interrupt vector, bits `[7:0]`.
    pub vector: u8,
    /// Delivery mode, bits `[10:8]`.
    pub delivery: DeliveryMode,
    /// Pin polarity, bit 13: `true` = active low.
    pub active_low: bool,
    /// Trigger mode, bit 15: `true` = level.
    pub level: bool,
    /// Mask, bit 16: `true` = the pin delivers nothing.
    pub masked: bool,
    /// Destination APIC ID, bits `[63:56]` (physical mode, bit 11 = 0).
    pub dest: u8,
}

const BIT_ACTIVE_LOW: u64 = 1 << 13;
const BIT_LEVEL: u64 = 1 << 15;
const BIT_MASKED: u64 = 1 << 16;
const DEST_SHIFT: u32 = 56;
/// Every bit `to_raw` may set: vector, delivery, polarity, trigger, mask, dest.
/// Bit 11 (destination mode) stays 0 (physical); bits 12 and 14 (delivery
/// status, remote IRR) are read-only; `[55:17]` are reserved.
pub const WRITABLE_MASK: u64 =
    0xFF | (0b111 << 8) | BIT_ACTIVE_LOW | BIT_LEVEL | BIT_MASKED | (0xFF << DEST_SHIFT);

impl RedirectionEntry {
    /// A masked entry with every other field zero — the safe parking value.
    pub const MASKED: Self = Self {
        vector: 0,
        delivery: DeliveryMode::Fixed,
        active_low: false,
        level: false,
        masked: true,
        dest: 0,
    };

    /// Pack into the 64-bit register value. Never sets a read-only or reserved
    /// bit, and leaves destination mode physical.
    #[must_use]
    pub const fn to_raw(self) -> u64 {
        let mut raw = self.vector as u64 | (self.delivery.bits() << 8);
        if self.active_low {
            raw |= BIT_ACTIVE_LOW;
        }
        if self.level {
            raw |= BIT_LEVEL;
        }
        if self.masked {
            raw |= BIT_MASKED;
        }
        raw | ((self.dest as u64) << DEST_SHIFT)
    }

    /// Unpack a register value. `None` for a reserved delivery mode or a
    /// logical destination mode (bit 11), which `to_raw` never produces.
    #[must_use]
    pub const fn from_raw(raw: u64) -> Option<Self> {
        let Some(delivery) = DeliveryMode::from_bits(raw >> 8) else {
            return None;
        };
        if raw & (1 << 11) != 0 {
            return None;
        }
        Some(Self {
            vector: (raw & 0xFF) as u8,
            delivery,
            active_low: raw & BIT_ACTIVE_LOW != 0,
            level: raw & BIT_LEVEL != 0,
            masked: raw & BIT_MASKED != 0,
            dest: (raw >> DEST_SHIFT) as u8,
        })
    }

    /// Whether `hal` will program this entry. A masked entry is inert and may
    /// hold anything. An **unmasked** entry must be fixed delivery of a vector
    /// ≥ [`MIN_DEVICE_VECTOR`]: SMI, NMI, INIT and ExtINT delivery would let a
    /// device line reset or seize a core, lowest-priority needs a logical
    /// destination `hal` never programs, and a vector below `0x20` would enter
    /// an exception stub whose error-code expectation does not match.
    #[must_use]
    pub const fn is_programmable(self) -> bool {
        self.masked
            || (matches!(self.delivery, DeliveryMode::Fixed) && self.vector >= MIN_DEVICE_VECTOR)
    }
}

/// Decode the version register: `(version, max_redirection_entry)`.
#[must_use]
pub const fn decode_version(raw: u32) -> (u8, u8) {
    ((raw & 0xFF) as u8, ((raw >> 16) & 0xFF) as u8)
}

/// Whether a version-register value looks like a real IOAPIC: not all-ones
/// (nothing decodes the address) and at least one redirection entry beyond pin
/// 0 (`max_redirection_entry >= 1`; real parts report 23 or more).
#[must_use]
pub const fn version_plausible(raw: u32) -> bool {
    let (_, max) = decode_version(raw);
    raw != u32::MAX && max >= 1
}

// ── The mapped device ────────────────────────────────────────────────────────

/// Why [`IoApic::map`] refused an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapError {
    /// The address is not 16-byte aligned or the window would wrap.
    BadAddress,
    /// The window overlaps memory the kernel owns (`mm::overlaps_kernel_owned`).
    OverlapsRam,
    /// Mapping failed (memory management not up / out of frames).
    MapFailed,
    /// The version register read back implausibly — no IOAPIC there.
    NoDevice,
}

/// One mapped, version-checked IOAPIC. Only [`IoApic::map`] constructs it.
#[derive(Clone, Copy, Debug)]
pub struct IoApic {
    base: u64,
    id: u8,
    version: u8,
    max_entry: u8,
}

impl IoApic {
    /// Map the IOAPIC whose register window is at physical `phys` (the MADT
    /// type-1 `address`) and read its identity.
    ///
    /// The address comes from firmware, so it is checked before anything is
    /// mapped: it is the MADT's 32-bit field (so it cannot carry bits at or
    /// above `MAXPHYADDR` that a page-table leaf would ignore or alias — and
    /// `mm::map_mmio` independently refuses any such span, `mm::phys_span`),
    /// 16-byte aligned (both registers 4-byte aligned in one window), and
    /// overlapping no kernel-owned RAM. A lying table can therefore never turn
    /// the register writes below into stores to kernel memory; it can still
    /// make `hal` poke some *other* device's MMIO at that address, which is the
    /// residual trust placed in firmware (hal-tcb IO1). The window is mapped
    /// uncached, then the version register must read back plausibly.
    ///
    /// # Errors
    ///
    /// See [`MapError`].
    pub fn map(phys: u32) -> Result<Self, MapError> {
        let phys = u64::from(phys);
        if phys & 0xF != 0 {
            return Err(MapError::BadAddress);
        }
        if mm::overlaps_kernel_owned(phys, WINDOW_LEN as u64) {
            return Err(MapError::OverlapsRam);
        }
        let virt =
            mm::map_mmio(PhysAddr::new(phys), WINDOW_LEN).map_err(|_| MapError::MapFailed)?;
        let mut dev = Self {
            base: virt.as_u64(),
            id: 0,
            version: 0,
            max_entry: 0,
        };
        let (ver, id) = {
            let g = IOAPIC_LOCK.lock();
            (dev.sel_read(&g, REG_VER), dev.sel_read(&g, REG_ID))
        };
        if !version_plausible(ver) {
            return Err(MapError::NoDevice);
        }
        let (version, max_entry) = decode_version(ver);
        dev.version = version;
        dev.max_entry = max_entry;
        dev.id = ((id >> 24) & 0x0F) as u8;
        Ok(dev)
    }

    /// The ID register's APIC ID field.
    #[must_use]
    pub const fn id(&self) -> u8 {
        self.id
    }

    /// The version register's version field (`0x11` on 82093AA-compatible parts,
    /// `0x20` on QEMU/ICH).
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.version
    }

    /// Number of redirection entries (pins): `max_redirection_entry + 1`.
    #[must_use]
    pub const fn pins(&self) -> u16 {
        self.max_entry as u16 + 1
    }

    /// One indirect register read: select `reg`, read the window. Takes the
    /// held [`IOAPIC_LOCK`] guard, so every select/window pair — and every
    /// multi-register sequence a caller builds from these — runs under one
    /// acquisition: the pairing is enforced by the signature.
    fn sel_read(&self, _held: &SpinGuard<'_, ()>, reg: u32) -> u32 {
        // SAFETY: (IO2) `self.base` is the uncached mapping of a 0x20-byte IOAPIC
        // window that `map` validated (aligned, below MAXPHYADDR, not kernel RAM)
        // and mapped; it is never unmapped. `IOREGSEL` (+0) and `IOWIN` (+0x10)
        // are 4-byte aligned `u32` registers inside it. Volatile because they are
        // device registers; the caller holds the global lock, so the select and
        // the window access stay paired. Device register access cannot alias
        // Rust memory.
        unsafe {
            core::ptr::write_volatile((self.base + IOREGSEL) as *mut u32, reg);
            core::ptr::read_volatile((self.base + IOWIN) as *const u32)
        }
    }

    /// One indirect register write: select `reg`, write the window (lock held).
    fn sel_write(&self, _held: &SpinGuard<'_, ()>, reg: u32, value: u32) {
        // SAFETY: (IO2/IO3) as `sel_read` — the validated, mapped window; both
        // accesses are aligned volatile `u32` device-register stores under the
        // held pairing lock. Callers pass only a redirection-table index
        // `< 0x10 + 2 * pins` (checked in `write_entry`).
        unsafe {
            core::ptr::write_volatile((self.base + IOREGSEL) as *mut u32, reg);
            core::ptr::write_volatile((self.base + IOWIN) as *mut u32, value);
        }
    }

    /// Program pin `pin` with `entry`. Returns `false` (programming nothing) if
    /// `pin` is past the last redirection entry or `entry` is not
    /// [programmable](RedirectionEntry::is_programmable).
    ///
    /// The pin is masked first, the destination dword written next, and the
    /// final low dword (with `entry`'s own mask bit) last — so the pin never
    /// delivers with a half-written entry.
    #[must_use]
    pub fn write_entry(&self, pin: u8, entry: RedirectionEntry) -> bool {
        if pin > self.max_entry || !entry.is_programmable() {
            return false;
        }
        let raw = entry.to_raw();
        let low = REG_REDTBL + 2 * u32::from(pin);
        // One acquisition for the whole three-write sequence: no other core can
        // interleave a write to the same entry between its halves.
        let g = IOAPIC_LOCK.lock();
        self.sel_write(&g, low, (raw as u32) | (BIT_MASKED as u32));
        self.sel_write(&g, low + 1, (raw >> 32) as u32);
        self.sel_write(&g, low, raw as u32);
        true
    }

    /// Read pin `pin`'s entry back, or `None` past the last entry / for an
    /// encoding `hal` never writes.
    #[must_use]
    pub fn read_entry(&self, pin: u8) -> Option<RedirectionEntry> {
        if pin > self.max_entry {
            return None;
        }
        let low = REG_REDTBL + 2 * u32::from(pin);
        let raw = {
            let g = IOAPIC_LOCK.lock();
            u64::from(self.sel_read(&g, low)) | (u64::from(self.sel_read(&g, low + 1)) << 32)
        };
        RedirectionEntry::from_raw(raw)
    }

    /// Mask pin `pin` (park it as [`RedirectionEntry::MASKED`]).
    #[must_use]
    pub fn mask_pin(&self, pin: u8) -> bool {
        self.write_entry(pin, RedirectionEntry::MASKED)
    }
}

/// End-Of-Interrupt for a device IRQ that was delivered on `vector`.
///
/// EOIs the LAPIC if the LAPIC has `vector` in service (the interrupt arrived as
/// an IOAPIC message — and for a level-triggered pin this EOI's broadcast is what
/// clears the IOAPIC's remote-IRR), otherwise the 8259 (virtual-wire ExtINT,
/// which never sets a LAPIC ISR bit). Exactly one EOI is issued, to the
/// controller that actually delivered the interrupt. See the module docs.
pub fn device_eoi(vector: u8) {
    if !crate::apic::eoi_if_in_service(vector) {
        crate::pic::end_of_interrupt(vector);
    }
}

// ── Host unit tests (Miri runs these) ────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packs_the_pit_route_exactly() {
        let e = RedirectionEntry {
            vector: 0x20,
            delivery: DeliveryMode::Fixed,
            active_low: false,
            level: false,
            masked: false,
            dest: 0,
        };
        assert_eq!(e.to_raw(), 0x20);
        assert_eq!(RedirectionEntry::from_raw(e.to_raw()), Some(e));
    }

    #[test]
    fn packs_a_level_low_masked_route_to_cpu3() {
        let e = RedirectionEntry {
            vector: 0x2B,
            delivery: DeliveryMode::Fixed,
            active_low: true,
            level: true,
            masked: true,
            dest: 3,
        };
        assert_eq!(e.to_raw(), 0x0300_0000_0001_A02B);
        assert_eq!(RedirectionEntry::from_raw(e.to_raw()), Some(e));
    }

    #[test]
    fn from_raw_rejects_logical_and_reserved_and_ignores_ro_bits() {
        assert_eq!(RedirectionEntry::from_raw(1 << 11), None);
        assert_eq!(RedirectionEntry::from_raw(0b011 << 8), None);
        assert_eq!(RedirectionEntry::from_raw(0b110 << 8), None);
        let busy = (1 << 12) | (1 << 14) | 0x21;
        assert_eq!(
            RedirectionEntry::from_raw(busy).map(|e| e.vector),
            Some(0x21)
        );
    }

    #[test]
    fn only_fixed_device_vectors_are_programmable_unmasked() {
        let mut e = RedirectionEntry {
            masked: false,
            vector: 0x1F,
            ..RedirectionEntry::MASKED
        };
        assert!(!e.is_programmable());
        e.vector = 0x20;
        assert!(e.is_programmable());
        for mode in [
            DeliveryMode::LowestPriority,
            DeliveryMode::Smi,
            DeliveryMode::Nmi,
            DeliveryMode::Init,
            DeliveryMode::ExtInt,
        ] {
            e.delivery = mode;
            e.masked = false;
            assert!(!e.is_programmable(), "{mode:?} unmasked");
            e.masked = true;
            assert!(e.is_programmable(), "{mode:?} masked");
        }
        assert!(RedirectionEntry::MASKED.is_programmable());
    }

    #[test]
    fn version_decode() {
        assert_eq!(decode_version(0x0017_0020), (0x20, 23));
        assert!(version_plausible(0x0017_0020));
        assert!(!version_plausible(u32::MAX));
        assert!(!version_plausible(0x0000_0011));
    }
}

/// Kani: the redirection-entry packing is exact, total and never sets a
/// read-only, reserved or logical-destination bit.
#[cfg(kani)]
mod proofs {
    use super::*;

    fn any_mode() -> DeliveryMode {
        match kani::any::<u8>() % 6 {
            0 => DeliveryMode::Fixed,
            1 => DeliveryMode::LowestPriority,
            2 => DeliveryMode::Smi,
            3 => DeliveryMode::Nmi,
            4 => DeliveryMode::Init,
            _ => DeliveryMode::ExtInt,
        }
    }

    fn any_entry() -> RedirectionEntry {
        RedirectionEntry {
            vector: kani::any(),
            delivery: any_mode(),
            active_low: kani::any(),
            level: kani::any(),
            masked: kani::any(),
            dest: kani::any(),
        }
    }

    /// `from_raw(to_raw(e)) == e` for every entry, and `to_raw` stays inside
    /// `WRITABLE_MASK` with destination mode physical.
    #[kani::proof]
    fn redirection_entry_round_trips_and_sets_only_writable_bits() {
        let e = any_entry();
        let raw = e.to_raw();
        assert_eq!(raw & !WRITABLE_MASK, 0);
        assert_eq!(raw & (1 << 11), 0);
        assert_eq!(RedirectionEntry::from_raw(raw), Some(e));
        assert_eq!(raw & 0xFF, u64::from(e.vector));
        assert_eq!(raw >> 56, u64::from(e.dest));
        assert_eq!(raw & (1 << 16) != 0, e.masked);
    }

    /// `from_raw` is total over every 64-bit value, and whatever it accepts
    /// re-packs to the same writable bits.
    #[kani::proof]
    fn redirection_entry_from_raw_is_total() {
        let raw: u64 = kani::any();
        if let Some(e) = RedirectionEntry::from_raw(raw) {
            assert_eq!(e.to_raw(), raw & WRITABLE_MASK);
        }
    }

    /// Every entry `hal` will program unmasked is fixed delivery of a device
    /// vector — never SMI/NMI/INIT/ExtINT/lowest-priority, never an exception
    /// vector.
    #[kani::proof]
    fn programmable_entries_never_target_exception_vectors() {
        let e = any_entry();
        if e.is_programmable() && !e.masked {
            assert!(matches!(e.delivery, DeliveryMode::Fixed));
            assert!(e.vector >= MIN_DEVICE_VECTOR);
        }
    }
}
