//! `kernel::ioapic` — device-IRQ routing policy through the IOAPIC (SMP phase
//! 3b-ii). Safe Rust; every register access is a `hal` call.
//!
//! [`init`] walks the ACPI tables (`kernel::acpi`, over `hal::acpi::read_phys`),
//! maps every IOAPIC the MADT names (`hal::ioapic::IoApic::map`), masks the 8259
//! pair and the BSP's LINT0, and routes the ISA IRQs the kernel uses — the PIT
//! (IRQ0), the PS/2 keyboard (IRQ1) and mouse (IRQ12) — onto their GSIs,
//! honouring the MADT's Interrupt Source Overrides (under QEMU, IRQ0 → GSI 2).
//! [`route_nic`] later adds the e1000's legacy INTx line the same way. Vectors
//! are unchanged from the 8259 era (`0x20 + irq`), so every handler stays as it
//! was; only the EOI moves, and `hal::ioapic::device_eoi` makes that decision
//! from the LAPIC's own in-service register.
//!
//! # Destination: the BSP, explicitly
//!
//! Every routed IRQ names the BSP's APIC ID. That is a decision, not a default:
//! the PIT is the wall clock and the LAPIC-timer calibration reference, and
//! `clock::prove_mono`'s `pit-frozen=yes` relies on the PIT reaching only the
//! BSP (hal-tcb invariants 4.14/4.15); the keyboard and mouse rings are SPSC
//! with the BSP idle loop as the consumer and are not audited for a producer on
//! another core; the NIC frames are drained by that same loop. Spreading IRQs
//! across cores is load balancing — a product decision (STATE.md), not
//! something this phase does by accident.
//!
//! # Fail-safe
//!
//! Any failure before the switch (no RSDP, malformed MADT, no IOAPIC, an
//! unmappable window, an ISA IRQ whose GSI no IOAPIC serves) leaves the 8259
//! virtual wire exactly as it was. After the switch, the PIT must be seen
//! ticking through the IOAPIC within a bounded spin; if not, every IOAPIC pin is
//! masked again, LINT0 goes back to ExtINT and the 8259 lines are reopened —
//! the boot continues on the legacy path and the boot test fails on the
//! missing `[ioapic] … ok` line instead of hanging.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use hal::ioapic::{DeliveryMode, IoApic, RedirectionEntry};
use hal::sync::SpinMutex;

use crate::acpi::{self, IoApicEntry, MadtInfo, Polarity, Trigger};

/// ISA IRQ of the PIT.
pub const IRQ_PIT: u8 = 0;
/// ISA IRQ of the PS/2 keyboard.
pub const IRQ_KBD: u8 = 1;
/// ISA IRQ of the PS/2 mouse.
pub const IRQ_MOUSE: u8 = 12;

/// Fixed scratch for the ACPI walk (allocated once, never sized from firmware).
const ROOT_BUF_LEN: usize = 4 * 1024;
/// MADT scratch: 8 KiB holds ~500 x2APIC structures.
const MADT_BUF_LEN: usize = 8 * 1024;

/// PIT ticks the post-switch liveness check must observe.
const PIT_LIVE_TICKS: u64 = 3;
/// TSC-cycle bound for that check: 2^33 cycles is ~2–4 s at real TSC rates
/// (and under TCG, whose TSC follows the host clock) — reached only on failure.
const PIT_LIVE_TSC_LIMIT: u64 = 1 << 33;

/// Where one ISA IRQ lands: its GSI and the electrical properties of that pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IsaRoute {
    /// Global system interrupt.
    pub gsi: u32,
    /// Pin is active low.
    pub active_low: bool,
    /// Pin is level-triggered.
    pub level: bool,
}

/// Resolve ISA IRQ `irq` through the MADT's overrides: an ISA-bus override
/// supplies the GSI and any non-"conforms" polarity/trigger; otherwise the GSI
/// is the IRQ number. ISA's bus defaults are active-high, edge.
#[must_use]
pub fn isa_route(madt: &MadtInfo, irq: u8) -> IsaRoute {
    let (gsi, polarity, trigger) = match madt.override_for_isa(irq) {
        Some(o) => (o.gsi, o.polarity, o.trigger),
        None => (u32::from(irq), Polarity::Conforms, Trigger::Conforms),
    };
    IsaRoute {
        gsi,
        active_low: polarity == Polarity::ActiveLow,
        level: trigger == Trigger::Level,
    }
}

/// Find the IOAPIC (index into `ioapics`) and pin serving `gsi`, given each
/// IOAPIC's pin count. `None` if no IOAPIC covers it.
#[must_use]
pub fn locate(ioapics: &[IoApicEntry], pins: &[u16], gsi: u32) -> Option<(usize, u8)> {
    ioapics
        .iter()
        .zip(pins)
        .enumerate()
        .find_map(|(i, (io, &n))| {
            let off = gsi.checked_sub(io.gsi_base)?;
            if off < u32::from(n) {
                u8::try_from(off).ok().map(|pin| (i, pin))
            } else {
                None
            }
        })
}

/// The redirection entry for a routed device IRQ: fixed delivery of `vector`
/// to physical APIC ID `dest`, unmasked.
#[must_use]
pub const fn device_entry(route: IsaRoute, vector: u8, dest: u8) -> RedirectionEntry {
    RedirectionEntry {
        vector,
        delivery: DeliveryMode::Fixed,
        active_low: route.active_low,
        level: route.level,
        masked: false,
        dest,
    }
}

/// The route for a PCI device's legacy INTx line `irq` (its PCI
/// interrupt-line register), or `None` to leave the device polled.
///
/// Only a line the MADT declares **level-triggered** through an ISA-bus
/// override is routed: that is how the firmware says the line is a shared PCI
/// interrupt it steers onto that GSI (QEMU: IRQ 5/9/10/11, flags `0xD`). A line
/// without such an override is ambiguous — an ISA-style edge pin, or a PCI line
/// whose real GSI only the ACPI `_PRT` (AML, not interpreted here) knows — and
/// guessing could take over another source's pin (a PCI line of 2 with no
/// override would land on the PIT's GSI 2). A GSI in `taken` is refused too.
#[must_use]
pub fn pci_legacy_route(madt: &MadtInfo, irq: u8, taken: &[u32]) -> Option<IsaRoute> {
    let iso = madt.override_for_isa(irq)?;
    if iso.trigger != Trigger::Level || taken.contains(&iso.gsi) {
        return None;
    }
    Some(isa_route(madt, irq))
}

/// Routed sources, as bits of [`Router::routed`].
const SRC_PIT: u8 = 1 << 0;
const SRC_KBD: u8 = 1 << 1;
const SRC_MOUSE: u8 = 1 << 2;
const SRC_NIC: u8 = 1 << 3;

/// The live routing state, set once by [`init`].
struct Router {
    ioapics: [Option<IoApic>; acpi::MAX_IOAPICS],
    entries: [IoApicEntry; acpi::MAX_IOAPICS],
    pins: [u16; acpi::MAX_IOAPICS],
    count: usize,
    madt: MadtInfo,
    dest: u8,
    routed: u8,
    /// GSIs already carrying a route — no second source may claim one.
    gsis: [u32; 4],
    gsi_count: usize,
    irq0_gsi: u32,
    kbd_gsi: u32,
}

impl Router {
    fn route(&mut self, irq: u8, vector: u8, bit: u8) -> Option<IsaRoute> {
        let route = isa_route(&self.madt, irq);
        self.claim(vector, bit, route)
    }

    /// Program `route` for source `bit` unless its GSI is already routed.
    fn claim(&mut self, vector: u8, bit: u8, route: IsaRoute) -> Option<IsaRoute> {
        if self.gsis[..self.gsi_count].contains(&route.gsi) {
            return None;
        }
        let slot = self.gsis.get_mut(self.gsi_count)?;
        let (i, pin) = locate(
            &self.entries[..self.count],
            &self.pins[..self.count],
            route.gsi,
        )?;
        let io = self.ioapics[i]?;
        if !io.write_entry(pin, device_entry(route, vector, self.dest)) {
            return None;
        }
        *slot = route.gsi;
        self.gsi_count += 1;
        self.routed |= bit;
        Some(route)
    }

    fn mask_everything(&self) {
        for io in self.ioapics[..self.count].iter().flatten() {
            for pin in 0..io.pins() {
                if let Ok(p) = u8::try_from(pin) {
                    let _ = io.mask_pin(p);
                }
            }
        }
    }
}

static ROUTER: SpinMutex<Option<Router>> = SpinMutex::new(None);
/// Whether device IRQs are IOAPIC-routed (set after a successful switch).
static ACTIVE: AtomicBool = AtomicBool::new(false);
/// Whether the PIT was observed ticking through the IOAPIC after the switch.
static PIT_LIVE: AtomicBool = AtomicBool::new(false);
/// Keyboard IRQs serviced since the switch (bumped by the vector-33 handler).
static KBD_IRQS: AtomicU32 = AtomicU32::new(0);
/// Whether the first-keystroke evidence line has been printed.
static KBD_REPORTED: AtomicBool = AtomicBool::new(false);

/// Whether device IRQs are routed through the IOAPIC.
#[must_use]
pub fn active() -> bool {
    ACTIVE.load(Ordering::Acquire)
}

fn fail(why: &str) {
    hal::serial::write_str("[ioapic] ");
    hal::serial::write_str(why);
    hal::serial::print_line("; device IRQs stay on the 8259 virtual wire");
}

/// Reopen the 8259 lines `interrupts::init_timer` opened (rollback).
fn reopen_pic() {
    for irq in [IRQ_PIT, IRQ_KBD, 2, IRQ_MOUSE] {
        hal::pic::unmask_irq(irq);
    }
}

/// Discover the IOAPICs and move the PIT, keyboard and mouse onto them.
///
/// **BSP only, once, interrupts disabled**, after `interrupts::init_timer`
/// (handlers registered, PIT programmed, 8259 lines open) and
/// `hal::apic::enable_bsp` (a LAPIC access path — the new EOI target), before
/// `init_lapic_timer` (which then calibrates against the IOAPIC-routed PIT) and
/// before any AP is released. On failure the 8259 virtual wire is untouched
/// (or restored) and a reason is printed; [`active`] reports the outcome.
pub fn init() {
    let Some(rsdp) = hal::acpi::rsdp_phys() else {
        fail("no RSDP from the bootloader");
        return;
    };
    let mut root_buf = alloc::vec![0u8; ROOT_BUF_LEN];
    let mut madt_buf = alloc::vec![0u8; MADT_BUF_LEN];
    let madt = match acpi::discover_madt(rsdp, hal::acpi::read_phys, &mut root_buf, &mut madt_buf) {
        Ok(m) => m,
        Err(_) => {
            fail("ACPI MADT walk failed");
            return;
        }
    };
    drop(root_buf);
    drop(madt_buf);
    if madt.ioapic_count == 0 {
        fail("MADT lists no IOAPIC");
        return;
    }

    // The BSP's APIC ID: physical-mode IOAPIC destinations are 8 bits.
    let Ok(dest) = u8::try_from(hal::apic::cpuid_apic_id()) else {
        fail("BSP APIC ID does not fit an IOAPIC destination");
        return;
    };

    let mut r = Router {
        ioapics: [None; acpi::MAX_IOAPICS],
        entries: madt.ioapics,
        pins: [0; acpi::MAX_IOAPICS],
        count: usize::from(madt.ioapic_count),
        madt,
        dest,
        routed: 0,
        gsis: [0; 4],
        gsi_count: 0,
        irq0_gsi: 0,
        kbd_gsi: 0,
    };
    for i in 0..r.count {
        match IoApic::map(r.entries[i].address) {
            Ok(io) => {
                r.pins[i] = io.pins();
                r.ioapics[i] = Some(io);
            }
            Err(_) => {
                fail("an IOAPIC window could not be mapped");
                return;
            }
        }
    }
    // Every ISA IRQ we need must have a pin before anything is switched.
    for irq in [IRQ_PIT, IRQ_KBD, IRQ_MOUSE] {
        let gsi = isa_route(&r.madt, irq).gsi;
        if locate(&r.entries[..r.count], &r.pins[..r.count], gsi).is_none() {
            fail("an ISA IRQ's GSI is served by no IOAPIC");
            return;
        }
    }

    // ── The switch (IF = 0 on the BSP; no AP is running) ────────────────────
    // Park every pin, retire the 8259 and the virtual wire, then open exactly
    // the routes we own. No interrupt can be taken in between, so no IRQ is
    // ever deliverable on two paths at once.
    r.mask_everything();
    hal::pic::mask_all();
    let _ = hal::apic::mask_lint0();
    let pit = r.route(IRQ_PIT, hal::pic::PIC1_OFFSET, SRC_PIT);
    let kbd = r.route(IRQ_KBD, hal::keyboard::VECTOR_KEYBOARD, SRC_KBD);
    let mouse = r.route(IRQ_MOUSE, hal::mouse::VECTOR_MOUSE, SRC_MOUSE);
    let (Some(pit), Some(kbd), Some(_)) = (pit, kbd, mouse) else {
        rollback(&r);
        fail("programming a redirection entry failed");
        return;
    };
    r.irq0_gsi = pit.gsi;
    r.kbd_gsi = kbd.gsi;
    // An edge lost in the switch window would leave the i8042 holding a byte
    // and never raising IRQ1/IRQ12 again: drain it.
    let _ = hal::keyboard::drain_stale_output();

    // Prove the PIT now arrives through the IOAPIC (the 8259 cannot deliver it).
    let start = hal::pit::ticks();
    hal::cpu::enable_interrupts();
    let tsc0 = hal::cpu::rdtsc();
    while hal::pit::ticks().wrapping_sub(start) < PIT_LIVE_TICKS
        && hal::cpu::rdtsc().wrapping_sub(tsc0) < PIT_LIVE_TSC_LIMIT
    {
        core::hint::spin_loop();
    }
    hal::cpu::disable_interrupts();
    if hal::pit::ticks().wrapping_sub(start) < PIT_LIVE_TICKS {
        rollback(&r);
        fail("PIT did not tick through the IOAPIC");
        return;
    }
    PIT_LIVE.store(true, Ordering::Relaxed);
    *ROUTER.lock() = Some(r);
    ACTIVE.store(true, Ordering::Release);
}

/// Undo the switch: mask every IOAPIC pin, LINT0 back to ExtINT, reopen the 8259.
fn rollback(r: &Router) {
    r.mask_everything();
    let _ = hal::apic::lint0_extint();
    reopen_pic();
}

/// Route the NIC's legacy INTx line (its PCI interrupt-line register value)
/// to `vector` on the BSP, under [`pci_legacy_route`]'s rule: only a line an
/// ISA override declares level-triggered, and never onto a GSI another source
/// already holds; otherwise the NIC stays polled (the idle loop drains frames
/// either way).
///
/// This relies on the firmware's legacy PIRQ steering also driving the IOAPIC
/// pin with the same number — true on QEMU (ICH9's PIRQ router feeds the GSI
/// array that fronts both the 8259 and the IOAPIC). The general answer is the
/// ACPI `_PRT` (AML), which this kernel does not interpret; see hal-tcb
/// invariant 17. Returns whether the line was routed.
#[must_use]
pub fn route_nic(irq: u8, vector: u8) -> bool {
    if !active() || irq >= 16 {
        return false;
    }
    let mut guard = ROUTER.lock();
    let Some(r) = guard.as_mut() else {
        return false;
    };
    let Some(route) = pci_legacy_route(&r.madt, irq, &r.gsis[..r.gsi_count]) else {
        return false;
    };
    r.claim(vector, SRC_NIC, route).is_some()
}

/// Count one keyboard IRQ (called by the vector-33 handler).
pub fn note_kbd_irq() {
    KBD_IRQS.fetch_add(1, Ordering::Relaxed);
}

/// Whether the 8259 and the BSP's LINT0 read back fully masked right now.
fn legacy_path_closed() -> bool {
    hal::pic::masks() == (0xFF, 0xFF) && hal::apic::lint0_masked() == Some(true)
}

/// Print the routing summary (after `interrupts::init_nic_irq`). Values are
/// read back from hardware where hardware holds them (8259 IMRs, LINT0).
///
/// ```text
/// [ioapic] madt: ioapics=1 overrides=5 gsi-base=0 pins=24 pic=masked lint0=masked routed=pit,kbd,mouse,nic irq0-gsi=2 dest=apic0 pit-live=yes ok
/// ```
pub fn report() {
    let guard = ROUTER.lock();
    let Some(r) = guard.as_ref() else {
        hal::serial::print_line("[ioapic] inactive; device IRQs on the 8259 virtual wire");
        return;
    };
    let (m, s) = hal::pic::masks();
    let pic_masked = (m, s) == (0xFF, 0xFF);
    let lint0 = hal::apic::lint0_masked() == Some(true);
    let pit_live = PIT_LIVE.load(Ordering::Relaxed);
    let w = hal::serial::write_str;
    w("[ioapic] madt: ioapics=");
    hal::serial::write_dec(r.count as u64);
    w(" overrides=");
    hal::serial::write_dec(u64::from(r.madt.override_count));
    w(" gsi-base=");
    hal::serial::write_dec(u64::from(r.entries[0].gsi_base));
    w(" pins=");
    hal::serial::write_dec(u64::from(r.pins[0]));
    w(if pic_masked {
        " pic=masked"
    } else {
        " pic=OPEN"
    });
    w(if lint0 {
        " lint0=masked"
    } else {
        " lint0=OPEN"
    });
    w(" routed=");
    let mut first = true;
    for (bit, name) in [
        (SRC_PIT, "pit"),
        (SRC_KBD, "kbd"),
        (SRC_MOUSE, "mouse"),
        (SRC_NIC, "nic"),
    ] {
        if r.routed & bit != 0 {
            if !first {
                w(",");
            }
            w(name);
            first = false;
        }
    }
    w(" irq0-gsi=");
    hal::serial::write_dec(u64::from(r.irq0_gsi));
    w(" dest=apic");
    hal::serial::write_dec(u64::from(r.dest));
    w(if pit_live {
        " pit-live=yes"
    } else {
        " pit-live=no"
    });
    let all = pic_masked && lint0 && pit_live && r.routed & (SRC_PIT | SRC_KBD | SRC_MOUSE) == 7;
    hal::serial::print_line(if all { " ok" } else { " FAILED" });
}

/// Called by the idle loop for every scancode it drains: the first time, print
/// the evidence that keystrokes arrive through the IOAPIC — the keyboard
/// handler has run while the 8259 and LINT0 read back fully masked, so the
/// only path that can have delivered vector 33 is the IOAPIC pin.
///
/// ```text
/// [ioapic] kbd: irq1 -> gsi1 vector=33 irqs>=1 pic=masked lint0=masked via=ioapic ok
/// ```
pub fn note_first_scancode() {
    if !active() || KBD_REPORTED.swap(true, Ordering::Relaxed) {
        return;
    }
    let irqs = KBD_IRQS.load(Ordering::Relaxed);
    let gsi = ROUTER.lock().as_ref().map_or(0, |r| r.kbd_gsi);
    let closed = legacy_path_closed();
    let w = hal::serial::write_str;
    w("[ioapic] kbd: irq1 -> gsi");
    hal::serial::write_dec(u64::from(gsi));
    w(" vector=");
    hal::serial::write_dec(u64::from(hal::keyboard::VECTOR_KEYBOARD));
    w(if irqs >= 1 { " irqs>=1" } else { " irqs=0" });
    w(if closed {
        " pic=masked lint0=masked via=ioapic"
    } else {
        " legacy-path=OPEN"
    });
    hal::serial::print_line(if irqs >= 1 && closed {
        " ok"
    } else {
        " FAILED"
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acpi::tests::QEMU_Q35_MADT;

    fn qemu() -> MadtInfo {
        acpi::parse_madt(QEMU_Q35_MADT).expect("QEMU MADT")
    }

    #[test]
    fn qemu_isa_routes() {
        let m = qemu();
        assert_eq!(
            isa_route(&m, IRQ_PIT),
            IsaRoute {
                gsi: 2,
                active_low: false,
                level: false
            }
        );
        assert_eq!(
            isa_route(&m, IRQ_KBD),
            IsaRoute {
                gsi: 1,
                active_low: false,
                level: false
            }
        );
        assert_eq!(
            isa_route(&m, IRQ_MOUSE),
            IsaRoute {
                gsi: 12,
                active_low: false,
                level: false
            }
        );
        // The e1000's usual legacy line: level, active high per the override.
        assert_eq!(
            isa_route(&m, 11),
            IsaRoute {
                gsi: 11,
                active_low: false,
                level: true
            }
        );
    }

    #[test]
    fn locate_respects_gsi_base_and_pin_count() {
        let a = IoApicEntry {
            id: 0,
            address: 0xFEC0_0000,
            gsi_base: 0,
        };
        let b = IoApicEntry {
            id: 1,
            address: 0xFEC0_1000,
            gsi_base: 24,
        };
        let ios = [a, b];
        let pins = [24u16, 16];
        assert_eq!(locate(&ios, &pins, 2), Some((0, 2)));
        assert_eq!(locate(&ios, &pins, 23), Some((0, 23)));
        assert_eq!(locate(&ios, &pins, 24), Some((1, 0)));
        assert_eq!(locate(&ios, &pins, 39), Some((1, 15)));
        assert_eq!(locate(&ios, &pins, 40), None);
        assert_eq!(locate(&ios[..1], &pins[..1], 30), None);
    }

    #[test]
    fn device_entry_is_fixed_physical_unmasked() {
        let e = device_entry(
            IsaRoute {
                gsi: 11,
                active_low: true,
                level: true,
            },
            0x2B,
            0,
        );
        assert_eq!(e.delivery, DeliveryMode::Fixed);
        assert!(!e.masked && e.active_low && e.level && e.is_programmable());
        assert_eq!(e.to_raw(), 0x0000_0000_0000_A02B);
    }

    #[test]
    fn nic_lines_need_a_level_override_and_a_free_gsi() {
        let m = qemu();
        assert_eq!(
            pci_legacy_route(&m, 11, &[2, 1, 12]),
            Some(IsaRoute {
                gsi: 11,
                active_low: false,
                level: true
            })
        );
        // No override: ambiguous, stays polled (line 2 would hit the PIT's GSI).
        assert_eq!(pci_legacy_route(&m, 2, &[]), None);
        assert_eq!(pci_legacy_route(&m, 1, &[]), None);
        // The IRQ0 override is edge ("conforms"): not a PCI line.
        assert_eq!(pci_legacy_route(&m, 0, &[]), None);
        // A level override onto a GSI another source holds.
        assert_eq!(pci_legacy_route(&m, 10, &[10]), None);
        assert_eq!(pci_legacy_route(&m, 16, &[]), None);
    }

    #[test]
    fn non_isa_overrides_are_ignored() {
        let mut m = qemu();
        m.overrides[0].bus = 1;
        assert_eq!(isa_route(&m, IRQ_PIT).gsi, 0);
    }
}
