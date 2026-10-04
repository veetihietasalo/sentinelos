//! Intel 82540EM (QEMU `e1000`) gigabit NIC driver — part of the TCB.
//!
//! Brings up QEMU's emulated Intel e1000 (vendor `0x8086`, device `0x100E`):
//! finds it on the PCI bus ([`crate::pci`]), maps its MMIO register BAR
//! uncached ([`crate::mm::map_mmio`]), resets and configures the device, sets up
//! the receive (RX) and transmit (TX) descriptor rings in DMA-capable RAM
//! ([`crate::mm::DmaFrame`]), reads the burnt-in MAC address, enables TX/RX, and
//! arms the receive interrupt.
//!
//! All hardware access — the MMIO register reads/writes (volatile loads/stores
//! to the mapped BAR) and the descriptor-ring memory — is confined to this
//! module and documented in `kernel/docs/hal-tcb.md` (§6b). The public surface
//! is **safe**:
//!
//! - [`init`] — find + initialise the NIC; returns [`NicInfo`] (MAC + IRQ) or an
//!   [`InitError`] so the kernel can degrade gracefully when no NIC is present.
//! - [`mac`] — the six-byte MAC address (after `init`).
//! - [`send_frame`] — transmit one raw Ethernet frame (copies it into a TX
//!   buffer, advances the TX ring, polls for completion).
//! - [`poll_frame`] — pull one received frame into a caller buffer, or `None`.
//! - [`on_irq`] — the body of the NIC interrupt: ack the device's interrupt
//!   cause register and EOI the PIC. The kernel registers a one-line handler.
//! - [`IRQ`] — the PIC IRQ line the NIC is wired to (read from PCI at `init`).
//!
//! # Concurrency model
//!
//! Single-core at bring-up. `init` runs once with interrupts disabled. The ring
//! indices and the MMIO base live behind a [`crate::mm`]-style spinlock-free
//! design: the driver state is a single `static` guarded by a small spin mutex
//! ([`Nic`]), and `send_frame`/`poll_frame`/`on_irq` each take the lock briefly.
//! The e1000 maintains its own head/tail pointers in MMIO; we track the
//! software-side tail (TX) and head (RX) cursors.

use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use crate::mm::{self, DmaFrame, PhysAddr};

/// PCI vendor id of Intel.
pub const VENDOR_INTEL: u16 = 0x8086;
/// PCI device id of the 82540EM (QEMU's `e1000`).
pub const DEVICE_82540EM: u16 = 0x100E;

// ── e1000 MMIO register offsets (bytes from the BAR0 base) ─────────────────────

/// Device Control register.
const REG_CTRL: u32 = 0x0000;
/// Device Status register.
const REG_STATUS: u32 = 0x0008;
/// Interrupt Cause Read (reading it returns + clears pending causes).
const REG_ICR: u32 = 0x00C0;
/// Interrupt Mask Set/Read (writing 1s enables those interrupt causes).
const REG_IMS: u32 = 0x00D0;
/// Interrupt Mask Clear (writing 1s disables those causes).
const REG_IMC: u32 = 0x00D8;

/// Receive Control register.
const REG_RCTL: u32 = 0x0100;
/// Receive Descriptor Base Address Low.
const REG_RDBAL: u32 = 0x2800;
/// Receive Descriptor Base Address High.
const REG_RDBAH: u32 = 0x2804;
/// Receive Descriptor ring Length (bytes).
const REG_RDLEN: u32 = 0x2808;
/// Receive Descriptor Head.
const REG_RDH: u32 = 0x2810;
/// Receive Descriptor Tail.
const REG_RDT: u32 = 0x2818;

/// Transmit Control register.
const REG_TCTL: u32 = 0x0400;
/// Transmit IPG (inter-packet gap) register.
const REG_TIPG: u32 = 0x0410;
/// Transmit Descriptor Base Address Low.
const REG_TDBAL: u32 = 0x3800;
/// Transmit Descriptor Base Address High.
const REG_TDBAH: u32 = 0x3804;
/// Transmit Descriptor ring Length (bytes).
const REG_TDLEN: u32 = 0x3808;
/// Transmit Descriptor Head.
const REG_TDH: u32 = 0x3810;
/// Transmit Descriptor Tail.
const REG_TDT: u32 = 0x3818;

/// Receive-address registers (the burnt-in MAC): RAL0 / RAH0.
const REG_RAL0: u32 = 0x5400;
const REG_RAH0: u32 = 0x5404;

// ── Control / status bits ──────────────────────────────────────────────────────

/// CTRL.RST — device reset (self-clearing).
const CTRL_RST: u32 = 1 << 26;
/// CTRL.SLU — set link up.
const CTRL_SLU: u32 = 1 << 6;

/// RCTL.EN — receiver enable.
const RCTL_EN: u32 = 1 << 1;
/// RCTL.BAM — broadcast accept mode (receive broadcast frames, e.g. ARP).
const RCTL_BAM: u32 = 1 << 15;
/// RCTL.SECRC — strip the Ethernet CRC from received frames.
const RCTL_SECRC: u32 = 1 << 26;
/// RCTL buffer size 2048 bytes (BSIZE=00, BSEX=0).
const RCTL_BSIZE_2048: u32 = 0;
/// RCTL.SBP / UPE / MPE — promiscuous-ish; we set UPE+MPE so QEMU SLIRP frames
/// addressed to us (and multicast) are accepted even before exact-filter setup.
const RCTL_UPE: u32 = 1 << 3;
const RCTL_MPE: u32 = 1 << 4;

/// TCTL.EN — transmitter enable.
const TCTL_EN: u32 = 1 << 1;
/// TCTL.PSP — pad short packets.
const TCTL_PSP: u32 = 1 << 3;
/// TCTL collision-threshold field (bits 11:4), standard value 0x0F.
const TCTL_CT: u32 = 0x0F << 4;
/// TCTL collision-distance field (bits 21:12), standard value 0x40.
const TCTL_COLD: u32 = 0x40 << 12;

/// TX descriptor command: EOP (end of packet) | IFCS (insert FCS/CRC) | RS
/// (report status, so DD is written back on completion).
const TXD_CMD_EOP: u8 = 1 << 0;
const TXD_CMD_IFCS: u8 = 1 << 1;
const TXD_CMD_RS: u8 = 1 << 3;
/// TX descriptor status: DD (descriptor done) — set by the NIC on completion.
const TXD_STAT_DD: u8 = 1 << 0;

/// RX descriptor status: DD (descriptor done) — the NIC filled this buffer.
const RXD_STAT_DD: u8 = 1 << 0;
/// RX descriptor status: EOP (end of packet).
const RXD_STAT_EOP: u8 = 1 << 1;

/// ICR/IMS bit: RXT0 — receiver timer (a frame has arrived). The cause we mask
/// in so the NIC raises an interrupt on receive.
const INT_RXT0: u32 = 1 << 7;
/// ICR/IMS bit: RXDMT0 — RX descriptor minimum threshold hit.
const INT_RXDMT0: u32 = 1 << 4;

// ── Ring geometry ──────────────────────────────────────────────────────────────

/// Number of RX descriptors. 32 × 16 bytes = 512 bytes (fits in one frame, and
/// the ring length must be a multiple of 128 bytes — 512 satisfies that).
const RX_RING_LEN: usize = 32;
/// Number of TX descriptors (same sizing rationale as RX).
const TX_RING_LEN: usize = 32;
/// Per-packet DMA buffer size (matches RCTL BSIZE = 2048).
const PKT_BUF_SIZE: usize = 2048;

/// A legacy e1000 **receive** descriptor (16 bytes, `#[repr(C)]`).
#[repr(C)]
#[derive(Clone, Copy)]
struct RxDesc {
    /// Physical address of the packet buffer the NIC DMAs into.
    addr: u64,
    /// Length of the received frame (written by the NIC).
    length: u16,
    /// Packet checksum (unused here).
    checksum: u16,
    /// Status bits (DD/EOP/…), written by the NIC.
    status: u8,
    /// Receive errors (unused here).
    errors: u8,
    /// VLAN tag (unused here).
    special: u16,
}

/// A legacy e1000 **transmit** descriptor (16 bytes, `#[repr(C)]`).
#[repr(C)]
#[derive(Clone, Copy)]
struct TxDesc {
    /// Physical address of the buffer to transmit.
    addr: u64,
    /// Length of the frame to send.
    length: u16,
    /// Checksum offset (unused).
    cso: u8,
    /// Command bits (EOP/IFCS/RS).
    cmd: u8,
    /// Status bits (DD), written back by the NIC.
    status: u8,
    /// Checksum start (unused).
    css: u8,
    /// VLAN/special (unused).
    special: u16,
}

/// Why [`init`] could not bring up the NIC.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InitError {
    /// No matching e1000 device was found on the PCI bus.
    NotFound,
    /// BAR0 did not yield a usable MMIO base.
    NoMmio,
    /// The MMIO BAR could not be mapped into the kernel address space.
    MapFailed,
    /// A DMA frame (ring or packet buffer) could not be allocated.
    OutOfMemory,
}

/// What [`init`] set up, for the boot log: the MAC and the IRQ line.
#[derive(Clone, Copy, Debug)]
pub struct NicInfo {
    /// The NIC's six-byte MAC address.
    pub mac: [u8; 6],
    /// The legacy PIC IRQ line the NIC is wired to (from PCI config).
    pub irq: u8,
}

// ── MMIO accessors ─────────────────────────────────────────────────────────────

/// A handle to the e1000's memory-mapped register window (the mapped BAR0).
///
/// Carries the virtual base of the uncached MMIO mapping. All register access
/// goes through volatile 32-bit loads/stores so the compiler never elides or
/// reorders a device access.
#[derive(Clone, Copy)]
struct Mmio {
    base: u64,
}

impl Mmio {
    /// Read 32-bit register at `reg` (a byte offset from the BAR base).
    fn read(self, reg: u32) -> u32 {
        let ptr = (self.base + reg as u64) as *const u32;
        // SAFETY: `base` is the virtual base of the e1000's BAR0 MMIO window,
        // mapped uncached + writable by `mm::map_mmio` over the device's whole
        // 128 KiB register space. Every `reg` used in this module is a documented
        // e1000 register offset well within that window, and is 4-byte-aligned
        // (all constants are multiples of 4), so the load is in-bounds and
        // aligned. A volatile read returns the live device register value and has
        // no memory-safety-relevant side effect beyond the device's own
        // read-to-clear semantics (e.g. ICR), which the driver accounts for.
        unsafe { ptr::read_volatile(ptr) }
    }

    /// Write 32-bit `value` to register at `reg`.
    fn write(self, reg: u32, value: u32) {
        let ptr = (self.base + reg as u64) as *mut u32;
        // SAFETY: as in `read`, `base + reg` is a 4-byte-aligned address inside
        // the mapped, writable BAR0 window, and `reg` is a documented e1000
        // register offset. A volatile store writes the device register; its only
        // effect is on the NIC (configuration / ring tail / interrupt mask) and
        // it cannot alias or corrupt Rust-managed memory.
        unsafe { ptr::write_volatile(ptr, value) }
    }
}

// ── Driver state ───────────────────────────────────────────────────────────────

/// The full driver state for the single e1000 instance.
struct Nic {
    mmio: Mmio,
    /// DMA frame holding the RX descriptor ring.
    rx_ring: DmaFrame,
    /// DMA frame holding the TX descriptor ring.
    tx_ring: DmaFrame,
    /// Per-descriptor RX packet buffers (one DmaFrame holds two 2048-byte bufs).
    rx_bufs: [DmaFrame; RX_RING_LEN],
    /// Per-descriptor TX packet buffers.
    tx_bufs: [DmaFrame; TX_RING_LEN],
    /// Software RX cursor: the next descriptor we expect the NIC to fill.
    rx_cur: usize,
    /// Software TX cursor: the next descriptor we will hand to the NIC.
    tx_cur: usize,
    /// The MAC address read at init.
    mac: [u8; 6],
}

/// A tiny spin mutex local to this module (the `mm::sync` one is private). At
/// bring-up the kernel is single-core, so it never actually spins.
struct NicLock {
    locked: AtomicBool,
    inner: core::cell::UnsafeCell<Option<Nic>>,
}

// SAFETY: access to the inner `Option<Nic>` is serialised by the `locked`
// atomic (only one critical section runs at a time), and the kernel is
// single-core at bring-up, so the inner value is never touched concurrently —
// exactly the `Sync` invariant. The `Nic`'s raw addresses (MMIO base, DMA
// frames) are valid for the program's lifetime.
unsafe impl Sync for NicLock {}

impl NicLock {
    const fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
            inner: core::cell::UnsafeCell::new(None),
        }
    }

    /// Run `f` with exclusive access to the driver state.
    ///
    /// Interrupts are masked on the calling core for the whole critical
    /// section (and restored to their prior state after): [`on_irq`] takes this
    /// same lock from the NIC's interrupt handler, so a NIC IRQ landing while
    /// the idle loop held the lock (`poll_frame`, `link_up`, …) would otherwise
    /// spin forever on its own core. Latent while the line was 8259-routed;
    /// exposed by the level-triggered IOAPIC route (SMP 3b-ii).
    fn with<R>(&self, f: impl FnOnce(&mut Option<Nic>) -> R) -> R {
        let restore = crate::cpu::interrupts_enabled();
        crate::cpu::disable_interrupts();
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        // SAFETY: we hold the lock (the compare-exchange above succeeded and no
        // other critical section can run until we release it below), so we have
        // exclusive access to the `UnsafeCell` interior. The reference does not
        // escape `f`.
        let result = f(unsafe { &mut *self.inner.get() });
        self.locked.store(false, Ordering::Release);
        if restore {
            crate::cpu::enable_interrupts();
        }
        result
    }
}

/// The single global e1000 driver instance.
static NIC: NicLock = NicLock::new();

/// Whether [`init`] has successfully brought the NIC up.
static READY: AtomicBool = AtomicBool::new(false);

/// The PIC IRQ line the NIC is wired to, recorded at init (default `0xFF` = none).
static NIC_IRQ: AtomicU8 = AtomicU8::new(0xFF);

/// Whether the NIC has been initialised and is ready for TX/RX.
#[must_use]
pub fn is_ready() -> bool {
    READY.load(Ordering::Acquire)
}

/// The PIC IRQ line the NIC raises its receive interrupt on (valid after `init`).
#[must_use]
pub fn irq() -> u8 {
    NIC_IRQ.load(Ordering::Relaxed)
}

/// Convenience accessor for the IRQ vector after the PIC remap.
pub const fn vector_for(irq_line: u8) -> u8 {
    crate::pic::PIC1_OFFSET + irq_line
}

/// The NIC's MAC address, or all-zero if `init` has not run / failed.
#[must_use]
pub fn mac() -> [u8; 6] {
    NIC.with(|slot| slot.as_ref().map_or([0u8; 6], |n| n.mac))
}

/// Read the burnt-in MAC address from the Receive-Address registers (RAL0/RAH0),
/// which the e1000 loads from EEPROM at reset.
fn read_mac(mmio: Mmio) -> [u8; 6] {
    let low = mmio.read(REG_RAL0);
    let high = mmio.read(REG_RAH0);
    [
        (low & 0xFF) as u8,
        ((low >> 8) & 0xFF) as u8,
        ((low >> 16) & 0xFF) as u8,
        ((low >> 24) & 0xFF) as u8,
        (high & 0xFF) as u8,
        ((high >> 8) & 0xFF) as u8,
    ]
}

/// Write one RX descriptor into the ring frame at index `i`.
fn write_rx_desc(ring: &DmaFrame, i: usize, desc: RxDesc) {
    let ptr = (ring.virt().as_u64() as *mut RxDesc).wrapping_add(i);
    // SAFETY: `ring` is a DMA frame (4 KiB, HHDM-mapped, exclusively owned by the
    // driver); `i < RX_RING_LEN` (32) and `RX_RING_LEN * size_of::<RxDesc>()` =
    // 512 bytes ≤ 4096, so the indexed descriptor is fully within the frame and
    // 16-byte-aligned (frame base is 4 KiB-aligned, descriptors are 16 bytes).
    // The write is unaliased: the NIC only reads/writes descriptors after the
    // tail is advanced, and we program the ring base before enabling RX.
    unsafe { ptr::write_volatile(ptr, desc) }
}

/// Read one RX descriptor from the ring frame at index `i`.
fn read_rx_desc(ring: &DmaFrame, i: usize) -> RxDesc {
    let ptr = (ring.virt().as_u64() as *const RxDesc).wrapping_add(i);
    // SAFETY: same bounds/alignment argument as `write_rx_desc`. A volatile read
    // observes the latest descriptor state the NIC wrote back (status/length).
    unsafe { ptr::read_volatile(ptr) }
}

/// Write one TX descriptor into the ring frame at index `i`.
fn write_tx_desc(ring: &DmaFrame, i: usize, desc: TxDesc) {
    let ptr = (ring.virt().as_u64() as *mut TxDesc).wrapping_add(i);
    // SAFETY: identical reasoning to `write_rx_desc` for the TX ring frame:
    // `i < TX_RING_LEN` (32), 32 × 16 = 512 ≤ 4096, 16-byte-aligned, unaliased
    // (we only advance the TX tail after writing the descriptor + its buffer).
    unsafe { ptr::write_volatile(ptr, desc) }
}

/// Read one TX descriptor from the ring frame at index `i`.
fn read_tx_desc(ring: &DmaFrame, i: usize) -> TxDesc {
    let ptr = (ring.virt().as_u64() as *const TxDesc).wrapping_add(i);
    // SAFETY: as `write_tx_desc`; reads back the NIC-written status (DD bit).
    unsafe { ptr::read_volatile(ptr) }
}

/// Copy `src` bytes into the DMA packet buffer `buf`, up to its capacity.
fn copy_into_buf(buf: &DmaFrame, src: &[u8]) -> usize {
    let n = src.len().min(PKT_BUF_SIZE);
    let dst = buf.virt().as_u64() as *mut u8;
    for (i, &b) in src.iter().take(n).enumerate() {
        // SAFETY: `buf` is a 4 KiB DMA frame; `i < n ≤ PKT_BUF_SIZE` (2048) ≤
        // 4096, so `dst.add(i)` is within the frame, byte-aligned, writable, and
        // unaliased (the buffer is not handed to the NIC until after this copy).
        unsafe { ptr::write_volatile(dst.add(i), b) }
    }
    n
}

/// Copy `n` bytes out of the DMA packet buffer `buf` into `dst`.
fn copy_out_of_buf(buf: &DmaFrame, dst: &mut [u8], n: usize) -> usize {
    let n = n.min(dst.len()).min(PKT_BUF_SIZE);
    let src = buf.virt().as_u64() as *const u8;
    for (i, slot) in dst.iter_mut().take(n).enumerate() {
        // SAFETY: `buf` is a 4 KiB DMA frame the NIC just filled; `i < n ≤
        // PKT_BUF_SIZE` ≤ 4096, so `src.add(i)` is within the frame and aligned;
        // the read happens after the descriptor reports DD (frame complete), so
        // the bytes are valid and not being concurrently written.
        *slot = unsafe { ptr::read_volatile(src.add(i)) };
    }
    n
}

/// Find, map, reset, and configure the e1000 NIC.
///
/// Call **once**, after `mm::init` (it needs the heap/frame allocator + HHDM)
/// and after `interrupts::init` + `pic::init` (so its IRQ can be unmasked).
/// Interrupts should still be disabled. On success the device is transmitting
/// and receiving, and its RX interrupt is armed; the caller should then register
/// a vector handler for [`irq`] and unmask that PIC line.
///
/// # Errors
///
/// Returns [`InitError`] if no e1000 is present (so the kernel can boot headless),
/// or if the MMIO BAR / DMA rings could not be set up.
pub fn init() -> Result<NicInfo, InitError> {
    // 1. Locate the e1000 on the PCI bus (it sits on bus 0 in QEMU q35).
    let dev = crate::pci::scan_for(VENDOR_INTEL, DEVICE_82540EM, 1).ok_or(InitError::NotFound)?;

    // 2. Enable bus mastering + memory space so it can DMA and we can MMIO it.
    dev.enable_bus_master();

    // 3. Map BAR0 (the 128 KiB register window) uncached.
    let mmio_phys = dev.mmio_base();
    if mmio_phys == 0 {
        return Err(InitError::NoMmio);
    }
    let virt =
        mm::map_mmio(PhysAddr::new(mmio_phys), 128 * 1024).map_err(|_| InitError::MapFailed)?;
    let mmio = Mmio {
        base: virt.as_u64(),
    };

    // 4. Reset the device, then re-set link up. Reset is self-clearing.
    mmio.write(REG_CTRL, mmio.read(REG_CTRL) | CTRL_RST);
    // Spin briefly for the reset to complete (RST bit clears). Bounded so a
    // wedged device cannot hang boot.
    for _ in 0..1_000_000 {
        if mmio.read(REG_CTRL) & CTRL_RST == 0 {
            break;
        }
        core::hint::spin_loop();
    }
    // Set link up + clear any pending interrupts.
    mmio.write(REG_CTRL, mmio.read(REG_CTRL) | CTRL_SLU);
    mmio.write(REG_IMC, 0xFFFF_FFFF); // mask all interrupts during setup
    let _ = mmio.read(REG_ICR); // clear pending causes

    // 5. Read the MAC address (RAL0/RAH0, loaded from EEPROM at reset).
    let mac = read_mac(mmio);

    // 6. Allocate the RX ring + buffers, then point the NIC at them.
    let rx_ring = DmaFrame::alloc().ok_or(InitError::OutOfMemory)?;
    let mut rx_bufs = [rx_ring; RX_RING_LEN]; // placeholder; overwritten below
    for buf in rx_bufs.iter_mut() {
        *buf = DmaFrame::alloc().ok_or(InitError::OutOfMemory)?;
    }
    for (i, buf) in rx_bufs.iter().enumerate() {
        write_rx_desc(
            &rx_ring,
            i,
            RxDesc {
                addr: buf.phys().as_u64(),
                length: 0,
                checksum: 0,
                status: 0,
                errors: 0,
                special: 0,
            },
        );
    }
    let rx_base = rx_ring.phys().as_u64();
    mmio.write(REG_RDBAL, (rx_base & 0xFFFF_FFFF) as u32);
    mmio.write(REG_RDBAH, (rx_base >> 32) as u32);
    mmio.write(REG_RDLEN, (RX_RING_LEN * 16) as u32);
    mmio.write(REG_RDH, 0);
    mmio.write(REG_RDT, (RX_RING_LEN - 1) as u32); // hand all but one to the NIC

    // 7. Allocate the TX ring + buffers, then point the NIC at them.
    let tx_ring = DmaFrame::alloc().ok_or(InitError::OutOfMemory)?;
    let mut tx_bufs = [tx_ring; TX_RING_LEN]; // placeholder; overwritten below
    for buf in tx_bufs.iter_mut() {
        *buf = DmaFrame::alloc().ok_or(InitError::OutOfMemory)?;
    }
    for i in 0..TX_RING_LEN {
        write_tx_desc(
            &tx_ring,
            i,
            TxDesc {
                addr: 0,
                length: 0,
                cso: 0,
                cmd: 0,
                status: TXD_STAT_DD, // mark free so send_frame can use slot 0..
                css: 0,
                special: 0,
            },
        );
    }
    let tx_base = tx_ring.phys().as_u64();
    mmio.write(REG_TDBAL, (tx_base & 0xFFFF_FFFF) as u32);
    mmio.write(REG_TDBAH, (tx_base >> 32) as u32);
    mmio.write(REG_TDLEN, (TX_RING_LEN * 16) as u32);
    mmio.write(REG_TDH, 0);
    mmio.write(REG_TDT, 0);

    // 8. Configure TX: enable, pad short packets, standard CT/COLD; IPG default.
    mmio.write(REG_TCTL, TCTL_EN | TCTL_PSP | TCTL_CT | TCTL_COLD);
    mmio.write(REG_TIPG, 0x0060_200A); // standard IEEE 802.3 IPG for the e1000

    // 9. Configure RX: enable, broadcast accept (ARP!), strip CRC, 2048-byte
    //    buffers, plus unicast/multicast promiscuous so SLIRP frames reach us.
    mmio.write(
        REG_RCTL,
        RCTL_EN | RCTL_BAM | RCTL_SECRC | RCTL_BSIZE_2048 | RCTL_UPE | RCTL_MPE,
    );

    // 10. Arm the receive interrupt (RXT0 + RXDMT0). The PIC line is unmasked by
    //     the kernel after it registers the vector handler.
    mmio.write(REG_IMS, INT_RXT0 | INT_RXDMT0);
    let _ = mmio.read(REG_ICR); // clear any cause set during setup

    let irq_line = dev.interrupt_line();
    NIC_IRQ.store(irq_line, Ordering::Relaxed);

    // Stash the fully-built driver state.
    NIC.with(|slot| {
        *slot = Some(Nic {
            mmio,
            rx_ring,
            tx_ring,
            rx_bufs,
            tx_bufs,
            rx_cur: 0,
            tx_cur: 0,
            mac,
        });
    });
    READY.store(true, Ordering::Release);

    Ok(NicInfo { mac, irq: irq_line })
}

/// Transmit one raw Ethernet frame (already including dst/src MAC + ethertype,
/// **without** the FCS — the NIC inserts the CRC). Returns `true` if the frame
/// was queued and the descriptor reported completion, `false` if the NIC is not
/// ready or the TX ring slot never completed.
///
/// Copies `frame` into the current TX buffer, fills the descriptor, advances the
/// TX tail, and polls (bounded) for the descriptor-done (DD) writeback.
pub fn send_frame(frame: &[u8]) -> bool {
    if !is_ready() {
        return false;
    }
    NIC.with(|slot| {
        let Some(nic) = slot.as_mut() else {
            return false;
        };
        let i = nic.tx_cur;
        // Copy the frame into this slot's DMA buffer.
        let len = copy_into_buf(&nic.tx_bufs[i], frame);
        // Build the descriptor: EOP + insert-FCS + report-status.
        write_tx_desc(
            &nic.tx_ring,
            i,
            TxDesc {
                addr: nic.tx_bufs[i].phys().as_u64(),
                length: len as u16,
                cso: 0,
                cmd: TXD_CMD_EOP | TXD_CMD_IFCS | TXD_CMD_RS,
                status: 0,
                css: 0,
                special: 0,
            },
        );
        // Advance the software cursor and the hardware tail.
        let next = (i + 1) % TX_RING_LEN;
        nic.tx_cur = next;
        nic.mmio.write(REG_TDT, next as u32);

        // Poll (bounded) for the NIC to set DD on the descriptor we just queued.
        for _ in 0..1_000_000 {
            let d = read_tx_desc(&nic.tx_ring, i);
            if d.status & TXD_STAT_DD != 0 {
                return true;
            }
            core::hint::spin_loop();
        }
        false
    })
}

/// Pull one received Ethernet frame into `out`, returning its length, or `None`
/// if no frame is currently available.
///
/// Walks the RX ring from the software cursor: if the current descriptor has DD
/// set (the NIC filled it), copies the frame out, recycles the descriptor (clear
/// status, re-hand it to the NIC by advancing the RX tail), and advances the
/// cursor. `out` should be at least 1518 bytes (a full Ethernet frame).
pub fn poll_frame(out: &mut [u8]) -> Option<usize> {
    if !is_ready() {
        return None;
    }
    NIC.with(|slot| {
        let nic = slot.as_mut()?;
        let i = nic.rx_cur;
        let desc = read_rx_desc(&nic.rx_ring, i);
        if desc.status & RXD_STAT_DD == 0 {
            return None; // NIC has not filled this descriptor yet.
        }
        // We only handle single-descriptor frames (EOP set); QEMU never splits a
        // ≤2048-byte frame across descriptors, so this always holds here.
        let n = if desc.status & RXD_STAT_EOP != 0 {
            copy_out_of_buf(&nic.rx_bufs[i], out, desc.length as usize)
        } else {
            0
        };

        // Recycle this descriptor: clear its status and re-hand it to the NIC.
        write_rx_desc(
            &nic.rx_ring,
            i,
            RxDesc {
                addr: nic.rx_bufs[i].phys().as_u64(),
                length: 0,
                checksum: 0,
                status: 0,
                errors: 0,
                special: 0,
            },
        );
        // The tail must point at the last descriptor we have returned to the NIC.
        nic.mmio.write(REG_RDT, i as u32);
        nic.rx_cur = (i + 1) % RX_RING_LEN;

        if n == 0 {
            None
        } else {
            Some(n)
        }
    })
}

/// The body of the NIC receive interrupt (vector = [`vector_for`]`(`[`irq`]`())`).
///
/// Reads (and thereby clears) the device's Interrupt Cause Register to ack the
/// interrupt, then signals End-Of-Interrupt to the PIC. The actual received
/// frames are drained by the kernel's idle loop via [`poll_frame`] — the handler
/// stays tiny (ack + EOI), keeping the privileged work in the TCB. The kernel
/// registers a one-line safe `fn(&InterruptFrame)` for the NIC vector.
pub fn on_irq() {
    let line = NIC_IRQ.load(Ordering::Relaxed);
    if is_ready() {
        // Ack the device by reading ICR (read-to-clear).
        NIC.with(|slot| {
            if let Some(nic) = slot.as_ref() {
                let _ = nic.mmio.read(REG_ICR);
            }
        });
    }
    // EOI whichever controller delivered the NIC IRQ (LAPIC once IOAPIC-routed).
    if line != 0xFF {
        crate::ioapic::device_eoi(vector_for(line));
    }
}

/// Read the device STATUS register's link-up bit (bit 1) — for diagnostics.
#[must_use]
pub fn link_up() -> bool {
    NIC.with(|slot| {
        slot.as_ref()
            .map(|n| n.mmio.read(REG_STATUS) & (1 << 1) != 0)
            .unwrap_or(false)
    })
}
