//! Legacy ATA (IDE) **PIO** disk driver for the primary bus — part of the TCB.
//!
//! This module drives a legacy parallel-ATA hard disk on the **primary** IDE
//! channel using *programmed I/O* (PIO): the CPU moves every 512-byte sector
//! through the 16-bit data register one word at a time, polling the status
//! register (BSY/DRQ) for handshaking. No DMA and no interrupts are used, which
//! keeps the driver tiny and self-contained — exactly what the on-disk
//! filesystem persistence layer (`kernel::fs`) needs to survive a reboot.
//!
//! The primary channel's I/O ports are the standard PC legacy assignments:
//!
//! - **Command block** `0x1F0..=0x1F7` — data, error/features, sector count,
//!   the three LBA bytes, the drive/head select, and the status/command register.
//! - **Control block** `0x3F6` — the Device Control / Alternate Status register
//!   (we read the alternate status to poll without the side effect of clearing a
//!   pending interrupt, and to insert the mandatory 400 ns settle delay).
//!
//! Addressing is **28-bit LBA** (LBA28): up to `2^28` sectors (128 GiB), which is
//! far more than the small persistence image needs.
//!
//! All hardware access is funnelled through four private port primitives —
//! `inb`/`outb` (8-bit) and `inw`/`outw` (16-bit) — each documented with a
//! `# Safety` rustdoc section; see `kernel/docs/hal-tcb.md` (§7). The public
//! surface is **safe**:
//!
//! - [`identify`] — probe the primary master; returns [`DiskInfo`] (the sector
//!   count reported by IDENTIFY) or an [`AtaError`] so the kernel can degrade
//!   gracefully when no disk is attached.
//! - [`read_sectors`] — read `count` contiguous 512-byte sectors starting at
//!   `lba` into a caller buffer.
//! - [`write_sectors`] — write `count` contiguous 512-byte sectors starting at
//!   `lba` from a caller buffer (followed by a cache FLUSH so data hits media).
//!
//! # Concurrency model
//!
//! Identical to the other port-I/O drivers (`serial`, `pci`, `keyboard`):
//! single-core at bring-up, all access serialised by the single-threaded kernel
//! path that calls it (`kernel::fs` load/save). The command/status handshake is
//! a strict request→poll→transfer sequence that must not be interleaved with
//! another command, which the single-threaded caller guarantees.

use core::arch::asm;

/// Bytes per ATA sector (the universal 512-byte block size).
pub const SECTOR_SIZE: usize = 512;

/// 16-bit data words per sector (`512 / 2`).
const WORDS_PER_SECTOR: usize = SECTOR_SIZE / 2;

// ── Primary-channel command-block ports (`0x1F0..=0x1F7`) ───────────────────────

/// Data register (16-bit) — the PIO transfer window for sector words.
const REG_DATA: u16 = 0x1F0;
/// Sector count — number of sectors for the next read/write command.
const REG_SECCOUNT: u16 = 0x1F2;
/// LBA low byte (bits 0..7).
const REG_LBA_LO: u16 = 0x1F3;
/// LBA mid byte (bits 8..15).
const REG_LBA_MID: u16 = 0x1F4;
/// LBA high byte (bits 16..23).
const REG_LBA_HI: u16 = 0x1F5;
/// Drive / head select — also carries LBA bits 24..27 and the LBA-mode bit.
const REG_DRIVE: u16 = 0x1F6;
/// Status register (read) / Command register (write).
const REG_STATUS: u16 = 0x1F7;

/// Control-block Alternate Status / Device Control register (`0x3F6`).
const REG_ALT_STATUS: u16 = 0x3F6;

// ── Status-register bits (`0x1F7` / `0x3F6`) ────────────────────────────────────

/// BSY — the drive is busy; no other status bits are meaningful while set.
const STATUS_BSY: u8 = 1 << 7;
/// DRDY — the drive is ready to accept a command.
#[allow(dead_code)]
const STATUS_DRDY: u8 = 1 << 6;
/// DRQ — the drive wants to transfer a word of PIO data.
const STATUS_DRQ: u8 = 1 << 3;
/// ERR — the previous command ended in an error (check the error register).
const STATUS_ERR: u8 = 1 << 0;
/// DF — device fault.
const STATUS_DF: u8 = 1 << 5;

// ── Commands ────────────────────────────────────────────────────────────────────

/// `IDENTIFY DEVICE` — return a 256-word block describing the drive.
const CMD_IDENTIFY: u8 = 0xEC;
/// `READ SECTORS` (PIO, LBA28) — read `seccount` sectors via the data register.
const CMD_READ_PIO: u8 = 0x20;
/// `WRITE SECTORS` (PIO, LBA28) — write `seccount` sectors via the data register.
const CMD_WRITE_PIO: u8 = 0x30;
/// `FLUSH CACHE` — force any write-cached sectors out to the media.
const CMD_FLUSH: u8 = 0xE7;

/// Drive-select base for the **primary master** in LBA mode: bit 6 selects LBA
/// addressing, bit 5 and bit 7 are obsolete "always 1" bits, and the low nibble
/// holds LBA bits 24..27. The master is drive 0 (bit 4 clear).
const DRIVE_LBA_MASTER: u8 = 0xE0;

/// A bounded poll budget so a wedged/absent controller can never hang the kernel.
/// At PIO timescales 100 000 status reads is comfortably more than one command
/// ever needs, yet completes near-instantly under emulation.
const POLL_LIMIT: u32 = 100_000;

/// Why an ATA operation failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AtaError {
    /// No drive responded on the primary channel (status read back all-ones, or
    /// IDENTIFY never asserted DRQ) — boot headless / fall back to in-memory.
    NoDevice,
    /// The drive reported ERR/DF in its status register during the command.
    DeviceError,
    /// The drive did not clear BSY / assert the expected bit within the poll
    /// budget (a stuck or missing controller).
    Timeout,
    /// The caller passed a buffer whose length is not an exact multiple of the
    /// sector size, or a sector count that does not match the buffer.
    BadBuffer,
    /// The requested LBA range exceeds the 28-bit LBA address space.
    OutOfRange,
}

/// What [`identify`] discovered about the primary-master disk.
#[derive(Clone, Copy, Debug)]
pub struct DiskInfo {
    /// Total addressable 512-byte sectors (from IDENTIFY words 60..61, the
    /// user-addressable LBA28 sector count).
    pub sectors: u32,
}

impl DiskInfo {
    /// Total capacity in bytes (`sectors * 512`), as a `u64` to avoid overflow.
    #[must_use]
    pub const fn capacity_bytes(self) -> u64 {
        self.sectors as u64 * SECTOR_SIZE as u64
    }
}

/// Read one byte from the given x86 I/O port.
///
/// # Safety
///
/// Port I/O is device-dependent. The caller must ensure `port` names a register
/// that is safe to read with no memory-safety-relevant side effects. All call
/// sites read only primary-channel ATA status/error registers (`0x1F1`, `0x1F4`,
/// `0x1F5`, `0x1F7`, `0x3F6`), which are pure device reads.
#[inline]
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: `in al, dx` reads one byte from the I/O port in `dx` into `al`. The
    // contract that `port` is a valid, read-safe ATA register is delegated to
    // this function's `# Safety` section and upheld by every caller (only ATA
    // status/error/LBA ports). The instruction touches no memory (`nomem`) and no
    // stack (`nostack`).
    unsafe {
        asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack));
    }
    value
}

/// Write one byte to the given x86 I/O port.
///
/// # Safety
///
/// The caller must ensure `port` names a register that is safe to write with
/// `value`. All call sites write only primary-channel ATA command-block
/// registers (`0x1F2..=0x1F7`) with documented command/parameter bytes.
#[inline]
unsafe fn outb(port: u16, value: u8) {
    // SAFETY: `out dx, al` writes the byte in `al` to the I/O port in `dx`. The
    // contract that `port`/`value` are a valid, write-safe ATA register pair is
    // delegated to this function's `# Safety` section and upheld by every caller
    // (only ATA command-block registers with defined LBA/seccount/command bytes).
    // Device-only effect, `nomem`/`nostack`.
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack));
    }
}

/// Read one 16-bit word from the given x86 I/O port.
///
/// # Safety
///
/// The caller must ensure `port` names a 16-bit register safe to read. The only
/// call site reads the ATA data register (`0x1F0`) during a PIO read, and only
/// while the drive has asserted DRQ (it wants to hand us a word).
#[inline]
unsafe fn inw(port: u16) -> u16 {
    let value: u16;
    // SAFETY: `in ax, dx` reads a 16-bit word from the I/O port in `dx` into
    // `ax`. The contract that `port` is the read-safe ATA data port is delegated
    // to this `# Safety` section and upheld by the sole caller (`read_sectors`,
    // `0x1F0`, only after DRQ is set). Pure device read; `nomem`/`nostack`.
    unsafe {
        asm!("in ax, dx", out("ax") value, in("dx") port, options(nomem, nostack));
    }
    value
}

/// Write one 16-bit word to the given x86 I/O port.
///
/// # Safety
///
/// The caller must ensure `port` names a 16-bit register safe to write. The only
/// call site writes the ATA data register (`0x1F0`) during a PIO write, and only
/// while the drive has asserted DRQ (it is ready to accept a word).
#[inline]
unsafe fn outw(port: u16, value: u16) {
    // SAFETY: `out dx, ax` writes the 16-bit `ax` to the I/O port in `dx`. The
    // contract that `port` is the write-safe ATA data port is delegated to this
    // `# Safety` section and upheld by the sole caller (`write_sectors`, `0x1F0`,
    // only after DRQ is set). Device-only effect; `nomem`/`nostack`.
    unsafe {
        asm!("out dx, ax", in("dx") port, in("ax") value, options(nomem, nostack));
    }
}

/// Read the (command-block) status register at `0x1F7`.
fn status() -> u8 {
    // SAFETY: reads the read-only ATA status register on the primary channel; a
    // pure device read. Reading it also acknowledges a pending IRQ, but we run
    // IRQ-free, so that has no effect we depend on. `inb`'s contract holds.
    unsafe { inb(REG_STATUS) }
}

/// Read the **alternate** status register at `0x3F6` (control block).
///
/// Reading the alternate status returns the same value as the command-block
/// status but does **not** acknowledge a pending interrupt — used for the
/// mandatory 400 ns settle delay after selecting a drive / issuing a command.
fn alt_status() -> u8 {
    // SAFETY: reads the read-only ATA alternate-status register; a pure device
    // read with no side effect (unlike `0x1F7` it does not clear a pending IRQ).
    // `inb`'s contract holds.
    unsafe { inb(REG_ALT_STATUS) }
}

/// Insert the mandatory ~400 ns delay after a drive/command select by reading the
/// alternate status register four times (each read is one PIO bus cycle ≈ 100 ns).
fn delay_400ns() {
    for _ in 0..4 {
        let _ = alt_status();
    }
}

/// Spin (bounded) until BSY clears, returning the final status byte.
fn wait_not_busy() -> Result<u8, AtaError> {
    for _ in 0..POLL_LIMIT {
        let s = status();
        if s & STATUS_BSY == 0 {
            return Ok(s);
        }
        core::hint::spin_loop();
    }
    Err(AtaError::Timeout)
}

/// Spin (bounded) until BSY clears and DRQ sets (the drive wants a data word), or
/// surface ERR/DF as a [`AtaError::DeviceError`].
fn wait_for_drq() -> Result<(), AtaError> {
    for _ in 0..POLL_LIMIT {
        let s = status();
        if s & STATUS_BSY != 0 {
            core::hint::spin_loop();
            continue;
        }
        if s & (STATUS_ERR | STATUS_DF) != 0 {
            return Err(AtaError::DeviceError);
        }
        if s & STATUS_DRQ != 0 {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(AtaError::Timeout)
}

/// Select the primary master and program the LBA28 address + sector count for the
/// next command. `count` is the number of sectors (`1..=256`, with `0` meaning
/// 256 per the ATA convention; we never pass 0).
fn select_lba(lba: u32, count: u8) -> Result<(), AtaError> {
    if lba & 0xF000_0000 != 0 {
        // Bits 28..31 must be zero for LBA28 addressing.
        return Err(AtaError::OutOfRange);
    }
    // SAFETY: every `outb` below targets a documented primary-channel ATA
    // command-block register (`0x1F2..=0x1F6`) with a defined parameter byte (the
    // sector count, the three LBA bytes, and the drive-select/LBA-high nibble).
    // Programming these registers only sets up the next ATA command; it cannot
    // alias or corrupt Rust-managed memory. `outb`'s contract holds for each call.
    unsafe {
        // Drive/head: LBA master + LBA bits 24..27.
        outb(REG_DRIVE, DRIVE_LBA_MASTER | ((lba >> 24) & 0x0F) as u8);
        outb(REG_SECCOUNT, count);
        outb(REG_LBA_LO, (lba & 0xFF) as u8);
        outb(REG_LBA_MID, ((lba >> 8) & 0xFF) as u8);
        outb(REG_LBA_HI, ((lba >> 16) & 0xFF) as u8);
    }
    delay_400ns();
    Ok(())
}

/// Issue an ATA command byte to the command register (`0x1F7`).
fn issue_command(cmd: u8) {
    // SAFETY: writes the command register on the primary channel with a defined
    // ATA opcode (`IDENTIFY`/`READ`/`WRITE`/`FLUSH`). Issuing a command only
    // starts a device operation; it cannot corrupt Rust memory. `outb`'s contract
    // holds.
    unsafe { outb(REG_STATUS, cmd) }
    delay_400ns();
}

/// Probe the primary-master disk with `IDENTIFY DEVICE`.
///
/// Selects the primary master, issues `IDENTIFY`, and — if a device answers —
/// reads back its 256-word identification block, returning the user-addressable
/// LBA28 sector count.
///
/// # Errors
///
/// Returns [`AtaError::NoDevice`] when the channel is empty (status reads back
/// `0xFF`, the classic "floating bus" of an absent drive, or IDENTIFY never
/// asserts DRQ), so the kernel can boot without a disk attached. Returns
/// [`AtaError::DeviceError`]/[`AtaError::Timeout`] on a misbehaving controller.
pub fn identify() -> Result<DiskInfo, AtaError> {
    // Select the primary master (no LBA programming needed for IDENTIFY itself,
    // but the drive must be selected and the LBA/seccount registers zeroed).
    // SAFETY: writes the drive-select register and zeroes the seccount/LBA
    // registers on the primary channel — all documented command-block registers
    // with defined values; device-only effect. `outb`'s contract holds.
    unsafe {
        outb(REG_DRIVE, DRIVE_LBA_MASTER);
        outb(REG_SECCOUNT, 0);
        outb(REG_LBA_LO, 0);
        outb(REG_LBA_MID, 0);
        outb(REG_LBA_HI, 0);
    }
    delay_400ns();

    // A status of 0xFF is the floating bus of an absent controller.
    if status() == 0xFF {
        return Err(AtaError::NoDevice);
    }

    issue_command(CMD_IDENTIFY);

    // After IDENTIFY a present device sets BSY then clears it; a status of 0 means
    // no device is attached.
    if status() == 0 {
        return Err(AtaError::NoDevice);
    }
    wait_not_busy()?;

    // If LBA-mid/hi are non-zero the device is not a plain ATA disk (e.g. an
    // ATAPI CD-ROM signature 0x14/0xEB); treat it as "no usable disk here".
    // SAFETY: pure device reads of two command-block registers. `inb` contract.
    let (mid, hi) = unsafe { (inb(REG_LBA_MID), inb(REG_LBA_HI)) };
    if mid != 0 || hi != 0 {
        return Err(AtaError::NoDevice);
    }

    wait_for_drq()?;

    // Read the 256-word identification block; we only keep words 60..61 (the
    // LBA28 user-addressable sector count, little-endian dword).
    let mut id = [0u16; WORDS_PER_SECTOR];
    for word in id.iter_mut() {
        // SAFETY: the drive asserted DRQ (it wants to hand us a word), so reading
        // the data port `0x1F0` is the defined PIO transfer. `inw` contract holds.
        *word = unsafe { inw(REG_DATA) };
    }

    let sectors = (id[60] as u32) | ((id[61] as u32) << 16);
    if sectors == 0 {
        return Err(AtaError::NoDevice);
    }
    Ok(DiskInfo { sectors })
}

/// Read `count` contiguous 512-byte sectors starting at LBA `lba` into `buf`.
///
/// `buf.len()` must equal `count * 512`. The transfer is one PIO `READ SECTORS`
/// command followed by `count * 256` word reads of the data register, with a
/// BSY/DRQ poll before each sector.
///
/// # Errors
///
/// - [`AtaError::BadBuffer`] if `buf.len() != count * 512` or `count == 0`.
/// - [`AtaError::OutOfRange`] if the LBA range exceeds LBA28 or `count > 256`.
/// - [`AtaError::DeviceError`]/[`AtaError::Timeout`] on a drive error/stall.
pub fn read_sectors(lba: u32, count: u16, buf: &mut [u8]) -> Result<(), AtaError> {
    let count = validate(lba, count, buf.len())?;

    select_lba(lba, count as u8)?;
    wait_not_busy()?;
    issue_command(CMD_READ_PIO);

    for sector in 0..count as usize {
        wait_for_drq()?;
        let base = sector * SECTOR_SIZE;
        for word in 0..WORDS_PER_SECTOR {
            // SAFETY: DRQ is asserted (the drive wants to give us this word), so
            // reading the data port `0x1F0` is the defined PIO transfer. `inw`
            // contract holds.
            let w = unsafe { inw(REG_DATA) };
            // Little-endian: low byte first, then high byte.
            buf[base + word * 2] = (w & 0xFF) as u8;
            buf[base + word * 2 + 1] = (w >> 8) as u8;
        }
    }
    Ok(())
}

/// Write `count` contiguous 512-byte sectors starting at LBA `lba` from `buf`.
///
/// `buf.len()` must equal `count * 512`. The transfer is one PIO `WRITE SECTORS`
/// command followed by `count * 256` word writes of the data register (BSY/DRQ
/// polled before each sector), then a `FLUSH CACHE` so the data reaches media.
///
/// # Errors
///
/// Same as [`read_sectors`]: [`AtaError::BadBuffer`], [`AtaError::OutOfRange`],
/// or [`AtaError::DeviceError`]/[`AtaError::Timeout`].
pub fn write_sectors(lba: u32, count: u16, buf: &[u8]) -> Result<(), AtaError> {
    let count = validate(lba, count, buf.len())?;

    select_lba(lba, count as u8)?;
    wait_not_busy()?;
    issue_command(CMD_WRITE_PIO);

    for sector in 0..count as usize {
        wait_for_drq()?;
        let base = sector * SECTOR_SIZE;
        for word in 0..WORDS_PER_SECTOR {
            let lo = buf[base + word * 2] as u16;
            let hi = buf[base + word * 2 + 1] as u16;
            // SAFETY: DRQ is asserted (the drive is ready to accept this word), so
            // writing the data port `0x1F0` is the defined PIO transfer. `outw`
            // contract holds.
            unsafe { outw(REG_DATA, lo | (hi << 8)) };
        }
    }

    // FLUSH CACHE so write-cached sectors are committed to the backing media —
    // without this, data can be lost on power-off (the persistence guarantee).
    issue_command(CMD_FLUSH);
    let s = wait_not_busy()?;
    if s & (STATUS_ERR | STATUS_DF) != 0 {
        return Err(AtaError::DeviceError);
    }
    Ok(())
}

/// Validate a sector request and return the validated `count` (as a `u16`).
///
/// Checks the buffer length matches `count * 512`, the count is in `1..=256`, and
/// the LBA range fits LBA28.
fn validate(lba: u32, count: u16, buf_len: usize) -> Result<u16, AtaError> {
    if count == 0 || count > 256 {
        return Err(AtaError::OutOfRange);
    }
    if buf_len != count as usize * SECTOR_SIZE {
        return Err(AtaError::BadBuffer);
    }
    // The last accessed sector is `lba + count - 1`; it must fit LBA28.
    let last = lba as u64 + count as u64 - 1;
    if last >= (1u64 << 28) {
        return Err(AtaError::OutOfRange);
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `validate` rejects a zero count and an over-large count.
    #[test]
    fn validate_rejects_bad_count() {
        assert_eq!(validate(0, 0, 0), Err(AtaError::OutOfRange));
        assert_eq!(
            validate(0, 257, 257 * SECTOR_SIZE),
            Err(AtaError::OutOfRange)
        );
    }

    /// `validate` rejects a buffer whose length is not `count * 512`.
    #[test]
    fn validate_rejects_mismatched_buffer() {
        assert_eq!(validate(0, 1, 511), Err(AtaError::BadBuffer));
        assert_eq!(validate(0, 2, SECTOR_SIZE), Err(AtaError::BadBuffer));
    }

    /// `validate` accepts a well-formed single- and multi-sector request.
    #[test]
    fn validate_accepts_good_request() {
        assert_eq!(validate(0, 1, SECTOR_SIZE), Ok(1));
        assert_eq!(validate(100, 4, 4 * SECTOR_SIZE), Ok(4));
    }

    /// `validate` rejects an LBA range that overflows the 28-bit address space.
    #[test]
    fn validate_rejects_lba28_overflow() {
        // Last sector == 2^28 is out of range (valid LBAs are 0..2^28).
        assert_eq!(
            validate((1 << 28) - 1, 2, 2 * SECTOR_SIZE),
            Err(AtaError::OutOfRange)
        );
        // Last sector == 2^28 - 1 is the highest valid LBA28 address.
        assert_eq!(validate((1 << 28) - 1, 1, SECTOR_SIZE), Ok(1));
    }

    /// `DiskInfo::capacity_bytes` multiplies sectors by the 512-byte sector size.
    #[test]
    fn capacity_is_sectors_times_512() {
        assert_eq!(DiskInfo { sectors: 0 }.capacity_bytes(), 0);
        assert_eq!(DiskInfo { sectors: 1 }.capacity_bytes(), 512);
        assert_eq!(
            DiskInfo { sectors: 32_768 }.capacity_bytes(),
            16 * 1024 * 1024
        );
    }
}
