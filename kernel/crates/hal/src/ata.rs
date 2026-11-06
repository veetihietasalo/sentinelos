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
//!   `lba` from a caller buffer. **Unflushed** (SentinelFS FS-1b): it returns
//!   once the drive has accepted every sector and dropped BSY, which with a
//!   write cache means "in the drive's cache", not "on the media".
//! - [`flush`] — `FLUSH CACHE`: make every earlier write durable. Waits for
//!   BSY to clear *before* issuing the command (the pre-FS-1b code issued it
//!   straight after the data phase, while the drive could still be busy) and
//!   again for its completion, then checks ERR/DF.
//!
//! # Durability contract
//!
//! Between two successful [`flush`] calls the drive may persist any subset of
//! the sectors written, in any order; a single 512-byte sector write is
//! atomic; [`flush`] returning `Ok` means every earlier write is durable. That
//! is the model SentinelFS's commit protocol is designed against (spec §8:
//! dirty blocks → flush → superblock → flush). A caller that needs a write to
//! survive power loss calls [`flush`] after it (the toy `kernel::fs` does,
//! once per save).
//!
//! # Concurrency model
//!
//! The command/status handshake is a strict request→poll→transfer sequence
//! that must not be interleaved with another command on the channel. This
//! module does not serialise its callers; the kernel does. Since SentinelFS
//! FS-1a two kernel paths drive the disk (`kernel::fs` and the `sfs-commit`
//! task), and every call goes through `kernel::blk::ata`, which holds a
//! kernel-side channel lock (`CHANNEL`) for exactly one command — `identify`,
//! `read_sectors`, `write_sectors` and `flush` are one command each; no other
//! kernel file may name this module (`cargo xtask check-ata-callers`, run in
//! CI). That lock protects disk integrity, not memory safety: the port
//! accesses below are sound however callers interleave — an interleaved
//! command can corrupt a transfer, never memory (hal-tcb §4 invariant 16, §7).

use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

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

/// Device Control register (`0x3F6`, written; the same port reads as
/// Alternate Status).
const REG_DEVICE_CONTROL: u16 = 0x3F6;
/// Device Control: software reset (SRST, bit 2).
const CTRL_SRST: u8 = 1 << 2;
/// Device Control: device interrupts disabled (nIEN, bit 1). This driver
/// polls; after a reset it states "no device interrupts" explicitly rather
/// than inherit whatever the firmware left.
const CTRL_NIEN: u8 = 1 << 1;

/// Status waits are bounded by **time**, not by a count of status reads (a
/// count is no deadline: QEMU completes IDE PIO and `FLUSH CACHE`
/// asynchronously through host `pwrite`/`fdatasync`, and under host write
/// pressure 100 000 reads under TCG proved too short — CI's FS-1c runs).
/// Every budget is a **duration** ([`SECTOR_US`], [`FLUSH_US`], [`RESET_US`],
/// [`SRST_HOLD_US`], [`SRST_SETTLE_US`]) turned into TSC cycles by
/// [`cycles_for`]. Once the kernel has measured the TSC against the PIT
/// ([`set_tsc_hz`]) the cycles are that rate plus a 25 % margin, so a wedged
/// drive holds the channel about as long on a 0.5 GHz TSC as on a 5 GHz one.
/// Until then (or if the measurement was refused) the rate is assumed to be
/// [`FALLBACK_TSC_HZ`], the fastest plausible TSC, so a wait is never shorter
/// than its duration at any TSC ≤ 5 GHz — only longer on a slower one. A real
/// disk that never answers still fails.
const SECTOR_US: u64 = 800_000;
/// A `FLUSH CACHE`: ≥ 8 s.
const FLUSH_US: u64 = 8_000_000;
/// The wait for BSY to clear after a software reset: ATA allows a drive up to
/// 31 s. Only a drive that already timed out ever waits here.
const RESET_US: u64 = 31_000_000;
/// SRST is held ≥ 5 µs.
const SRST_HOLD_US: u64 = 5;
/// After clearing SRST, wait ≥ 2 ms before polling BSY (the drive may not even
/// assert BSY sooner).
const SRST_SETTLE_US: u64 = 2_000;

/// The TSC rate assumed while none has been measured: the fastest plausible
/// TSC, so every budget is at least its duration on any TSC up to this rate.
const FALLBACK_TSC_HZ: u64 = 5_000_000_000;
/// Measured rates outside `TSC_HZ_MIN..=TSC_HZ_MAX` are refused by
/// [`set_tsc_hz`] (the waits keep the fallback): no x86-64 TSC runs slower
/// than 100 MHz or faster than 10 GHz, so such a reading is a broken
/// measurement, not a CPU.
pub const TSC_HZ_MIN: u64 = 100_000_000;
/// See [`TSC_HZ_MIN`].
pub const TSC_HZ_MAX: u64 = 10_000_000_000;

/// The measured TSC rate in Hz, `0` until [`set_tsc_hz`] accepts one.
static TSC_HZ: AtomicU64 = AtomicU64::new(0);

/// Record the TSC rate the kernel measured against the PIT, so the ATA waits
/// become real durations. **Set once:** the first accepted rate stays, later
/// calls return `false`. A rate outside [`TSC_HZ_MIN`]`..=`[`TSC_HZ_MAX`] is
/// refused (`false`) and the waits keep [`FALLBACK_TSC_HZ`]. Safe: the value
/// only sizes deadlines; a wrong one makes a wait end early (`Timeout`, a
/// channel reset, an error) or late, never a wrong success.
pub fn set_tsc_hz(hz: u64) -> bool {
    (TSC_HZ_MIN..=TSC_HZ_MAX).contains(&hz)
        && TSC_HZ
            .compare_exchange(0, hz, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
}

/// The TSC rate the waits use: the measured one, if [`set_tsc_hz`] accepted
/// one.
#[must_use]
pub fn tsc_hz() -> Option<u64> {
    match TSC_HZ.load(Ordering::Relaxed) {
        0 => None,
        hz => Some(hz),
    }
}

/// TSC cycles for a wait of `us` microseconds: at the measured rate plus 25 %
/// (covers the calibration's error, a few PIT-interrupt latencies over a
/// 100 ms window), or at [`FALLBACK_TSC_HZ`] when no rate is known. Pure, so
/// the budgets are checked at compile time. No overflow: `us ≤ RESET_US` and
/// `hz ≤ TSC_HZ_MAX` keep `us × hz × 5` below 2^61.
const fn cycles_for(us: u64, measured_hz: Option<u64>) -> u64 {
    match measured_hz {
        Some(hz) => us * hz / 1_000_000 * 5 / 4,
        None => us * FALLBACK_TSC_HZ / 1_000_000,
    }
}

/// [`cycles_for`] at the rate the waits use now.
fn budget(us: u64) -> u64 {
    cycles_for(us, tsc_hz())
}

/// The fallback sector budget, in cycles (what [`budget`]`(SECTOR_US)` is
/// before a rate is measured).
#[cfg(test)]
const SECTOR_BUDGET: u64 = cycles_for(SECTOR_US, None);

// Unmeasured: the same cycle budgets as before the TSC was measured (≥ 0.8 s
// per sector, ≥ 8 s per flush, ≥ 31 s per reset, ≥ 5 µs hold, ≥ 2 ms settle,
// all at 5 GHz). Measured: at least the duration at the slowest and fastest
// accepted rates. The backstop stays far above the old 100 000-read limit.
const _: () = {
    assert!(cycles_for(SECTOR_US, None) == 4_000_000_000);
    assert!(cycles_for(FLUSH_US, None) == 40_000_000_000);
    assert!(cycles_for(RESET_US, None) >= 5_000_000_000 * 31);
    assert!(cycles_for(SRST_HOLD_US, None) >= 5_000 * 5);
    assert!(cycles_for(SRST_SETTLE_US, None) >= 5_000_000 * 2);
    assert!(cycles_for(SECTOR_US, Some(TSC_HZ_MIN)) >= TSC_HZ_MIN * 8 / 10);
    assert!(cycles_for(RESET_US, Some(TSC_HZ_MAX)) >= TSC_HZ_MAX * 31);
    assert!(cycles_for(SRST_HOLD_US, Some(TSC_HZ_MIN)) >= TSC_HZ_MIN / 200_000);
    assert!(POLL_BACKSTOP > 100_000 * 1000);
};

/// A backstop on status reads in case the TSC does not advance (it always
/// does on x86-64; this keeps the loop bounded regardless).
const POLL_BACKSTOP: u64 = 500_000_000;

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
/// registers (`0x1F2..=0x1F7`) with documented command/parameter bytes, or
/// the control-block Device Control register (`0x3F6`) with `SRST | nIEN`
/// or `nIEN` (the timeout recovery, [`reset_channel`]).
#[inline]
unsafe fn outb(port: u16, value: u8) {
    // SAFETY: `out dx, al` writes the byte in `al` to the I/O port in `dx`. The
    // contract that `port`/`value` are a valid, write-safe ATA register pair is
    // delegated to this function's `# Safety` section and upheld by every caller
    // (ATA command-block registers `0x1F2..=0x1F7` with defined LBA/seccount/
    // command bytes, and the Device Control register `0x3F6` with
    // `SRST | nIEN` or `nIEN` from `reset_channel`). Device-only effect,
    // `nomem`/`nostack`.
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

/// What one status read means to a wait.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Poll {
    /// The condition holds: stop, `Ok(status)`.
    Ready,
    /// Not yet: read again.
    Wait,
    /// The drive reported an error: stop, `DeviceError`.
    Fail,
}

/// The wait loop, pure (no ports, no clock of its own) so the host tests and
/// Kani can drive it: read the status, classify it, and stop when it is
/// ready or failed, when `now()` has moved more than `budget` past its first
/// reading, or after `backstop` reads. A clock that steps backwards counts as
/// no time elapsed (the backstop still bounds the loop).
fn poll_until(
    mut read: impl FnMut() -> u8,
    mut now: impl FnMut() -> u64,
    budget: u64,
    backstop: u64,
    classify: impl Fn(u8) -> Poll,
) -> Result<u8, AtaError> {
    let start = now();
    let mut polls = 0u64;
    loop {
        let s = read();
        match classify(s) {
            Poll::Ready => return Ok(s),
            Poll::Fail => return Err(AtaError::DeviceError),
            Poll::Wait => {}
        }
        polls += 1;
        if polls >= backstop || now().saturating_sub(start) > budget {
            return Err(AtaError::Timeout);
        }
        // A pause hint only; Kani cannot model the `pause` intrinsic.
        #[cfg(not(kani))]
        core::hint::spin_loop();
    }
}

/// BSY clear: ready.
fn not_busy(s: u8) -> Poll {
    if s & STATUS_BSY == 0 {
        Poll::Ready
    } else {
        Poll::Wait
    }
}

/// BSY clear and DRQ set: ready; BSY clear with ERR/DF: failed.
fn drq_ready(s: u8) -> Poll {
    if s & STATUS_BSY != 0 {
        Poll::Wait
    } else if s & (STATUS_ERR | STATUS_DF) != 0 {
        Poll::Fail
    } else if s & STATUS_DRQ != 0 {
        Poll::Ready
    } else {
        Poll::Wait
    }
}

/// Wait (deadline `budget` TSC cycles, from [`budget`]) for BSY to clear;
/// returns the status.
fn wait_not_busy_for(budget: u64) -> Result<u8, AtaError> {
    poll_until(status, crate::cpu::rdtsc, budget, POLL_BACKSTOP, not_busy)
}

/// Spin (deadline-bounded) until BSY clears, returning the final status byte.
fn wait_not_busy() -> Result<u8, AtaError> {
    wait_not_busy_for(budget(SECTOR_US))
}

/// Spin (bounded) until BSY clears and DRQ sets (the drive wants a data word), or
/// surface ERR/DF as a [`AtaError::DeviceError`].
fn wait_for_drq() -> Result<(), AtaError> {
    poll_until(
        status,
        crate::cpu::rdtsc,
        budget(SECTOR_US),
        POLL_BACKSTOP,
        drq_ready,
    )
    .map(|_| ())
}

/// Recover the channel after a timeout: a command that timed out may still be
/// running, or stopped mid-transfer with DRQ pending, and the next command
/// must not start against that. Software reset (SRST) aborts whatever the
/// drive is doing and returns it to the post-reset state: write
/// `SRST | nIEN`, hold ≥ 5 µs ([`SRST_HOLD_US`]), write `nIEN` (SRST clear,
/// device interrupts off — this driver polls), wait ≥ 2 ms
/// ([`SRST_SETTLE_US`]), then wait for BSY to clear (bounded by
/// [`RESET_US`], the 31 s ATA allows). The next command selects the drive
/// and programs every register again, as each one already does.
fn reset_channel() {
    // SAFETY: writes the primary channel's Device Control register (`0x3F6`)
    // with `SRST | nIEN` — a documented control-block register and value. A
    // reset only affects the drive (it aborts the command in progress, and
    // nIEN only gates the drive's interrupt line, which this driver never
    // uses); it cannot alias or corrupt Rust memory. `outb`'s contract holds.
    unsafe { outb(REG_DEVICE_CONTROL, CTRL_SRST | CTRL_NIEN) };
    spin_cycles(budget(SRST_HOLD_US));
    // SAFETY: as above, with SRST clear and nIEN set.
    unsafe { outb(REG_DEVICE_CONTROL, CTRL_NIEN) };
    spin_cycles(budget(SRST_SETTLE_US));
    let _ = wait_not_busy_for(budget(RESET_US));
}

/// Busy-wait at least `cycles` TSC cycles (bounded by the read backstop if
/// the TSC does not advance).
fn spin_cycles(cycles: u64) {
    let start = crate::cpu::rdtsc();
    for _ in 0..POLL_BACKSTOP {
        if crate::cpu::rdtsc().saturating_sub(start) >= cycles {
            return;
        }
        #[cfg(not(kani))]
        core::hint::spin_loop();
    }
}

/// After a timeout, reset the channel before handing the error back (see
/// [`reset_channel`]); every other outcome passes through.
fn recover<T>(r: Result<T, AtaError>) -> Result<T, AtaError> {
    if r.as_ref().is_err_and(|e| *e == AtaError::Timeout) {
        reset_channel();
    }
    r
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
///
/// A command written while the drive is busy is ignored, so callers make sure
/// BSY is clear first: `read_sectors` / `write_sectors` poll `wait_not_busy`
/// after `select_lba`, and `flush` after its select (the FS-1b fix).
/// `identify` (unchanged) does not poll first: it runs once per opener, and
/// under the kernel's channel lock the previous command has always finished
/// — `write_sectors` and `flush` now return only after BSY clears, and a read
/// ends with its last data word.
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
///
/// An absent disk answers at once (`NoDevice`); a present one that never
/// answers now blocks its caller for up to [`SECTOR_US`] then the reset's
/// [`SRST_SETTLE_US`] + [`RESET_US`] — seconds to tens of seconds, by design
/// (deadlines, not read counts). The kernel calls it from the `sfs-commit`
/// task and the toy `kernel::fs` probe, never from an interrupt path.
pub fn identify() -> Result<DiskInfo, AtaError> {
    recover(identify_inner())
}

fn identify_inner() -> Result<DiskInfo, AtaError> {
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
    recover(read_sectors_inner(lba, count, buf))
}

fn read_sectors_inner(lba: u32, count: u16, buf: &mut [u8]) -> Result<(), AtaError> {
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
/// polled before each sector); it returns once the drive has dropped BSY after
/// the last sector without reporting ERR/DF.
///
/// **Not durable on its own** (FS-1b API split, hal-tcb row A2): the data may
/// sit in the drive's write cache until the next [`flush`]. Before FS-1b this
/// function ended every command with `FLUSH CACHE`.
///
/// # Errors
///
/// Same as [`read_sectors`]: [`AtaError::BadBuffer`], [`AtaError::OutOfRange`],
/// or [`AtaError::DeviceError`]/[`AtaError::Timeout`].
pub fn write_sectors(lba: u32, count: u16, buf: &[u8]) -> Result<(), AtaError> {
    recover(write_sectors_inner(lba, count, buf))
}

fn write_sectors_inner(lba: u32, count: u16, buf: &[u8]) -> Result<(), AtaError> {
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

    // The command completes when the drive drops BSY after the last sector;
    // ERR/DF then report a failed write. Waiting here also means the next
    // command on the channel (often `flush`) never starts against a busy drive.
    let s = wait_not_busy()?;
    if s & (STATUS_ERR | STATUS_DF) != 0 {
        return Err(AtaError::DeviceError);
    }
    Ok(())
}

/// `FLUSH CACHE`: make every sector written before this call durable.
///
/// Selects the primary master, waits for BSY to clear (a command written while
/// the drive is busy is ignored — the A2 weakness of the pre-FS-1b code, which
/// issued `FLUSH CACHE` straight after a write's data phase), issues
/// `FLUSH CACHE`, and waits (bounded) for it to complete. A drive without a
/// write cache completes it at once.
///
/// # Errors
///
/// [`AtaError::Timeout`] if the drive stays busy past its deadline (before
/// or after the command), [`AtaError::DeviceError`] if it reports ERR/DF. On
/// either error nothing is known about the durability of the writes since the
/// last successful flush.
pub fn flush() -> Result<(), AtaError> {
    recover(flush_inner())
}

fn flush_inner() -> Result<(), AtaError> {
    // SAFETY: writes the primary channel's drive/head register (`0x1F6`) with
    // the defined "LBA mode, master" select byte — a documented command-block
    // register and value. Selecting the drive only routes the next command; it
    // cannot alias or corrupt Rust-managed memory. `outb`'s contract holds.
    unsafe { outb(REG_DRIVE, DRIVE_LBA_MASTER) };
    delay_400ns();
    wait_not_busy()?;
    issue_command(CMD_FLUSH);
    let s = wait_not_busy_for(budget(FLUSH_US))?;
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

#[cfg(test)]
mod wait_tests {
    use super::*;

    /// A clock that advances `step` per reading.
    fn clock(step: u64) -> impl FnMut() -> u64 {
        let mut t = 0u64;
        move || {
            t += step;
            t
        }
    }

    #[test]
    fn a_wait_ends_at_its_deadline_not_at_a_read_count() {
        // A drive busy forever: a 100-cycle budget at 10 cycles per read ends
        // after ~10 reads, far below the backstop.
        let mut reads = 0u64;
        let r = poll_until(
            || {
                reads += 1;
                STATUS_BSY
            },
            clock(10),
            100,
            1_000_000,
            not_busy,
        );
        assert_eq!(r, Err(AtaError::Timeout));
        assert!((9..=12).contains(&reads), "{reads}");
        // A slow but answering drive: busy for 150 000 reads (more than the
        // old fixed 100 000-read limit) is fine within the deadline.
        let mut n = 0u64;
        let r = poll_until(
            || {
                n += 1;
                if n > 150_000 {
                    STATUS_DRDY
                } else {
                    STATUS_BSY
                }
            },
            clock(1),
            SECTOR_BUDGET,
            POLL_BACKSTOP,
            not_busy,
        );
        assert_eq!(r, Ok(STATUS_DRDY));
    }

    #[test]
    fn drq_waits_report_errors_and_readiness() {
        let mut seq = [STATUS_BSY, STATUS_DRDY, STATUS_DRDY | STATUS_DRQ].into_iter();
        assert_eq!(
            poll_until(|| seq.next().unwrap_or(0), clock(1), 100, 100, drq_ready),
            Ok(STATUS_DRDY | STATUS_DRQ)
        );
        let mut seq = [STATUS_BSY, STATUS_ERR].into_iter();
        assert_eq!(
            poll_until(|| seq.next().unwrap_or(0), clock(1), 100, 100, drq_ready),
            Err(AtaError::DeviceError)
        );
        // BSY masks ERR/DRQ (their bits are not valid while busy).
        assert_eq!(drq_ready(STATUS_BSY | STATUS_ERR | STATUS_DRQ), Poll::Wait);
    }

    #[test]
    fn a_stuck_or_backwards_clock_is_bounded_by_the_backstop() {
        let mut reads = 0u64;
        let r = poll_until(
            || {
                reads += 1;
                STATUS_BSY
            },
            || 7,
            0,
            50,
            not_busy,
        );
        assert_eq!((r, reads), (Err(AtaError::Timeout), 50));
        let mut t = 1_000u64;
        let r = poll_until(
            || STATUS_BSY,
            || {
                t -= 1;
                t
            },
            10,
            20,
            not_busy,
        );
        assert_eq!(r, Err(AtaError::Timeout), "backwards time is no time");
    }
}

/// Kani proof harness — exhaustive proof of the disk-I/O safety gate.
///
/// Compiled only under `cargo kani`; the normal stable build excludes it. Run
/// with `cargo kani -p hal`.
#[cfg(kani)]
mod proofs {
    use super::*;

    /// The wait loop over any status sequence and any clock (three reads at
    /// most): `Ok(s)` only for a status classified ready, `DeviceError` only
    /// for one classified failed, and `Timeout` only once the clock moved
    /// past the budget or the backstop was reached — so a timeout is always
    /// a deadline, and a ready drive is never reported as one.
    #[kani::proof]
    #[kani::unwind(5)]
    fn poll_until_is_a_deadline() {
        let statuses: [u8; 3] = kani::any();
        let times: [u64; 4] = kani::any();
        let budget: u64 = kani::any();
        let (mut ri, mut ti) = (0usize, 0usize);
        let mut last_status = 0u8;
        let mut last_time = 0u64;
        let start = times[0];
        let r = poll_until(
            || {
                let s = statuses[ri.min(2)];
                ri += 1;
                last_status = s;
                s
            },
            || {
                let t = times[ti.min(3)];
                ti += 1;
                last_time = t;
                t
            },
            budget,
            3,
            drq_ready,
        );
        match r {
            Ok(s) => assert!(drq_ready(s) == Poll::Ready),
            Err(AtaError::DeviceError) => assert!(drq_ready(last_status) == Poll::Fail),
            Err(AtaError::Timeout) => {
                assert!(drq_ready(last_status) == Poll::Wait);
                assert!(ri >= 3 || last_time.saturating_sub(start) > budget);
            }
            Err(_) => panic!("poll_until reports only ready, failed or timeout"),
        }
        assert!(ri <= 3);
    }

    /// `validate` is the gate every PIO transfer passes through, so its acceptance
    /// set *is* the safety contract of `read_sectors`/`write_sectors`. Prove that
    /// for **any** `(lba, count, buf_len)`, an `Ok(n)` result implies every
    /// precondition the transfer relies on: the returned count equals the input,
    /// the count is a legal LBA28 sector count (`1..=256`), the buffer is exactly
    /// `count * 512` bytes (no over/under-read of the caller's slice), and the last
    /// addressed sector fits LBA28 (no wrap past the 128 GiB limit). Equivalently:
    /// no unsafe request is ever accepted.
    #[kani::proof]
    fn validate_only_accepts_safe_requests() {
        let lba: u32 = kani::any();
        let count: u16 = kani::any();
        let buf_len: usize = kani::any();
        if let Ok(n) = validate(lba, count, buf_len) {
            assert!(n == count);
            assert!(count >= 1 && count <= 256);
            assert!(buf_len == count as usize * SECTOR_SIZE);
            assert!((lba as u64) + (count as u64) - 1 < (1u64 << 28));
        }
    }
}
