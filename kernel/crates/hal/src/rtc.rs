//! CMOS real-time clock (MC146818-compatible, ports `0x70`/`0x71`) — TCB.
//!
//! Read-only: returns the clock's **raw** register bytes. Decoding (BCD or
//! binary, 12 or 24 h, the century, the weekday) is plain arithmetic and lives
//! in the safe kernel (`kernel::wall`), so this module's whole job is
//! two port instructions in a bounded, consistent read.
//!
//! Consistency: the RTC updates its time registers once a second, and a read
//! that straddles the update can mix two seconds (e.g. 12:59:59 → 12:00:00).
//! [`read`] waits (bounded) until Status A's update-in-progress bit is clear,
//! reads every register, and repeats until two whole reads agree.
//!
//! Index writes leave bit 7 of port `0x70` clear, so NMIs stay enabled: we
//! don't change the NMI mask the firmware left. Call from one core at a time
//! (boot does it once, on the BSP, before the APs run kernel code): the
//! index/data port pair is not atomic.
//!
//! All `unsafe` is registered in `kernel/docs/hal-tcb.md` (§2n).

use core::arch::asm;

/// CMOS index (register select) port.
const CMOS_INDEX: u16 = 0x70;
/// CMOS data port.
const CMOS_DATA: u16 = 0x71;

const REG_SECONDS: u8 = 0x00;
const REG_MINUTES: u8 = 0x02;
const REG_HOURS: u8 = 0x04;
const REG_DAY: u8 = 0x07;
const REG_MONTH: u8 = 0x08;
const REG_YEAR: u8 = 0x09;
/// Status A: bit 7 = update in progress.
const REG_STATUS_A: u8 = 0x0A;
/// Status B: bit 2 = binary (else BCD), bit 1 = 24-hour (else 12-hour + PM bit).
const REG_STATUS_B: u8 = 0x0B;
/// Century, where the firmware keeps it (the ACPI FADT names the register;
/// 0x32 is the de-facto default QEMU, VirtualBox and most PCs use). May be 0.
const REG_CENTURY: u8 = 0x32;

const STATUS_A_UIP: u8 = 1 << 7;
/// Bound on update-in-progress polls. UIP is set for at most ~2 ms per second;
/// each poll is two port accesses (~1 µs each on real hardware), so this
/// covers it many times over without a timer.
const UIP_SPIN_LIMIT: u32 = 100_000;
/// Bound on read-until-stable attempts.
const READ_ATTEMPTS: u32 = 8;

/// The RTC's time and date registers exactly as the chip holds them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RtcRaw {
    /// Seconds register (0x00).
    pub seconds: u8,
    /// Minutes register (0x02).
    pub minutes: u8,
    /// Hours register (0x04); in 12-hour mode bit 7 is the PM flag.
    pub hours: u8,
    /// Day of month register (0x07).
    pub day: u8,
    /// Month register (0x08).
    pub month: u8,
    /// Year register (0x09), two digits (00–99).
    pub year: u8,
    /// Register 0x32; `0` or garbage where the firmware doesn't keep it.
    pub century: u8,
    /// Status B, for the BCD/binary and 12/24-hour flags.
    pub status_b: u8,
}

/// Read one CMOS register.
///
/// # Safety
///
/// `reg` must be a CMOS register below 0x80 whose read has no side effect
/// (every register this module names). The caller must not race another core
/// on the index/data port pair.
#[inline]
unsafe fn cmos_read(reg: u8) -> u8 {
    let value: u8;
    // SAFETY: `out 0x70, al` selects register `reg` with bit 7 clear (NMIs stay
    // as they were), then `in al, 0x71` reads it. Port I/O touches no Rust
    // memory (`nomem`) and no stack (`nostack`); the selected registers are
    // read-only status/time bytes, so the read changes no device state. The
    // single-core contract is the caller's (# Safety).
    unsafe {
        asm!(
            "out dx, al",
            in("dx") CMOS_INDEX,
            in("al") reg & 0x7F,
            options(nomem, nostack, preserves_flags)
        );
        asm!(
            "in al, dx",
            in("dx") CMOS_DATA,
            out("al") value,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

/// Wait (bounded) for update-in-progress to clear, then read every register once.
fn read_once() -> RtcRaw {
    for _ in 0..UIP_SPIN_LIMIT {
        // SAFETY: Status A is a read-only status register (`cmos_read` contract);
        // boot calls `read` from the BSP alone.
        if unsafe { cmos_read(REG_STATUS_A) } & STATUS_A_UIP == 0 {
            break;
        }
        core::hint::spin_loop();
    }
    // SAFETY: every register named here is a read-only time/date/status byte
    // below 0x80 (`cmos_read` contract); single caller as above.
    unsafe {
        RtcRaw {
            seconds: cmos_read(REG_SECONDS),
            minutes: cmos_read(REG_MINUTES),
            hours: cmos_read(REG_HOURS),
            day: cmos_read(REG_DAY),
            month: cmos_read(REG_MONTH),
            year: cmos_read(REG_YEAR),
            century: cmos_read(REG_CENTURY),
            status_b: cmos_read(REG_STATUS_B),
        }
    }
}

/// Read the RTC: the first two consecutive whole reads that agree, or `None`
/// if [`READ_ATTEMPTS`] reads never settled (a clock that keeps changing
/// under us, or no RTC answering).
///
/// Call from one core at a time (see the module docs).
#[must_use]
pub fn read() -> Option<RtcRaw> {
    let mut last = read_once();
    for _ in 0..READ_ATTEMPTS {
        let next = read_once();
        if next == last {
            return Some(next);
        }
        last = next;
    }
    None
}
