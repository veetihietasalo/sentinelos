//! Wall-clock date and time from the CMOS RTC (`hal::rtc`), read once at boot.
//!
//! The RTC is read a single time ([`init`]); after that the time of day is the
//! boot reading plus whole PIT seconds since, so the lock screen and the
//! desktop clock never touch the CMOS ports again. Decoding the raw registers
//! (BCD or binary, 12 or 24 h, century) is plain arithmetic, kept here and out
//! of the TCB.
//!
//! The time is shown as the RTC holds it. Most firmwares and VirtualBox keep
//! local time, QEMU keeps UTC (`-rtc base=utc` is its default); there is no
//! time-zone handling yet. Without a usable RTC the UI keeps its old fixed
//! start time and date line.

use alloc::string::String;
use core::sync::atomic::{AtomicU64, Ordering};

/// Seconds since 1970-01-01 (in the RTC's own time zone) at the boot reading;
/// `u64::MAX` until [`init`] decodes a valid reading.
static BOOT_EPOCH_SECS: AtomicU64 = AtomicU64::new(u64::MAX);
/// Whole PIT seconds since boot at the moment of that reading.
static BOOT_ELAPSED_SECS: AtomicU64 = AtomicU64::new(0);

/// A decoded calendar date and time of day.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WallTime {
    /// Full year, e.g. 2026.
    pub year: u16,
    /// Month, 1–12.
    pub month: u8,
    /// Day of month, 1–31.
    pub day: u8,
    /// 0 = Sunday … 6 = Saturday.
    pub weekday: u8,
    /// Hour, 0–23.
    pub hour: u8,
    /// Minute, 0–59.
    pub minute: u8,
    /// Second, 0–59.
    pub second: u8,
}

const DAY_NAMES: [&str; 7] = [
    "SUNDAY",
    "MONDAY",
    "TUESDAY",
    "WEDNESDAY",
    "THURSDAY",
    "FRIDAY",
    "SATURDAY",
];
const MONTH_NAMES: [&str; 12] = [
    "JANUARY",
    "FEBRUARY",
    "MARCH",
    "APRIL",
    "MAY",
    "JUNE",
    "JULY",
    "AUGUST",
    "SEPTEMBER",
    "OCTOBER",
    "NOVEMBER",
    "DECEMBER",
];

/// Status B bit 2: registers hold binary values (else BCD).
const STATUS_B_BINARY: u8 = 1 << 2;
/// Status B bit 1: 24-hour mode (else 12-hour with bit 7 of hours = PM).
const STATUS_B_24H: u8 = 1 << 1;

/// Read the RTC once, decode it and remember it as the boot wall time. Logs
/// `[rtc] YYYY-MM-DD HH:MM:SS` or why no time is available. Call once on the
/// BSP; `elapsed_secs` is whole PIT seconds since boot.
pub fn init(elapsed_secs: u64) {
    let Some(raw) = hal::rtc::read() else {
        hal::serial::write_str("[rtc] no stable reading; clock keeps its fixed start\n");
        return;
    };
    let Some(t) = decode(&raw) else {
        hal::serial::write_str("[rtc] reading out of range; clock keeps its fixed start\n");
        return;
    };
    BOOT_ELAPSED_SECS.store(elapsed_secs, Ordering::Relaxed);
    BOOT_EPOCH_SECS.store(to_epoch_secs(&t), Ordering::Release);
    hal::serial::write_str("[rtc] ");
    write_dec_pad(u64::from(t.year), 4);
    hal::serial::write_str("-");
    write_dec_pad(u64::from(t.month), 2);
    hal::serial::write_str("-");
    write_dec_pad(u64::from(t.day), 2);
    hal::serial::write_str(" ");
    write_dec_pad(u64::from(t.hour), 2);
    hal::serial::write_str(":");
    write_dec_pad(u64::from(t.minute), 2);
    hal::serial::write_str(":");
    write_dec_pad(u64::from(t.second), 2);
    hal::serial::write_str(" (as the RTC keeps it)\n");
}

/// The wall time `elapsed_secs` whole PIT seconds after boot, or `None`
/// without a boot reading.
#[must_use]
pub fn at(elapsed_secs: u64) -> Option<WallTime> {
    let boot = BOOT_EPOCH_SECS.load(Ordering::Acquire);
    if boot == u64::MAX {
        return None;
    }
    let since = elapsed_secs.saturating_sub(BOOT_ELAPSED_SECS.load(Ordering::Relaxed));
    Some(from_epoch_secs(boot.saturating_add(since)))
}

/// The lock screen's date line, e.g. `FRIDAY  NOVEMBER 6` (two spaces, as the
/// UI's fixed line had).
#[must_use]
pub fn date_line(t: &WallTime) -> String {
    let mut s = String::new();
    s.push_str(DAY_NAMES[usize::from(t.weekday % 7)]);
    s.push_str("  ");
    s.push_str(MONTH_NAMES[usize::from(t.month.clamp(1, 12) - 1)]);
    s.push(' ');
    if t.day >= 10 {
        s.push(char::from(b'0' + t.day / 10));
    }
    s.push(char::from(b'0' + t.day % 10));
    s
}

/// Decode the raw registers; `None` if any field is out of range.
#[must_use]
pub fn decode(raw: &hal::rtc::RtcRaw) -> Option<WallTime> {
    let binary = raw.status_b & STATUS_B_BINARY != 0;
    let conv = |v: u8| -> Option<u8> {
        if binary {
            Some(v)
        } else if v & 0x0F <= 9 && v >> 4 <= 9 {
            Some((v >> 4) * 10 + (v & 0x0F))
        } else {
            None
        }
    };
    let pm = raw.hours & 0x80 != 0;
    let mut hour = conv(raw.hours & 0x7F)?;
    if raw.status_b & STATUS_B_24H == 0 {
        // 12-hour mode: 12 AM is 0, 12 PM is 12.
        if !(1..=12).contains(&hour) {
            return None;
        }
        hour = hour % 12 + if pm { 12 } else { 0 };
    }
    let minute = conv(raw.minutes)?;
    let second = conv(raw.seconds)?;
    let day = conv(raw.day)?;
    let month = conv(raw.month)?;
    let yy = conv(raw.year)?;
    // Trust the century register only when it decodes to something sane.
    let century = conv(raw.century)
        .filter(|c| (19..=30).contains(c))
        .unwrap_or(20);
    if hour > 23
        || minute > 59
        || second > 59
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
    {
        return None;
    }
    let year = u16::from(century) * 100 + u16::from(yy);
    let days = days_from_civil(i64::from(year), u32::from(month), u32::from(day));
    Some(WallTime {
        year,
        month,
        day,
        weekday: weekday(days),
        hour,
        minute,
        second,
    })
}

fn to_epoch_secs(t: &WallTime) -> u64 {
    let days = days_from_civil(i64::from(t.year), u32::from(t.month), u32::from(t.day));
    let secs_of_day = u64::from(t.hour) * 3600 + u64::from(t.minute) * 60 + u64::from(t.second);
    // Years 1900–3099 only (see `decode`); 1900–1969 clamps to the epoch.
    u64::try_from(days).unwrap_or(0) * 86_400 + secs_of_day
}

fn from_epoch_secs(secs: u64) -> WallTime {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    WallTime {
        year: year as u16,
        month: month as u8,
        day: day as u8,
        weekday: weekday(days),
        hour: (rem / 3600) as u8,
        minute: ((rem % 3600) / 60) as u8,
        second: (rem % 60) as u8,
    }
}

/// 0 = Sunday; 1970-01-01 (day 0) was a Thursday.
fn weekday(days: i64) -> u8 {
    (days + 4).rem_euclid(7) as u8
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Inverse of [`days_from_civil`].
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// Zero-padded decimal through the fmt-free serial helper (`println!` with
/// integer args faults on this target; see `lib.rs`).
fn write_dec_pad(v: u64, width: u32) {
    let mut pow = 10u64.pow(width.saturating_sub(1));
    while pow > 1 && v < pow {
        hal::serial::write_str("0");
        pow /= 10;
    }
    hal::serial::write_dec(v);
}
