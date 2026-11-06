//! Wall-clock date and time from the CMOS RTC (`hal::rtc`), read once at boot.
//!
//! The idle loop reads the RTC live ([`now`], ~10 times a second) for the lock
//! screen and desktop clock. Counting PIT seconds from a boot reading drifts
//! under a hypervisor (lost ticks), so that ([`at`]) is only the fallback when
//! a live read fails. Decoding the raw registers
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

/// The current wall time: a live RTC reading, or, if the RTC doesn't give a
/// valid one, the boot reading plus `elapsed_secs` ([`at`]). Call from the BSP
/// only (`hal::rtc`'s single-caller contract): the idle loop does.
#[must_use]
pub fn now(elapsed_secs: u64) -> Option<WallTime> {
    hal::rtc::read()
        .and_then(|raw| decode(&raw))
        .or_else(|| at(elapsed_secs))
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

#[cfg(test)]
mod tests {
    use super::*;
    use hal::rtc::RtcRaw;

    /// Status B as firmware usually leaves it: BCD, 24-hour.
    const BCD_24H: u8 = STATUS_B_24H;

    fn raw(status_b: u8, hours: u8) -> RtcRaw {
        // 2026-11-06 23:40:01 in BCD, century 0x20.
        RtcRaw {
            seconds: 0x01,
            minutes: 0x40,
            hours,
            day: 0x06,
            month: 0x11,
            year: 0x26,
            century: 0x20,
            status_b,
        }
    }

    #[test]
    fn decodes_bcd_24h() {
        let t = decode(&raw(BCD_24H, 0x23)).unwrap();
        assert_eq!((t.year, t.month, t.day), (2026, 11, 6));
        assert_eq!((t.hour, t.minute, t.second), (23, 40, 1));
        // 2026-11-06 is a Friday.
        assert_eq!(t.weekday, 5);
    }

    #[test]
    fn decodes_binary() {
        let r = RtcRaw {
            seconds: 1,
            minutes: 40,
            hours: 23,
            day: 6,
            month: 11,
            year: 26,
            century: 20,
            status_b: STATUS_B_BINARY | STATUS_B_24H,
        };
        assert_eq!(decode(&r), decode(&raw(BCD_24H, 0x23)));
    }

    #[test]
    fn twelve_hour_mode() {
        // 12-hour BCD: bit 7 = PM.
        assert_eq!(decode(&raw(0, 0x12)).unwrap().hour, 0); // 12 AM
        assert_eq!(decode(&raw(0, 0x80 | 0x12)).unwrap().hour, 12); // 12 PM
        assert_eq!(decode(&raw(0, 0x80 | 0x11)).unwrap().hour, 23); // 11 PM
        assert_eq!(decode(&raw(0, 0x01)).unwrap().hour, 1); // 1 AM
        assert_eq!(decode(&raw(0, 0x00)), None); // no hour 0 in 12-hour mode
    }

    #[test]
    fn rejects_bad_values() {
        assert_eq!(decode(&raw(BCD_24H, 0x24)), None); // hour 24
        assert_eq!(decode(&raw(BCD_24H, 0x1A)), None); // not BCD
        let mut r = raw(BCD_24H, 0x23);
        r.month = 0x13;
        assert_eq!(decode(&r), None);
        r.month = 0x11;
        r.day = 0x00;
        assert_eq!(decode(&r), None);
    }

    #[test]
    fn century_falls_back_to_20() {
        let mut r = raw(BCD_24H, 0x23);
        r.century = 0x00; // firmware doesn't keep one
        assert_eq!(decode(&r).unwrap().year, 2026);
        r.century = 0xFF; // garbage
        assert_eq!(decode(&r).unwrap().year, 2026);
    }

    #[test]
    fn calendar_math() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(weekday(0), 4); // Thursday
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        // Leap day, and the day after.
        let leap = days_from_civil(2024, 2, 29);
        assert_eq!(civil_from_days(leap), (2024, 2, 29));
        assert_eq!(civil_from_days(leap + 1), (2024, 3, 1));
        // 2100 is not a leap year.
        assert_eq!(
            civil_from_days(days_from_civil(2100, 2, 28) + 1),
            (2100, 3, 1)
        );
    }

    #[test]
    fn rolls_over_midnight_and_year() {
        let t = decode(&RtcRaw {
            seconds: 0x59,
            minutes: 0x59,
            hours: 0x23,
            day: 0x31,
            month: 0x12,
            year: 0x26,
            century: 0x20,
            status_b: BCD_24H,
        })
        .unwrap();
        let next = from_epoch_secs(to_epoch_secs(&t) + 1);
        assert_eq!((next.year, next.month, next.day), (2027, 1, 1));
        assert_eq!((next.hour, next.minute, next.second), (0, 0, 0));
        // 2027-01-01 is a Friday.
        assert_eq!(next.weekday, 5);
    }

    #[test]
    fn date_line_format() {
        let t = decode(&raw(BCD_24H, 0x23)).unwrap();
        assert_eq!(date_line(&t), "FRIDAY  NOVEMBER 6");
        let mut r = raw(BCD_24H, 0x23);
        r.day = 0x14; // 2026-11-14, a Saturday
        assert_eq!(date_line(&decode(&r).unwrap()), "SATURDAY  NOVEMBER 14");
    }
}
