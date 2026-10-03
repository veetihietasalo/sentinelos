//! The denial log — fixed-size, allocation-free, rate-limited (amendment A8;
//! threat T-DOS-3 in `docs/security/threat-model.md`).
//!
//! Every authority refusal the host makes is reported here: who (the
//! kernel-stamped [`Sender`]), what they presented (the raw [`CapIndex`]),
//! what they tried ([`Action`]), why it was refused ([`DenyReason`]) and when
//! (a mono tick). Components only ever see "denied"; the reason lives here.
//!
//! # Rate limiting, without losing count
//!
//! A misbehaving component must not be able to flush the log, so each holder
//! (one bucket per instance slot, plus one for refusals that have no instance
//! yet) has a token bucket: [`DENY_BURST`] records, then one more per
//! [`DENY_REFILL_TICKS`]. A denial with no token is **suppressed, never
//! silent**: it is counted globally and per holder, and that holder's next
//! record carries `suppressed_before`. The ring keeps the newest
//! [`DENY_LOG_LEN`] records and counts every overwrite. So
//! `logged + suppressed == total` always holds, and the console is never a
//! component-controlled channel (nothing is printed per denial).
//!
//! Kani: `proofs::deny_log_counts_every_denial` (totals and the per-holder
//! rate bound over a symbolic sequence). The IntegrityLog (PR-4) makes this
//! durable and signed; this is the in-memory, per-boot first step.

use super::{CapIndex, DenyReason, Tick};
use crate::host::codec::Sender;

/// Records the ring keeps (the newest win; overwrites are counted).
pub const DENY_LOG_LEN: usize = 32;
/// Records one holder may write back to back before suppression starts.
pub const DENY_BURST: u32 = 8;
/// Ticks per refilled token (0.5 s at 100 Hz).
pub const DENY_REFILL_TICKS: Tick = 50;

/// What the refused party attempted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    /// `bus::send`.
    Send,
    /// `bus::request`.
    Request,
    /// `bus::reply`.
    Reply,
    /// `bus::delegate`.
    Delegate,
    /// `bus::revoke`.
    Revoke,
    /// `bus::release`.
    Release,
    /// A manifest capability at instantiation.
    Grant,
}

impl Action {
    /// Fixed label for `fmt`-free console output.
    pub const fn label(self) -> &'static str {
        match self {
            Action::Send => "send",
            Action::Request => "request",
            Action::Reply => "reply",
            Action::Delegate => "delegate",
            Action::Revoke => "revoke",
            Action::Release => "release",
            Action::Grant => "grant",
        }
    }
}

/// One logged refusal.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DenyRecord {
    /// Position among all records ever logged this boot (0-based).
    pub seq: u64,
    /// Mono tick of the refusal.
    pub tick: Tick,
    /// Who was refused, as the kernel knows them.
    pub holder: Sender,
    /// The index they presented, verbatim.
    pub index: CapIndex,
    /// What they tried.
    pub action: Action,
    /// Why it was refused.
    pub reason: DenyReason,
    /// This holder's refusals suppressed since its previous record.
    pub suppressed_before: u32,
}

/// Counters over the whole boot. `logged + suppressed == total`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct DenyTotals {
    /// Every refusal reported.
    pub total: u64,
    /// Refusals written as records.
    pub logged: u64,
    /// Refusals counted but not written (rate limit).
    pub suppressed: u64,
    /// Records pushed out of the ring by newer ones.
    pub overwritten: u64,
}

#[derive(Clone, Copy)]
struct Bucket {
    tokens: u32,
    last: Tick,
    suppressed_since: u32,
}

/// The log: `B` rate-limit buckets, an `N`-record ring.
pub struct DenyLog<const B: usize, const N: usize> {
    ring: [Option<DenyRecord>; N],
    /// Index of the oldest record.
    head: usize,
    len: usize,
    buckets: [Bucket; B],
    burst: u32,
    refill: Tick,
    totals: DenyTotals,
}

impl<const B: usize, const N: usize> Default for DenyLog<B, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const B: usize, const N: usize> DenyLog<B, N> {
    const SIZES_OK: () = assert!(B >= 1 && N >= 1);

    /// The production limits.
    pub const fn new() -> Self {
        Self::with_limits(DENY_BURST, DENY_REFILL_TICKS)
    }

    /// Custom limits (tests and Kani use small ones). `refill` is at least 1.
    pub const fn with_limits(burst: u32, refill: Tick) -> Self {
        #[allow(clippy::let_unit_value)]
        let () = Self::SIZES_OK;
        Self {
            ring: [None; N],
            head: 0,
            len: 0,
            buckets: [Bucket {
                tokens: burst,
                last: 0,
                suppressed_since: 0,
            }; B],
            burst,
            refill: if refill == 0 { 1 } else { refill },
            totals: DenyTotals {
                total: 0,
                logged: 0,
                suppressed: 0,
                overwritten: 0,
            },
        }
    }

    /// Report one refusal by `holder` (rate-limited in bucket `bucket`; out of
    /// range means the last bucket). Returns whether a record was written.
    /// Total: never panics, never allocates.
    pub fn record(
        &mut self,
        now: Tick,
        bucket: usize,
        holder: Sender,
        index: CapIndex,
        action: Action,
        reason: DenyReason,
    ) -> bool {
        self.totals.total = self.totals.total.saturating_add(1);
        let b = &mut self.buckets[bucket.min(B - 1)];
        // Refill whole tokens for the whole periods elapsed (never backwards).
        if now > b.last {
            let periods = (now - b.last) / self.refill;
            if periods > 0 {
                let add = u32::try_from(periods).unwrap_or(u32::MAX);
                b.tokens = b.tokens.saturating_add(add).min(self.burst);
                b.last = b.last.saturating_add(periods.saturating_mul(self.refill));
            }
        }
        if b.tokens == 0 {
            b.suppressed_since = b.suppressed_since.saturating_add(1);
            self.totals.suppressed = self.totals.suppressed.saturating_add(1);
            return false;
        }
        b.tokens -= 1;
        let rec = DenyRecord {
            seq: self.totals.logged,
            tick: now,
            holder,
            index,
            action,
            reason,
            suppressed_before: b.suppressed_since,
        };
        b.suppressed_since = 0;
        if self.len == N {
            // Full: the newest record replaces the oldest, counted.
            self.ring[self.head] = Some(rec);
            self.head = (self.head + 1) % N;
            self.totals.overwritten = self.totals.overwritten.saturating_add(1);
        } else {
            self.ring[(self.head + self.len) % N] = Some(rec);
            self.len += 1;
        }
        self.totals.logged = self.totals.logged.saturating_add(1);
        true
    }

    /// A new instance took bucket `bucket`'s slot: give it a full budget
    /// starting at `now`.
    pub fn reset_bucket(&mut self, bucket: usize, now: Tick) {
        if let Some(b) = self.buckets.get_mut(bucket) {
            *b = Bucket {
                tokens: self.burst,
                last: now,
                suppressed_since: 0,
            };
        }
    }

    /// The boot's counters.
    pub fn totals(&self) -> DenyTotals {
        self.totals
    }

    /// Records currently held.
    pub fn len(&self) -> usize {
        self.len
    }

    /// `true` when no record is held.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The `i`-th oldest record held.
    pub fn get(&self, i: usize) -> Option<DenyRecord> {
        if i < self.len {
            self.ring[(self.head + i) % N]
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{ComponentId, InstanceId};

    fn who(n: u64) -> Sender {
        Sender {
            instance: InstanceId(n),
            component: ComponentId([n as u8; 32]),
        }
    }

    fn deny(log: &mut DenyLog<3, 4>, now: Tick, bucket: usize) -> bool {
        log.record(
            now,
            bucket,
            who(bucket as u64),
            CapIndex(7),
            Action::Send,
            DenyReason::NotHeld,
        )
    }

    #[test]
    fn a_burst_is_logged_then_suppressed_and_counted() {
        let mut log: DenyLog<3, 4> = DenyLog::with_limits(2, 10);
        assert!(deny(&mut log, 0, 0));
        assert!(deny(&mut log, 0, 0));
        assert!(!deny(&mut log, 1, 0), "third in the burst is suppressed");
        assert!(!deny(&mut log, 2, 0));
        // Another holder has its own budget.
        assert!(deny(&mut log, 2, 1));
        let t = log.totals();
        assert_eq!((t.total, t.logged, t.suppressed), (5, 3, 2));
        // One period later: one token back, and the record says what it missed.
        assert!(deny(&mut log, 10, 0));
        let last = log.get(log.len() - 1).unwrap();
        assert_eq!(last.suppressed_before, 2);
        assert_eq!(last.holder, who(0));
        assert_eq!(last.seq, 3);
        assert!(!deny(&mut log, 10, 0));
    }

    #[test]
    fn the_ring_keeps_the_newest_and_counts_overwrites() {
        let mut log: DenyLog<3, 4> = DenyLog::with_limits(100, 1);
        for i in 0..6 {
            assert!(deny(&mut log, i, 2));
        }
        assert_eq!(log.len(), 4);
        assert_eq!(log.get(0).unwrap().seq, 2, "two oldest were overwritten");
        assert_eq!(log.get(3).unwrap().seq, 5);
        assert_eq!(log.get(4), None);
        let t = log.totals();
        assert_eq!((t.logged, t.overwritten), (6, 2));
    }

    #[test]
    fn out_of_range_buckets_share_the_last_and_reset_restores_a_budget() {
        let mut log: DenyLog<3, 4> = DenyLog::with_limits(1, 1000);
        assert!(deny(&mut log, 0, 99));
        assert!(!deny(&mut log, 0, 2), "99 and 2 share the last bucket");
        log.reset_bucket(2, 0);
        assert!(deny(&mut log, 0, 2));
        // A clock that does not move never refills; one that jumps is clamped.
        assert!(!deny(&mut log, 0, 2));
        assert!(deny(&mut log, u64::MAX, 2));
        assert!(log.totals().total == log.totals().logged + log.totals().suppressed);
    }
}

/// Kani harnesses for the log. Compiled only under `cargo kani`.
#[cfg(kani)]
mod proofs {
    use super::*;
    use crate::host::{ComponentId, InstanceId};

    /// Over a bounded symbolic sequence of refusals — symbolic holders
    /// (including out-of-range buckets) and a symbolic, non-decreasing clock —
    /// on a 2-bucket, 3-record log with burst 2 and refill 3: every refusal is
    /// counted (`logged + suppressed == total`), the ring never holds more than
    /// its size and counts what it overwrote, records are numbered in order,
    /// and no holder ever gets more records than `burst + elapsed / refill`.
    #[kani::proof]
    #[kani::unwind(8)]
    fn deny_log_counts_every_denial() {
        const STEPS: usize = 6;
        const BURST: u32 = 2;
        const REFILL: Tick = 3;
        let mut log: DenyLog<2, 3> = DenyLog::with_limits(BURST, REFILL);
        let mut per_bucket = [0u64; 2];
        let mut now: Tick = 0;
        for _ in 0..STEPS {
            now += Tick::from(kani::any::<u8>() % 4);
            let bucket: usize = kani::any();
            let holder = Sender {
                instance: InstanceId(kani::any()),
                component: ComponentId([0; 32]),
            };
            let logged = log.record(
                now,
                bucket,
                holder,
                CapIndex(kani::any()),
                Action::Send,
                DenyReason::NotHeld,
            );
            if logged {
                per_bucket[bucket.min(1)] += 1;
                let newest = log.get(log.len() - 1);
                assert!(newest.is_some_and(|r| r.seq + 1 == log.totals().logged));
            }
            let t = log.totals();
            assert!(t.logged + t.suppressed == t.total);
            assert!(log.len() <= 3);
            assert!(t.overwritten == t.logged.saturating_sub(3));
            for b in 0..2 {
                assert!(per_bucket[b] <= u64::from(BURST) + now / REFILL);
            }
        }
    }
}
