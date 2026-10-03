//! What the PR-2 probe components were handed — the boot proof's recorder
//! (`crate::bus::proof`), kept out of the component module itself
//! (`super::probe`) so that module names nothing of the kernel beyond its
//! `bus::Ctx` (threat T-NAT-1, `cargo xtask check-component-imports`).
//!
//! A probe's message handler calls [`record`] with the envelope exactly as it
//! was delivered, so the proof can check `from` as the **recipient** saw it.

use super::codec::{Envelope, Kind, Sender};
use super::InstanceId;
use crate::cap::CapIndex;
use hal::sync::SpinMutex;

/// One envelope a probe's handler was handed — exactly what the recipient
/// observed, `from` included.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Seen {
    /// The recipient.
    pub at: InstanceId,
    /// The kernel-stamped sender, as delivered.
    pub from: Sender,
    /// The kind (with its tag or granted index).
    pub kind: Kind,
    /// The sender's index that authorised it, as delivered.
    pub cap: CapIndex,
    /// Payload length.
    pub len: u16,
    /// bob's answer to a request: `Some(true)` answered, `Some(false)` his
    /// answer was refused, `None` not answered (or not a request).
    pub answered: Option<bool>,
}

/// Envelopes the log keeps; later ones are only counted.
pub const SEEN_LEN: usize = 32;

struct SeenLog {
    buf: [Option<Seen>; SEEN_LEN],
    len: usize,
    overflow: u64,
}

/// A leaf lock (nothing is acquired while it is held), never taken from IRQ
/// context, taken with interrupts masked anyway, never while the host lock is
/// held.
static SEEN: SpinMutex<SeenLog> = SpinMutex::new(SeenLog {
    buf: [None; SEEN_LEN],
    len: 0,
    overflow: 0,
});

/// Record that `at` was handed `env` (and, for bob, how his answer went).
pub(crate) fn record(at: InstanceId, env: &Envelope, answered: Option<bool>) {
    let s = Seen {
        at,
        from: env.from,
        kind: env.kind,
        cap: env.cap,
        len: env.payload.len() as u16,
        answered,
    };
    crate::bus::irq_masked(|| {
        let mut log = SEEN.lock();
        if log.len < SEEN_LEN {
            let i = log.len;
            log.buf[i] = Some(s);
            log.len += 1;
        } else {
            log.overflow = log.overflow.saturating_add(1);
        }
    });
}

/// Forget everything seen so far.
pub fn seen_reset() {
    crate::bus::irq_masked(|| {
        let mut log = SEEN.lock();
        log.len = 0;
        log.overflow = 0;
    });
}

/// The newest envelope `at` was handed, if any is still recorded.
pub fn seen_last_for(at: InstanceId) -> Option<Seen> {
    crate::bus::irq_masked(|| {
        let log = SEEN.lock();
        log.buf[..log.len]
            .iter()
            .rev()
            .flatten()
            .find(|s| s.at == at)
            .copied()
    })
}

/// Envelopes handed to any probe since the last reset (recorded + overflow).
pub fn seen_total() -> u64 {
    crate::bus::irq_masked(|| {
        let log = SEEN.lock();
        log.len as u64 + log.overflow
    })
}
