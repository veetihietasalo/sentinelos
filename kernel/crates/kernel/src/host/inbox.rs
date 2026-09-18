//! Fixed-capacity FIFO — the per-instance inbox ring (spec §7).
//!
//! Every component instance owns one `InboxRing<Wire, MAX_INBOX>`. A sender
//! whose target's ring is full gets `Err(Busy)` and the ring is left exactly as
//! it was: **nothing is dropped silently and nothing grows**. The ring never
//! allocates, so pushing from any context is safe under the scheduler's
//! "no allocation under an IRQ-taken lock" rule.
//!
//! Generic over the element so the Kani harness proves the same code over
//! `InboxRing<u8, 3>` that production runs over `InboxRing<Wire, 8>`:
//! `proofs::inbox_ring_is_fifo_and_never_loses_or_overwrites_bounded`.

/// The ring is full; the push did not happen.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Busy;

/// A bounded FIFO over `[Option<T>; N]`.
#[derive(Clone, Copy)]
pub struct InboxRing<T: Copy, const N: usize> {
    buf: [Option<T>; N],
    head: usize,
    len: usize,
}

impl<T: Copy, const N: usize> Default for InboxRing<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Copy, const N: usize> InboxRing<T, N> {
    /// An empty ring.
    pub const fn new() -> Self {
        Self {
            buf: [None; N],
            head: 0,
            len: 0,
        }
    }

    /// Maximum number of queued items.
    pub const fn capacity() -> usize {
        N
    }

    /// Number of queued items.
    pub fn len(&self) -> usize {
        self.len
    }

    /// `true` when nothing is queued.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// `true` when the next `push` would return `Busy`.
    pub fn is_full(&self) -> bool {
        self.len == N
    }

    /// Enqueue at the tail; `Err(Busy)` (and no change) when full.
    pub fn push(&mut self, item: T) -> Result<(), Busy> {
        if self.len == N {
            return Err(Busy);
        }
        self.buf[(self.head + self.len) % N] = Some(item);
        self.len += 1;
        Ok(())
    }

    /// Dequeue the oldest item, if any.
    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        let item = self.buf[self.head].take();
        self.head = (self.head + 1) % N;
        self.len -= 1;
        item
    }

    /// The `i`-th queued item from the head, if `i < len()`. Inspection for
    /// the host tests and the Kani harness; production only pushes and pops.
    #[cfg_attr(not(any(test, kani)), allow(dead_code))]
    pub fn get(&self, i: usize) -> Option<T> {
        if i < self.len {
            self.buf[(self.head + i) % N]
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Busy, InboxRing};

    #[test]
    fn fifo_order_and_wraparound() {
        let mut ring: InboxRing<u32, 3> = InboxRing::new();
        assert!(ring.is_empty());
        assert_eq!(InboxRing::<u32, 3>::capacity(), 3);
        for i in 0..3 {
            ring.push(i).unwrap();
        }
        assert!(ring.is_full());
        assert_eq!(ring.pop(), Some(0));
        ring.push(3).unwrap(); // wraps around the physical end
        assert_eq!(ring.get(0), Some(1));
        assert_eq!(ring.get(2), Some(3));
        assert_eq!(ring.get(3), None);
        assert_eq!(ring.pop(), Some(1));
        assert_eq!(ring.pop(), Some(2));
        assert_eq!(ring.pop(), Some(3));
        assert_eq!(ring.pop(), None);
    }

    #[test]
    fn full_ring_refuses_and_keeps_its_contents() {
        let mut ring: InboxRing<u8, 2> = InboxRing::new();
        ring.push(10).unwrap();
        ring.push(11).unwrap();
        assert_eq!(ring.push(12), Err(Busy));
        assert_eq!(ring.len(), 2);
        assert_eq!(ring.get(0), Some(10));
        assert_eq!(ring.get(1), Some(11));
        assert_eq!(ring.pop(), Some(10));
        assert_eq!(ring.pop(), Some(11));
        assert_eq!(ring.pop(), None);
    }
}

/// Kani proof harnesses. Compiled only under `cargo kani`.
#[cfg(kani)]
mod proofs {
    use super::{Busy, InboxRing};

    /// Over a bounded, symbolic mix of pushes and pops on a 3-slot ring: items
    /// come out in the order they went in, a push onto a full ring is refused
    /// and changes nothing, a pop from an empty ring yields nothing, and the
    /// length always equals pushes-accepted minus pops-served — so no item is
    /// ever lost, duplicated, or overwritten. The direct analogue of
    /// `sched::proofs::invariant4_no_lost_or_duplicated_ids_bounded`.
    #[kani::proof]
    fn inbox_ring_is_fifo_and_never_loses_or_overwrites_bounded() {
        const STEPS: usize = 6;
        const CAP: usize = 3;
        let mut ring: InboxRing<u8, CAP> = InboxRing::new();
        // Items are pushed as 0, 1, 2, … so order is checkable by value.
        let mut next_push: u8 = 0;
        let mut next_pop: u8 = 0;
        for _ in 0..STEPS {
            let before = ring.len();
            let do_push: bool = kani::any();
            if do_push {
                match ring.push(next_push) {
                    Ok(()) => {
                        assert!(before < CAP);
                        assert!(ring.len() == before + 1);
                        next_push += 1;
                    }
                    Err(Busy) => {
                        assert!(before == CAP);
                        assert!(ring.len() == CAP);
                    }
                }
            } else {
                match ring.pop() {
                    Some(v) => {
                        assert!(before > 0);
                        assert!(v == next_pop);
                        assert!(ring.len() == before - 1);
                        next_pop += 1;
                    }
                    None => assert!(before == 0),
                }
            }
            assert!(ring.len() == usize::from(next_push - next_pop));
            // Everything still queued is exactly the unpopped prefix, in order.
            for i in 0..CAP {
                match ring.get(i) {
                    Some(v) => assert!(v == next_pop + i as u8),
                    None => assert!(i >= ring.len()),
                }
            }
        }
    }
}
