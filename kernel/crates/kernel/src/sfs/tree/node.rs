//! The B+tree node algebra, `Node<V, CAP>` (spec §7.2), separate from any
//! block encoding so Kani can prove it at `CAP = 4` (A19) while the kernel
//! runs it at the real fan-out.
//!
//! A node is a sorted run of `(Key, V)` entries. Every entry has a **weight**
//! ([`Entry::weight`]): the bytes it occupies in the 4 KiB encoding (a leaf
//! item's table slot plus its data; an internal entry's key plus pointer). A
//! node fits its block iff its total weight is at most the block's payload,
//! the `limit` every policy function here takes. The rules, all deterministic
//! functions of the entries alone:
//!
//! - **Split at half** ([`Node::split_point`]): a node over `limit` is cut at
//!   the index that makes the two halves' weights closest, ties to the lower
//!   index. As long as no single entry weighs more than `limit / 2`
//!   (the format guarantees it: §7.2 caps inline data at 1 KiB and extents at
//!   32 hashes), both halves fit and neither underflows.
//! - **Merge below a quarter** ([`Node::underflows`], [`Node::rebalance`]): a
//!   node under `limit / 4` is combined with a sibling — merged into one if the
//!   pair fits, otherwise re-cut with the same half rule, which leaves both at
//!   or above a quarter.
//!
//! The separator between two siblings is always the first key of the right
//! one (the parent stores, for every child, the lowest key in it).
//!
//! **What "deterministic" buys, honestly.** Each rule is a pure function of
//! the entries it is given, so replaying the same operation sequence yields
//! the same nodes (principle 4's *deterministic history*). It does **not**
//! make the shape a function of the key set alone: an insert-split-then-merge
//! B+tree reaches different node boundaries for the same keys inserted in
//! different orders. What is order-independent is the tree's *items* (its
//! in-order contents), which the host tests check (§5 principle 4 as built;
//! the FS-1b deviation note in the spec).
//!
//! Storage is two inline arrays of exactly `CAP` entries — cheap for Kani at
//! `CAP = 4`. A kernel-sized node is several kilobytes, so the kernel never
//! builds a group of them on a task stack: [`boxed`] puts them on the heap
//! one at a time. Nothing here allocates otherwise, and every loop is
//! bounded by `CAP`.

use crate::sfs::key::Key;
use alloc::boxed::Box;

/// `n` empty nodes on the heap, built one at a time (a single node is the
/// largest stack temporary — never the whole group, which matters on a
/// kernel task's stack in a debug build).
#[must_use]
pub fn boxed<V: Entry, const CAP: usize>(n: usize, fill: V) -> Box<[Node<V, CAP>]> {
    (0..n).map(|_| Node::new(fill)).collect()
}

/// A node entry's value: something with an on-disk weight.
pub trait Entry: Copy {
    /// Bytes the entry occupies in its encoded node (table slot + data).
    fn weight(&self) -> u32;
}

/// The all-zero key, used to fill unused slots.
pub const KEY_ZERO: Key = Key {
    obj: 0,
    kind: 0,
    off: 0,
};

/// A node operation was refused; the node is unchanged.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NodeError {
    /// The in-memory node has no room for another entry (`CAP` reached).
    Full,
    /// An index past the entries, or an operation that needs more entries.
    Index,
    /// The entries would not stay strictly sorted.
    Order,
}

/// What [`Node::rebalance`] did with an underflowing pair.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Rebalance {
    /// Everything now lives in the left node; the right one is empty.
    Merged,
    /// The entries were re-cut at half; the new separator is the right node's
    /// first key.
    Split(Key),
}

/// A B+tree node of at most `CAP` entries in memory.
#[derive(Clone, Debug)]
pub struct Node<V: Entry, const CAP: usize> {
    len: usize,
    keys: [Key; CAP],
    vals: [V; CAP],
}

impl<V: Entry, const CAP: usize> Node<V, CAP> {
    /// An empty node; `fill` initialises the unused value slots.
    #[must_use]
    pub fn new(fill: V) -> Self {
        Node {
            len: 0,
            keys: [KEY_ZERO; CAP],
            vals: [fill; CAP],
        }
    }

    /// Number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the node has no entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Drop every entry.
    pub fn clear(&mut self) {
        self.len = 0;
    }

    /// The `i`-th key.
    #[must_use]
    pub fn key(&self, i: usize) -> Option<Key> {
        if i < self.len {
            self.keys.get(i).copied()
        } else {
            None
        }
    }

    /// The `i`-th value.
    #[must_use]
    pub fn val(&self, i: usize) -> Option<V> {
        if i < self.len {
            self.vals.get(i).copied()
        } else {
            None
        }
    }

    /// The live keys.
    #[must_use]
    pub fn keys(&self) -> &[Key] {
        self.keys.get(..self.len).unwrap_or(&[])
    }

    /// Replace the `i`-th value.
    ///
    /// # Errors
    ///
    /// [`NodeError::Index`] past the entries.
    pub fn set_val(&mut self, i: usize, v: V) -> Result<(), NodeError> {
        if i >= self.len {
            return Err(NodeError::Index);
        }
        *self.vals.get_mut(i).ok_or(NodeError::Index)? = v;
        Ok(())
    }

    /// Replace the `i`-th key, keeping the order strict.
    ///
    /// # Errors
    ///
    /// [`NodeError::Index`] past the entries; [`NodeError::Order`] if `k` would
    /// not sit strictly between its neighbours.
    pub fn set_key(&mut self, i: usize, k: Key) -> Result<(), NodeError> {
        if i >= self.len {
            return Err(NodeError::Index);
        }
        let after_prev = i == 0 || self.key(i - 1).is_some_and(|p| p < k);
        let before_next = self.key(i + 1).is_none_or(|n| k < n);
        if !(after_prev && before_next) {
            return Err(NodeError::Order);
        }
        *self.keys.get_mut(i).ok_or(NodeError::Index)? = k;
        Ok(())
    }

    /// Total weight of the entries.
    #[must_use]
    pub fn weight(&self) -> u64 {
        self.vals
            .iter()
            .take(self.len)
            .map(|v| u64::from(v.weight()))
            .sum()
    }

    /// Binary search: `Ok(i)` if `k` is the `i`-th key, else `Err(i)` with the
    /// index it would be inserted at.
    pub fn search(&self, k: &Key) -> Result<usize, usize> {
        self.keys().binary_search(k)
    }

    /// For an internal node: the child whose range holds `k` — the last entry
    /// whose key is `≤ k`, or entry 0 when `k` sorts before them all.
    #[must_use]
    pub fn child_index(&self, k: &Key) -> usize {
        match self.search(k) {
            Ok(i) => i,
            Err(i) => i.saturating_sub(1),
        }
    }

    /// Insert `(k, v)` at index `i`, shifting the tail right.
    ///
    /// # Errors
    ///
    /// [`NodeError::Full`] at `CAP`; [`NodeError::Index`] for `i > len`;
    /// [`NodeError::Order`] if the result would not be strictly sorted.
    pub fn insert(&mut self, i: usize, k: Key, v: V) -> Result<(), NodeError> {
        if self.len >= CAP || self.len >= self.keys.len() || self.len >= self.vals.len() {
            return Err(NodeError::Full);
        }
        if i > self.len {
            return Err(NodeError::Index);
        }
        let after_prev = i == 0 || self.key(i - 1).is_some_and(|p| p < k);
        let before_next = self.key(i).is_none_or(|n| k < n);
        if !(after_prev && before_next) {
            return Err(NodeError::Order);
        }
        self.keys.copy_within(i..self.len, i + 1);
        self.vals.copy_within(i..self.len, i + 1);
        self.keys[i] = k;
        self.vals[i] = v;
        self.len += 1;
        Ok(())
    }

    /// Append `(k, v)` after the last entry.
    ///
    /// # Errors
    ///
    /// As [`insert`](Self::insert).
    pub fn push(&mut self, k: Key, v: V) -> Result<(), NodeError> {
        self.insert(self.len, k, v)
    }

    /// Remove and return the `i`-th entry, shifting the tail left.
    ///
    /// # Errors
    ///
    /// [`NodeError::Index`] past the entries.
    pub fn remove(&mut self, i: usize) -> Result<(Key, V), NodeError> {
        let (k, v) = (
            self.key(i).ok_or(NodeError::Index)?,
            self.val(i).ok_or(NodeError::Index)?,
        );
        self.keys.copy_within(i + 1..self.len, i);
        self.vals.copy_within(i + 1..self.len, i);
        self.len -= 1;
        Ok((k, v))
    }

    /// Append every entry of `other` (whose keys must all sort after ours).
    ///
    /// # Errors
    ///
    /// [`NodeError::Full`] if the result exceeds `CAP`; [`NodeError::Order`]
    /// if `other`'s first key does not sort after our last. Unchanged on error.
    pub fn append(&mut self, other: &Self) -> Result<(), NodeError> {
        let n = other.len;
        if self.len + n > CAP {
            return Err(NodeError::Full);
        }
        if let (Some(last), Some(first)) = (self.len.checked_sub(1), other.key(0)) {
            if self.key(last).is_none_or(|l| l >= first) {
                return Err(NodeError::Order);
            }
        }
        let (dk, dv) = (
            self.keys
                .get_mut(self.len..self.len + n)
                .ok_or(NodeError::Full)?,
            self.vals
                .get_mut(self.len..self.len + n)
                .ok_or(NodeError::Full)?,
        );
        dk.copy_from_slice(other.keys.get(..n).ok_or(NodeError::Index)?);
        dv.copy_from_slice(other.vals.get(..n).ok_or(NodeError::Index)?);
        self.len += n;
        Ok(())
    }

    /// Move entries `[at, len)` into `dst` (which is cleared first) and keep
    /// `[0, at)`.
    ///
    /// # Errors
    ///
    /// [`NodeError::Index`] unless `0 < at < len` (both halves non-empty).
    pub fn split_off(&mut self, at: usize, dst: &mut Self) -> Result<(), NodeError> {
        if at == 0 || at >= self.len {
            return Err(NodeError::Index);
        }
        let n = self.len - at;
        let (sk, sv) = (
            self.keys.get(at..self.len).ok_or(NodeError::Index)?,
            self.vals.get(at..self.len).ok_or(NodeError::Index)?,
        );
        let (dk, dv) = (
            dst.keys.get_mut(..n).ok_or(NodeError::Full)?,
            dst.vals.get_mut(..n).ok_or(NodeError::Full)?,
        );
        dk.copy_from_slice(sk);
        dv.copy_from_slice(sv);
        dst.len = n;
        self.len = at;
        Ok(())
    }

    /// Where a split at half cuts: the index `i` in `1..len` that makes the
    /// two halves' weights closest (`|2·W(0..i) − W|` minimal), ties to the
    /// lowest `i`. `None` for fewer than two entries.
    #[must_use]
    pub fn split_point(&self) -> Option<usize> {
        if self.len < 2 {
            return None;
        }
        let total = self.weight();
        let mut left = 0u64;
        let mut best: Option<(usize, u64)> = None;
        for i in 1..self.len {
            left += u64::from(self.val(i - 1)?.weight());
            let diff = (2 * left).abs_diff(total);
            if best.is_none_or(|(_, d)| diff < d) {
                best = Some((i, diff));
            }
        }
        best.map(|(i, _)| i)
    }

    /// Split at half ([`split_point`](Self::split_point)) into `dst`; returns
    /// the separator (the first key of `dst`).
    ///
    /// # Errors
    ///
    /// [`NodeError::Index`] for fewer than two entries.
    pub fn split(&mut self, dst: &mut Self) -> Result<Key, NodeError> {
        let at = self.split_point().ok_or(NodeError::Index)?;
        self.split_off(at, dst)?;
        dst.key(0).ok_or(NodeError::Index)
    }

    /// Whether the node no longer fits a block of payload `limit`.
    #[must_use]
    pub fn overflows(&self, limit: u32) -> bool {
        self.weight() > u64::from(limit)
    }

    /// Whether the node is below a quarter of `limit` (merge candidate).
    #[must_use]
    pub fn underflows(&self, limit: u32) -> bool {
        4 * self.weight() < u64::from(limit)
    }

    /// Combine an adjacent pair, `left` then `right` (one of which
    /// underflows): merge into `left` when the pair fits `limit`, else re-cut
    /// at half. `right` is the scratch that receives the new right half.
    ///
    /// # Errors
    ///
    /// [`NodeError::Full`] if the pair exceeds `CAP` in memory,
    /// [`NodeError::Order`] if `right` does not follow `left`.
    pub fn rebalance(
        left: &mut Self,
        right: &mut Self,
        limit: u32,
    ) -> Result<Rebalance, NodeError> {
        left.append(right)?;
        right.clear();
        if !left.overflows(limit) {
            return Ok(Rebalance::Merged);
        }
        Ok(Rebalance::Split(left.split(right)?))
    }

    /// Whether the keys are strictly increasing (an invariant every operation
    /// keeps; exposed for proofs and decode checks).
    #[must_use]
    pub fn is_sorted(&self) -> bool {
        self.keys().windows(2).all(|w| w[0] < w[1])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct W(u32);
    impl Entry for W {
        fn weight(&self) -> u32 {
            self.0
        }
    }

    fn k(n: u64) -> Key {
        Key {
            obj: n,
            kind: 1,
            off: 0,
        }
    }

    fn node(ws: &[u32]) -> Node<W, 16> {
        let mut n = Node::new(W(0));
        for (i, &w) in ws.iter().enumerate() {
            n.push(k(i as u64 * 10), W(w)).unwrap();
        }
        n
    }

    #[test]
    fn insert_keeps_order_and_refuses_duplicates() {
        let mut n: Node<W, 4> = Node::new(W(0));
        n.insert(0, k(5), W(1)).unwrap();
        n.insert(0, k(1), W(1)).unwrap();
        n.insert(2, k(9), W(1)).unwrap();
        assert_eq!(n.keys(), &[k(1), k(5), k(9)]);
        assert_eq!(n.insert(1, k(5), W(1)), Err(NodeError::Order));
        assert_eq!(n.insert(0, k(7), W(1)), Err(NodeError::Order));
        assert_eq!(n.insert(9, k(7), W(1)), Err(NodeError::Index));
        n.insert(2, k(7), W(1)).unwrap();
        assert_eq!(n.insert(4, k(10), W(1)), Err(NodeError::Full));
        assert_eq!(n.remove(1), Ok((k(5), W(1))));
        assert_eq!(n.keys(), &[k(1), k(7), k(9)]);
        assert_eq!(n.child_index(&k(0)), 0);
        assert_eq!(n.child_index(&k(8)), 1);
        assert_eq!(n.child_index(&k(9)), 2);
        assert!(n.is_sorted());
    }

    #[test]
    fn split_point_balances_weight_ties_low() {
        assert_eq!(node(&[1, 1, 1, 1]).split_point(), Some(2));
        assert_eq!(node(&[1, 1, 1]).split_point(), Some(1));
        assert_eq!(node(&[10, 1, 1, 1]).split_point(), Some(1));
        assert_eq!(node(&[1, 1, 1, 10]).split_point(), Some(3));
        assert_eq!(node(&[5]).split_point(), None);
    }

    #[test]
    fn split_and_rebalance_preserve_entries() {
        let mut a = node(&[3, 3, 3, 3, 3]);
        let before: Vec<Key> = a.keys().to_vec();
        let mut b = Node::new(W(0));
        let sep = a.split(&mut b).unwrap();
        assert_eq!(sep, b.key(0).unwrap());
        let mut all = a.keys().to_vec();
        all.extend_from_slice(b.keys());
        assert_eq!(all, before);
        // A tiny left and a big right re-cut at half.
        let mut l = node(&[1]);
        let mut r: Node<W, 16> = Node::new(W(0));
        for i in 0..6 {
            r.push(k(100 + i), W(4)).unwrap();
        }
        let out = Node::rebalance(&mut l, &mut r, 20).unwrap();
        assert!(matches!(out, Rebalance::Split(_)));
        assert!(!l.underflows(20) && !r.underflows(20));
        assert!(!l.overflows(20) && !r.overflows(20));
        // A pair that fits merges.
        let mut l = node(&[1]);
        let mut r: Node<W, 16> = Node::new(W(0));
        r.push(k(100), W(2)).unwrap();
        assert_eq!(Node::rebalance(&mut l, &mut r, 20), Ok(Rebalance::Merged));
        assert_eq!(l.len(), 2);
        assert!(r.is_empty());
        // Out-of-order pairs are refused and nothing changes.
        let mut l = node(&[1, 1]);
        let mut r = node(&[1]);
        assert_eq!(Node::rebalance(&mut l, &mut r, 20), Err(NodeError::Order));
        assert_eq!(l.len(), 2);
    }

    #[test]
    fn set_key_keeps_strict_order() {
        let mut n = node(&[1, 1, 1]);
        assert_eq!(n.set_key(0, k(15)), Err(NodeError::Order));
        n.set_key(0, k(0)).unwrap();
        n.set_key(1, k(19)).unwrap();
        assert_eq!(n.set_key(1, k(20)), Err(NodeError::Order));
        assert_eq!(n.set_key(3, k(99)), Err(NodeError::Index));
    }
}

/// Kani harnesses over `Node<_, 4>` (A19: shrunken generics, never 4 KiB
/// blocks or SHA-256). Weights are symbolic in `1..=MAX_W` with
/// `MAX_W ≤ LIMIT / 2` — the format's guarantee for real entries (§7.2).
#[cfg(kani)]
mod proofs {
    use super::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct W(u8);
    impl Entry for W {
        fn weight(&self) -> u32 {
            u32::from(self.0)
        }
    }

    const LIMIT: u32 = 8;
    const MAX_W: u8 = 4;

    fn any_key() -> Key {
        // Small key space: enough to reach every order relation.
        let obj: u8 = kani::any();
        kani::assume(obj < 16);
        Key {
            obj: u64::from(obj),
            kind: 0,
            off: 0,
        }
    }

    /// A sorted node of exactly `n` entries with symbolic keys and weights.
    fn any_node(n: usize) -> Node<W, 4> {
        let mut node = Node::new(W(0));
        let mut prev: Option<Key> = None;
        for _ in 0..n {
            let key = any_key();
            if let Some(p) = prev {
                kani::assume(p < key);
            }
            let w: u8 = kani::any();
            kani::assume(w >= 1 && w <= MAX_W);
            let pushed = node.push(key, W(w));
            assert!(pushed.is_ok());
            prev = Some(key);
        }
        node
    }

    /// Split: an overflowing node of up to 4 entries is cut into two
    /// non-empty, sorted halves that fit the limit, keep every entry in order
    /// (key-set preservation), and are separated by the right half's first key.
    #[kani::proof]
    #[kani::unwind(6)]
    fn node4_split_is_sorted_balanced_and_preserving() {
        let n: usize = kani::any();
        kani::assume(n >= 2 && n <= 4);
        let mut a = any_node(n);
        kani::assume(a.overflows(LIMIT));
        let orig = a.clone();
        let mut b = Node::new(W(0));
        let sep = a.split(&mut b);
        assert!(sep.is_ok());
        let sep = sep.unwrap_or(KEY_ZERO);
        // Occupancy: both non-empty, both fit, neither underflows.
        assert!(!a.is_empty() && !b.is_empty());
        assert!(a.len() + b.len() == n);
        assert!(!a.overflows(LIMIT) && !b.overflows(LIMIT));
        assert!(!a.underflows(LIMIT) && !b.underflows(LIMIT));
        // Sorted, separated.
        assert!(a.is_sorted() && b.is_sorted());
        assert!(b.key(0) == Some(sep));
        for i in 0..a.len() {
            assert!(a.key(i).is_some_and(|x| x < sep));
        }
        // Preservation: left ++ right == original, entry for entry.
        for i in 0..n {
            let got = if i < a.len() {
                (a.key(i), a.val(i))
            } else {
                (b.key(i - a.len()), b.val(i - a.len()))
            };
            assert!(got == (orig.key(i), orig.val(i)));
        }
    }

    /// Merge / rebalance: an adjacent pair where one side underflows ends
    /// either merged into a node that fits, or re-cut into two non-empty,
    /// non-underflowing, fitting halves with the right one's first key as
    /// separator — entries preserved in order either way.
    #[kani::proof]
    #[kani::unwind(6)]
    fn node4_merge_is_sorted_balanced_and_preserving() {
        let nl: usize = kani::any();
        let nr: usize = kani::any();
        // Each bounded first, so the sum cannot overflow.
        kani::assume(nl >= 1 && nl <= 3 && nr >= 1 && nr <= 3);
        kani::assume(nl + nr <= 4);
        let mut l = any_node(nl);
        let mut r = any_node(nr);
        kani::assume(l.key(nl - 1) < r.key(0));
        kani::assume(!l.overflows(LIMIT) && !r.overflows(LIMIT));
        kani::assume(l.underflows(LIMIT) || r.underflows(LIMIT));
        let (ol, or) = (l.clone(), r.clone());
        let out = Node::rebalance(&mut l, &mut r, LIMIT);
        assert!(out.is_ok());
        match out {
            Ok(Rebalance::Merged) => {
                assert!(r.is_empty() && l.len() == nl + nr);
                assert!(!l.overflows(LIMIT));
            }
            Ok(Rebalance::Split(sep)) => {
                assert!(!l.is_empty() && !r.is_empty());
                assert!(l.len() + r.len() == nl + nr);
                assert!(!l.overflows(LIMIT) && !r.overflows(LIMIT));
                assert!(!l.underflows(LIMIT) && !r.underflows(LIMIT));
                assert!(r.key(0) == Some(sep));
                for i in 0..l.len() {
                    assert!(l.key(i).is_some_and(|x| x < sep));
                }
            }
            Err(_) => {}
        }
        assert!(l.is_sorted() && r.is_sorted());
        for i in 0..nl + nr {
            let want = if i < nl {
                (ol.key(i), ol.val(i))
            } else {
                (or.key(i - nl), or.val(i - nl))
            };
            let got = if i < l.len() {
                (l.key(i), l.val(i))
            } else {
                (r.key(i - l.len()), r.val(i - l.len()))
            };
            assert!(got == want);
        }
    }
}
