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
        // Shift `[i, len)` right by one. Every loop here runs over the
        // capacity (a constant) and tests its range per element: the same
        // results as `copy_within`, but CBMC unwinds a fixed trip count
        // instead of modelling a symbolic-length move (which ran it out of
        // memory at CAP = 4).
        for j in (1..CAP).rev() {
            if j > i && j <= self.len {
                self.move_entry(j - 1, j);
            }
        }
        self.set_entry(i, k, v);
        self.len += 1;
        Ok(())
    }

    /// Store `(k, v)` in slot `i` (a no-op past the capacity, which callers
    /// never reach).
    fn set_entry(&mut self, i: usize, k: Key, v: V) {
        if let (Some(dk), Some(dv)) = (self.keys.get_mut(i), self.vals.get_mut(i)) {
            *dk = k;
            *dv = v;
        }
    }

    /// Copy slot `from` to slot `to`.
    fn move_entry(&mut self, from: usize, to: usize) {
        if let (Some(&k), Some(&v)) = (self.keys.get(from), self.vals.get(from)) {
            self.set_entry(to, k, v);
        }
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
        for j in 0..CAP {
            if j >= i && j + 1 < self.len {
                self.move_entry(j + 1, j);
            }
        }
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
        for j in 0..CAP {
            if j < n {
                if let (Some(&k), Some(&v)) = (other.keys.get(j), other.vals.get(j)) {
                    self.set_entry(self.len + j, k, v);
                }
            }
        }
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
        for j in 0..CAP {
            if j < n {
                if let (Some(&k), Some(&v)) = (self.keys.get(at + j), self.vals.get(at + j)) {
                    dst.set_entry(j, k, v);
                }
            }
        }
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
        for i in 1..CAP {
            if i >= self.len {
                break;
            }
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
        (1..CAP).all(|i| i >= self.len || self.keys.get(i - 1) < self.keys.get(i))
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
    /// non-empty, sorted halves that fit the limit and do not underflow,
    /// separated by the right half's first key.
    #[kani::proof]
    #[kani::unwind(6)]
    fn node4_split_is_sorted_and_balanced() {
        let n: usize = kani::any();
        kani::assume(n >= 2 && n <= 4);
        let mut a = any_node(n);
        kani::assume(a.overflows(LIMIT));
        let mut b = Node::new(W(0));
        let sep = a.split(&mut b);
        assert!(sep.is_ok());
        let sep = sep.unwrap_or(KEY_ZERO);
        assert!(!a.is_empty() && !b.is_empty());
        assert!(a.len() + b.len() == n);
        assert!(!a.overflows(LIMIT) && !b.overflows(LIMIT));
        assert!(!a.underflows(LIMIT) && !b.underflows(LIMIT));
        assert!(a.is_sorted() && b.is_sorted());
        assert!(b.key(0) == Some(sep));
        assert!(a.key(a.len() - 1).is_some_and(|k| k < sep));
    }

    /// Split preserves the key set: appending the right half back onto the
    /// left (append is proven order-preserving below) gives the original
    /// node, entry for entry.
    #[kani::proof]
    #[kani::unwind(6)]
    fn node4_split_preserves_entries() {
        let n: usize = kani::any();
        kani::assume(n >= 2 && n <= 4);
        let mut a = any_node(n);
        let orig = a.clone();
        let mut b = Node::new(W(0));
        assert!(a.split(&mut b).is_ok());
        assert!(a.append(&b).is_ok());
        assert!(a.len() == n);
        for i in 0..4 {
            assert!(a.key(i) == orig.key(i) && a.val(i) == orig.val(i));
        }
    }

    /// Append preserves: `l ++ r` holds every entry of `l` then every entry
    /// of `r`, in order, and stays sorted. With the split harness this
    /// covers rebalance's key-set preservation: a rebalance is an append,
    /// then (if the pair does not fit) a split.
    #[kani::proof]
    #[kani::unwind(6)]
    fn node4_append_preserves_entries_in_order() {
        let nl: usize = kani::any();
        let nr: usize = kani::any();
        kani::assume(nl >= 1 && nl <= 2 && nr >= 1 && nr <= 2);
        let mut l = any_node(nl);
        let r = any_node(nr);
        kani::assume(l.key(nl - 1) < r.key(0));
        let ol = l.clone();
        assert!(l.append(&r).is_ok());
        assert!(l.len() == nl + nr && l.is_sorted());
        for i in 0..4 {
            if i < nl {
                assert!(l.key(i) == ol.key(i) && l.val(i) == ol.val(i));
            } else if i < nl + nr {
                assert!(l.key(i) == r.key(i - nl) && l.val(i) == r.val(i - nl));
            }
        }
    }

    /// Merge / rebalance: an adjacent pair where one side underflows ends
    /// either merged into one node that fits, or re-cut into two non-empty,
    /// non-underflowing, fitting, sorted halves separated by the right one's
    /// first key — and no entry is lost or invented (counts; the entries
    /// themselves by [`node4_append_preserves_entries_in_order`] and
    /// [`node4_split_preserves_entries`], since rebalance is
    /// append-then-split).
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
        let (first, last) = (l.key(0), r.key(nr - 1));
        let total = l.weight() + r.weight();
        match Node::rebalance(&mut l, &mut r, LIMIT) {
            Ok(Rebalance::Merged) => {
                assert!(r.is_empty() && l.len() == nl + nr);
                assert!(!l.overflows(LIMIT));
                assert!(l.key(0) == first && l.key(nl + nr - 1) == last);
            }
            Ok(Rebalance::Split(sep)) => {
                assert!(!l.is_empty() && !r.is_empty());
                assert!(l.len() + r.len() == nl + nr);
                assert!(!l.overflows(LIMIT) && !r.overflows(LIMIT));
                assert!(!l.underflows(LIMIT) && !r.underflows(LIMIT));
                assert!(r.key(0) == Some(sep));
                assert!(l.key(l.len() - 1).is_some_and(|k| k < sep));
                assert!(l.key(0) == first && r.key(r.len() - 1) == last);
            }
            Err(_) => panic!("a fitting pair never fails to rebalance at CAP 4"),
        }
        assert!(l.weight() + r.weight() == total);
        assert!(l.is_sorted() && r.is_sorted());
    }
}
