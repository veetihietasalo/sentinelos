//! The capability tables: a fixed slab of per-instance tables, and the only
//! code that puts a capability into one (spec §8, threat entries T-CAP-*).
//!
//! # Producers
//!
//! Exactly three operations install a capability, and nothing else writes a
//! table entry (Kani: `proofs::no_capability_without_a_producer` over a
//! bounded sequence, and the inductive steps that extend it to any length):
//!
//! - [`CapSpace::grant`] — at instantiation, `request ∧ policy` (the meet);
//! - [`CapSpace::delegate`] — a holder of `Delegate` derives a child that is
//!   `⊑` its parent (same target, never more), into another table, recording
//!   the parent;
//! - [`CapSpace::mint_reply`] — the host, per request: a one-shot right to
//!   answer it (spec §7), at most [`MAX_PENDING_REPLIES`] per table.
//!
//! # Indices
//!
//! A [`CapIndex`] is `generation:48 ‖ table:8 ‖ slot:8` (a `u64`; widened from
//! `24 ‖ 4 ‖ 4` in PR-2b, amendment A13). It is valid only if its table is the
//! holder's own (otherwise *foreign*), its slot is occupied, and its
//! generation is the slot's current one. Every free bumps the slot's
//! generation, so an index to a revoked, released, used or reclaimed
//! capability is *stale* forever and can never alias a newer capability; a
//! slot whose generation would wrap is retired instead — the never-wrap
//! backstop, which at 48 bits no boot reaches (2⁴⁸ − 1 frees of one slot:
//! 325 days at 10⁷ frees/s; threat T-DOS-5). Generation 0 is never issued, so
//! `CapIndex(0)` (`CapIndex::KERNEL`) is never valid in any table.
//!
//! # Revocation
//!
//! Every derived capability records its parent as `(table, slot, generation)`
//! — the delegation tree the host records (spec §8). [`CapSpace::revoke`]
//! frees the descendants of a capability, [`CapSpace::release`] the
//! capability itself and its descendants; every removal finishes with an
//! orphan sweep that frees whatever lost its parent, to the end of every
//! chain, bounded by the slab size (Kani:
//! `proofs::revoke_removes_every_descendant`). Between operations no live
//! capability has a dead parent. For `Capability`, expiry needs no cascade —
//! a child never outlives its parent (`expires' ≤ expires`) — but the sweep
//! runs anyway.
//!
//! # What the tables store
//!
//! `CapSpace<T, S, C>` is generic over the stored value through
//! [`Authority`] (`C = Capability` everywhere in the kernel). The tables touch
//! a value only through that trait, so the structural guarantees above hold
//! for any `C`; the Kani harnesses prove them over a 5-byte token whose `⊑` is
//! an arbitrary symbolic relation, and the lattice laws are proven on
//! `Capability` itself — the split `sched` made for its Invariant #4 proof
//! (policy proven over a small container), here made over the payload.
//!
//! # Bounds
//!
//! `T` tables of `S` slots, both `<= 256` (the index fields are eight bits;
//! T-CON-3's revocation cost bounds the slab, not the index).
//! Production is `CapSpace<MAX_INSTANCES, MAX_CAPS>`; the harnesses run the
//! same code at `CapSpace<2, 2>`. Every loop is a constant-range loop over `T`
//! and `S`; nothing allocates.

use super::{Access, Authority, CapError, CapIndex, Capability, DenyReason, Tick};

/// Capabilities one instance can hold at once.
pub const MAX_CAPS: usize = 16;
/// Largest generation a slot reaches; freeing it then retires the slot.
pub const GEN_MAX: u64 = (1 << 48) - 1;
/// Reply capabilities one table may hold at once (threat T-DOS-2).
pub const MAX_PENDING_REPLIES: usize = 4;

const SLOT_BITS: u32 = 8;
const TABLE_BITS: u32 = 8;
const FIELD_MASK: u64 = 0xFF;
const GEN_SHIFT: u32 = SLOT_BITS + TABLE_BITS;

impl CapIndex {
    /// The index naming `slot` of `table` at generation `gen`. Callers pass
    /// `table, slot < 256` and `gen <= GEN_MAX`; excess bits are masked off
    /// (a generation above [`GEN_MAX`] loses its top bits).
    pub const fn compose(table: usize, slot: usize, gen: u64) -> CapIndex {
        CapIndex(
            ((gen & GEN_MAX) << GEN_SHIFT)
                | (((table as u64) & FIELD_MASK) << SLOT_BITS)
                | ((slot as u64) & FIELD_MASK),
        )
    }

    /// `(table, slot, generation)`.
    pub const fn parts(self) -> (usize, usize, u64) {
        (
            ((self.0 >> SLOT_BITS) & FIELD_MASK) as usize,
            (self.0 & FIELD_MASK) as usize,
            self.0 >> GEN_SHIFT,
        )
    }
}

/// Which producer installed a capability. Kept for audit and the invariants.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Origin {
    /// [`CapSpace::grant`]: manifest ∧ policy, at instantiation.
    Grant,
    /// [`CapSpace::delegate`]: derived from a live parent, `⊑` it.
    Delegate,
    /// [`CapSpace::mint_reply`]: the host's one-shot reply right.
    Reply,
}

/// One exact capability: table, slot and the generation it was installed at.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CapRef {
    /// Table (instance slot).
    pub table: u8,
    /// Slot within the table.
    pub slot: u8,
    /// Generation of the slot when the capability was installed.
    pub gen: u64,
}

/// A live table entry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Entry<C = Capability> {
    /// The capability.
    pub cap: C,
    /// The capability it was derived from (delegated capabilities only).
    pub parent: Option<CapRef>,
    /// Which producer installed it.
    pub origin: Origin,
}

#[derive(Clone, Copy)]
struct Slot<C> {
    /// Generation the next (or current) occupant carries. Starts at 1.
    gen: u64,
    /// The generation space is exhausted: never reused.
    retired: bool,
    entry: Option<Entry<C>>,
}

impl<C: Authority> Slot<C> {
    const EMPTY: Slot<C> = Slot {
        gen: 1,
        retired: false,
        entry: None,
    };
}

/// `T` capability tables of `S` slots each — the fixed slab (spec §8:
/// `CAP_TABLES`, kernel-only). Table `t` belongs to the instance in host slot
/// `t`.
pub struct CapSpace<const T: usize, const S: usize, C = Capability> {
    tables: [[Slot<C>; S]; T],
}

impl<const T: usize, const S: usize, C: Authority> Default for CapSpace<T, S, C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const T: usize, const S: usize, C: Authority> CapSpace<T, S, C> {
    /// The index fields are eight bits each; a larger slab could not be named.
    const FITS_THE_INDEX: () = assert!(T >= 1 && T <= 256 && S >= 1 && S <= 256);

    /// Empty tables.
    pub const fn new() -> Self {
        // Force the compile-time size check for this instantiation.
        #[allow(clippy::let_unit_value)]
        let () = Self::FITS_THE_INDEX;
        Self {
            tables: [[Slot::EMPTY; S]; T],
        }
    }

    /// Resolve `idx` in `holder`'s table to a slot holding a live entry —
    /// structure only (table, slot, generation); no expiry or op check.
    fn locate(&self, holder: usize, idx: CapIndex) -> Result<usize, DenyReason> {
        let (t, s, g) = idx.parts();
        if g == 0 || t >= T || holder >= T {
            return Err(DenyReason::NotHeld);
        }
        if t != holder {
            return Err(DenyReason::Foreign);
        }
        if s >= S {
            return Err(DenyReason::NotHeld);
        }
        let slot = self.tables[t][s];
        if slot.retired {
            // Every generation of a retired slot was issued once.
            return Err(DenyReason::Stale);
        }
        match slot.entry {
            Some(_) if slot.gen == g => Ok(s),
            _ if g < slot.gen => Err(DenyReason::Stale),
            _ => Err(DenyReason::NotHeld),
        }
    }

    /// The entry `idx` names in `holder`'s table, live or expired.
    pub fn get(&self, holder: usize, idx: CapIndex) -> Result<Entry<C>, DenyReason> {
        let s = self.locate(holder, idx)?;
        self.tables[holder][s].entry.ok_or(DenyReason::NotHeld)
    }

    /// **Producer 1.** Install `requested ∧ bound` (the policy's bound) in
    /// `table`. Refused when they share nothing (`PolicyRefused`) or the result
    /// is not well formed. For `Capability` the result is `⊑ bound` and
    /// `⊑ requested` (Kani: the meet lies below both).
    pub fn grant(&mut self, table: usize, requested: &C, bound: &C) -> Result<CapIndex, CapError> {
        if table >= T {
            return Err(CapError::NoSuchTable);
        }
        let cap = requested
            .meet(bound)
            .ok_or(CapError::Deny(DenyReason::PolicyRefused))?;
        if !cap.is_well_formed() {
            return Err(CapError::Deny(DenyReason::Malformed));
        }
        self.install(
            table,
            Entry {
                cap,
                parent: None,
                origin: Origin::Grant,
            },
        )
    }

    /// Everything [`Self::delegate`] checks before it installs, in the same
    /// order, changing nothing: `holder`'s capability `idx` is live and may
    /// delegate, `child` is well formed and `⊑` it — the one predicate,
    /// `Authority::is_attenuation_of`, which for `Capability` includes "same
    /// target" — and `recipient` is a table. On success, the parent's exact
    /// reference, which `delegate` records. Callers check authority with this
    /// before any capacity they own (the bus: the recipient's inbox), so a
    /// refusal or a `Busy` never spends a generation of anyone's table.
    pub fn check_delegate(
        &self,
        holder: usize,
        idx: CapIndex,
        recipient: usize,
        child: &C,
        now: Tick,
    ) -> Result<CapRef, CapError> {
        let s = self.locate(holder, idx).map_err(CapError::Deny)?;
        let parent_gen = self.tables[holder][s].gen;
        let parent = self.tables[holder][s]
            .entry
            .ok_or(CapError::Deny(DenyReason::NotHeld))?;
        if !parent.cap.is_live(now) {
            return Err(CapError::Deny(DenyReason::Expired));
        }
        if !parent.cap.may_delegate() {
            return Err(CapError::Deny(DenyReason::NotDelegable));
        }
        if !child.is_well_formed() {
            return Err(CapError::Deny(DenyReason::Malformed));
        }
        if !child.is_attenuation_of(&parent.cap) {
            return Err(CapError::Deny(DenyReason::Amplification));
        }
        if recipient >= T {
            return Err(CapError::NoSuchTable);
        }
        Ok(CapRef {
            table: holder as u8,
            slot: s as u8,
            gen: parent_gen,
        })
    }

    /// **Producer 2.** Install `child`, derived from `holder`'s capability
    /// `idx`, in `recipient`'s table, after [`Self::check_delegate`]: the
    /// parent must be live and may delegate; the child must be well formed
    /// and `⊑` the parent. Never modifies the parent.
    pub fn delegate(
        &mut self,
        holder: usize,
        idx: CapIndex,
        recipient: usize,
        child: &C,
        now: Tick,
    ) -> Result<CapIndex, CapError> {
        let parent = self.check_delegate(holder, idx, recipient, child, now)?;
        self.install(
            recipient,
            Entry {
                cap: *child,
                parent: Some(parent),
                origin: Origin::Delegate,
            },
        )
    }

    /// **Producer 3.** Install the host's one-shot reply right `right` in
    /// `table` (`Capability::reply_right` builds it). At most
    /// [`MAX_PENDING_REPLIES`] per table (`TableFull` beyond).
    pub fn mint_reply(&mut self, table: usize, right: C) -> Result<CapIndex, CapError> {
        if table >= T {
            return Err(CapError::NoSuchTable);
        }
        if !right.is_well_formed() {
            return Err(CapError::Deny(DenyReason::Malformed));
        }
        if self.pending_replies(table) >= MAX_PENDING_REPLIES {
            return Err(CapError::TableFull);
        }
        self.install(
            table,
            Entry {
                cap: right,
                parent: None,
                origin: Origin::Reply,
            },
        )
    }

    /// Revoke everything derived from `holder`'s capability `idx`, at any
    /// depth, in any table; the capability itself stays. Returns how many
    /// capabilities were freed. Allowed on an expired capability.
    pub fn revoke(&mut self, holder: usize, idx: CapIndex) -> Result<usize, CapError> {
        let s = self.locate(holder, idx).map_err(CapError::Deny)?;
        let root = CapRef {
            table: holder as u8,
            slot: s as u8,
            gen: self.tables[holder][s].gen,
        };
        let mut freed = 0;
        for t in 0..T {
            for x in 0..S {
                if self.tables[t][x]
                    .entry
                    .is_some_and(|e| e.parent == Some(root))
                {
                    self.free(t, x);
                    freed += 1;
                }
            }
        }
        Ok(freed + self.collect_orphans())
    }

    /// Drop `holder`'s capability `idx` and everything derived from it.
    /// Returns how many capabilities were freed (at least one).
    pub fn release(&mut self, holder: usize, idx: CapIndex) -> Result<usize, CapError> {
        let s = self.locate(holder, idx).map_err(CapError::Deny)?;
        self.free(holder, s);
        Ok(1 + self.collect_orphans())
    }

    /// Free every capability matching `pred`, then everything derived from
    /// them. Returns how many were freed. (`terminate`, reclamation.)
    pub fn free_where(&mut self, pred: impl Fn(&Entry<C>) -> bool) -> usize {
        let mut freed = 0;
        for t in 0..T {
            for s in 0..S {
                if self.tables[t][s].entry.is_some_and(|e| pred(&e)) {
                    self.free(t, s);
                    freed += 1;
                }
            }
        }
        freed + self.collect_orphans()
    }

    /// Free every capability in `table` and everything derived from them.
    pub fn clear_table(&mut self, table: usize) -> usize {
        if table >= T {
            return 0;
        }
        let mut freed = 0;
        for s in 0..S {
            let slot = self.tables[table][s];
            if slot.entry.is_some() {
                self.free(table, s);
                freed += 1;
            }
        }
        freed + self.collect_orphans()
    }

    /// Reclaim every capability expired at `now` (their descendants are
    /// expired too: `expires' ≤ expires`).
    pub fn reap_expired(&mut self, now: Tick) -> usize {
        self.free_where(|e| !e.cap.is_live(now))
    }

    /// Reclaim the capabilities in `table` expired at `now` (and, as always,
    /// anything derived from them) — the bus's on-demand reclamation before it
    /// allocates in a full table.
    pub fn reap_expired_in(&mut self, table: usize, now: Tick) -> usize {
        if table >= T {
            return 0;
        }
        let mut freed = 0;
        for s in 0..S {
            if self.tables[table][s]
                .entry
                .is_some_and(|e| !e.cap.is_live(now))
            {
                self.free(table, s);
                freed += 1;
            }
        }
        freed + self.collect_orphans()
    }

    /// Reply capabilities currently held in `table`.
    pub fn pending_replies(&self, table: usize) -> usize {
        self.count(table, |e| e.origin == Origin::Reply)
    }

    /// Capabilities currently held in `table`.
    pub fn live_count(&self, table: usize) -> usize {
        self.count(table, |_| true)
    }

    /// Whether `table` has a free slot.
    pub fn has_room(&self, table: usize) -> bool {
        table < T && self.free_slot(table).is_some()
    }

    /// Slots of `table` a new capability could take now: empty and not
    /// retired. Instantiation checks its grants fit before changing anything.
    pub fn usable_slots(&self, table: usize) -> usize {
        if table >= T {
            return 0;
        }
        let mut n = 0;
        for s in 0..S {
            let slot = self.tables[table][s];
            if slot.entry.is_none() && !slot.retired {
                n += 1;
            }
        }
        n
    }

    /// The entry in `table`'s `slot` and its generation, if occupied
    /// (audit, tests, and the Kani invariants).
    pub fn entry_at(&self, table: usize, slot: usize) -> Option<(Entry<C>, u64)> {
        if table >= T || slot >= S {
            return None;
        }
        let s = self.tables[table][slot];
        s.entry.map(|e| (e, s.gen))
    }

    // Three shapes in this impl are for the verifier (the Kani harnesses
    // below are what they buy; times in the spec). Their run-time cost is
    // small but not zero:
    //
    // - The scans are constant-range index loops, not iterator chains: an
    //   iterator over a row picked by a symbolic table number leaves CBMC a
    //   loop guard it cannot bound, so it unrolls to the harness limit instead
    //   of `S` (measured; the same lesson as `sched`'s Invariant #4 harness).
    // - A slot at a run-time position is copied out and written back whole,
    //   never borrowed: CBMC turns a reference at a symbolic position into a
    //   byte-level extract (or update) over the whole slab, a copy into one
    //   array read.
    // - The orphan sweep reads the slab once, propagates over a flag map and
    //   writes the slab once, instead of rescanning a slab it keeps changing.
    //   So every removal pays at least three passes over all `T * S` slots
    //   (scan, one propagation round, free), plus a round per chain link — up
    //   to `(T * S)²` flag steps — under the host lock with interrupts masked
    //   (spec §8, threat T-CON-3). No fast path: the code stays as verified.

    fn count(&self, table: usize, pred: impl Fn(&Entry<C>) -> bool) -> usize {
        if table >= T {
            return 0;
        }
        let mut n = 0;
        for s in 0..S {
            if self.tables[table][s].entry.is_some_and(|e| pred(&e)) {
                n += 1;
            }
        }
        n
    }

    fn free_slot(&self, table: usize) -> Option<usize> {
        if table >= T {
            return None;
        }
        for s in 0..S {
            let slot = self.tables[table][s];
            if slot.entry.is_none() && !slot.retired {
                return Some(s);
            }
        }
        None
    }

    /// Put `entry` in the first free slot of `table`.
    fn install(&mut self, table: usize, entry: Entry<C>) -> Result<CapIndex, CapError> {
        let s = self.free_slot(table).ok_or(CapError::TableFull)?;
        let mut slot = self.tables[table][s];
        slot.entry = Some(entry);
        self.tables[table][s] = slot;
        Ok(CapIndex::compose(table, s, slot.gen))
    }

    /// Empty a slot and move its generation on, so every index to what it held
    /// is stale from now on. At [`GEN_MAX`] the slot is retired instead of
    /// wrapping — a stale index can never become valid again.
    fn free(&mut self, table: usize, slot: usize) {
        let mut s = self.tables[table][slot];
        if s.entry.take().is_some() {
            if s.gen >= GEN_MAX {
                s.retired = true;
            } else {
                s.gen += 1;
            }
            self.tables[table][slot] = s;
        }
    }

    fn is_live_ref(&self, r: CapRef) -> bool {
        let (t, s) = (usize::from(r.table), usize::from(r.slot));
        if t >= T || s >= S {
            return false;
        }
        let slot = self.tables[t][s];
        slot.entry.is_some() && slot.gen == r.gen
    }

    /// Free every capability whose parent is no longer live, and everything
    /// below it, to the end of every chain. Returns how many were freed.
    ///
    /// The slab is read once and written once, around a small scratch map:
    ///
    /// 1. a capability whose recorded parent is not live is *doomed*; every
    ///    other derived one notes where its (live) parent sits;
    /// 2. doom flows from parent to child, a round at a time — a chain has at
    ///    most `T * S - 1` links, so `T * S` rounds reach the end of every
    ///    chain (early exit once a round changes nothing);
    /// 3. every doomed capability is freed.
    ///
    /// A capability is freed iff its parent was gone or is freed here — the
    /// fixpoint of "free the orphans", in at most `(T * S)²` flag steps and no
    /// slab rescans. Scratch: `3 * T * S` bytes for the positions plus
    /// `T * S` flags on the stack (1 KiB at 16 × 16).
    // Constant-range index loops on purpose (the verifier shapes above).
    #[allow(clippy::needless_range_loop)]
    fn collect_orphans(&mut self) -> usize {
        let mut parent_at: [[Option<(u8, u8)>; S]; T] = [[None; S]; T];
        let mut doomed = [[false; S]; T];
        for t in 0..T {
            for s in 0..S {
                if let Some(Entry {
                    parent: Some(p), ..
                }) = self.tables[t][s].entry
                {
                    if self.is_live_ref(p) {
                        parent_at[t][s] = Some((p.table, p.slot));
                    } else {
                        doomed[t][s] = true;
                    }
                }
            }
        }
        for _ in 0..(T * S) {
            let mut changed = false;
            for t in 0..T {
                for s in 0..S {
                    // In range: `is_live_ref` checked both fields.
                    if let Some((pt, ps)) = parent_at[t][s] {
                        if !doomed[t][s] && doomed[usize::from(pt)][usize::from(ps)] {
                            doomed[t][s] = true;
                            changed = true;
                        }
                    }
                }
            }
            if !changed {
                break;
            }
        }
        let mut freed = 0;
        for t in 0..T {
            for s in 0..S {
                if doomed[t][s] {
                    self.free(t, s);
                    freed += 1;
                }
            }
        }
        freed
    }

    /// Test hook: the generation of `slot` of `table`, occupied or not.
    #[cfg(test)]
    pub(crate) fn gen_for_test(&self, table: usize, slot: usize) -> u64 {
        self.tables[table][slot].gen
    }

    /// Test hook: move `slot` of `table` to generation `gen` (empty slots only).
    #[cfg(test)]
    pub(crate) fn set_gen_for_test(&mut self, table: usize, slot: usize, gen: u64) {
        if self.tables[table][slot].entry.is_none() {
            self.tables[table][slot].gen = gen;
        }
    }
}

impl<const T: usize, const S: usize> CapSpace<T, S, Capability> {
    /// May `holder` perform `access` with `idx` at tick `now`? The capability
    /// on success; the precise reason otherwise. Deny by default: anything not
    /// found in the holder's own table is refused. The checks are exactly
    /// [`Capability::permits`], split so the log can say which one failed.
    pub fn check(
        &self,
        holder: usize,
        idx: CapIndex,
        access: &Access,
        now: Tick,
    ) -> Result<Capability, DenyReason> {
        let cap = self.get(holder, idx)?.cap;
        if !cap.is_live(now) {
            return Err(DenyReason::Expired);
        }
        if !cap.ops.contains(access.op()) {
            return Err(DenyReason::OpNotAllowed);
        }
        if !cap.attenuation.admits(access) {
            return Err(DenyReason::Attenuation);
        }
        Ok(cap)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Attenuation, Op, OpSet, ReplyTag, Target};
    use super::*;
    use crate::host::codec::MAX_PAYLOAD;
    use crate::host::InstanceId;

    type Space = CapSpace<4, 4>;

    /// A chain through all 256 slots of the production slab, each child at an
    /// EARLIER scan position than its parent: each propagation round of the
    /// orphan sweep can doom only one more link, so a round bound that is only
    /// enough at the Kani size (2 × 2) leaves live orphans here (T-CAP-4).
    #[test]
    #[cfg_attr(miri, ignore)]
    fn release_frees_a_full_slab_chain_in_worst_scan_order() {
        const T: usize = crate::host::MAX_INSTANCES;
        const S: usize = MAX_CAPS;
        let c = Capability {
            target: Target::Instance(InstanceId(1)),
            ops: OpSet::of(&[Op::Send, Op::Delegate]),
            attenuation: Attenuation::Message { max_len: 8 },
            expires: None,
        };
        let filler = Capability {
            ops: OpSet::of(&[Op::Send]),
            ..c
        };
        let mut sp: CapSpace<T, S> = CapSpace::new();
        let mut fill = [[CapIndex::KERNEL; S]; T];
        for (t, row) in fill.iter_mut().enumerate() {
            for cell in row.iter_mut() {
                *cell = sp.grant(t, &filler, &filler).unwrap();
            }
        }
        let (mut prev, mut root) = (None::<(usize, CapIndex)>, None);
        for p in (0..T * S).rev() {
            let (t, s) = (p / S, p % S);
            sp.release(t, fill[t][s]).unwrap();
            let idx = match prev {
                None => sp.grant(t, &c, &c).unwrap(),
                Some((pt, pidx)) => sp.delegate(pt, pidx, t, &c, 0).unwrap(),
            };
            assert_eq!((idx.parts().0, idx.parts().1), (t, s));
            root.get_or_insert((t, idx));
            prev = Some((t, idx));
        }
        let (rt, ridx) = root.unwrap();
        assert_eq!(sp.release(rt, ridx), Ok(T * S));
        assert!((0..T).all(|t| sp.live_count(t) == 0), "an orphan survived");
    }

    #[test]
    fn usable_slots_skip_occupied_and_retired_slots() {
        let mut sp = Space::new();
        assert_eq!(sp.usable_slots(0), 4);
        assert_eq!(sp.usable_slots(99), 0);
        let c = send_to(9, &[Op::Send], 8, None);
        let idx = sp.grant(0, &c, &c).unwrap();
        assert_eq!(sp.usable_slots(0), 3);
        // Retire the slot: its last generation is spent at the next free.
        sp.release(0, idx).unwrap();
        sp.set_gen_for_test(0, 0, GEN_MAX);
        let last = sp.grant(0, &c, &c).unwrap();
        assert_eq!(last.parts(), (0, 0, GEN_MAX));
        sp.release(0, last).unwrap();
        assert_eq!(
            sp.usable_slots(0),
            3,
            "a retired slot is never usable again"
        );
        assert_eq!(sp.clear_table(0), 0);
        assert_eq!(
            sp.usable_slots(0),
            3,
            "and clearing the table does not revive it"
        );
    }

    fn send_to(n: u64, ops: &[Op], max_len: u16, expires: Option<Tick>) -> Capability {
        Capability {
            target: Target::Instance(InstanceId(n)),
            ops: OpSet::of(ops),
            attenuation: Attenuation::Message { max_len },
            expires,
        }
    }

    /// A child over instance 9 — the target `rooted()`'s root designates.
    fn child(ops: &[Op], max_len: u16, expires: Option<Tick>) -> Capability {
        send_to(9, ops, max_len, expires)
    }

    fn msg(op: Op, len: usize) -> Access {
        Access::Message { op, len }
    }

    /// A root in table 0 that may send to instance 9 and delegate.
    fn rooted() -> (Space, CapIndex) {
        let mut sp = Space::new();
        let c = send_to(9, &[Op::Send, Op::Request, Op::Delegate], 64, None);
        let idx = sp.grant(0, &c, &c).unwrap();
        (sp, idx)
    }

    #[test]
    fn index_encoding_round_trips_and_zero_is_never_issued() {
        let i = CapIndex::compose(3, 7, 42);
        assert_eq!(i.parts(), (3, 7, 42));
        assert_eq!(
            CapIndex::compose(15, 15, GEN_MAX).parts(),
            (15, 15, GEN_MAX)
        );
        // The wide index (A13): 48-bit generations, 8-bit table and slot.
        assert_eq!(GEN_MAX, (1u64 << 48) - 1);
        assert_eq!(
            CapIndex::compose(255, 255, GEN_MAX).parts(),
            (255, 255, GEN_MAX)
        );
        assert_eq!(CapIndex::compose(255, 255, GEN_MAX).0, u64::MAX);
        assert_eq!(CapIndex::compose(1, 2, 3).0, (3 << 16) | (1 << 8) | 2);
        // A generation past 2²⁴ — unreachable before A13 — still round-trips.
        assert_eq!(CapIndex::compose(0, 0, 1 << 24).parts(), (0, 0, 1 << 24));
        let (sp, idx) = rooted();
        assert_ne!(idx, CapIndex::KERNEL);
        assert_eq!(idx.parts().2, 1, "first generation is 1");
        for holder in 0..4 {
            assert_eq!(sp.get(holder, CapIndex::KERNEL), Err(DenyReason::NotHeld));
        }
    }

    #[test]
    fn grant_is_the_meet_of_request_and_policy() {
        let mut sp = Space::new();
        let asked = send_to(5, &[Op::Send, Op::Request], MAX_PAYLOAD as u16, None);
        let rule = send_to(5, &[Op::Send, Op::Delegate], 32, Some(100));
        let idx = sp.grant(1, &asked, &rule).unwrap();
        let e = sp.get(1, idx).unwrap();
        assert_eq!(e.cap, send_to(5, &[Op::Send], 32, Some(100)));
        assert_eq!((e.origin, e.parent), (Origin::Grant, None));
        // Nothing shared → nothing granted, nothing installed.
        let other = send_to(5, &[Op::Delegate], 8, None);
        assert_eq!(
            sp.grant(1, &asked, &other),
            Err(CapError::Deny(DenyReason::PolicyRefused))
        );
        assert_eq!(sp.grant(9, &asked, &rule), Err(CapError::NoSuchTable));
        assert_eq!(sp.live_count(1), 1);
    }

    #[test]
    fn check_refuses_not_held_foreign_stale_expired_op_and_attenuation() {
        let mut sp = Space::new();
        let c = send_to(9, &[Op::Send], 8, Some(50));
        let idx = sp.grant(0, &c, &c).unwrap();
        assert!(sp.check(0, idx, &msg(Op::Send, 8), 49).is_ok());
        // Not held: well-formed index for an empty slot of the holder's table.
        let empty = CapIndex::compose(0, 3, 1);
        assert_eq!(
            sp.check(0, empty, &msg(Op::Send, 0), 0),
            Err(DenyReason::NotHeld)
        );
        // A future generation was never issued either.
        let (t, s, g) = idx.parts();
        let future = CapIndex::compose(t, s, g + 1);
        assert_eq!(
            sp.check(0, future, &msg(Op::Send, 0), 0),
            Err(DenyReason::NotHeld)
        );
        // Foreign: the same number presented by another table's holder.
        assert_eq!(
            sp.check(1, idx, &msg(Op::Send, 0), 0),
            Err(DenyReason::Foreign)
        );
        // Out-of-range slot and table.
        assert_eq!(
            sp.check(0, CapIndex::compose(0, 9, 1), &msg(Op::Send, 0), 0),
            Err(DenyReason::NotHeld)
        );
        assert_eq!(
            sp.check(0, CapIndex::compose(7, 0, 1), &msg(Op::Send, 0), 0),
            Err(DenyReason::NotHeld)
        );
        assert_eq!(
            sp.check(0, idx, &msg(Op::Send, 0), 50),
            Err(DenyReason::Expired)
        );
        assert_eq!(
            sp.check(0, idx, &msg(Op::Request, 0), 0),
            Err(DenyReason::OpNotAllowed)
        );
        assert_eq!(
            sp.check(0, idx, &msg(Op::Send, 9), 0),
            Err(DenyReason::Attenuation)
        );
        // Stale: released, and still stale after the slot is reused.
        assert_eq!(sp.release(0, idx), Ok(1));
        assert_eq!(
            sp.check(0, idx, &msg(Op::Send, 0), 0),
            Err(DenyReason::Stale)
        );
        let again = sp.grant(0, &c, &c).unwrap();
        assert_eq!(again.parts().1, idx.parts().1, "same slot reused");
        assert_ne!(again, idx);
        assert_eq!(
            sp.check(0, idx, &msg(Op::Send, 0), 0),
            Err(DenyReason::Stale)
        );
        assert!(sp.check(0, again, &msg(Op::Send, 0), 0).is_ok());
    }

    #[test]
    fn delegate_attenuates_or_equals_and_records_the_parent() {
        let (mut sp, root) = rooted();
        // Equal is allowed.
        let eq = sp
            .delegate(
                0,
                root,
                1,
                &child(&[Op::Send, Op::Request, Op::Delegate], 64, None),
                0,
            )
            .unwrap();
        let e = sp.get(1, eq).unwrap();
        assert_eq!(e.cap, sp.get(0, root).unwrap().cap);
        assert_eq!(e.origin, Origin::Delegate);
        assert_eq!(
            e.parent,
            Some(CapRef {
                table: 0,
                slot: root.parts().1 as u8,
                gen: root.parts().2
            })
        );
        // Strictly weaker is allowed.
        let weak = sp
            .delegate(0, root, 2, &child(&[Op::Send], 8, Some(10)), 0)
            .unwrap();
        // Amplification on every axis is refused, and nothing is installed.
        let before = (0..4).map(|t| sp.live_count(t)).sum::<usize>();
        assert_eq!(
            sp.delegate(0, root, 1, &child(&[Op::Send], 65, None), 0),
            Err(CapError::Deny(DenyReason::Amplification)),
            "looser attenuation"
        );
        assert_eq!(
            sp.delegate(0, root, 1, &send_to(10, &[Op::Send], 8, None), 0),
            Err(CapError::Deny(DenyReason::Amplification)),
            "another target"
        );
        assert_eq!(
            sp.delegate(0, root, 1, &child(&[Op::Send, Op::Reply], 8, None), 0),
            Err(CapError::Deny(DenyReason::Malformed)),
            "an op the target never allows"
        );
        assert_eq!(
            sp.delegate(2, weak, 3, &child(&[Op::Send], 8, Some(9)), 0),
            Err(CapError::Deny(DenyReason::NotDelegable)),
            "weak lacks Delegate"
        );
        let mortal = sp
            .delegate(
                0,
                root,
                3,
                &child(&[Op::Send, Op::Delegate], 8, Some(10)),
                0,
            )
            .unwrap();
        assert_eq!(
            sp.delegate(3, mortal, 1, &child(&[Op::Send], 8, Some(11)), 0),
            Err(CapError::Deny(DenyReason::Amplification)),
            "later expiry than a mortal parent"
        );
        assert_eq!(
            sp.delegate(3, mortal, 1, &child(&[Op::Send], 8, None), 0),
            Err(CapError::Deny(DenyReason::Amplification)),
            "never-expiring child of a mortal parent"
        );
        assert_eq!(
            sp.delegate(3, mortal, 1, &child(&[], 8, Some(5)), 0),
            Err(CapError::Deny(DenyReason::Malformed))
        );
        // An expired parent delegates nothing.
        assert_eq!(
            sp.delegate(3, mortal, 1, &child(&[Op::Send], 8, Some(10)), 10),
            Err(CapError::Deny(DenyReason::Expired))
        );
        assert_eq!(
            sp.delegate(3, mortal, 9, &child(&[Op::Send], 8, Some(10)), 0),
            Err(CapError::NoSuchTable)
        );
        assert_eq!(
            (0..4).map(|t| sp.live_count(t)).sum::<usize>(),
            before + 1,
            "only `mortal` was added"
        );
    }

    #[test]
    fn revoke_cascades_through_every_table_and_spares_the_rest() {
        let (mut sp, root) = rooted();
        let a = sp
            .delegate(0, root, 1, &child(&[Op::Send, Op::Delegate], 64, None), 0)
            .unwrap();
        let b = sp
            .delegate(1, a, 2, &child(&[Op::Send, Op::Delegate], 32, None), 0)
            .unwrap();
        let c = sp
            .delegate(2, b, 3, &child(&[Op::Send], 16, None), 0)
            .unwrap();
        // An unrelated root and its child survive.
        let other = send_to(4, &[Op::Send, Op::Delegate], 8, None);
        let o = sp.grant(3, &other, &other).unwrap();
        let oc = sp
            .delegate(3, o, 1, &send_to(4, &[Op::Send], 8, None), 0)
            .unwrap();
        // A sibling of `a` from the same root also goes.
        let sib = sp
            .delegate(0, root, 2, &child(&[Op::Send], 4, None), 0)
            .unwrap();

        assert_eq!(sp.revoke(0, root), Ok(4));
        assert!(sp.get(0, root).is_ok(), "revoke keeps the root itself");
        for (holder, idx) in [(1, a), (2, b), (3, c), (2, sib)] {
            assert_eq!(sp.get(holder, idx), Err(DenyReason::Stale));
        }
        assert!(sp.get(3, o).is_ok() && sp.get(1, oc).is_ok());
        // Release takes the root and (now nothing) below it.
        assert_eq!(sp.release(0, root), Ok(1));
        assert_eq!(sp.get(0, root), Err(DenyReason::Stale));
        // Releasing an intermediate takes its subtree only.
        let o2 = sp.delegate(1, oc, 2, &send_to(4, &[Op::Send], 8, None), 0);
        assert_eq!(o2, Err(CapError::Deny(DenyReason::NotDelegable)));
        assert_eq!(sp.release(3, o), Ok(2), "o and oc");
        assert_eq!(sp.revoke(3, o), Err(CapError::Deny(DenyReason::Stale)));
    }

    #[test]
    fn reply_caps_are_bounded_one_shot_rights() {
        let mut sp = Space::new();
        let right = |tag: u64| Capability::reply_right(InstanceId(5), ReplyTag(tag), 100);
        let mut minted = [CapIndex::KERNEL; MAX_PENDING_REPLIES];
        for (tag, slot) in minted.iter_mut().enumerate() {
            *slot = sp.mint_reply(2, right(tag as u64)).unwrap();
        }
        assert_eq!(
            sp.mint_reply(2, right(99)),
            Err(CapError::TableFull),
            "pending replies are capped per table"
        );
        let e = sp.get(2, minted[0]).unwrap();
        assert_eq!(e.origin, Origin::Reply);
        assert_eq!(e.cap.ops, OpSet::of(&[Op::Reply]));
        assert!(sp.check(2, minted[0], &msg(Op::Reply, 10), 99).is_ok());
        assert_eq!(
            sp.check(2, minted[0], &msg(Op::Send, 0), 0),
            Err(DenyReason::OpNotAllowed)
        );
        assert_eq!(
            sp.delegate(2, minted[0], 1, &right(0), 0),
            Err(CapError::Deny(DenyReason::NotDelegable))
        );
        // Using it is the caller's `release`; then it is stale.
        assert_eq!(sp.release(2, minted[0]), Ok(1));
        assert_eq!(
            sp.check(2, minted[0], &msg(Op::Reply, 0), 0),
            Err(DenyReason::Stale)
        );
        // Expiry reclaims the rest.
        assert_eq!(sp.reap_expired(100), MAX_PENDING_REPLIES - 1);
        assert_eq!(sp.pending_replies(2), 0);
        // A malformed right is refused; so is a table out of range.
        let bad = Capability {
            ops: OpSet::of(&[Op::Reply, Op::Delegate]),
            ..right(1)
        };
        assert_eq!(
            sp.mint_reply(2, bad),
            Err(CapError::Deny(DenyReason::Malformed))
        );
        assert_eq!(sp.mint_reply(9, right(1)), Err(CapError::NoSuchTable));
    }

    #[test]
    fn free_where_takes_descendants_along() {
        let (mut sp, root) = rooted();
        let a = sp
            .delegate(0, root, 1, &child(&[Op::Send], 8, None), 0)
            .unwrap();
        let r = sp
            .mint_reply(1, Capability::reply_right(InstanceId(9), ReplyTag(1), 50))
            .unwrap();
        // Everything naming instance 9: the root, its child, the reply right.
        let freed = sp.free_where(|e| e.cap.target.names(InstanceId(9)));
        assert_eq!(freed, 3);
        assert_eq!(sp.get(1, a), Err(DenyReason::Stale));
        assert_eq!(sp.get(1, r), Err(DenyReason::Stale));
        assert_eq!(sp.clear_table(0), 0);
        assert_eq!(sp.clear_table(99), 0);
        assert_eq!(sp.reap_expired_in(99, 0), 0);
    }

    #[test]
    fn a_slot_is_retired_rather_than_wrapping_its_generation() {
        let mut sp = Space::new();
        let c = send_to(1, &[Op::Send], 8, None);
        sp.set_gen_for_test(0, 0, GEN_MAX);
        let last = sp.grant(0, &c, &c).unwrap();
        assert_eq!(last.parts(), (0, 0, GEN_MAX));
        assert_eq!(sp.release(0, last), Ok(1));
        assert_eq!(sp.get(0, last), Err(DenyReason::Stale));
        let next = sp.grant(0, &c, &c).unwrap();
        assert_eq!(next.parts().1, 1, "slot 0 is retired, never reused");
        assert_eq!(
            sp.get(0, CapIndex::compose(0, 0, 1)),
            Err(DenyReason::Stale)
        );
        // Fill the table: one slot short of capacity.
        for _ in 0..2 {
            sp.grant(0, &c, &c).unwrap();
        }
        assert_eq!(sp.grant(0, &c, &c), Err(CapError::TableFull));
        assert!(!sp.has_room(0));
    }

    /// Property test (deterministic PRNG, no dependencies): a long random mix
    /// of every operation, with garbage indices and arbitrary values, keeps
    /// the table invariants the Kani harnesses prove at a small bound — here
    /// on the production value type, at the production size, thousands of
    /// steps deep.
    #[test]
    fn random_operation_sequences_keep_every_invariant() {
        struct Lcg(u64);
        impl Lcg {
            fn next(&mut self) -> u64 {
                self.0 = self
                    .0
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                self.0 >> 33
            }
        }
        const T: usize = crate::host::MAX_INSTANCES;
        let mut rng = Lcg(0x5EED_CA95);
        let mut sp: CapSpace<T, MAX_CAPS> = CapSpace::new();
        // Ghost: (generation, entry) as produced, per slot.
        let mut ghost: [[Option<(u64, Entry)>; MAX_CAPS]; T] = [[None; MAX_CAPS]; T];
        let mut bounds: [[Option<Capability>; MAX_CAPS]; T] = [[None; MAX_CAPS]; T];
        let mut issued: alloc::vec::Vec<(usize, CapIndex)> = alloc::vec::Vec::new();
        let mut now: Tick = 0;
        // Miri interprets every step; the deep run is the native one.
        let steps = if cfg!(miri) { 200 } else { 20_000 };
        for _ in 0..steps {
            now += rng.next() % 3;
            let t = (rng.next() as usize) % T;
            let any_idx = |rng: &mut Lcg, issued: &[(usize, CapIndex)]| -> CapIndex {
                if !issued.is_empty() && rng.next() % 4 != 0 {
                    issued[(rng.next() as usize) % issued.len()].1
                } else {
                    CapIndex((rng.next() << 32) ^ rng.next())
                }
            };
            let any_cap = |rng: &mut Lcg| Capability {
                target: Target::Instance(InstanceId(rng.next() % 3)),
                ops: OpSet::from_bits((rng.next() % 16) as u32),
                attenuation: Attenuation::Message {
                    max_len: (rng.next() % 300) as u16,
                },
                expires: if rng.next() % 2 == 0 {
                    None
                } else {
                    Some(now + rng.next() % 40)
                },
            };
            let produced = match rng.next() % 6 {
                0 => {
                    let (req, b) = (any_cap(&mut rng), any_cap(&mut rng));
                    sp.grant(t, &req, &b).ok().map(|i| (i, Some(b)))
                }
                1 => {
                    let idx = any_idx(&mut rng, &issued);
                    let child = any_cap(&mut rng);
                    let recipient = (rng.next() as usize) % T;
                    sp.delegate(t, idx, recipient, &child, now)
                        .ok()
                        .map(|i| (i, None))
                }
                2 => {
                    let _ = sp.revoke(t, any_idx(&mut rng, &issued));
                    None
                }
                3 => {
                    let _ = sp.release(t, any_idx(&mut rng, &issued));
                    None
                }
                4 => {
                    let to = InstanceId(rng.next() % 3);
                    let right = Capability::reply_right(to, ReplyTag(rng.next()), now + 5);
                    sp.mint_reply(t, right).ok().map(|i| (i, None))
                }
                _ => {
                    sp.reap_expired(now);
                    None
                }
            };
            if let Some((idx, bound)) = produced {
                let (pt, ps, pg) = idx.parts();
                ghost[pt][ps] = sp.entry_at(pt, ps).map(|(e, g)| (g, e));
                assert_eq!(ghost[pt][ps].map(|(g, _)| g), Some(pg));
                bounds[pt][ps] = bound;
                issued.push((pt, idx));
            }
            for (tt, row) in ghost.iter().enumerate() {
                for (ss, g) in row.iter().enumerate() {
                    let Some((e, gen)) = sp.entry_at(tt, ss) else {
                        continue;
                    };
                    assert_eq!(*g, Some((gen, e)), "only a producer writes an entry");
                    assert!(e.cap.is_well_formed());
                    match e.origin {
                        Origin::Grant => {
                            assert!(e.parent.is_none());
                            assert!(e.cap.is_attenuation_of(&bounds[tt][ss].unwrap()));
                        }
                        Origin::Delegate => {
                            let p = e.parent.unwrap();
                            let (pe, pg) = sp
                                .entry_at(usize::from(p.table), usize::from(p.slot))
                                .expect("no orphans");
                            assert_eq!(pg, p.gen, "no orphans");
                            assert!(e.cap.is_attenuation_of(&pe.cap));
                        }
                        Origin::Reply => {
                            assert!(e.parent.is_none());
                            assert_eq!(e.cap.ops, OpSet::of(&[Op::Reply]));
                        }
                    }
                }
            }
            assert!((0..T).all(|tt| sp.pending_replies(tt) <= MAX_PENDING_REPLIES));
        }
    }
}

/// Kani harnesses for the tables. Compiled only under `cargo kani`; each was
/// measured to discharge in under 60 s locally (times in the component spec's
/// §14 PR-2 row). All run on a 2 × 2 slab.
///
/// # The target, and its inductive extension
///
/// `no_capability_without_a_producer` is the target as spec §8 states it, in
/// the form of `sched`'s Invariant #4 harness: a bounded, fully symbolic
/// sequence of operations from the empty slab, with a ghost of what each
/// producer returned. Two steps fit the budget (three take 139 s).
///
/// The other structural harnesses remove the bound. Each starts from **any**
/// slab state that satisfies the table invariant (`invariant` below) —
/// symbolic generations, retirements, entries, parent records and values —
/// and applies one call of a mutator with symbolic arguments. Between them
/// they cover every `&mut self` method of [`CapSpace`] (its fields are
/// private: nothing else writes a table), and the empty slab satisfies the
/// invariant, so by induction what they prove holds after **every** sequence
/// of operations, of any length:
///
/// - `producers_install_exactly_what_they_checked`: `grant`, `delegate`,
///   `mint_reply`;
/// - `revoke_removes_every_descendant`: `revoke`, `release`;
/// - `reclamation_frees_the_chosen_and_their_descendants`: `reap_expired`,
///   `reap_expired_in`, `clear_table`, `free_where`.
///
/// They run the production code over `Token`, a 5-byte [`Authority`] whose
/// `⊑`, well-formedness, liveness and delegability are free symbolic data:
/// what they prove holds for **every** such relation, hence for
/// `Capability`'s, whose lattice laws `cap::proofs` proves separately over
/// full-width symbolic values. `delegate_never_amplifies` runs on
/// `Capability` itself.
///
/// Since PR-2b (A13) every generation and index here is the production
/// width — 48-bit generations in a `u64` index, `any_slot` drawing from
/// `1..=GEN_MAX`. That grew the formulas ~30 % and roughly doubled the
/// default solver's (cadical) time; the four table harnesses below therefore
/// name `minisat`, which discharges the same formulas in about half the time
/// locally (times in spec §14, PR-2b row). The solver changes how fast, not
/// what, is proven.
#[cfg(kani)]
mod proofs {
    use super::super::proofs::{any_access, any_capability, any_capability_of_kind};
    use super::super::Op;
    use super::*;

    /// Tables in the harness slab.
    const T: usize = 2;
    /// Slots per table in the harness slab.
    const S: usize = 2;

    type Space = CapSpace<T, S, Token>;
    type Tables = [[Slot<Token>; S]; T];

    /// A tiny `Authority`: `⊑` is the arbitrary relation carried in `below`
    /// (`a ⊑ b` iff bit `b.id` of `a.below` is set), and every predicate is a
    /// free bit. Values are immutable once installed, so the relation between
    /// two installed values never changes — exactly as for `Capability`.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    struct Token {
        id: u8,
        below: u8,
        well_formed: bool,
        delegable: bool,
        until: u8,
    }

    impl Authority for Token {
        fn is_well_formed(&self) -> bool {
            self.well_formed
        }
        fn is_live(&self, now: Tick) -> bool {
            now < Tick::from(self.until)
        }
        fn may_delegate(&self) -> bool {
            self.delegable
        }
        fn is_attenuation_of(&self, parent: &Self) -> bool {
            self.below & (1 << (parent.id & 7)) != 0
        }
        fn meet(&self, other: &Self) -> Option<Self> {
            if self.is_attenuation_of(other) {
                Some(*self)
            } else if other.is_attenuation_of(self) {
                Some(*other)
            } else {
                None
            }
        }
    }

    fn any_token() -> Token {
        Token {
            id: kani::any::<u8>() & 7,
            below: kani::any(),
            well_formed: kani::any(),
            delegable: kani::any(),
            until: kani::any(),
        }
    }

    fn any_index() -> CapIndex {
        CapIndex(kani::any())
    }

    /// A table number, in range or not.
    fn any_table() -> usize {
        usize::from(kani::any::<u8>())
    }

    /// Any slot: any generation in `1..=GEN_MAX`, retired or not, empty or
    /// holding any token with any origin and any parent record (in range or
    /// not).
    fn any_slot() -> Slot<Token> {
        let gen: u64 = kani::any();
        kani::assume(gen >= 1 && gen <= GEN_MAX);
        let parent = if kani::any() {
            Some(CapRef {
                table: kani::any(),
                slot: kani::any(),
                gen: kani::any(),
            })
        } else {
            None
        };
        let origin = match kani::any::<u8>() % 3 {
            0 => Origin::Grant,
            1 => Origin::Delegate,
            _ => Origin::Reply,
        };
        Slot {
            gen,
            retired: kani::any(),
            entry: if kani::any() {
                Some(Entry {
                    cap: any_token(),
                    parent,
                    origin,
                })
            } else {
                None
            },
        }
    }

    /// Any slab state that satisfies [`invariant`].
    fn any_valid_space() -> Space {
        let mut sp = Space::new();
        for t in 0..T {
            for s in 0..S {
                sp.tables[t][s] = any_slot();
            }
        }
        kani::assume(invariant(&sp));
        sp
    }

    /// The live capability `r` names: that slot, occupied, at that generation.
    /// A constant-range scan rather than an index: a symbolic index into the
    /// slab costs CBMC a byte-level extract over the whole object.
    fn resolve(sp: &Space, r: CapRef) -> Option<Entry<Token>> {
        let mut found = None;
        for t in 0..T {
            for s in 0..S {
                let slot = &sp.tables[t][s];
                if usize::from(r.table) == t && usize::from(r.slot) == s && slot.gen == r.gen {
                    found = slot.entry;
                }
            }
        }
        found
    }

    /// The table invariant — what the producers establish and every mutator
    /// keeps:
    ///
    /// - every generation is in `1..=GEN_MAX`, and a retired slot is empty;
    /// - every capability is well formed;
    /// - a granted or reply capability has no parent;
    /// - a delegated capability's parent is live (that slot, that
    ///   generation), may delegate, and the child is `⊑` it: no orphans.
    fn invariant(sp: &Space) -> bool {
        let mut ok = true;
        for t in 0..T {
            for s in 0..S {
                let slot = &sp.tables[t][s];
                ok &= slot.gen >= 1 && slot.gen <= GEN_MAX;
                if let Some(e) = slot.entry {
                    ok &= !slot.retired && e.cap.is_well_formed();
                    ok &= match (e.origin, e.parent) {
                        (Origin::Grant | Origin::Reply, parent) => parent.is_none(),
                        (Origin::Delegate, Some(p)) => resolve(sp, p).is_some_and(|pe| {
                            pe.cap.may_delegate() && e.cap.is_attenuation_of(&pe.cap)
                        }),
                        (Origin::Delegate, None) => false,
                    };
                }
            }
        }
        ok
    }

    /// Nothing changed: every slot has the same entry, generation and
    /// retirement as in `before`.
    fn unchanged(before: &Tables, sp: &Space) -> bool {
        let mut same = true;
        for t in 0..T {
            for s in 0..S {
                let (old, cur) = (&before[t][s], &sp.tables[t][s]);
                same &= cur.entry == old.entry && cur.gen == old.gen && cur.retired == old.retired;
            }
        }
        same
    }

    /// The outcome of one removal from the valid state `before` to `sp`, where
    /// `chosen(table, slot, entry)` is what the call frees directly:
    ///
    /// - a capability is freed **iff** it was chosen or its parent was freed;
    /// - a survivor is exactly what was there, at the same generation;
    /// - a freed slot's generation moves on, or the slot retires, so no index
    ///   to what it held resolves again;
    /// - an empty slot is untouched: nothing is installed;
    /// - the invariant holds after.
    fn removed_exactly(
        before: &Tables,
        sp: &Space,
        chosen: impl Fn(usize, usize, &Entry<Token>) -> bool,
    ) {
        assert!(invariant(sp));
        for t in 0..T {
            for s in 0..S {
                let (old, cur) = (&before[t][s], &sp.tables[t][s]);
                match old.entry {
                    Some(e) => {
                        // `before` is valid, so the parent was live; it is
                        // unresolvable now iff this call freed it.
                        let parent_freed = e.parent.is_some_and(|p| resolve(sp, p).is_none());
                        if chosen(t, s, &e) || parent_freed {
                            assert!(cur.entry.is_none() && (cur.retired || cur.gen > old.gen));
                        } else {
                            assert!(cur.entry == old.entry && cur.gen == old.gen && !cur.retired);
                        }
                    }
                    None => {
                        assert!(cur.entry.is_none() && cur.gen == old.gen);
                        assert!(cur.retired == old.retired);
                    }
                }
            }
        }
    }

    /// **No capability without a producer** — spec §8's target over a bounded
    /// sequence, the analogue of `sched`'s Invariant #4 harness. From the
    /// empty slab, any two operations — `grant`, `delegate`, `revoke`,
    /// `release`, `mint_reply`, `reap_expired`, on symbolic tables with
    /// symbolic 64-bit (mostly garbage) indices, values and ticks — leave in
    /// the tables only capabilities that a producer call returned for that
    /// slot and generation, unchanged since (the ghost); each granted one is
    /// exactly `request ∧ bound`; and the table invariant holds (well formed;
    /// a delegated one `⊑` a live parent that may delegate; no orphans).
    /// Checked after the last step, which covers one step too: Kani explores
    /// steps that change nothing. The inductive harnesses below extend the
    /// statement to every length.
    #[kani::proof]
    #[kani::unwind(8)]
    #[kani::solver(minisat)]
    fn no_capability_without_a_producer() {
        const STEPS: usize = 2;
        let table = || -> usize {
            let t: usize = kani::any();
            kani::assume(t < T);
            t
        };
        let mut sp = Space::new();
        let mut ghost: [[Option<(u64, Entry<Token>)>; S]; T] = [[None; S]; T];
        let mut granted: [[Option<Token>; S]; T] = [[None; S]; T];
        for _ in 0..STEPS {
            let now = Tick::from(kani::any::<u8>());
            let produced: Option<(CapIndex, Option<Token>)> = match kani::any::<u8>() % 6 {
                0 => {
                    let (req, bound) = (any_token(), any_token());
                    sp.grant(table(), &req, &bound)
                        .ok()
                        .map(|i| (i, req.meet(&bound)))
                }
                1 => sp
                    .delegate(table(), any_index(), table(), &any_token(), now)
                    .ok()
                    .map(|i| (i, None)),
                2 => {
                    let _ = sp.revoke(table(), any_index());
                    None
                }
                3 => {
                    let _ = sp.release(table(), any_index());
                    None
                }
                4 => sp.mint_reply(table(), any_token()).ok().map(|i| (i, None)),
                _ => {
                    sp.reap_expired(now);
                    None
                }
            };
            if let Some((idx, meet)) = produced {
                let (t, s, g) = idx.parts();
                assert!(t < T && s < S);
                let there = sp.entry_at(t, s);
                assert!(there.is_some_and(|(_, gen)| gen == g));
                ghost[t][s] = there.map(|(e, gen)| (gen, e));
                granted[t][s] = meet;
            }
        }
        assert!(invariant(&sp));
        for t in 0..T {
            for s in 0..S {
                if let Some((e, gen)) = sp.entry_at(t, s) {
                    assert!(ghost[t][s] == Some((gen, e)));
                    if e.origin == Origin::Grant {
                        assert!(granted[t][s] == Some(e.cap));
                    }
                }
            }
        }
    }

    /// **The producers install exactly what they checked** — the inductive
    /// step for `grant`, `delegate` and `mint_reply`, and the base case: the
    /// empty slab satisfies the invariant. From any valid slab state, one call
    /// with symbolic arguments (any table, in range or not; any 32-bit index;
    /// any values, bound and tick):
    ///
    /// - keeps the invariant: a granted or reply capability is well formed
    ///   and parentless; a delegated one is `⊑` a live parent that may
    ///   delegate;
    /// - on success changes exactly one slot — the one the returned index
    ///   names, which was empty and unretired, at its current generation —
    ///   and installs there exactly what the producer checked: for `grant`
    ///   the meet `request ∧ bound`, for `delegate` the requested child, for
    ///   `mint_reply` the right, with that producer's origin;
    /// - names the new capability as nobody's parent: the delegation records
    ///   only ever gain leaves, so they stay a forest;
    /// - on refusal changes nothing.
    ///
    /// With the two removal steps below (every other mutator only frees, and
    /// keeps the invariant), by induction every capability in any table, after
    /// any sequence of operations, was installed by `grant`, by an attenuating
    /// `delegate` or by `mint_reply`, and is unchanged since.
    #[kani::proof]
    #[kani::unwind(4)]
    #[kani::solver(minisat)]
    fn producers_install_exactly_what_they_checked() {
        assert!(invariant(&Space::new()));

        let mut sp = any_valid_space();
        let before = sp.tables;
        let table = any_table();
        let value = any_token();
        let (result, expected, origin) = match kani::any::<u8>() % 3 {
            0 => {
                let bound = any_token();
                let result = sp.grant(table, &value, &bound);
                (result, value.meet(&bound), Origin::Grant)
            }
            1 => {
                let (recipient, now) = (any_table(), Tick::from(kani::any::<u8>()));
                let result = sp.delegate(table, any_index(), recipient, &value, now);
                (result, Some(value), Origin::Delegate)
            }
            _ => (sp.mint_reply(table, value), Some(value), Origin::Reply),
        };

        assert!(invariant(&sp));
        let Ok(idx) = result else {
            assert!(unchanged(&before, &sp));
            return;
        };
        let (nt, ns, ng) = idx.parts();
        let new = CapRef {
            table: nt as u8,
            slot: ns as u8,
            gen: ng,
        };
        for t in 0..T {
            for s in 0..S {
                let (old, cur) = (&before[t][s], &sp.tables[t][s]);
                assert!(cur.gen == old.gen && cur.retired == old.retired);
                if (t, s) == (nt, ns) {
                    assert!(old.entry.is_none() && !old.retired && ng == old.gen);
                    assert!(cur
                        .entry
                        .is_some_and(|e| e.origin == origin && Some(e.cap) == expected));
                } else {
                    assert!(cur.entry == old.entry);
                }
                assert!(cur.entry.is_none_or(|e| e.parent != Some(new)));
            }
        }
    }

    /// **`revoke` removes every descendant — and nothing else** (`release`:
    /// and the capability itself). The inductive step for both. From any
    /// valid slab state, `revoke` or `release` of a symbolic 32-bit index by a
    /// symbolic holder (in range or not). On refusal nothing changes. On
    /// success, with `v` the capability the index named, `removed_exactly`
    /// holds where the call itself frees `v` (`release`) or `v`'s children
    /// (`revoke`):
    ///
    /// - a capability is freed **iff** it is `v` and this is `release`, or
    ///   its parent is `v` and this is `revoke`, or its parent was freed;
    /// - survivors are unchanged; freed slots move their generation on;
    ///   nothing is installed; the invariant holds after.
    ///
    /// That is the whole of "every descendant, nothing else": the delegation
    /// records form a forest (`producers_install_exactly_what_they_checked`:
    /// they only gain leaves; here: survivors are unchanged), so by induction
    /// on depth every descendant of `v` is freed, and the parent chain of
    /// anything freed — each link freed — ends at `v`; `v` itself, which no
    /// ancestor's freeing reaches, survives `revoke`.
    #[kani::proof]
    #[kani::unwind(8)]
    #[kani::solver(minisat)]
    fn revoke_removes_every_descendant() {
        let mut sp = any_valid_space();
        let before = sp.tables;
        let (holder, idx) = (any_table(), any_index());
        let releasing: bool = kani::any();
        let result = if releasing {
            sp.release(holder, idx)
        } else {
            sp.revoke(holder, idx)
        };
        if result.is_err() {
            assert!(unchanged(&before, &sp));
            return;
        }
        let (vt, vs, vg) = idx.parts();
        let v = CapRef {
            table: vt as u8,
            slot: vs as u8,
            gen: vg,
        };
        // `locate` accepted it: the holder's own table, a live slot.
        assert!(vt == holder && resolve(&Space { tables: before }, v).is_some());
        removed_exactly(&before, &sp, |t, s, e| {
            if releasing {
                (t, s) == (vt, vs)
            } else {
                e.parent == Some(v)
            }
        });
    }

    /// **Reclamation frees what it chose, and their descendants — nothing
    /// else.** The inductive step for the remaining mutators. From any valid
    /// slab state, one of them with symbolic arguments: `reap_expired(now)`
    /// (chooses every capability expired at `now`), `reap_expired_in(table,
    /// now)` (those in `table`), `clear_table(table)` (all of `table`) or
    /// `free_where(pred)` (a symbolic predicate over the values).
    /// `removed_exactly` holds: freed iff chosen or the parent was freed;
    /// survivors unchanged; freed slots move their generation on; nothing
    /// installed; invariant kept.
    #[kani::proof]
    #[kani::unwind(8)]
    #[kani::solver(minisat)]
    fn reclamation_frees_the_chosen_and_their_descendants() {
        let mut sp = any_valid_space();
        let before = sp.tables;
        let (table, now) = (any_table(), Tick::from(kani::any::<u8>()));
        let ids: u8 = kani::any();
        let picked = |e: &Entry<Token>| ids & (1 << (e.cap.id & 7)) != 0;
        let op = kani::any::<u8>() % 4;
        match op {
            0 => {
                sp.reap_expired(now);
            }
            1 => {
                sp.reap_expired_in(table, now);
            }
            2 => {
                sp.clear_table(table);
            }
            _ => {
                sp.free_where(picked);
            }
        }
        removed_exactly(&before, &sp, |t, _, e| match op {
            0 => !e.cap.is_live(now),
            1 => t == table && !e.cap.is_live(now),
            2 => t == table,
            _ => picked(e),
        });
    }

    /// **`delegate` never amplifies** — on `Capability` itself. For a symbolic
    /// parent (installed through `grant`), a fully symbolic requested child
    /// (any target, any ops, any attenuation, any expiry), a symbolic
    /// recipient, tick and presented index (the real one or garbage): if
    /// `delegate` succeeds, what it installed is exactly the requested child,
    /// it has the parent's target, the parent carries `Delegate`, the child is
    /// `⊑` the parent, and — semantically, independent of how `⊑` is written —
    /// every access the child permits at any tick, the parent permits. The
    /// parent is never modified; a refusal installs nothing.
    ///
    /// FS-1c split it by the parent's kind (bus here, storage in
    /// [`delegate_never_amplifies_storage`]) to keep each under 60 s; only a
    /// well-formed parent is ever granted, so no parent is lost. Here the
    /// requested child is of every kind (bus, reply, storage, and malformed
    /// mixtures), so a cross-kind delegation is exercised at the table level.
    #[kani::proof]
    #[kani::unwind(7)] // 7: the loops over storage paths and references (FS-1c)
    fn delegate_never_amplifies() {
        delegate_never_amplifies_from(any_capability_of_kind(false), any_capability, any_access);
    }

    /// [`delegate_never_amplifies`] for a storage parent of constant shape
    /// (`/a` on the live tree; symbolic blobs, quota, ops and expiry) and a
    /// symbolic storage child and storage access (FS-1c). The child is
    /// storage: a child of any other kind fails `⊑` on its target and
    /// its attenuation's kind (`cap::proofs::attenuation_order_is_sound_and_transitive`
    /// covers every kind against every kind), and generating it here costs
    /// this harness its 60 s budget.
    #[kani::proof]
    #[kani::unwind(7)]
    fn delegate_never_amplifies_storage() {
        let parent = Capability {
            target: super::super::Target::Service(super::super::ServiceId::Storage),
            ops: super::super::OpSet::from_bits(kani::any()),
            attenuation: super::super::Attenuation::Storage(
                super::super::storage::proofs::storage_parent_attenuation(),
            ),
            expires: if kani::any() { Some(kani::any()) } else { None },
        };
        delegate_never_amplifies_from(
            parent,
            || any_capability_of_kind(true),
            || super::super::Access::Storage(super::super::storage::proofs::some_storage_access()),
        );
    }

    fn delegate_never_amplifies_from(
        parent: Capability,
        any_child: fn() -> Capability,
        any_access: fn() -> super::super::Access,
    ) {
        let mut sp: CapSpace<T, S> = CapSpace::new();
        let Ok(pidx) = sp.grant(0, &parent, &parent) else {
            return;
        };
        let (_, pslot, _) = pidx.parts();
        assert!(sp.entry_at(0, pslot).is_some_and(|(e, _)| e.cap == parent));

        let requested = any_child();
        let presented = if kani::any() { pidx } else { any_index() };
        let recipient: usize = kani::any();
        kani::assume(recipient < T);
        let now: Tick = kani::any();
        match sp.delegate(0, presented, recipient, &requested, now) {
            Ok(cidx) => {
                let (ct, cs, _) = cidx.parts();
                let child = sp.entry_at(ct, cs);
                assert!(child.is_some_and(|(c, _)| c.cap == requested));
                assert!(requested.target == parent.target);
                assert!(parent.ops.contains(Op::Delegate));
                assert!(requested.is_attenuation_of(&parent));
                let access = any_access();
                let at: Tick = kani::any();
                if requested.permits(&access, at) {
                    assert!(parent.permits(&access, at));
                }
            }
            Err(_) => {
                assert!(sp.live_count(0) + sp.live_count(1) == 1);
            }
        }
        assert!(sp.entry_at(0, pslot).is_some_and(|(e, _)| e.cap == parent));
    }
}
