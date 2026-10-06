//! Park / unpark: block a task until another task (or its deadline) wakes it
//! (SentinelFS spec §15 A25; scheduler design doc, "Park / unpark").
//!
//! # API
//!
//! - [`park`] blocks the calling task until [`unpark`]ed.
//! - [`park_until`] blocks it until unparked **or** until
//!   `crate::clock::mono_ticks() >= deadline`, and says which ([`Woken`]).
//! - [`unpark`] wakes a parked task, or — if the task is running or ready —
//!   stores its **wake permit**, so its next park returns at once. One permit,
//!   not counted (`std::thread::park` semantics). An unpark of an exited,
//!   reaped or never-issued id is a refused no-op ([`UnparkOutcome::Refused`]);
//!   ids are never reused within a boot (`NEXT_TASK_ID` only counts up), so a
//!   stale id can never wake a later task.
//!
//! Callers re-check their own condition in a loop around `park`.
//!
//! # Refused parks
//!
//! A park is **refused** — it returns [`Woken::Unparked`] at once and changes
//! nothing — when the caller is a core's idle task (the fallback that must
//! always be runnable), has preemption disabled (blocking would hand the core
//! on inside an open critical section), or runs with interrupts disabled
//! (IRQ context, or an `IF = 0` section: no tick could ever wake it). Each of
//! these is a caller bug, and a `while !done { park() }` loop would turn it
//! into a hot spin, so each is a `debug_assert!` (the kernel is built in the
//! dev profile: the boot faults loudly). In a release build the park still
//! returns at once — it never blocks a core that cannot be switched.
//!
//! # Where the state lives
//!
//! A parked task is on **no** ring: not its core's `ready`, not `zombies`, not
//! `current` — only the [`super::TASKS`] slab knows it, as
//! [`TaskState::Parked`]. Its permit and the reason it was woken are two plain
//! fields of its `Task`. A `park_until` deadline is one entry in its core's
//! fixed [`Sleepers`] set ([`super::CpuSched::sleepers`], capacity
//! [`super::MAX_TASKS`]), which that core's [`super::on_tick`] drains: an O(1)
//! compare against the cached earliest deadline on every tick, and at most
//! `MAX_TASKS` entries visited on a tick where something expires. No
//! allocation anywhere; every structure is a fixed array.
//!
//! # Locks
//!
//! No new lock. Park, unpark and the deadline drain all take the owning
//! core's queue lock and then [`super::TASKS`] — the existing **queue →
//! table** order — with `IF = 0`, and never across an allocation or a
//! switch. `unpark` first reads the target's core under `TASKS` alone and
//! releases it before taking the queue lock, so it never holds the table
//! while acquiring a queue (the pinned core never changes, and a vanished
//! task is re-checked under both locks). Both locks are on the
//! "reachable from IRQ context, only taken with `IF = 0`" side of hal-tcb
//! §5e.
//!
//! # IRQ context
//!
//! [`unpark`] **may** be called from IRQ context (no caller does today): it
//! allocates nothing (a ring store and an array swap-remove), takes only the
//! two IRQ-side scheduler locks, with `IF = 0`, in queue → table order, never
//! nested on itself, and sends its reschedule IPI with `IF = 0` too — so an
//! IRQ can never land between the two xAPIC ICR writes of a `send_ipi` on
//! the same core (`spawn_on`'s IPI is sent with `IF = 0` for the same
//! reason). It does not switch, and sends no IPI to its own core: a task
//! woken on the calling core runs at that core's next switch — the next
//! tick if the core's idle is current (the tick reschedules whenever the idle
//! runs with `ready` non-empty), else the current task's yield, park or
//! slice expiry. [`park`] and [`park_until`] are task context only, with
//! interrupts and preemption enabled (see "Refused parks").
//!
//! # Cross-core wake-up
//!
//! A task is woken only by its own core switching to it; `unpark` from
//! another core pushes it on that core's ring (under that core's lock) and
//! sends the existing reschedule IPI (vector `0xF0`) so a core asleep in
//! `sti; hlt` notices. No core ever touches another core's `current`. The
//! park itself pushes nothing: the parking task is taken off `current` and
//! switched away from inside one `IF = 0` section, and only its own core can
//! ever switch back to it, so a remote unpark that lands between the lock
//! release and the completed register save is safe — exactly as a yield's
//! requeue before its switch is.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use super::{
    local_cpu, with_interrupts_disabled, CpuSched, ReadyQueue, TaskId, TaskState, TaskTable,
    CPU_SCHED, PREEMPT, TASKS,
};
use crate::smp::MAX_CPUS;

// ── Public types ────────────────────────────────────────────────────────────

/// Why a [`park`] / [`park_until`] returned.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Woken {
    /// An [`unpark`] woke the task, or consumed a stored permit at once (also
    /// the answer of a refused park — see the module docs).
    Unparked,
    /// The `park_until` deadline was reached: `mono_ticks() >= deadline`.
    Deadline,
}

/// What an [`unpark`] did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UnparkOutcome {
    /// The task was parked; it is now runnable on its core.
    Woke,
    /// The task was running or ready; its permit is set, so its next park
    /// returns at once.
    PermitStored,
    /// No such live task (exited, reaped, or never issued): nothing changed.
    Refused,
}

// ── Pure state machine (production, host tests and Kani share it) ──────────

/// A fixed set of `(task, deadline)` pairs — one core's `park_until`
/// sleepers.
///
/// # Invariants
///
/// - An id appears at most once, and only while that task is
///   [`TaskState::Parked`] by a `park_until` — every path that wakes a task
///   removes its entry under the same lock that changes its state.
/// - `earliest` is the minimum deadline present, or `u64::MAX` when empty,
///   so a tick with nothing due is one compare.
/// - Capacity `N` is [`super::MAX_TASKS`] in production: there are never
///   more parked tasks than tasks, so [`Sleepers::insert`] cannot fail.
pub(super) struct Sleepers<const N: usize> {
    ids: [TaskId; N],
    at: [u64; N],
    len: usize,
    earliest: u64,
}

impl<const N: usize> Sleepers<N> {
    pub(super) const fn new() -> Self {
        Self {
            ids: [TaskId::IDLE; N],
            at: [0; N],
            len: 0,
            earliest: u64::MAX,
        }
    }

    /// Number of entries.
    #[cfg_attr(not(any(test, kani)), allow(dead_code))]
    fn len(&self) -> usize {
        self.len
    }

    /// The `i`-th entry, if `i < len()` (inspection for tests and proofs).
    #[cfg_attr(not(any(test, kani)), allow(dead_code))]
    fn get(&self, i: usize) -> Option<(TaskId, u64)> {
        if i < self.len && i < N {
            Some((self.ids[i], self.at[i]))
        } else {
            None
        }
    }

    fn is_full(&self) -> bool {
        self.len >= N
    }

    /// Add `id` with deadline `at`. `false` (nothing stored) only when full.
    fn insert(&mut self, id: TaskId, at: u64) -> bool {
        if self.is_full() {
            return false;
        }
        self.ids[self.len] = id;
        self.at[self.len] = at;
        self.len += 1;
        self.earliest = self.earliest.min(at);
        true
    }

    /// Remove `id`'s entry, if any.
    fn remove(&mut self, id: TaskId) {
        for i in 0..N {
            if i < self.len && self.ids[i] == id {
                self.swap_remove(i);
                self.recompute();
                return;
            }
        }
    }

    fn swap_remove(&mut self, i: usize) {
        let last = self.len - 1;
        self.ids[i] = self.ids[last];
        self.at[i] = self.at[last];
        self.len = last;
    }

    fn recompute(&mut self) {
        let mut earliest = u64::MAX;
        for i in 0..N {
            if i < self.len {
                earliest = earliest.min(self.at[i]);
            }
        }
        self.earliest = earliest;
    }

    /// Remove every entry whose deadline is `<= now` and hand each id to
    /// `wake`. O(1) when nothing is due; otherwise at most `N` iterations
    /// (each either removes an entry or moves past one).
    fn drain_expired(&mut self, now: u64, mut wake: impl FnMut(TaskId)) {
        if now < self.earliest {
            return;
        }
        let mut i = 0;
        for _ in 0..N {
            if i >= self.len {
                break;
            }
            if self.at[i] <= now {
                let id = self.ids[i];
                self.swap_remove(i);
                wake(id);
            } else {
                i += 1;
            }
        }
        self.recompute();
    }
}

/// Mutable access to the park-relevant fields of one task — what the pure
/// steps need from the task table, so production ([`TaskTable`]) and the
/// host/Kani models share every step below.
pub(super) struct ParkView<'a> {
    pub(super) state: &'a mut TaskState,
    pub(super) permit: &'a mut bool,
    pub(super) woken: &'a mut Woken,
    pub(super) idle: bool,
}

/// A task table, as seen by the park steps.
pub(super) trait ParkTable {
    /// The park fields of `id`, or `None` if no such task is in the table.
    fn view(&mut self, id: TaskId) -> Option<ParkView<'_>>;
}

impl ParkTable for TaskTable {
    fn view(&mut self, id: TaskId) -> Option<ParkView<'_>> {
        self.get_mut(id).map(|t| ParkView {
            state: &mut t.state,
            permit: &mut t.permit,
            woken: &mut t.woken,
            idle: t.idle,
        })
    }
}

/// What [`park_step`] decided.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum ParkStep {
    /// Return to the caller at once with this answer; nothing was switched.
    Return(Woken),
    /// The park was refused, for this reason: nothing changed.
    Refused(Refusal),
    /// The caller is now parked; switch to this task.
    Switch(TaskId),
}

/// Why a park was refused. Every one is a caller bug or a broken invariant,
/// so [`park`] `debug_assert!`s on it, naming the reason.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Refusal {
    /// The caller is not in the task table.
    UnknownCaller,
    /// The caller is a core's idle task, which must stay runnable.
    Idle,
    /// Nothing else is runnable (impossible for a non-idle caller: its
    /// core's idle is then on `ready`).
    EmptyReady,
    /// The sleeper set is full (impossible at capacity `MAX_TASKS`).
    SleepersFull,
    /// A switch handle could not be minted (production glue only; checked
    /// before [`park_step`] runs, so nothing changed).
    MissingHandle,
}

impl Refusal {
    /// Fail a debug build, naming the reason (fmt-free: one literal each).
    fn debug_fail(self) {
        match self {
            Refusal::UnknownCaller => {
                debug_assert!(false, "park refused: the caller is not in the task table");
            }
            Refusal::Idle => debug_assert!(false, "park refused: called by a core's idle task"),
            Refusal::EmptyReady => {
                debug_assert!(false, "park refused: the ready ring is empty");
            }
            Refusal::SleepersFull => {
                debug_assert!(false, "park refused: the sleeper set is full");
            }
            Refusal::MissingHandle => {
                debug_assert!(false, "park refused: a switch handle is missing");
            }
        }
    }
}

/// The pure park decision for the task `*current` at mono time `now`.
///
/// In order: a park by an unknown or idle task is [`ParkStep::Refused`]; a
/// stored permit is consumed and returns
/// [`Woken::Unparked`]; a deadline already reached returns
/// [`Woken::Deadline`]; otherwise the next ready task becomes `*current`
/// (Running), the caller becomes [`TaskState::Parked`] on no ring, and its
/// deadline (if any) joins `sleepers`. If nothing else is runnable — never the
/// case for a non-idle task, since its core's idle is then on `ready` — or the
/// sleeper set is full (cannot happen at capacity `MAX_TASKS`), it is
/// [`ParkStep::Refused`]. Nothing is mutated before the switch target is
/// known.
pub(super) fn park_step<Q: ReadyQueue, T: ParkTable, const N: usize>(
    ready: &mut Q,
    sleepers: &mut Sleepers<N>,
    table: &mut T,
    current: &mut TaskId,
    now: u64,
    deadline: Option<u64>,
) -> ParkStep {
    let me = *current;
    {
        let Some(v) = table.view(me) else {
            return ParkStep::Refused(Refusal::UnknownCaller);
        };
        if v.idle {
            return ParkStep::Refused(Refusal::Idle);
        }
        if core::mem::take(v.permit) {
            return ParkStep::Return(Woken::Unparked);
        }
    }
    if deadline.is_some_and(|d| now >= d) {
        return ParkStep::Return(Woken::Deadline);
    }
    if deadline.is_some() && sleepers.is_full() {
        return ParkStep::Refused(Refusal::SleepersFull);
    }
    let Some(next) = ready.pop_front() else {
        return ParkStep::Refused(Refusal::EmptyReady);
    };
    if let Some(v) = table.view(me) {
        *v.state = TaskState::Parked;
        *v.woken = Woken::Unparked;
    }
    if let Some(d) = deadline {
        // Cannot fail: checked `is_full` above, under the same lock.
        let _stored = sleepers.insert(me, d);
    }
    if let Some(v) = table.view(next) {
        *v.state = TaskState::Running;
    }
    *current = next;
    ParkStep::Switch(next)
}

/// The pure unpark step for `id` on its own core's structures: wake it if
/// parked (Ready, on the tail of `ready`, its deadline entry dropped), store
/// its permit if it is running or ready, refuse if it is exited, unknown, or
/// a core's idle task (which never parks, so a permit could never be
/// consumed).
pub(super) fn unpark_step<Q: ReadyQueue, T: ParkTable, const N: usize>(
    ready: &mut Q,
    sleepers: &mut Sleepers<N>,
    table: &mut T,
    id: TaskId,
) -> UnparkOutcome {
    let Some(v) = table.view(id) else {
        return UnparkOutcome::Refused;
    };
    if v.idle {
        return UnparkOutcome::Refused;
    }
    match *v.state {
        TaskState::Exited => UnparkOutcome::Refused,
        TaskState::Ready | TaskState::Running => {
            *v.permit = true;
            UnparkOutcome::PermitStored
        }
        TaskState::Parked => {
            *v.state = TaskState::Ready;
            *v.woken = Woken::Unparked;
            sleepers.remove(id);
            ready.push_back(id);
            UnparkOutcome::Woke
        }
    }
}

/// The pure deadline step of one core's tick at mono time `now`: every
/// sleeper whose deadline is `<= now` becomes Ready (woken by
/// [`Woken::Deadline`]) on the tail of `ready`. Returns how many woke.
pub(super) fn expire_step<Q: ReadyQueue, T: ParkTable, const N: usize>(
    ready: &mut Q,
    sleepers: &mut Sleepers<N>,
    table: &mut T,
    now: u64,
) -> usize {
    let mut woke = 0;
    sleepers.drain_expired(now, |id| {
        if let Some(v) = table.view(id) {
            if *v.state == TaskState::Parked {
                *v.state = TaskState::Ready;
                *v.woken = Woken::Deadline;
                ready.push_back(id);
                woke += 1;
            }
        }
    });
    woke
}

/// Whether an unpark must send the reschedule IPI: only when it woke a task
/// pinned to another core (a local wake is seen at this core's next switch).
pub(super) fn wants_ipi(outcome: UnparkOutcome, target_cpu: usize, local: usize) -> bool {
    outcome == UnparkOutcome::Woke && target_cpu != local
}

// ── Production glue ─────────────────────────────────────────────────────────

/// Block the calling task until it is [`unpark`]ed. Returns at once if its
/// permit was already set (consuming it). Task context only; must not be
/// called with preemption disabled or a spinlock held (a refused park returns
/// at once — see the module docs).
pub fn park() {
    let _woken = park_current(None);
}

/// Block the calling task until it is [`unpark`]ed or
/// `crate::clock::mono_ticks() >= deadline`, whichever comes first, and say
/// which. A permit already set returns [`Woken::Unparked`] at once; a
/// deadline already reached returns [`Woken::Deadline`] at once. The deadline
/// is checked by the task's own core on every tick, so it fires on the first
/// tick at or past it and never before. Same context rules as [`park`].
pub fn park_until(deadline: u64) -> Woken {
    park_current(Some(deadline))
}

fn park_current(deadline: Option<u64>) -> Woken {
    let cpu = local_cpu();
    let preemptible = PREEMPT[cpu].count.load(Ordering::Relaxed) == 0;
    debug_assert!(preemptible, "park with preemption disabled");
    let interrupts = hal::cpu::interrupts_enabled();
    debug_assert!(interrupts, "park with interrupts disabled (IRQ context?)");
    if !preemptible || !interrupts {
        return Woken::Unparked;
    }
    /// What the locked section decided, carried out after both guards drop.
    enum Decided {
        Return(Woken),
        Refused(Refusal),
        Switch(TaskId, hal::context::TaskHandle, hal::context::TaskHandle),
    }
    with_interrupts_disabled(|| {
        let now = crate::clock::mono_ticks();
        let decided = {
            // Lock order: this core's queue, then the task table.
            let mut queue = CPU_SCHED[cpu].lock();
            let state: &mut CpuSched = &mut queue;
            let mut tasks = TASKS.lock();
            let me = state.current;
            // Decide before mutating, glue included: mint both switch
            // handles — the caller's, and the ready ring's head (the only
            // task `park_step` can switch to) — before it runs. A handle is
            // a pointer token, not a borrow, so `park_step` may then take the
            // table.
            let head = state.ready.get(0);
            let prev_h = tasks
                .get_mut(me)
                .map(|t| hal::context::TaskHandle::new(&mut t.ctx));
            let next_h = head
                .and_then(|h| tasks.get_mut(h))
                .map(|t| hal::context::TaskHandle::new(&mut t.ctx));
            if prev_h.is_none() || (head.is_some() && next_h.is_none()) {
                Decided::Refused(Refusal::MissingHandle)
            } else {
                match park_step(
                    &mut state.ready,
                    &mut state.sleepers,
                    &mut *tasks,
                    &mut state.current,
                    now,
                    deadline,
                ) {
                    ParkStep::Return(w) => Decided::Return(w),
                    ParkStep::Refused(r) => Decided::Refused(r),
                    ParkStep::Switch(next) => match (prev_h, next_h) {
                        // `next` is the head popped by `park_step`.
                        (Some(p), Some(n)) if head == Some(next) => Decided::Switch(me, p, n),
                        // Unreachable: the head was checked above.
                        _ => Decided::Refused(Refusal::MissingHandle),
                    },
                }
            }
        }; // both guards dropped here — never held across `switch`.
        let me = match decided {
            Decided::Return(w) => return w,
            Decided::Refused(r) => {
                r.debug_fail();
                return Woken::Unparked;
            }
            Decided::Switch(me, prev_h, next_h) => {
                PREEMPT[cpu].switches.fetch_add(1, Ordering::Relaxed);
                hal::context::switch(prev_h, next_h);
                me
            }
        };
        // Resumed on this same core (tasks are pinned), still `IF = 0`: an
        // unpark or this core's tick made us Ready and recorded why.
        TASKS.lock().get(me).map_or(Woken::Unparked, |t| t.woken)
    })
}

/// Wake task `id` if it is parked, else store its permit so its next park
/// returns at once; a dead, unknown or idle id is refused and nothing
/// changes. A wake on another core sends that core the reschedule IPI; a
/// wake on this core is picked up at its next tick if this core's idle is
/// running (see [`super::on_tick`]), else at the current task's next switch.
/// Callable from any core, from task **and IRQ** context (see the module
/// docs for the argument); never blocks, never allocates, never switches.
pub fn unpark(id: TaskId) -> UnparkOutcome {
    with_interrupts_disabled(|| {
        // The pinned core, read under the table alone (released before any
        // queue lock is taken: queue → table is the only nesting order).
        let Some(cpu) = TASKS.lock().get(id).map(|t| t.cpu as usize) else {
            return UnparkOutcome::Refused;
        };
        if cpu >= MAX_CPUS {
            return UnparkOutcome::Refused;
        }
        let outcome = {
            let mut queue = CPU_SCHED[cpu].lock();
            let state: &mut CpuSched = &mut queue;
            let mut tasks = TASKS.lock();
            unpark_step(&mut state.ready, &mut state.sleepers, &mut *tasks, id)
        };
        if wants_ipi(outcome, cpu, local_cpu()) {
            if let Some(lapic) = crate::smp::lapic_id_of(cpu as u32) {
                let _sent = hal::apic::send_ipi(lapic, crate::interrupts::VECTOR_RESCHED_IPI);
            }
        }
        outcome
    })
}

/// Debug/introspection: whether task `id` exists and is parked.
#[must_use]
pub fn task_is_parked(id: TaskId) -> bool {
    with_interrupts_disabled(|| {
        TASKS
            .lock()
            .get(id)
            .is_some_and(|t| t.state == TaskState::Parked)
    })
}

// ── Boot proof ──────────────────────────────────────────────────────────────

/// Progress of the park proof task, published for the BSP.
static PP_STAGE: AtomicU32 = AtomicU32::new(0);
/// Set by the BSP once its pre-park unpark returned.
static PP_PERMIT_SENT: AtomicBool = AtomicBool::new(false);
/// What the proof task's blocking park returned (`true` = `Unparked`).
static PP_CROSS_WOKEN: AtomicBool = AtomicBool::new(false);
/// Whether the proof task's `park_until` returned `Deadline` at or past it.
static PP_DEADLINE_OK: AtomicBool = AtomicBool::new(false);
/// The proof task's deadline park: the ticks it asked for and the ticks it
/// actually waited (for the informational line).
static PP_DEADLINE_WAITED: AtomicU64 = AtomicU64::new(0);
/// Mono tick at which the local-wake probe task resumed (`u64::MAX` before).
static PL_RAN_AT: AtomicU64 = AtomicU64::new(u64::MAX);

const STAGE_STARTED: u32 = 1;
const STAGE_PERMIT_OK: u32 = 2;
const STAGE_PARKING: u32 = 3;
const STAGE_WOKEN: u32 = 4;
const STAGE_DEADLINE_DONE: u32 = 5;
const STAGE_FAILED: u32 = 0xFF;

/// How far ahead the proof task's `park_until` deadline is.
const PROOF_DEADLINE_TICKS: u64 = 5;
/// Upper bound on every wait in the proof (3 s; TCG vCPUs get descheduled).
const PROOF_TIMEOUT_TICKS: u64 = 300;
/// The BSP idle window: its own ticks must advance by at least this many —
/// two and a half time slices, so a still-runnable BSP task would be switched
/// to at least twice.
const IDLE_WINDOW_TICKS: u64 = 25;

/// The park proof task, pinned to an application processor.
fn park_proof_task() {
    PP_STAGE.store(STAGE_STARTED, Ordering::Release);
    // 1. Unpark before park: wait (spinning, not parking) until the BSP's
    //    unpark has returned, then park. It must return at once — the BSP
    //    sends nothing else until it sees STAGE_PERMIT_OK.
    let start = crate::clock::mono_ticks();
    while !PP_PERMIT_SENT.load(Ordering::Acquire) {
        if crate::clock::mono_ticks().wrapping_sub(start) > PROOF_TIMEOUT_TICKS {
            PP_STAGE.store(STAGE_FAILED, Ordering::Release);
            return;
        }
        core::hint::spin_loop();
    }
    park();
    PP_STAGE.store(STAGE_PERMIT_OK, Ordering::Release);

    // 2. Cross-core: block until the BSP, seeing this task parked, unparks it.
    PP_STAGE.store(STAGE_PARKING, Ordering::Release);
    let woken = park_until(crate::clock::mono_ticks().saturating_add(10 * PROOF_TIMEOUT_TICKS));
    PP_CROSS_WOKEN.store(woken == Woken::Unparked, Ordering::Release);
    PP_STAGE.store(STAGE_WOKEN, Ordering::Release);

    // 3. Deadline: nobody unparks; this core's tick must wake it, not early.
    let begin = crate::clock::mono_ticks();
    let deadline = begin.saturating_add(PROOF_DEADLINE_TICKS);
    let woken = park_until(deadline);
    let after = crate::clock::mono_ticks();
    PP_DEADLINE_WAITED.store(after.wrapping_sub(begin), Ordering::Relaxed);
    PP_DEADLINE_OK.store(
        woken == Woken::Deadline && after >= deadline,
        Ordering::Release,
    );
    PP_STAGE.store(STAGE_DEADLINE_DONE, Ordering::Release);
}

/// The local-wake probe: park on the BSP, record when it resumed, exit.
fn park_local_task() {
    park();
    PL_RAN_AT.store(crate::clock::mono_ticks(), Ordering::Release);
}

/// Informational: mono ticks from kmain (the BSP's idle) unparking a task
/// parked on the BSP itself — no IPI — until that task runs, with kmain
/// halted meanwhile. The tick's "idle is current and `ready` is not empty"
/// rule bounds it by about one tick; before it, the wait was the rest of the
/// idle's 10-tick slice. `None` if the probe could not run.
fn measure_local_wake(bsp: usize) -> Option<u64> {
    PL_RAN_AT.store(u64::MAX, Ordering::Release);
    let id = super::spawn_on(bsp as u32, "park-local", park_local_task).ok()?;
    let begin = crate::clock::mono_ticks();
    while !task_is_parked(id)
        && crate::clock::mono_ticks().wrapping_sub(begin) < PROOF_TIMEOUT_TICKS
    {
        super::yield_now();
    }
    if !task_is_parked(id) {
        return None;
    }
    let t0 = crate::clock::mono_ticks();
    if unpark(id) != UnparkOutcome::Woke {
        return None;
    }
    while PL_RAN_AT.load(Ordering::Acquire) == u64::MAX
        && crate::clock::mono_ticks().wrapping_sub(t0) < PROOF_TIMEOUT_TICKS
    {
        super::idle_halt();
    }
    match PL_RAN_AT.load(Ordering::Acquire) {
        u64::MAX => None,
        ran => Some(ran.wrapping_sub(t0)),
    }
}

/// Wait (bounded) for the proof task to reach `stage`; `false` on timeout or
/// if it reported failure.
fn wait_stage(stage: u32) -> bool {
    super::wait_on_other_core(
        || {
            let s = PP_STAGE.load(Ordering::Acquire);
            s >= stage
        },
        PROOF_TIMEOUT_TICKS,
    ) && PP_STAGE.load(Ordering::Acquire) != STAGE_FAILED
}

/// Run the park/unpark boot proof and print the asserted line
///
/// ```text
/// [sched] park: cross-core=ok permit-before-park=ok deadline=ok dead-unpark=refused sfs-commit=parked bsp-idles=yes ok
/// ```
///
/// - `permit-before-park`: the BSP unparks a task on an AP while it runs
///   (`PermitStored`); the task's next `park` returns at once — nothing else
///   could wake it, so a lost permit is a timeout.
/// - `cross-core`: the BSP waits until that task is parked, unparks it
///   (`Woke`, sent by IPI), and the task's `park_until` (far deadline)
///   returns `Unparked`.
/// - `deadline`: the task's `park_until(now + 5)` returns `Deadline`, at or
///   past the deadline, with nobody unparking it.
/// - `dead-unpark`: once the task has exited and been reaped, unparking its
///   id is `Refused`.
/// - `sfs-commit`: the task id `sfs_commit` (the SentinelFS commit task) is
///   parked — it is a normal blocked task, not a poller.
/// - `bsp-idles`: over a window in which the BSP's own scheduler tick
///   advances [`IDLE_WINDOW_TICKS`] (so its idle's time slice expires at least
///   twice) with kmain halted, the BSP performs **zero** switches and the
///   commit task is still parked. The old yield-poll made the commit task
///   runnable, so each expiry switched to it.
///
/// Runs on the BSP, as kmain, after `sfs::prove_mount`. Interrupts are opened
/// for its duration (the idle window halts on them; the spawn below then
/// allocates preemptibly, per hal-tcb §5e) and restored after.
pub fn prove_park(sfs_commit: Option<TaskId>) {
    use hal::serial::{write_dec, write_str};

    let were_enabled = hal::cpu::interrupts_enabled();
    hal::cpu::enable_interrupts();
    let bsp = local_cpu();

    // The commit task parks itself once it has nothing to do; give it the
    // core until it has (bounded).
    let sfs_parked_at = |id: Option<TaskId>| id.is_some_and(task_is_parked);
    let begin = crate::clock::mono_ticks();
    while !sfs_parked_at(sfs_commit)
        && crate::clock::mono_ticks().wrapping_sub(begin) < PROOF_TIMEOUT_TICKS
    {
        super::yield_now();
    }

    let target = (1..crate::smp::cpu_count() as u32)
        .find(|&c| c as usize != bsp && super::cpu_is_schedulable(c));

    PP_STAGE.store(0, Ordering::Release);
    PP_PERMIT_SENT.store(false, Ordering::Release);
    PP_CROSS_WOKEN.store(false, Ordering::Release);
    PP_DEADLINE_OK.store(false, Ordering::Release);

    let mut permit_ok = false;
    let mut cross_ok = false;
    let mut deadline_ok = false;
    let mut dead_refused = false;
    if let Some(Ok(id)) = target.map(|cpu| super::spawn_on(cpu, "park-proof", park_proof_task)) {
        if wait_stage(STAGE_STARTED) {
            let first = unpark(id);
            PP_PERMIT_SENT.store(true, Ordering::Release);
            permit_ok = first == UnparkOutcome::PermitStored && wait_stage(STAGE_PERMIT_OK);
        }
        if permit_ok
            && wait_stage(STAGE_PARKING)
            && super::wait_on_other_core(|| task_is_parked(id), PROOF_TIMEOUT_TICKS)
        {
            let second = unpark(id);
            cross_ok = second == UnparkOutcome::Woke
                && wait_stage(STAGE_WOKEN)
                && PP_CROSS_WOKEN.load(Ordering::Acquire);
        }
        if cross_ok && wait_stage(STAGE_DEADLINE_DONE) {
            deadline_ok = PP_DEADLINE_OK.load(Ordering::Acquire);
        }
        // The AP's idle reaps the exited task; then its id must be refused.
        if super::wait_on_other_core(|| super::task_name(id).is_none(), PROOF_TIMEOUT_TICKS) {
            dead_refused = unpark(id) == UnparkOutcome::Refused;
        }
    }

    let local_wake = measure_local_wake(bsp);

    // The idle window: kmain halts; count the BSP's ticks and switches.
    let sfs_before = sfs_parked_at(sfs_commit);
    let ticks0 = PREEMPT[bsp].ticks.load(Ordering::Relaxed);
    let switches0 = PREEMPT[bsp].switches.load(Ordering::Relaxed);
    let begin = crate::clock::mono_ticks();
    let mut halts: u64 = 0;
    while PREEMPT[bsp]
        .ticks
        .load(Ordering::Relaxed)
        .wrapping_sub(ticks0)
        < IDLE_WINDOW_TICKS
        && crate::clock::mono_ticks().wrapping_sub(begin) < PROOF_TIMEOUT_TICKS
    {
        super::idle_halt();
        halts += 1;
    }
    let ticks = PREEMPT[bsp]
        .ticks
        .load(Ordering::Relaxed)
        .wrapping_sub(ticks0);
    let switches = PREEMPT[bsp]
        .switches
        .load(Ordering::Relaxed)
        .wrapping_sub(switches0);
    let sfs_after = sfs_parked_at(sfs_commit);
    let bsp_idles = ticks >= IDLE_WINDOW_TICKS && switches == 0 && halts > 0;
    let sfs_ok = sfs_before && sfs_after;

    if !were_enabled {
        hal::cpu::disable_interrupts();
    }

    write_str("[sched] park: target=");
    match target {
        Some(cpu) => {
            write_str("cpu");
            write_dec(u64::from(cpu));
        }
        None => write_str("none"),
    }
    write_str(" deadline-waited=");
    write_dec(PP_DEADLINE_WAITED.load(Ordering::Relaxed));
    write_str("/");
    write_dec(PROOF_DEADLINE_TICKS);
    write_str(" local-wake-ticks=");
    match local_wake {
        Some(t) => write_dec(t),
        None => write_str("none"),
    }
    write_str(" bsp-window ticks=");
    write_dec(ticks);
    write_str(" halts=");
    write_dec(halts);
    write_str(" switches=");
    write_dec(switches);
    write_str("\n");

    let ok_no = |b: bool| if b { "ok" } else { "FAIL" };
    write_str("[sched] park: cross-core=");
    write_str(ok_no(cross_ok));
    write_str(" permit-before-park=");
    write_str(ok_no(permit_ok));
    write_str(" deadline=");
    write_str(ok_no(deadline_ok));
    write_str(" dead-unpark=");
    write_str(if dead_refused { "refused" } else { "ACCEPTED" });
    write_str(" sfs-commit=");
    write_str(match (sfs_commit, sfs_ok) {
        (None, _) => "none",
        (Some(_), true) => "parked",
        (Some(_), false) => "runnable",
    });
    write_str(" bsp-idles=");
    write_str(if bsp_idles { "yes" } else { "no" });
    let all = permit_ok && cross_ok && deadline_ok && dead_refused && sfs_ok && bsp_idles;
    write_str(if all { " ok\n" } else { " FAIL\n" });
}

// ── Host tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{
        expire_step, park_step, unpark_step, wants_ipi, ParkStep, ParkTable, ParkView, Refusal,
        Sleepers, UnparkOutcome, Woken,
    };
    use crate::sched::{ReadyQueue, ReadyRing, TaskId, TaskState};

    /// A small task table: id `i` is slot `i`; id 0 is the idle.
    pub(super) struct Model<const T: usize> {
        pub(super) state: [TaskState; T],
        pub(super) permit: [bool; T],
        pub(super) woken: [Woken; T],
    }

    impl<const T: usize> Model<T> {
        fn new() -> Self {
            let mut state = [TaskState::Ready; T];
            state[0] = TaskState::Running;
            Self {
                state,
                permit: [false; T],
                woken: [Woken::Unparked; T],
            }
        }
    }

    impl<const T: usize> ParkTable for Model<T> {
        fn view(&mut self, id: TaskId) -> Option<ParkView<'_>> {
            let i = id.as_usize();
            if i >= T {
                return None;
            }
            Some(ParkView {
                state: &mut self.state[i],
                permit: &mut self.permit[i],
                woken: &mut self.woken[i],
                idle: i == 0,
            })
        }
    }

    /// One core: the idle (0) running, tasks 1..T ready in order.
    struct Core<const T: usize> {
        ready: ReadyRing<8>,
        sleepers: Sleepers<8>,
        table: Model<T>,
        current: TaskId,
    }

    impl<const T: usize> Core<T> {
        fn new() -> Self {
            let mut ready = ReadyRing::new();
            for i in 1..T {
                ready.push_back(TaskId(i as u64));
            }
            Self {
                ready,
                sleepers: Sleepers::new(),
                table: Model::new(),
                current: TaskId(0),
            }
        }
        /// Switch to `id` by yielding round-robin until it is current.
        fn run(&mut self, id: u64) {
            for _ in 0..16 {
                if self.current == TaskId(id) {
                    return;
                }
                let prev = self.current;
                let next = self.ready.pop_front().expect("runnable");
                self.ready.push_back(prev);
                self.table.state[prev.as_usize()] = TaskState::Ready;
                self.table.state[next.as_usize()] = TaskState::Running;
                self.current = next;
            }
            panic!("task {id} never became current");
        }
        fn park(&mut self, now: u64, deadline: Option<u64>) -> ParkStep {
            park_step(
                &mut self.ready,
                &mut self.sleepers,
                &mut self.table,
                &mut self.current,
                now,
                deadline,
            )
        }
        fn unpark(&mut self, id: u64) -> UnparkOutcome {
            unpark_step(
                &mut self.ready,
                &mut self.sleepers,
                &mut self.table,
                TaskId(id),
            )
        }
        fn tick(&mut self, now: u64) -> usize {
            expire_step(&mut self.ready, &mut self.sleepers, &mut self.table, now)
        }
        fn in_ready(&self, id: u64) -> bool {
            (0..self.ready.len()).any(|i| self.ready.get(i) == Some(TaskId(id)))
        }
    }

    #[test]
    fn unpark_before_park_makes_the_next_park_return_at_once() {
        let mut c: Core<3> = Core::new();
        c.run(1);
        assert_eq!(c.unpark(1), UnparkOutcome::PermitStored);
        assert_eq!(c.park(0, None), ParkStep::Return(Woken::Unparked));
        assert_eq!(c.current, TaskId(1), "no switch");
        assert_eq!(c.table.state[1], TaskState::Running);
        // The permit was consumed: the next park blocks.
        assert_eq!(c.park(0, None), ParkStep::Switch(TaskId(2)));
        assert_eq!(c.table.state[1], TaskState::Parked);
    }

    #[test]
    fn the_permit_is_one_not_counted() {
        let mut c: Core<3> = Core::new();
        c.run(1);
        assert_eq!(c.unpark(1), UnparkOutcome::PermitStored);
        assert_eq!(c.unpark(1), UnparkOutcome::PermitStored);
        assert_eq!(c.park(0, None), ParkStep::Return(Woken::Unparked));
        assert!(matches!(c.park(0, None), ParkStep::Switch(_)));
    }

    #[test]
    fn a_parked_task_is_on_no_ring_until_unparked() {
        let mut c: Core<3> = Core::new();
        c.run(1);
        assert_eq!(c.park(0, None), ParkStep::Switch(TaskId(2)));
        assert!(!c.in_ready(1));
        assert_ne!(c.current, TaskId(1));
        // Ticks and yields never bring it back.
        assert_eq!(c.tick(1_000_000), 0);
        c.run(0);
        c.run(2);
        assert!(!c.in_ready(1));
        assert_eq!(c.unpark(1), UnparkOutcome::Woke);
        assert!(c.in_ready(1));
        assert_eq!(c.table.state[1], TaskState::Ready);
        assert_eq!(c.table.woken[1], Woken::Unparked);
        assert!(!c.table.permit[1], "a wake does not also store a permit");
    }

    #[test]
    fn a_deadline_wakes_on_its_tick_never_before_and_only_once() {
        let mut c: Core<3> = Core::new();
        c.run(1);
        assert_eq!(c.park(100, Some(105)), ParkStep::Switch(TaskId(2)));
        assert_eq!(c.sleepers.len(), 1);
        for now in 100..105 {
            assert_eq!(c.tick(now), 0, "not before its tick");
            assert_eq!(c.table.state[1], TaskState::Parked);
        }
        assert_eq!(c.tick(105), 1);
        assert_eq!(c.table.state[1], TaskState::Ready);
        assert_eq!(c.table.woken[1], Woken::Deadline);
        assert_eq!(c.sleepers.len(), 0);
        assert_eq!(c.tick(106), 0, "fires once");
        assert_eq!(c.tick(200), 0);
    }

    #[test]
    fn a_deadline_already_reached_returns_at_once() {
        let mut c: Core<3> = Core::new();
        c.run(1);
        assert_eq!(c.park(50, Some(50)), ParkStep::Return(Woken::Deadline));
        assert_eq!(c.park(51, Some(50)), ParkStep::Return(Woken::Deadline));
        assert_eq!(c.current, TaskId(1));
        assert_eq!(c.sleepers.len(), 0);
    }

    #[test]
    fn an_unpark_cancels_the_deadline() {
        let mut c: Core<3> = Core::new();
        c.run(1);
        assert!(matches!(c.park(0, Some(10)), ParkStep::Switch(_)));
        assert_eq!(c.unpark(1), UnparkOutcome::Woke);
        assert_eq!(c.sleepers.len(), 0);
        assert_eq!(c.tick(10), 0, "the cancelled deadline never fires");
        assert_eq!(c.table.woken[1], Woken::Unparked);
    }

    #[test]
    fn a_deadline_then_an_unpark_stores_a_permit() {
        let mut c: Core<3> = Core::new();
        c.run(1);
        assert!(matches!(c.park(0, Some(3)), ParkStep::Switch(_)));
        assert_eq!(c.tick(3), 1);
        // Ready, not yet run: the unpark is kept for the next park.
        assert_eq!(c.unpark(1), UnparkOutcome::PermitStored);
        c.run(1);
        assert_eq!(c.table.woken[1], Woken::Deadline);
        assert_eq!(c.park(4, Some(100)), ParkStep::Return(Woken::Unparked));
    }

    #[test]
    fn the_idle_never_parks_and_is_never_unparked() {
        let mut c: Core<3> = Core::new();
        assert_eq!(c.park(0, None), ParkStep::Refused(Refusal::Idle));
        assert_eq!(c.park(0, Some(5)), ParkStep::Refused(Refusal::Idle));
        assert_eq!(c.current, TaskId(0));
        assert_eq!(c.table.state[0], TaskState::Running);
        assert_eq!(c.sleepers.len(), 0);
        // A permit the idle could never consume is never stored.
        assert_eq!(c.unpark(0), UnparkOutcome::Refused);
        assert!(!c.table.permit[0]);
        c.run(1);
        assert_eq!(c.unpark(0), UnparkOutcome::Refused, "ready, still refused");
        assert!(!c.table.permit[0]);
    }

    #[test]
    fn unpark_of_a_dead_or_unknown_id_is_refused_and_changes_nothing() {
        let mut c: Core<3> = Core::new();
        c.table.state[2] = TaskState::Exited;
        let ready_before = c.ready.len();
        assert_eq!(c.unpark(2), UnparkOutcome::Refused);
        assert!(!c.table.permit[2]);
        assert_eq!(c.unpark(99), UnparkOutcome::Refused);
        assert_eq!(c.ready.len(), ready_before);
    }

    #[test]
    fn unpark_of_a_dead_id_through_the_real_table_is_refused() {
        // No task with this id exists (ids are never reused, so an id past
        // the counter can never have existed): the production path refuses.
        assert_eq!(super::unpark(TaskId(u64::MAX - 1)), UnparkOutcome::Refused);
        assert!(!super::task_is_parked(TaskId(u64::MAX - 1)));
    }

    #[test]
    fn cross_core_unpark_touches_only_the_target_core_and_wants_an_ipi() {
        // Two cores, each with its own ring, sleepers and (here) table; task 1
        // is pinned to core A and parks there.
        let mut a: Core<3> = Core::new();
        let mut b: Core<3> = Core::new();
        a.run(1);
        assert!(matches!(a.park(0, Some(1000)), ParkStep::Switch(_)));
        let b_before = (b.ready.len(), b.current, b.sleepers.len());
        // Core B's unpark runs A's step on A's structures (under A's lock in
        // production) and asks for the IPI because the target is remote.
        let out = a.unpark(1);
        assert_eq!(out, UnparkOutcome::Woke);
        assert!(wants_ipi(out, 0, 1));
        assert_eq!((b.ready.len(), b.current, b.sleepers.len()), b_before);
        assert_ne!(a.current, TaskId(1), "A's current is A's to change");
        assert!(a.in_ready(1));
        // A local wake, a stored permit and a refusal never IPI.
        assert!(!wants_ipi(UnparkOutcome::Woke, 1, 1));
        assert!(!wants_ipi(UnparkOutcome::PermitStored, 0, 1));
        assert!(!wants_ipi(UnparkOutcome::Refused, 0, 1));
        b.run(2);
    }

    #[test]
    fn sleepers_keep_the_earliest_and_drain_every_expired_entry() {
        let mut s: Sleepers<4> = Sleepers::new();
        assert!(s.insert(TaskId(1), 30));
        assert!(s.insert(TaskId(2), 10));
        assert!(s.insert(TaskId(3), 20));
        assert!(s.insert(TaskId(4), 10));
        assert!(!s.insert(TaskId(5), 1), "full");
        assert_eq!(s.earliest, 10);
        let mut woke = alloc::vec::Vec::new();
        s.drain_expired(9, |id| woke.push(id));
        assert!(woke.is_empty());
        s.drain_expired(20, |id| woke.push(id));
        woke.sort();
        assert_eq!(woke, [TaskId(2), TaskId(3), TaskId(4)]);
        assert_eq!(s.len(), 1);
        assert_eq!(s.earliest, 30);
        s.remove(TaskId(1));
        assert_eq!(s.len(), 0);
        assert_eq!(s.earliest, u64::MAX);
        assert_eq!(s.get(0), None);
    }
}

// ── Kani proofs ─────────────────────────────────────────────────────────────

/// Kani proofs over the pure park machine — the same [`park_step`],
/// [`unpark_step`] and [`expire_step`] production runs, over the production
/// [`super::ReadyRing`] and [`Sleepers`] at small capacities, with a small
/// array task table, and the production [`super::pick_next_parking_exits`]
/// for yields, slice-expiry switches and exits.
///
/// One core: a cross-core unpark runs the target core's step on that core's
/// structures under its lock, so the one-core model is the whole state any
/// unpark can touch, and which core it came from changes nothing in it.
///
/// Each harness is an **induction step**: from any state satisfying all three
/// invariants ([`Model::any_valid`]: every ring position, ring content,
/// sleeper entry, task state, permit, ghost and the clock symbolic, then
/// assumed consistent), one symbolic operation keeps its property's
/// invariant; and the boot state satisfies them all (the base case). So each
/// property holds after any number of operations, not just within a bound.
/// Bounded-trace versions (3–4 operations from the boot state) were measured
/// at 34–76 s each and dropped: the induction subsumes them.
///
/// The clock bounds in [`Model::any_valid`] (`now < 2^32`, deadlines
/// `< 2^33`) are an order/translation abstraction: production only compares
/// these values and adds a small offset to one, so the induction is proven
/// for every state in that range, and any production state with the same
/// order relations behaves identically; the bounds only rule out overflow
/// of the model's own `now + k` / `now + 1`.
///
/// Bounds (shrunk to keep each harness under 60 s): 3 tasks — 0 is the idle,
/// which never parks or exits, plus two that can both be parked at once, both
/// with deadlines — and one id past the table (a dead id); rings and the
/// sleeper set at capacity 2 (every non-idle task). The operation is one of:
/// park (no deadline, or `now + 0..=2`), unpark (any id), tick (`now`
/// advances by 0 or 1, deadlines drain, then a switch if any woke or,
/// symbolically, on slice expiry — with no advance this is a yield), or exit.
#[cfg(kani)]
mod proofs {
    use super::{
        expire_step, park_step, unpark_step, ParkStep, ParkTable, ParkView, Refusal, Sleepers,
        UnparkOutcome, Woken,
    };
    use crate::sched::{pick_next_parking_exits, ReadyRing, TaskId, TaskState};

    const IDS: usize = 3;
    /// Ring and sleeper capacity: room for every non-idle task.
    const CAP: usize = 2;

    struct Table {
        state: [TaskState; IDS],
        permit: [bool; IDS],
        woken: [Woken; IDS],
    }

    impl ParkTable for Table {
        fn view(&mut self, id: TaskId) -> Option<ParkView<'_>> {
            let i = id.as_usize();
            if i >= IDS {
                return None;
            }
            Some(ParkView {
                state: &mut self.state[i],
                permit: &mut self.permit[i],
                woken: &mut self.woken[i],
                idle: i == 0,
            })
        }
    }

    /// Which property the harness asserts inline (the others' ghosts are
    /// still kept, their assertions skipped).
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Prop {
        LostWakeup,
        Places,
        Deadline,
    }

    struct Model {
        ready: ReadyRing<CAP>,
        zombies: ReadyRing<CAP>,
        sleepers: Sleepers<CAP>,
        t: Table,
        current: TaskId,
        now: u64,
        prop: Prop,
        // Ghosts.
        /// An unpark (not refused) reached the task since its last park call.
        owed: [bool; IDS],
        /// The task's permit was stored by an unpark since its last park
        /// returned.
        permit_owed: [bool; IDS],
        /// The deadline of the task's current blocking park, if any.
        deadline: [Option<u64>; IDS],
        /// Deadline wakes during the task's current blocking park.
        fires: [u8; IDS],
        // What the step did, for the harnesses' `cover!`s.
        /// A park switched away with a deadline (a sleeper entry was added).
        ev_park_deadline: bool,
        /// A tick's drain woke at least one task.
        ev_expiry: bool,
        /// An unpark woke a task and removed its sleeper entry.
        ev_unpark_removed: bool,
    }

    impl Model {
        /// Any task running (the others ready, in round-robin order after
        /// it), any permits already stored, the clock at 0.
        fn new(prop: Prop) -> Self {
            let first: usize = kani::any();
            kani::assume(first < IDS);
            let mut ready = ReadyRing::new();
            let mut state = [TaskState::Ready; IDS];
            state[first] = TaskState::Running;
            for k in 1..IDS {
                let i = (first + k) % IDS;
                super::ReadyQueue::push_back(&mut ready, TaskId::from_usize(i));
            }
            let permit: [bool; IDS] = kani::any();
            Self {
                ready,
                zombies: ReadyRing::new(),
                sleepers: Sleepers::new(),
                t: Table {
                    state,
                    permit,
                    woken: [Woken::Unparked; IDS],
                },
                current: TaskId::from_usize(first),
                now: 0,
                prop,
                owed: [false; IDS],
                permit_owed: [false; IDS],
                deadline: [None; IDS],
                fires: [0; IDS],
                ev_park_deadline: false,
                ev_expiry: false,
                ev_unpark_removed: false,
            }
        }

        /// Switch `current` round-robin (a yield, a tick's switch, an exit),
        /// with the state updates `reschedule_locked_on` makes.
        fn switch(&mut self, exiting: bool) {
            let prev = self.current;
            if let Some(next) =
                pick_next_parking_exits(&mut self.ready, &mut self.zombies, prev, exiting)
            {
                self.t.state[prev.as_usize()] = if exiting {
                    TaskState::Exited
                } else {
                    TaskState::Ready
                };
                self.t.state[next.as_usize()] = TaskState::Running;
                self.current = next;
            }
        }

        fn park(&mut self) {
            let me = self.current.as_usize();
            let deadline = if kani::any() {
                let k: u64 = kani::any();
                kani::assume(k <= 2);
                Some(self.now + k)
            } else {
                None
            };
            let had_permit = self.permit_owed[me];
            self.owed[me] = false;
            let r = park_step(
                &mut self.ready,
                &mut self.sleepers,
                &mut self.t,
                &mut self.current,
                self.now,
                deadline,
            );
            // (a) an unpark before the park makes it return at once.
            if self.prop == Prop::LostWakeup && had_permit {
                assert!(r == ParkStep::Return(Woken::Unparked));
            }
            match r {
                ParkStep::Return(w) => {
                    self.permit_owed[me] = false;
                    // (c) never a deadline answer before the deadline.
                    if self.prop == Prop::Deadline && w == Woken::Deadline {
                        assert!(deadline.is_some_and(|d| self.now >= d));
                    }
                }
                ParkStep::Refused(r) => {
                    // Only the idle is ever refused: a non-idle task always
                    // finds its core's idle on `ready`.
                    if self.prop == Prop::Places {
                        assert!(me == 0 && r == Refusal::Idle);
                    }
                }
                ParkStep::Switch(next) => {
                    if self.prop == Prop::Places {
                        assert!(me != 0, "the idle never parks");
                        assert!(next.as_usize() != me);
                    }
                    self.deadline[me] = deadline;
                    self.fires[me] = 0;
                    self.ev_park_deadline = deadline.is_some();
                }
            }
        }

        fn unpark(&mut self) {
            let id: usize = kani::any();
            kani::assume(id <= IDS);
            let was = if id < IDS {
                Some(self.t.state[id])
            } else {
                None
            };
            let sleepers_before = self.sleepers.len();
            let out = unpark_step(
                &mut self.ready,
                &mut self.sleepers,
                &mut self.t,
                TaskId::from_usize(id),
            );
            self.ev_unpark_removed =
                out == UnparkOutcome::Woke && self.sleepers.len() < sleepers_before;
            match was {
                // Dead, unknown, or the idle (which never parks, so its
                // permit could never be consumed): refused.
                None | Some(TaskState::Exited) => {
                    if self.prop == Prop::LostWakeup {
                        assert!(out == UnparkOutcome::Refused);
                    }
                }
                Some(_) if id == 0 => {
                    if self.prop == Prop::LostWakeup {
                        assert!(out == UnparkOutcome::Refused);
                    }
                }
                Some(TaskState::Parked) => {
                    if self.prop == Prop::LostWakeup {
                        assert!(out == UnparkOutcome::Woke);
                    }
                    self.owed[id] = true;
                }
                Some(_) => {
                    if self.prop == Prop::LostWakeup {
                        assert!(out == UnparkOutcome::PermitStored);
                    }
                    self.owed[id] = true;
                    self.permit_owed[id] = true;
                }
            }
        }

        fn tick(&mut self) {
            if kani::any() {
                self.now += 1;
            }
            let before = self.t.state;
            let woke = expire_step(&mut self.ready, &mut self.sleepers, &mut self.t, self.now);
            let mut counted = 0;
            for i in 0..IDS {
                if before[i] == TaskState::Parked && self.t.state[i] != TaskState::Parked {
                    counted += 1;
                    self.fires[i] = self.fires[i].saturating_add(1);
                    if self.prop == Prop::Deadline {
                        // (c) a deadline wake: at or past the deadline, once.
                        assert!(self.t.woken[i] == Woken::Deadline);
                        assert!(self.deadline[i].is_some_and(|d| self.now >= d));
                        assert!(self.fires[i] == 1);
                    }
                }
                // (c) a deadline that has passed has fired.
                if self.prop == Prop::Deadline && self.t.state[i] == TaskState::Parked {
                    assert!(!self.deadline[i].is_some_and(|d| self.now >= d));
                }
            }
            if self.prop == Prop::Deadline {
                assert!(counted == woke);
            }
            self.ev_expiry = woke > 0;
            if woke > 0 || kani::any() {
                self.switch(false);
            }
        }

        /// One symbolic operation: park, unpark, tick, or — if `exits` —
        /// exit (of a non-idle task).
        fn step(&mut self, exits: bool) {
            let op: u8 = kani::any();
            kani::assume(op < 3 || (exits && op == 3));
            match op {
                0 => self.park(),
                1 => self.unpark(),
                2 => self.tick(),
                _ => {
                    if self.current != TaskId::IDLE {
                        self.switch(true);
                    }
                }
            }
        }

        /// (a)'s invariant: an owed unpark is never left parked, and a stored
        /// permit survives until a park consumes it; the idle is never owed
        /// one (an unpark of it is refused).
        fn lost_ok(&self) -> bool {
            let mut ok = !self.owed[0] && !self.permit_owed[0];
            for i in 0..IDS {
                ok &= !(self.owed[i] && self.t.state[i] == TaskState::Parked);
                ok &= !(self.permit_owed[i]
                    && self.t.state[i] != TaskState::Exited
                    && !self.t.permit[i]);
            }
            ok
        }

        /// (b)'s invariant: every id is exactly where its state says — a
        /// parked one on no ring and not current — every id on at most one of
        /// current/ready/zombies, the idle never parked or exited, and the
        /// sleepers name exactly the parked tasks with a deadline, once each,
        /// with that deadline, and `earliest` bounds every one of them.
        fn places_ok(&self) -> bool {
            let mut ready = [0u8; IDS];
            let mut zombie = [0u8; IDS];
            let mut sleeping = [0u8; IDS];
            let mut ok = true;
            for i in 0..CAP {
                if let Some(q) = self.ready.get(i) {
                    ready[q.as_usize()] += 1;
                }
                if let Some(z) = self.zombies.get(i) {
                    zombie[z.as_usize()] += 1;
                }
                if let Some((s, d)) = self.sleepers.get(i) {
                    sleeping[s.as_usize()] += 1;
                    ok &= self.deadline[s.as_usize()] == Some(d);
                }
            }
            ok &= self.earliest_ok();
            ok &= self.t.state[self.current.as_usize()] == TaskState::Running;
            ok &= matches!(self.t.state[0], TaskState::Running | TaskState::Ready);
            for i in 0..IDS {
                let cur = u8::from(self.current.as_usize() == i);
                ok &= ready[i] + zombie[i] + cur <= 1;
                ok &= match self.t.state[i] {
                    TaskState::Running => cur == 1,
                    TaskState::Ready => ready[i] == 1,
                    TaskState::Exited => zombie[i] == 1,
                    TaskState::Parked => {
                        ready[i] + zombie[i] + cur == 0
                            && sleeping[i] == u8::from(self.deadline[i].is_some())
                    }
                };
                ok &= self.t.state[i] == TaskState::Parked || sleeping[i] == 0;
            }
            ok
        }

        /// The sleeper set's own invariant: the cached `earliest` is at most
        /// every stored deadline (so the tick's `now < earliest` shortcut
        /// never skips a due entry). Production keeps it exact; `<=` is what
        /// correctness needs, and it is what is assumed and re-proven.
        fn earliest_ok(&self) -> bool {
            let mut ok = true;
            for j in 0..CAP {
                if let Some((_, d)) = self.sleepers.get(j) {
                    ok &= self.sleepers.earliest <= d;
                }
            }
            ok
        }

        /// (c)'s invariant: a parked task's deadline has not passed (it would
        /// have fired on the tick that reached it), it has not fired during
        /// this park, and the sleeper set's `earliest` bounds every entry.
        fn deadline_ok(&self) -> bool {
            let mut ok = self.earliest_ok();
            for i in 0..IDS {
                if self.t.state[i] == TaskState::Parked {
                    ok &= !self.deadline[i].is_some_and(|d| self.now >= d);
                    ok &= self.fires[i] == 0;
                }
            }
            ok
        }

        /// Any state satisfying all three invariants, the clock anywhere
        /// below 2^32. The sleeper set's cached `earliest` is symbolic too,
        /// constrained only by the invariants (`earliest <=` every entry).
        fn any_valid(prop: Prop) -> Self {
            let mut ready: ReadyRing<CAP> = ReadyRing::new();
            let mut zombies: ReadyRing<CAP> = ReadyRing::new();
            let mut sleepers: Sleepers<CAP> = Sleepers::new();
            ready.head = kani::any();
            ready.len = kani::any();
            zombies.head = kani::any();
            zombies.len = kani::any();
            sleepers.len = kani::any();
            kani::assume(ready.head < CAP && ready.len <= CAP);
            kani::assume(zombies.head < CAP && zombies.len <= CAP);
            kani::assume(sleepers.len <= CAP);
            let now: u64 = kani::any();
            kani::assume(now < 1 << 32);
            for i in 0..CAP {
                let (a, b, c): (usize, usize, usize) = kani::any();
                kani::assume(a < IDS && b < IDS && c < IDS);
                ready.buf[i] = TaskId::from_usize(a);
                zombies.buf[i] = TaskId::from_usize(b);
                sleepers.ids[i] = TaskId::from_usize(c);
                let at: u64 = kani::any();
                kani::assume(at < 1 << 33);
                sleepers.at[i] = at;
            }
            sleepers.earliest = kani::any();
            let current: usize = kani::any();
            kani::assume(current < IDS);
            let mut deadline = [None; IDS];
            for d in &mut deadline {
                if kani::any() {
                    let at: u64 = kani::any();
                    kani::assume(at < 1 << 33);
                    *d = Some(at);
                }
            }
            let m = Self {
                ready,
                zombies,
                sleepers,
                t: Table {
                    state: kani::any(),
                    permit: kani::any(),
                    woken: kani::any(),
                },
                current: TaskId::from_usize(current),
                now,
                prop,
                owed: kani::any(),
                permit_owed: kani::any(),
                deadline,
                fires: kani::any(),
                ev_park_deadline: false,
                ev_expiry: false,
                ev_unpark_removed: false,
            };
            kani::assume(m.places_ok() && m.lost_ok() && m.deadline_ok());
            m
        }
    }

    /// The base case of the three induction steps below: the boot state (any
    /// first running task, the others ready in order, any stored permits)
    /// satisfies all three invariants. And the inductive assumption is not
    /// vacuous: [`Model::any_valid`] can produce a state with both non-idle
    /// tasks parked, exactly one with a deadline.
    #[kani::proof]
    fn park_invariants_hold_at_boot() {
        let init = Model::new(Prop::Places);
        assert!(init.places_ok() && init.lost_ok() && init.deadline_ok());
        let m = Model::any_valid(Prop::Places);
        kani::cover!(
            m.t.state[1] == TaskState::Parked
                && m.t.state[2] == TaskState::Parked
                && m.sleepers.len() == 1
        );
    }

    /// The step's interesting transitions are reachable from the inductive
    /// assumption, so no induction step below passes by never reaching them:
    /// a park that switches away with a deadline, a tick whose drain wakes a
    /// task, and an unpark that wakes a task and drops its sleeper entry.
    ///
    /// The same `any_valid` + `step` the three induction steps run (the
    /// `Prop` only selects which assertions are checked, and CBMC assertions
    /// never prune paths, so reachability is identical). Kept in its own
    /// harness rather than in each step: the three cover goals cost each
    /// step 10+ s and pushed two of them past the 60 s cap.
    #[kani::proof]
    #[kani::unwind(4)]
    fn park_transitions_are_reachable() {
        let mut m = Model::any_valid(Prop::Places);
        m.step(true);
        kani::cover!(m.ev_park_deadline, "park switched away with a deadline");
        kani::cover!(m.ev_expiry, "a tick's drain woke a task");
        kani::cover!(
            m.ev_unpark_removed,
            "an unpark woke a task and dropped its deadline"
        );
    }

    /// (a) No lost wakeup. From **any** state satisfying the three
    /// invariants, one operation of any kind (park, unpark of any id, tick
    /// with or without a clock advance — a yield — or exit) keeps (a)'s
    /// invariant — a task unparked since its last park call is never parked,
    /// a stored permit survives until a park consumes it — and the inline
    /// assertions hold: a park with a permit owed returns at once, and every
    /// unpark answers by the target's state (parked → `Woke`, running/ready →
    /// `PermitStored`, exited/unknown → `Refused`). With the base case
    /// ([`park_invariants_hold_at_boot`]), by induction this holds on every
    /// interleaving of any length, which subsumes every bounded trace.
    #[kani::proof]
    #[kani::unwind(4)]
    fn park_no_lost_wakeup_inductive() {
        let mut m = Model::any_valid(Prop::LostWakeup);
        m.step(true);
        assert!(m.lost_ok());
    }

    /// (b) A parked task is never on a ready ring (nor current, nor a
    /// zombie), every id is on at most one ring — Invariant #4 extended to
    /// `Parked` — the idle never parks, and the sleeper set names exactly the
    /// parked tasks that have deadlines, with those deadlines. Inductive, as
    /// (a).
    #[kani::proof]
    #[kani::unwind(4)]
    fn parked_task_is_on_no_ring_inductive() {
        let mut m = Model::any_valid(Prop::Places);
        m.step(true);
        assert!(m.places_ok());
    }

    /// (c) A deadline fires at most once per park and never before its tick
    /// (the inline assertions on every wake), is not missed (a parked task's
    /// deadline is always still ahead), and a park answers `Deadline` at once
    /// only when it has already passed. Inductive, as (a).
    #[kani::proof]
    #[kani::unwind(4)]
    fn deadline_fires_once_never_early_inductive() {
        let mut m = Model::any_valid(Prop::Deadline);
        m.step(true);
        assert!(m.deadline_ok());
    }
}
