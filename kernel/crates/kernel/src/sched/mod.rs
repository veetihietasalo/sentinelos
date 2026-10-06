//! Preemptive kernel-thread scheduler (PR-A + PR-B of
//! `docs/specs/2026-07-15-scheduler-design.md`).
//!
//! A round-robin scheduler for **kernel threads only** (one shared address
//! space, ring 0). The trusted core is [`hal::context`] — one `global_asm!`
//! register switch plus a thin safe wrapper; everything here (the run queue,
//! task lifetime, and the full public API) is safe Rust
//! (`#![forbid(unsafe_code)]`).
//!
//! # PR-A scope (cooperative)
//!
//! [`init`], [`spawn`], [`yield_now`], [`exit`], and [`current_id`] — a
//! round-robin scheduler driven entirely by voluntary [`yield_now`]/[`exit`]
//! calls. See [`prove_cooperative`].
//!
//! # PR-B scope (preemptive)
//!
//! [`on_tick`] — hooked from `kernel::interrupts::handle_timer` (the PIT/IRQ0
//! handler) — decrements the current task's remaining time slice
//! ([`TIME_SLICE_TICKS`] per quantum) and, on expiry, either switches away
//! right there at the timer-IRQ tail ([`PreemptState::count`] `== 0`) or defers to
//! the [`preempt_enable`] that next brings [`PreemptState::count`] back to `0`
//! ([`PreemptState::need_resched`]). See [`prove_preemptive`] for the payoff boot proof (a
//! GEMM task's live vector accumulators surviving genuine, uninvited timer
//! preemption bit-exact) and the "Interrupt-flag discipline" section below for
//! how this avoids the PR-A review's force-`sti` carry-item.
//!
//! # SMP scope (PR-2 of the AP bring-up design — per-CPU, no work stealing)
//!
//! Every core has its **own** run queue ([`CPU_SCHED`]`[cpu]`: `current`,
//! `ready`, `zombies`) and its own preemption state ([`PREEMPT`]`[cpu]`), indexed
//! by the dense cpu index `kernel::smp` assigns (BSP = 0). Tasks are **pinned**:
//! [`spawn_on`] places a task on one core's queue and it never migrates; the BSP
//! decides placement ([`spawn`] = the local core). A remote placement is
//! followed by a **reschedule IPI** (`hal::apic::send_ipi`, vector
//! `kernel::interrupts::VECTOR_RESCHED_IPI`) so the target core — idling in
//! `sti; hlt` ([`ap_idle_loop`]) — wakes and switches to the task at the ISR
//! tail ([`on_resched_ipi`], the same shape as [`on_tick`]). Each AP adopted its
//! own control flow as its idle task in [`init_ap`], exactly as the BSP adopted
//! `kmain` in [`init`]. Since SMP phase 3 every core has its own LAPIC-timer
//! tick (`kernel::interrupts::handle_lapic_timer` → [`on_tick`] on that core),
//! so tasks on an AP are timer-preempted exactly like the BSP's. See
//! [`prove_pinned`] and [`prove_ap_preemptive`] for the boot proofs.
//!
//! # Park / unpark (SentinelFS spec §15 A25)
//!
//! [`park`] / [`park_until`] block the calling task — off every ring, state
//! [`TaskState::Parked`] — until [`unpark`] (from any core, task or IRQ
//! context) or a mono-tick deadline wakes it; an unpark that finds the task
//! awake stores its one wake permit, so no wakeup is lost. Deadlines live in a
//! fixed per-core set drained by [`on_tick`]. No new lock: the same queue →
//! table order, allocation-free. See the `sched/park.rs` module docs and
//! [`prove_park`].
//!
//! # Locking discipline
//!
//! Two kinds of lock, one order. [`CPU_SCHED`]`[cpu]` guards that core's queue;
//! [`TASKS`] guards the global task table (task lifetime + control blocks).
//! Order is always **queue → table** (never the reverse), and neither is ever
//! held across [`hal::context::switch`] — the `(prev, next)` `TaskHandle`s are
//! copied out and both guards are dropped before the switch runs, because the
//! handles are heap-stable tokens, not guard-borrows. [`hal::sync::SpinMutex`]
//! does **not** itself disable interrupts, so both locks are only ever taken
//! with interrupts *already* disabled on the local core. See Invariants 1–5 in
//! the design doc, now stated per core.
//!
//! **No allocation under either lock — a cross-core rule.** Both locks are
//! taken from IRQ context (the BSP's timer tick, an AP's reschedule IPI). If a
//! holder ever allocated while holding one, this cycle would exist: core A
//! holds `TASKS` and waits for the heap lock; core B's *interrupted task* holds
//! the heap lock while B's IPI handler waits for `TASKS`. So the task table is
//! a fixed slab ([`TaskTable`]) and every ready queue a fixed ring
//! ([`ReadyRing`]); a `Box<Task>` is allocated *before* any lock is taken and
//! freed *after* the last one is released. This also retired the earlier
//! "pre-reserve `VecDeque` capacity" machinery — the property it maintained is
//! now structural.
//!
//! # ISR-context allocation freedom (PR-A/PR-B combined-review fix)
//!
//! [`on_tick`]'s only production entry into the run-queue machinery —
//! [`reschedule_locked`] and everything it calls ([`pick_next`],
//! [`hal::context::switch`]) — runs in genuine interrupt-gate context and
//! **never allocates or frees heap memory**. This matters because
//! `hal::mm::LockedHeap`'s global-allocator lock is a plain
//! [`hal::sync::SpinMutex`] that, like [`CPU_SCHED`]/[`TASKS`], does **not** itself
//! disable interrupts: if the *interrupted* task happened to be mid-`alloc`/`dealloc`
//! (e.g. inside [`spawn`]'s `Box::new` calls, which run with interrupts
//! enabled, outside [`with_interrupts_disabled`] — see that function's docs
//! for why this is fine), a heap operation reached from inside the timer ISR
//! would spin on that same already-held lock forever — the single core that
//! holds it can never resume to release it, a self-deadlock. This was a real
//! bug: [`reschedule_locked`] used to reap an exited task's `Box<Task>` (and
//! its boxed [`hal::context::XsaveArea`]) itself, dropping it — and
//! therefore potentially deallocating — right there in IRQ context. The fix
//! is two standing invariants:
//!
//! 1. **Reaping happens only in an idle loop.** Only [`idle_reap`] ever drops
//!    a `Box<Task>`, and only the idle tasks call it (kmain's idle loop and
//!    [`ap_idle_loop`]) — never [`on_tick`]'s direct call into
//!    [`reschedule_locked_on`], which performs no allocation or deallocation
//!    at all. Nor does [`reschedule`] reap any more (FS-1a review): it runs with
//!    interrupts disabled, so a reap there — on every [`yield_now`] and every
//!    draining [`preempt_enable`] — would spin forever on the heap lock if a
//!    task preempted on the same core held it, freezing the core. The idle
//!    frees with interrupts *and* preemption enabled, so a contended heap lock
//!    is waited out preemptibly (the holder runs at the next tick).
//! 2. **`ready` never allocates.** [`pick_next`]'s `ready.push_back` is
//!    reachable from [`on_tick`] and [`on_resched_ipi`]; every ready queue is a
//!    fixed-capacity [`ReadyRing`] (capacity [`MAX_TASKS`], the size of the task
//!    slab, so it can never fill), so that push is a plain array store. The
//!    zombie list an exit appends to is the same kind of ring.
//!
//! 3. **Deadline wakes never allocate.** [`on_tick`]'s park step
//!    (`park::expire_step`) moves expired entries out of the core's fixed
//!    [`CpuSched::sleepers`] array onto its fixed ready ring, O(1) when none
//!    is due and at most [`MAX_TASKS`] entries when some are.
//!
//! Net invariant, restated: **the ISR-context scheduler path (`on_tick` /
//! `on_resched_ipi` → `park::expire_step` / `reschedule_locked_on` →
//! `pick_next` → `hal::context::switch`) never allocates or frees** — nor
//! does [`unpark`], which is IRQ-callable.
//!
//! # Interrupt-flag discipline (PR-B)
//!
//! Two distinct call paths reach [`hal::context::switch`], and each has a
//! different, deliberate `IF` (interrupt-flag) contract:
//!
//! - **Voluntary/cooperative** ([`yield_now`], [`exit`], the deferred drain
//!   inside [`preempt_enable`]): [`reschedule`] saves the caller's actual `IF`
//!   state ([`hal::cpu::interrupts_enabled`]), disables interrupts, runs
//!   [`reschedule_locked`], and restores exactly the saved state afterward —
//!   **not** an unconditional `sti`. [`with_interrupts_disabled`] is the same
//!   pattern, used by every other lock-taking accessor
//!   (`spawn_on`/`current_id`/`task_ids`/`task_name`/`task_stack_pages`/`init`/
//!   `init_ap`), so that **the lock-holding portion** of each cannot be
//!   reentered by a timer preemption or reschedule IPI trying to re-acquire the
//!   same lock from a nested IRQ on the same core (a self-deadlock, since a
//!   spinlock holder can never run again to release it once interrupted). This
//!   protects only the scheduler's own locks, not the whole calling function:
//!   [`spawn_on`], for instance, calls `Box::new` (the *heap* allocator's own,
//!   separate lock) *before* ever entering [`with_interrupts_disabled`], so that
//!   portion genuinely can be interrupted by a real tick. That is sound only because of the separate
//!   invariant in "ISR-context allocation freedom" above — `on_tick` itself
//!   never contends for the heap lock — not because of this wrapper.
//! - **Timer preemption** ([`on_tick`]) and **reschedule IPIs**
//!   ([`on_resched_ipi`]): call [`reschedule_locked_on`] *directly*
//!   — no wrapper, no `sti`/`cli` at all. This runs in interrupt-gate context,
//!   where `IF` is *already* clear on entry; it must return with `IF` still
//!   clear so the ISR stub's own `iretq` restores the **interrupted task's
//!   own** saved `RFLAGS`. An explicit `sti` here (the PR-A review's flagged
//!   bug — `reschedule` used to force-enable unconditionally at its tail) would
//!   be a premature `sti` before that `iretq`, opening a window for nested
//!   timer reentrancy the single-level-nesting invariant (design doc,
//!   "Stack sizing") does not expect.
//!
//! [`task_prologue`] still unconditionally enables interrupts — this is
//! **not** the same bug: a freshly-trampolined task is running on its own
//! brand-new stack with no pending `iretq` of its own (the outer ISR frame, if
//! any, belongs to whichever task got preempted to make room for it, parked on
//! a *different* stack), so establishing the "preemptible baseline" there is
//! never early relative to any interrupt return, regardless of whether the
//! switch that started this task was cooperative or timer-driven.

use alloc::boxed::Box;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::smp::MAX_CPUS;

mod park;
pub use park::{park, park_until, prove_park, task_is_parked, unpark, UnparkOutcome, Woken};

// ── Task identity ───────────────────────────────────────────────────────────

/// A unique, monotonically increasing kernel-thread identifier.
///
/// Never reused: even after a task exits and is reaped, its `TaskId` is
/// retired for good, so a stale id can never be confused with a later task's.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct TaskId(u64);

impl TaskId {
    /// The fixed id [`init`] adopts the currently-running control flow
    /// (`kmain`) as — the scheduler's permanent idle task.
    const IDLE: TaskId = TaskId(0);

    fn as_usize(self) -> usize {
        self.0 as usize
    }

    fn from_usize(v: usize) -> Self {
        Self(v as u64)
    }
}

/// Monotonic id allocator. Starts at `1` — `0` is reserved for
/// [`TaskId::IDLE`]. Ids are never reused, matching [`TaskId`]'s contract.
static NEXT_TASK_ID: AtomicU64 = AtomicU64::new(1);

fn next_task_id() -> TaskId {
    TaskId(NEXT_TASK_ID.fetch_add(1, Ordering::Relaxed))
}

/// A lock-free cell holding at most one [`TaskId`] — for a subsystem that
/// must name a service task (e.g. to [`unpark`] it) from any context, IRQ
/// included, without taking a lock. One `AtomicU64`; `u64::MAX` (an id the
/// counter never reaches) means empty. It hands out only ids it was given:
/// there is no way to build a `TaskId` from an integer.
pub struct TaskIdCell(AtomicU64);

impl TaskIdCell {
    /// An empty cell.
    #[must_use]
    pub const fn new() -> Self {
        Self(AtomicU64::new(u64::MAX))
    }

    /// Store `id` (Release: pairs with [`TaskIdCell::get`]).
    pub fn set(&self, id: TaskId) {
        self.0.store(id.0, Ordering::Release);
    }

    /// The stored id, if any.
    #[must_use]
    pub fn get(&self) -> Option<TaskId> {
        match self.0.load(Ordering::Acquire) {
            u64::MAX => None,
            v => Some(TaskId(v)),
        }
    }
}

impl Default for TaskIdCell {
    fn default() -> Self {
        Self::new()
    }
}

// ── Task control block ──────────────────────────────────────────────────────

/// A task's scheduling state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
enum TaskState {
    /// Runnable, waiting in its core's [`CpuSched::ready`].
    Ready,
    /// The task currently executing on its core — exactly one per core, named
    /// by that core's [`CpuSched::current`].
    Running,
    /// Blocked in [`park`]/[`park_until`]: on **no** ring (not `ready`, not
    /// `zombies`, not `current`); at most one entry in its core's
    /// [`CpuSched::sleepers`] if it parked with a deadline. Only an
    /// [`unpark`] or that core's tick ([`on_tick`]) makes it `Ready` again.
    Parked,
    /// Departed for good; its id is parked in its core's [`CpuSched::zombies`]
    /// until that core's idle task reaps it ([`idle_reap`]) — always after the
    /// switch that left it has completed.
    Exited,
}

/// A kernel-thread task control block.
///
/// `ctx` and `xsave` are heap-stable inside the owning `Box<Task>`: a
/// [`hal::context::TaskHandle`] minted from `&mut task.ctx` stays valid for as
/// long as the `Box` lives, even though the `Box` handle itself may be moved
/// (e.g. between map operations) — moving a `Box` moves the pointer, not the
/// pointee.
///
/// **Invariant:** a `Box<Task>` is dropped only by [`idle_reap`] — called
/// solely from the idle loops (kmain's and [`ap_idle_loop`]), in thread
/// context with interrupts and preemption enabled; **never** from the
/// IRQ-context paths of [`on_tick`]/[`on_resched_ipi`] nor from [`reschedule`]
/// (see the module docs' "ISR-context allocation freedom" section) — *after*
/// the task has been removed from its core's
/// `current`/`ready`/`zombies` bookkeeping in a way that makes it permanently
/// unreachable as a switch target — so every `TaskHandle` minted from it
/// outlives its uses. A task lives on exactly one core's bookkeeping, so no
/// other core can ever hold a handle to it. Dropping it also drops the boxed [`hal::context::XsaveArea`],
/// which zeroizes on `Drop` (no vector-register residue outlives a task).
struct Task {
    /// This task's identifier (the [`TaskTable`] slot is found by scanning for
    /// it — see [`task_ids`]).
    id: TaskId,
    /// Name it was [`spawn`]ed with (boot-proof / debug output — see
    /// [`task_name`]).
    name: &'static str,
    /// The dense index of the core this task is pinned to — the only core whose
    /// run queue ever holds its id and whose `current` it can ever be. Set at
    /// [`spawn_on`]/[`init`]/[`init_ap`]; never changes (no migration).
    cpu: u32,
    /// Current scheduling state.
    state: TaskState,
    /// The kernel-thread body [`spawn`] was given. Invoked exactly once, by
    /// [`task_shim`] (looked up by [`TaskId`] — see the trampoline contract in
    /// [`hal::context`]).
    entry: fn(),
    /// The saved/fabricated switch context (HAL-opaque).
    ctx: hal::context::Context,
    /// This task's kernel stack. `None` only for the adopted idle task (see
    /// [`init`]), whose stack is whatever the boot entry shim set up — not one
    /// [`hal::mm::alloc_kernel_stack`] allocated, so there is nothing here for
    /// us to own or (eventually) reclaim. See [`task_stack_pages`].
    stack: Option<hal::mm::KernelStack>,
    /// This task's vector-state save area (eager per-task `xsave`/`xrstor`;
    /// see [`hal::context::switch`]). Boxed so its address is heap-stable
    /// independent of `Task`'s own location, and so dropping it (on reap) runs
    /// [`hal::context::XsaveArea`]'s zeroize-on-`Drop`. Never read directly —
    /// `ctx` captured a raw pointer into it at construction time (see
    /// `hal::context::Context::{adopt_running,for_new_task}`) — it is held
    /// here purely for ownership (heap-stable address + the zeroize-on-`Drop`
    /// reap behaviour).
    #[allow(dead_code)]
    xsave: Box<hal::context::XsaveArea>,
    /// Remaining PIT ticks in this task's current time slice (PR-B).
    /// Initialised to [`TIME_SLICE_TICKS`] ([`spawn`]/[`init`]) and
    /// decremented once per tick by [`on_tick`] while this task is
    /// [`current`](SchedState::current); on reaching `0` it is reloaded back
    /// to [`TIME_SLICE_TICKS`] in the same step that reports expiry, so a
    /// task always gets a fresh full quantum for its next turn regardless of
    /// whether this expiry actually triggered a switch (see [`tick_slice`]).
    slice: u32,
    /// The wake permit ([`unpark`] of a task that is not parked sets it; the
    /// next [`park`] consumes it and returns at once). One, not counted.
    permit: bool,
    /// Why the task last left [`TaskState::Parked`] — set by whoever woke it,
    /// read by the task when its park returns.
    woken: Woken,
    /// Whether this is a core's adopted idle task, which never parks (it is
    /// the fallback that must always be runnable).
    idle: bool,
}

/// Upper bound on live tasks (all cores together): the size of the
/// [`TaskTable`] slab and of every core's [`ReadyRing`]. Fixed so that neither
/// ever allocates (see the module docs' locking discipline). Plenty for the
/// boot proofs and the shell; a spawn past it fails with
/// [`SpawnError::TooManyTasks`] rather than growing anything under a lock.
pub const MAX_TASKS: usize = 64;

/// Fixed-capacity FIFO of task ids — the production ready queue (and each
/// core's zombie list, [`CpuSched::zombies`]).
///
/// A ring over a `[TaskId; N]` array: O(1) `pop_front`/`push_back`, **no
/// allocation ever**, which is what lets [`pick_next`] run from IRQ context on
/// any core without the heap-lock cycle described in the module docs. Capacity
/// `N` is [`MAX_TASKS`] in production, so a ring can never fill: every task id
/// is in at most one core's `current`/`ready`/`zombies` (Invariant #4), and the
/// slab holds at most `MAX_TASKS` tasks. The Kani harness proves the same
/// [`pick_next`] over a small `ReadyRing<6>`.
struct ReadyRing<const N: usize> {
    buf: [TaskId; N],
    head: usize,
    len: usize,
}

impl<const N: usize> ReadyRing<N> {
    const fn new() -> Self {
        Self {
            buf: [TaskId::IDLE; N],
            head: 0,
            len: 0,
        }
    }

    /// Number of queued ids.
    fn len(&self) -> usize {
        self.len
    }

    /// The `i`-th queued id from the head, if `i < len()` (inspection for the
    /// host tests and the Kani harness; production only pops and pushes).
    #[cfg_attr(not(any(test, kani)), allow(dead_code))]
    fn get(&self, i: usize) -> Option<TaskId> {
        if i < self.len {
            Some(self.buf[(self.head + i) % N])
        } else {
            None
        }
    }
}

impl<const N: usize> ReadyQueue for ReadyRing<N> {
    fn pop_front(&mut self) -> Option<TaskId> {
        if self.len == 0 {
            return None;
        }
        let id = self.buf[self.head];
        self.head = (self.head + 1) % N;
        self.len -= 1;
        Some(id)
    }

    fn push_back(&mut self, id: TaskId) {
        // Unreachable by construction (see the type docs): assert in debug
        // builds so a future change that broke that reasoning fails loudly
        // instead of silently dropping an id (which would violate Invariant #4).
        debug_assert!(
            self.len < N,
            "ReadyRing overflow — more queued ids than MAX_TASKS"
        );
        if self.len < N {
            self.buf[(self.head + self.len) % N] = id;
            self.len += 1;
        }
    }
}

/// One core's run-queue state, guarded by its slot of [`CPU_SCHED`].
struct CpuSched {
    /// The task currently running on this core.
    current: TaskId,
    /// Runnable tasks pinned to this core, in round-robin order. Invariant:
    /// never contains `current`.
    ready: ReadyRing<MAX_TASKS>,
    /// Exited tasks awaiting reap, oldest first. Freed only by this core's
    /// idle task, through [`idle_reap`] (thread context, interrupts and
    /// preemption enabled) — never by [`reschedule`], never from an IRQ path.
    /// Every id here still owns its [`TASKS`] slot until reaped, so with
    /// capacity [`MAX_TASKS`] the ring can never fill.
    zombies: ReadyRing<MAX_TASKS>,
    /// Tasks parked here by [`park_until`], with their mono-tick deadlines.
    /// Drained by this core's [`on_tick`]; an [`unpark`] removes its target's
    /// entry. Names only `Parked` tasks pinned here, so it can never fill.
    sleepers: park::Sleepers<MAX_TASKS>,
}

impl CpuSched {
    const fn new() -> Self {
        Self {
            current: TaskId::IDLE,
            ready: ReadyRing::new(),
            zombies: ReadyRing::new(),
            sleepers: park::Sleepers::new(),
        }
    }
}

/// Every core's run-queue state, by dense cpu index (BSP = 0). Each slot is
/// acquired only with interrupts disabled on the local core, only **before**
/// [`TASKS`] when both are needed, and never held across
/// [`hal::context::switch`] (see [`reschedule_locked_on`]).
static CPU_SCHED: [hal::sync::SpinMutex<CpuSched>; MAX_CPUS] =
    [const { hal::sync::SpinMutex::new(CpuSched::new()) }; MAX_CPUS];

/// The fixed task slab: the single stable heap home for every live `Task`
/// (each `Box<Task>` is heap-stable; the slot only holds the pointer). Insert
/// and remove are pointer moves — **no allocation under the lock** (the module
/// docs' cross-core rule). Lookup is a linear scan over [`MAX_TASKS`] slots,
/// trivially cheap at this scale and allocation-free.
struct TaskTable {
    slots: [Option<Box<Task>>; MAX_TASKS],
}

impl TaskTable {
    const fn new() -> Self {
        Self {
            slots: [const { None }; MAX_TASKS],
        }
    }

    fn get(&self, id: TaskId) -> Option<&Task> {
        self.slots
            .iter()
            .flatten()
            .map(|t| &**t)
            .find(|t| t.id == id)
    }

    fn get_mut(&mut self, id: TaskId) -> Option<&mut Task> {
        self.slots
            .iter_mut()
            .flatten()
            .map(|t| &mut **t)
            .find(|t| t.id == id)
    }

    /// Store `task` in a free slot; gives it back if the slab is full.
    fn insert(&mut self, task: Box<Task>) -> Result<(), Box<Task>> {
        match self.slots.iter_mut().find(|s| s.is_none()) {
            Some(slot) => {
                *slot = Some(task);
                Ok(())
            }
            None => Err(task),
        }
    }

    /// Take the task `id` out of the slab (the caller drops it **after**
    /// releasing the lock).
    fn remove(&mut self, id: TaskId) -> Option<Box<Task>> {
        self.slots
            .iter_mut()
            .find(|s| s.as_ref().is_some_and(|t| t.id == id))
            .and_then(Option::take)
    }

    fn iter(&self) -> impl Iterator<Item = &Task> {
        self.slots.iter().flatten().map(|t| &**t)
    }
}

/// The task table lock. Acquired only with interrupts disabled on the local
/// core, only **after** a [`CPU_SCHED`] slot when both are needed, never held
/// across [`hal::context::switch`], and never while allocating or freeing.
static TASKS: hal::sync::SpinMutex<TaskTable> = hal::sync::SpinMutex::new(TaskTable::new());

/// The dense index of the core this code is running on (`0` = BSP), from
/// `kernel::smp`. Before the CPUs are enumerated only the BSP runs, so an
/// unknown answer is the BSP.
#[cfg(target_os = "none")]
fn local_cpu() -> usize {
    crate::smp::this_cpu_index().map_or(0, |i| i as usize)
}

/// Host builds (unit tests) have one logical core and no `cpuid`-derived
/// identity to consult: always core 0.
#[cfg(not(target_os = "none"))]
fn local_cpu() -> usize {
    0
}

// ── Preemption state (PR-B) ─────────────────────────────────────────────────

/// Ticks per preemptive time slice, at [`hal::pit::TICK_HZ`] (100 Hz) — a
/// 100 ms quantum. Long enough that a task's own work dominates timer
/// overhead, short enough that the PR-B boot proof ([`prove_preemptive`])
/// observes several preemptions within a fraction of a second. (The design
/// doc left the exact value an open question, "start at 1 tick?"; 10 is used
/// here as the documented fallback default.)
const TIME_SLICE_TICKS: u32 = 10;

/// One core's preemption state (PR-B, made per-core in PR-2). Plain atomics:
/// no lock, written only by code running on that core.
struct PreemptState {
    /// Per-current-task critical-section depth. The timer / a reschedule IPI
    /// never switches this core away while nonzero;
    /// [`preempt_disable`]/[`preempt_enable`] bracket such sections.
    count: AtomicU32,
    /// Set when [`on_tick`]/[`on_resched_ipi`] wanted to reschedule but `count`
    /// was nonzero, so the switch is deferred to the [`preempt_enable`] call
    /// that next brings the count back to `0`.
    need_resched: AtomicBool,
    /// Count of **involuntary** switches actually performed on this core — every
    /// time [`on_tick`]/[`on_resched_ipi`] (directly) or a deferred
    /// [`preempt_enable`] drain called [`reschedule_locked_on`] and it *actually
    /// switched* (never a no-op pass). Read by [`prove_preemptive`] (core 0,
    /// where only the timer drives it) as the "N preemptions occurred"
    /// evidence; never touched by voluntary [`yield_now`]/[`exit`].
    events: AtomicU64,
    /// The subset of `events` performed **directly by [`on_tick`]** — genuine
    /// timer-driven preemptions, excluding IPI-driven switches and deferred
    /// drains. Read by [`prove_ap_preemptive`], where the two proof tasks also
    /// arrive by IPI and those switches must not count as timer evidence.
    tick_events: AtomicU64,
    /// Every switch this core performed, voluntary or not (yield, exit, park,
    /// tick, IPI). [`prove_park`]'s idle-window evidence: zero over a window
    /// of ticks means nothing but the idle ran.
    switches: AtomicU64,
    /// Scheduler ticks ([`on_tick`] calls) this core has taken.
    ticks: AtomicU64,
    /// Set by [`idle_halt`] for exactly the span this core's idle task is
    /// halted waiting for an interrupt. [`on_tick`] reschedules a current
    /// idle with a non-empty `ready` only while it is set — never while the
    /// idle is doing work (kmain runs the whole desktop loop as the BSP's
    /// idle; a ready task must not preempt it on every tick).
    in_idle_halt: AtomicBool,
    /// Switches [`on_tick`] made only because the halted idle had work (a
    /// local unpark): counted here, not in `events`/`tick_events`.
    idle_wakes: AtomicU64,
}

impl PreemptState {
    const fn new() -> Self {
        Self {
            count: AtomicU32::new(0),
            need_resched: AtomicBool::new(false),
            events: AtomicU64::new(0),
            tick_events: AtomicU64::new(0),
            switches: AtomicU64::new(0),
            ticks: AtomicU64::new(0),
            in_idle_halt: AtomicBool::new(false),
            idle_wakes: AtomicU64::new(0),
        }
    }

    /// Enter a critical section: `count += 1`.
    fn disable(&self) {
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// Leave a critical section: `count -= 1`. Returns `true` iff the count
    /// just reached `0` **and** a reschedule had been deferred meanwhile (the
    /// flag is consumed) — i.e. the caller must now drain it.
    fn enable_and_take_pending(&self) -> bool {
        let prev = self.count.fetch_sub(1, Ordering::Relaxed);
        prev == 1 && self.need_resched.swap(false, Ordering::Relaxed)
    }
}

/// Every core's preemption state, by dense cpu index.
static PREEMPT: [PreemptState; MAX_CPUS] = [const { PreemptState::new() }; MAX_CPUS];

/// While `true`, [`on_tick`] still charges each task's slice but never turns a
/// slice expiry into a switch — neither immediately nor deferred via
/// [`PreemptState::need_resched`]. Set only by [`prove_cooperative`], for exactly the span
/// of the PR-A cooperative boot proof, and cleared before it returns.
///
/// WHY THIS EXISTS. The cooperative proof asserts that the two proof tasks'
/// prints strictly alternate. Invariant #4 guarantees the *schedule*
/// alternates (`ready` never contains `current`), but the recorded sequence
/// is a record of *prints*, and those two only coincide when nothing but
/// [`yield_now`] moves the CPU. A fresh task's [`task_prologue`] resets
/// [`PreemptState::count`] to `0` and enables interrupts the instant it starts
/// running, so on every switch-in there is a window — before the task reaches
/// its first [`print_marker_atomic`] and the `preempt_disable` inside it — in
/// which a pending PIT tick can preempt it before it prints. When that lands,
/// the task that just yielded is picked again and prints twice in a row: the
/// schedule alternated correctly, but the print log does not show it.
///
/// Issue #21 defect 3 recognised this race and made the verdict phase-
/// agnostic, which covered the window on the *first* switch-in. The window is
/// on *every* switch-in, so the flake survived (observed 2026-07-25 on KVM CI:
/// `B0 A0 A1 B1 A2 B2`, `interleave=broken`, alongside `deferred-tick-
/// preemptions observed=3` in the same run).
///
/// Suppressing timer-driven switches for the proof's duration makes the phase
/// genuinely cooperative, so strict alternation becomes a real guarantee
/// rather than a hoped-for outcome — the assertion stays strong and stops
/// flaking. Timer preemption itself is not left unproven: [`prove_preemptive`]
/// is the proof for that, and it runs with this flag clear.
static COOP_PROOF_NO_PREEMPT: AtomicBool = AtomicBool::new(false);

/// How many slice expiries [`COOP_PROOF_NO_PREEMPT`] suppressed during the
/// cooperative proof. Reported (informationally) by [`prove_cooperative`]: a
/// nonzero count is the evidence that real PIT ticks *did* fire during the
/// proof and that suppression — not luck, and not a phase too short to be
/// ticked — is what kept the interleave strict.
static COOP_PROOF_SUPPRESSED: AtomicU64 = AtomicU64::new(0);

/// Enter a preemption-disabled critical section on the calling core.
///
/// Increments this core's [`PreemptState::count`]; pairs with
/// [`preempt_enable`]. While nonzero, [`on_tick`]/[`on_resched_ipi`] defer a
/// reschedule via `need_resched` instead of switching immediately. Tasks are
/// pinned, so the core is the same at the matching `preempt_enable`.
pub fn preempt_disable() {
    PREEMPT[local_cpu()].disable();
}

/// Leave a preemption-disabled critical section on the calling core.
///
/// Decrements this core's count; if it reaches `0` and a reschedule was
/// deferred while disabled, drains it by rescheduling immediately (via the
/// voluntary/cooperative [`schedule`] wrapper — this runs in normal task
/// context, never from inside an ISR, so the usual interrupt-flag save/restore
/// applies).
pub fn preempt_enable() {
    let cpu = local_cpu();
    if PREEMPT[cpu].enable_and_take_pending() && schedule() {
        PREEMPT[cpu].events.fetch_add(1, Ordering::Relaxed);
    }
}

/// The timer-IRQ hook (PR-B): called once per PIT tick from
/// `kernel::interrupts::handle_timer`, i.e. from **interrupt-gate context**
/// (`IF` already clear on entry — see `hal::idt`'s interrupt-gate type byte).
///
/// Decrements the current task's remaining time slice ([`tick_slice`]); on
/// expiry, either switches away right here at the timer-IRQ tail (if
/// [`PreemptState::count`] `== 0`) or defers to [`PreemptState::need_resched`] for the next
/// [`preempt_enable`] to drain.
///
/// First, under the same locks, it wakes every task parked on this core by
/// [`park_until`] whose deadline is `<= crate::clock::mono_ticks()`
/// (`park::expire_step`). Cost in IRQ context: one compare when nothing is
/// due; otherwise one pass over this core's sleeper set (≤ [`MAX_TASKS`]
/// entries) with a [`TaskTable`] lookup (≤ [`MAX_TASKS`] slots) per expired
/// entry — about 64 × 64 slot visits in the worst case, bounded and
/// allocation-free.
///
/// Then it reschedules — as on a slice expiry, through [`tick_action`] — if
/// the slice expired, **or** a deadline woke a task, **or** this core's idle
/// task is **halted** ([`idle_halt`]) while `ready` is non-empty (a task woken
/// on this core by an [`unpark`], which sends no IPI to its own core). An idle
/// doing work — kmain runs the desktop loop — is not preempted by this rule;
/// it hands over at its next halt. So deadline and local
/// unpark wakes **preempt mid-slice**: the round-robin switch happens on this
/// tick, and the woken task runs on it if it is at the head of `ready` —
/// otherwise in its turn behind the tasks ahead of it. Only a slice expiry
/// counts as [`PreemptState::tick_events`] (the AP preemption proof's
/// evidence); a slice expiry or deadline wake counts as
/// [`PreemptState::events`]; the halted idle making way counts as
/// [`PreemptState::idle_wakes`].
///
/// # Interrupt-flag discipline
///
/// This function — and everything it calls transitively, including
/// [`reschedule_locked`]/[`hal::context::switch`] — never touches `IF`. It
/// must return with `IF` exactly as the interrupt gate left it (clear), so
/// the ISR stub's own `iretq` — for *whichever* task ends up resuming here,
/// possibly long after this exact call, via a completely different future
/// switch — restores that task's own saved `RFLAGS`. See the module docs'
/// "Interrupt-flag discipline" section.
pub fn on_tick() {
    let cpu = local_cpu();
    PREEMPT[cpu].ticks.fetch_add(1, Ordering::Relaxed);
    let now = crate::clock::mono_ticks();
    let halted = PREEMPT[cpu].in_idle_halt.load(Ordering::Relaxed);
    let (expired, woke, idle_work) = {
        // Lock order: this core's queue, then the task table.
        let mut queue = CPU_SCHED[cpu].lock();
        let state: &mut CpuSched = &mut queue;
        let mut tasks = TASKS.lock();
        // `park_until` deadlines due on this core: O(1) when none is.
        let woke = park::expire_step(&mut state.ready, &mut state.sleepers, &mut *tasks, now);
        let (expired, idle) = match tasks.get_mut(state.current) {
            Some(t) => (tick_slice(&mut t.slice), t.idle),
            None => (false, false),
        };
        (expired, woke > 0, halted && idle && state.ready.len() > 0)
    };
    // A wake (a deadline here, or an unpark while the idle sat halted) is
    // handled like a slice expiry, so the switch happens on this tick rather
    // than at the end of the current task's quantum.
    if !expired && !woke && !idle_work {
        return;
    }
    // A slice expiry or a deadline wake is a real involuntary switch
    // (`events`); the halted idle making way is not.
    let involuntary = expired || woke;

    match tick_action(
        COOP_PROOF_NO_PREEMPT.load(Ordering::Relaxed),
        PREEMPT[cpu].count.load(Ordering::Relaxed),
    ) {
        TickAction::Suppress => {
            if expired {
                COOP_PROOF_SUPPRESSED.fetch_add(1, Ordering::Relaxed);
            }
        }
        TickAction::Switch => {
            if reschedule_locked_on(cpu, false) {
                if involuntary {
                    PREEMPT[cpu].events.fetch_add(1, Ordering::Relaxed);
                } else {
                    PREEMPT[cpu].idle_wakes.fetch_add(1, Ordering::Relaxed);
                }
                if expired {
                    PREEMPT[cpu].tick_events.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        TickAction::Defer => PREEMPT[cpu].need_resched.store(true, Ordering::Relaxed),
    }
}

/// The reschedule-IPI hook (PR-2): called from
/// `kernel::interrupts::handle_resched_ipi` on the core that received the IPI,
/// i.e. from **interrupt-gate context** (`IF` clear), after the LAPIC EOI.
///
/// Another core (the BSP, in [`spawn_on`]) has pushed a task onto **this**
/// core's ready queue: switch to it right here at the ISR tail if preemption is
/// enabled, else defer exactly like [`on_tick`]. No slice accounting — an IPI
/// is a wake-up, not a tick. Same interrupt-flag discipline as [`on_tick`]:
/// never touches `IF`; the ISR stub's `iretq` restores whichever task resumes.
/// For a core idling in [`ap_idle_loop`] the "task" that resumes here later —
/// when the placed task exits — is the idle itself, which returns through the
/// stub to its `sti; hlt`.
pub fn on_resched_ipi() {
    let cpu = local_cpu();
    // `tick_action(false, …)` never yields `Suppress`: the cooperative proof's
    // suppression is a BSP-only, timer-only concern.
    match tick_action(false, PREEMPT[cpu].count.load(Ordering::Relaxed)) {
        TickAction::Switch => {
            if reschedule_locked_on(cpu, false) {
                PREEMPT[cpu].events.fetch_add(1, Ordering::Relaxed);
            }
        }
        TickAction::Defer | TickAction::Suppress => {
            PREEMPT[cpu].need_resched.store(true, Ordering::Relaxed);
        }
    }
}

/// What [`on_tick`] does about a slice expiry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TickAction {
    /// Withhold the switch entirely and count it — the cooperative proof is
    /// running ([`COOP_PROOF_NO_PREEMPT`]).
    Suppress,
    /// Switch now: preemption is enabled and nothing is deferring it.
    Switch,
    /// Defer via [`PreemptState::need_resched`] for [`preempt_enable`] to drain — we are
    /// inside a [`preempt_disable`] critical section.
    Defer,
}

/// Pure slice-expiry *policy*, decoupled from lock/HAL/global state so it is
/// directly host- and Kani-testable — mirrors how [`tick_slice`] isolates the
/// countdown and [`pick_next`] isolates the queue policy. The sole production
/// caller is [`on_tick`], on the expiry path only.
///
/// Suppression is checked FIRST, and deliberately does not fall through to
/// [`TickAction::Defer`]: deferring would merely postpone the same preemption
/// to the next [`preempt_enable`], which is exactly the flake
/// [`COOP_PROOF_NO_PREEMPT`] exists to remove.
fn tick_action(coop_proof_no_preempt: bool, preempt_count: u32) -> TickAction {
    if coop_proof_no_preempt {
        TickAction::Suppress
    } else if preempt_count == 0 {
        TickAction::Switch
    } else {
        TickAction::Defer
    }
}

/// Pure slice-expiry decision, decoupled from `Task`/lock/HAL state so it is
/// directly host- and Kani-testable — mirrors how [`pick_next`] isolates the
/// round-robin queue policy from the same concerns. The sole production
/// caller is [`on_tick`].
///
/// Decrements `slice` by one tick (saturating — never wraps even if `slice`
/// were somehow already `0`). On reaching `0`, reloads it to
/// [`TIME_SLICE_TICKS`] (so the task always gets a fresh full quantum for its
/// next turn, whether or not this particular expiry ends up triggering an
/// actual switch) and reports expiry (`true`).
fn tick_slice(slice: &mut u32) -> bool {
    *slice = slice.saturating_sub(1);
    if *slice == 0 {
        *slice = TIME_SLICE_TICKS;
        true
    } else {
        false
    }
}

/// Run `f` with maskable interrupts disabled, restoring the previous
/// interrupt state afterward — the same "read `IF`, disable, run,
/// conditionally restore" pattern `hal::serial`'s console guard
/// (`with_console`) uses internally, applied here to guard **the scheduler's
/// own locks** ([`CPU_SCHED`]/[`TASKS`]) against a reentrant timer preemption
/// or reschedule IPI firing mid-critical-section on the same core.
/// Necessary because [`hal::sync::SpinMutex`] does **not** itself disable
/// interrupts (see its module docs) — without this, any of these accessors
/// holding a scheduler lock with interrupts enabled would be vulnerable to
/// [`on_tick`]/[`on_resched_ipi`] trying to re-acquire the same lock from a
/// nested IRQ and spinning forever on the core that can never release it (a
/// self-deadlock). Cross-core contention is fine: the other core's holder is
/// still running and will release.
///
/// Used by every lock-taking accessor **except** the bare IRQ-context calls
/// into [`reschedule_locked_on`], which must never touch `IF` at all — see the
/// module docs' "Interrupt-flag discipline" section.
///
/// **Scope note (not over-claiming further than the scheduler's locks):** this
/// only protects the lock-holding statements actually passed as `f` — it does
/// **not** retroactively make an entire calling function immune to preemption.
/// [`spawn_on`], for example, calls `Box::new` (the *heap* allocator's own
/// separate lock) *before* ever calling this helper, so that portion genuinely
/// can be interrupted by a real tick. That is sound only because the IRQ paths
/// never contend for the heap lock (see the module docs' "ISR-context
/// allocation freedom" section), not because of anything this function does.
fn with_interrupts_disabled<R>(f: impl FnOnce() -> R) -> R {
    let was_enabled = hal::cpu::interrupts_enabled();
    hal::cpu::disable_interrupts();
    let result = f();
    if was_enabled {
        hal::cpu::enable_interrupts();
    }
    result
}

// ── Scheduling core ──────────────────────────────────────────────────────────

/// The entire queue interface [`pick_next`] needs: take the head, put a task
/// on the tail. Deliberately this small — it exists so the round-robin policy
/// can be stated independently of the *container*: production and the Kani
/// harness both use the allocation-free [`ReadyRing`] (at different
/// capacities), the host tests a `VecDeque` for readable expected values.
trait ReadyQueue {
    /// Remove and return the task at the head, or `None` if empty.
    fn pop_front(&mut self) -> Option<TaskId>;
    /// Append a task to the tail.
    fn push_back(&mut self, id: TaskId);
}

/// Host-test convenience only: lets the policy tests below state expected
/// queue contents as plain `VecDeque`s. Production uses [`ReadyRing`].
#[cfg(test)]
impl ReadyQueue for alloc::collections::VecDeque<TaskId> {
    fn pop_front(&mut self) -> Option<TaskId> {
        alloc::collections::VecDeque::pop_front(self)
    }
    fn push_back(&mut self, id: TaskId) {
        alloc::collections::VecDeque::push_back(self, id)
    }
}

/// Pure round-robin scheduling decision, decoupled from any HAL/heap resource
/// (`Task`/`Context`/`KernelStack`) so the entire queue **policy** — rotation,
/// exit bookkeeping, and Invariant #4 (`ready` never contains `current`; no id
/// lost or duplicated across `current`/`ready`/`zombie`) — is directly host-
/// and Miri-testable without touching hardware state (see the `tests` module
/// below). [`reschedule`] is the only production caller.
///
/// Pops the front of `ready` as the next task to run. Unless `prev_exiting`,
/// pushes `prev_id` onto the back of `ready` (round-robin); if exiting,
/// records `prev_id` into `*zombie` instead — an exited task is never
/// requeued, it is reaped later. Returns `None` (queue left untouched) if
/// nothing else is runnable.
///
/// Generic over [`ReadyQueue`] rather than a concrete container, so the same
/// function serves production ([`ReadyRing<MAX_TASKS>`]), the host tests
/// (`VecDeque`, for readable expected values) and the Kani harness
/// (`ReadyRing<6>`). Under CBMC, `VecDeque`'s heap model (`RawVec`, wrap-around
/// index arithmetic, allocation reasoning) once dominated the formula and
/// capped the bounded proof at 2 scheduler passes — deeper bounds exhausted
/// 15 GiB with no verdict; the allocation-free ring proves the same policy to a
/// far greater depth, and since PR-2 it *is* the production container.
fn pick_next<Q: ReadyQueue>(
    ready: &mut Q,
    zombie: &mut Option<TaskId>,
    prev_id: TaskId,
    prev_exiting: bool,
) -> Option<TaskId> {
    let next_id = ready.pop_front()?;
    if prev_exiting {
        *zombie = Some(prev_id);
    } else {
        ready.push_back(prev_id);
    }
    Some(next_id)
}

/// [`pick_next`] plus the exit bookkeeping around it — the whole pure part of
/// [`reschedule_locked_on`]: an exiting `prev_id` is appended to `zombies`
/// (oldest first), where it waits for the core's idle task ([`idle_reap`]).
/// Nothing is freed here, and several exits may queue up between two idle
/// passes without any being lost. Shared by production, the host tests and the
/// Kani harness, so the glue they check is the glue that runs.
fn pick_next_parking_exits<Q: ReadyQueue, Z: ReadyQueue>(
    ready: &mut Q,
    zombies: &mut Z,
    prev_id: TaskId,
    prev_exiting: bool,
) -> Option<TaskId> {
    let mut exited = None;
    let next_id = pick_next(ready, &mut exited, prev_id, prev_exiting)?;
    if let Some(id) = exited {
        zombies.push_back(id);
    }
    Some(next_id)
}

/// The scheduler's core reschedule step **for core `cpu`**: decide the next
/// runnable task via [`pick_next`] over that core's queue, update task states,
/// and — with both locks **dropped** first — perform the actual
/// [`hal::context::switch`]. Returns whether a switch actually happened
/// (`false` if nothing else was runnable on this core, in which case
/// `current`/`ready` are left untouched).
///
/// `cpu` must be the **calling** core (the switch runs on it); every caller
/// passes [`local_cpu`].
///
/// # Never allocates or frees
///
/// This function performs **no heap allocation or deallocation** — see the
/// module docs' "ISR-context allocation freedom" and locking sections. It
/// never reaps a zombie (that is [`idle_reap`]'s job, idle task only), and
/// both pushes ([`pick_next`]'s `ready.push_back`, an exit's
/// `zombies.push_back`) are stores into a fixed [`ReadyRing`].
/// This is what makes it sound for [`on_tick`] and [`on_resched_ipi`] to call
/// this function directly from genuine interrupt-gate context.
///
/// # Interrupt-flag discipline
///
/// This function **never touches `IF`** — it assumes interrupts are already
/// disabled by the caller and must stay that way for its own duration (both
/// to satisfy [`hal::context::switch`]'s precondition and, per
/// [`with_interrupts_disabled`]'s docs, to prevent a reentrant IRQ from
/// deadlocking on this core's locks). Its callers each have a different reason
/// `IF` is already off:
///
/// - [`reschedule`] (the voluntary/cooperative wrapper: [`yield_now`],
///   [`exit`], the deferred drain in [`preempt_enable`]) explicitly disables
///   interrupts first and restores the caller's actual prior state after.
/// - [`on_tick`] / [`on_resched_ipi`] call this **directly**, with no wrapper —
///   they run in interrupt-gate context, where `IF` was cleared by hardware on
///   entry, and must return leaving it clear so the ISR stub's own `iretq`
///   restores the *interrupted* task's saved `RFLAGS`.
///
/// # Other invariants upheld
///
/// - Lock order queue → table; both guards go out of scope **before** `switch`
///   runs — never held across it.
/// - An exiting task is only appended to `zombies` here, never freed: it is
///   still running on its own stack until the `switch` below completes, and
///   only the idle task of this same core (which cannot run before then — `IF`
///   is clear throughout) ever reaps it.
fn reschedule_locked_on(cpu: usize, exiting: bool) -> bool {
    let switch_pair = {
        let mut queue = CPU_SCHED[cpu].lock();
        // One real `&mut CpuSched` (through `DerefMut`, taken exactly once) so
        // the borrow checker can see `state.ready`/`state.zombies` as disjoint
        // fields below.
        let state: &mut CpuSched = &mut queue;
        let mut tasks = TASKS.lock();

        let prev_id = state.current;
        match pick_next_parking_exits(&mut state.ready, &mut state.zombies, prev_id, exiting) {
            Some(next_id) => {
                if let Some(t) = tasks.get_mut(prev_id) {
                    t.state = if exiting {
                        TaskState::Exited
                    } else {
                        TaskState::Ready
                    };
                }
                if let Some(t) = tasks.get_mut(next_id) {
                    t.state = TaskState::Running;
                }
                state.current = next_id;

                let prev_h = tasks
                    .get_mut(prev_id)
                    .map(|t| hal::context::TaskHandle::new(&mut t.ctx));
                let next_h = tasks
                    .get_mut(next_id)
                    .map(|t| hal::context::TaskHandle::new(&mut t.ctx));
                match (prev_h, next_h) {
                    (Some(p), Some(n)) => Some((p, n)),
                    _ => None,
                }
            }
            None => None,
        }
    }; // both guards dropped here — never held across `switch`.

    let switched = switch_pair.is_some();
    if let Some((prev_h, next_h)) = switch_pair {
        PREEMPT[cpu].switches.fetch_add(1, Ordering::Relaxed);
        hal::context::switch(prev_h, next_h);
    }
    switched
}

/// Unlink the oldest zombie of core `cpu` from the scheduler: pop it from the
/// core's `zombies` and remove its `Box<Task>` from [`TASKS`], with
/// interrupts disabled (both are scheduler locks; the queue lock is released
/// before the table lock is taken). `None` once the core has no zombie left.
///
/// Frees nothing: the caller, [`idle_reap`], drops the returned box after every
/// lock is released and with interrupts back on.
fn take_zombie_on(cpu: usize) -> Option<Box<Task>> {
    with_interrupts_disabled(|| loop {
        let zid = CPU_SCHED[cpu].lock().zombies.pop_front()?;
        if let Some(dead) = TASKS.lock().remove(zid) {
            return Some(dead);
        }
        // A zombie keeps its table slot until reaped, so this is unreachable;
        // if it ever happened there would be nothing to free — skip the id.
    })
}

/// Voluntary/cooperative reschedule wrapper for the **calling core**: saves the
/// caller's actual `IF` state, disables interrupts, runs
/// [`reschedule_locked_on`], and restores exactly the saved state afterward
/// (via [`with_interrupts_disabled`]) — **not** an
/// unconditional `sti`, unlike PR-A's original implementation (the
/// combined-review carry-item this PR fixes). Used by [`yield_now`],
/// [`exit`], and the deferred drain in [`preempt_enable`] — every caller runs
/// in normal task context, never from inside the timer ISR (see
/// [`reschedule_locked_on`]'s docs for that path). Returns whether a switch
/// actually happened.
///
/// It does **not** reap. It used to, first thing, with interrupts disabled —
/// and a reap frees heap memory: had a task on this core been preempted while
/// holding the heap lock, the very next yield here would have spun on that
/// lock at `IF = 0` forever (nothing could switch back to the holder), freezing
/// the core. Zombies now wait in [`CpuSched::zombies`] for [`idle_reap`].
fn reschedule(exiting: bool) -> bool {
    with_interrupts_disabled(|| reschedule_locked_on(local_cpu(), exiting))
}

/// Voluntarily reschedule (round-robin), keeping `current` runnable. Returns
/// whether a switch actually happened. Used by [`yield_now`] and the deferred
/// drain in [`preempt_enable`].
fn schedule() -> bool {
    reschedule(false)
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Bring up the scheduler on the BSP: adopt the currently-running control flow
/// (`kmain`) as core 0's permanent idle task, [`TaskId::IDLE`].
///
/// Call once, after the kernel heap is up (construction needs `alloc`: `Box`)
/// and before the first [`spawn`]/[`yield_now`]. Application processors adopt
/// their own idle later via [`init_ap`].
pub fn init() {
    adopt_idle(0, TaskId::IDLE);
}

/// Bring up the scheduler on an **application processor**: adopt the calling
/// AP's current control flow (`kernel::smp::ap_main`, on its bootloader stack)
/// as core `cpu_index`'s idle task, with a fresh [`TaskId`].
///
/// Called by the AP itself, once, with interrupts masked, **before** it
/// publishes `online` — so by the time [`spawn_on`] may target this core, its
/// queue has a `current` (the idle) to switch away from. Returns the idle's id,
/// or `None` for the BSP index / an out-of-range index (nothing adopted).
pub fn init_ap(cpu_index: u32) -> Option<TaskId> {
    let cpu = cpu_index as usize;
    if cpu == 0 || cpu >= MAX_CPUS {
        return None;
    }
    let id = next_task_id();
    adopt_idle(cpu, id);
    Some(id)
}

/// Adopt the calling control flow as core `cpu`'s idle task `id`
/// ([`hal::context::Context::adopt_running`]): its stack is whatever it is
/// already running on (the bootloader's), so there is no
/// [`hal::mm::KernelStack`] to own. The `Box` is allocated *before* any lock is
/// taken; under the locks only pointer moves happen.
fn adopt_idle(cpu: usize, id: TaskId) {
    let mut xsave = Box::new(hal::context::XsaveArea::new_init());
    let ctx = hal::context::Context::adopt_running(&mut xsave);
    let idle = Box::new(Task {
        id,
        name: "idle",
        cpu: cpu as u32,
        state: TaskState::Running,
        entry: idle_entry_unused,
        ctx,
        stack: None,
        xsave,
        slice: TIME_SLICE_TICKS,
        permit: false,
        woken: Woken::Unparked,
        idle: true,
    });

    with_interrupts_disabled(|| {
        // Table first (alone), then the queue (alone): no nesting needed here.
        let overflow = TASKS.lock().insert(idle).err();
        if let Some(rejected) = overflow {
            // Slab full before this core's idle could be registered: nothing
            // sane to do at boot but report; the `Box` is dropped with no lock
            // held. (Unreachable in practice — the slab is MAX_TASKS >> cores.)
            drop(rejected);
            hal::serial::print_line("[sched] init: task table full; idle not registered");
            return;
        }
        CPU_SCHED[cpu].lock().current = id;
    });
}

/// Placeholder `entry` for the adopted idle task.
///
/// Never actually invoked through [`task_shim`]: the idle task is *adopted*
/// ([`hal::context::Context::adopt_running`]), not spawned via
/// [`hal::context::Context::for_new_task`], so its body is whatever `kmain`
/// already runs (the rest of `kmain` + [`crate::idle_loop`]), not this.
fn idle_entry_unused() {}

/// Why [`spawn_on`] could not place a task.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SpawnError {
    /// The target core is unknown or not (yet) running the scheduler.
    CpuNotOnline(u32),
    /// No guard-paged kernel stack could be allocated (frame allocator empty).
    StackAllocation,
    /// The task table already holds [`MAX_TASKS`] live tasks.
    TooManyTasks,
    /// [`spawn_on_with_stack`] was asked for a stack of this many pages,
    /// outside `1..=`[`MAX_STACK_PAGES`]. Nothing was allocated.
    StackSize(usize),
}

impl SpawnError {
    /// Short label for serial output.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            SpawnError::CpuNotOnline(_) => "target cpu not online",
            SpawnError::StackAllocation => "could not allocate a kernel stack",
            SpawnError::TooManyTasks => "task table full",
            SpawnError::StackSize(_) => "stack size out of range",
        }
    }
}

/// Whether core `cpu` can be handed a task: the BSP always (it is running this
/// code, or the only core before enumeration); an AP once `kernel::smp` reports
/// it online — which it does only *after* the AP has adopted its idle
/// ([`init_ap`]), so an online core always has a `current` to switch from.
fn cpu_is_schedulable(cpu: u32) -> bool {
    if cpu as usize >= MAX_CPUS {
        return false;
    }
    cpu == 0 || crate::smp::by_index(cpu).is_some_and(crate::smp::PerCpu::is_online)
}

/// Spawn a new kernel thread running `entry` on **this** core, and push it onto
/// this core's ready queue — [`spawn_on`] with the local core as target.
///
/// Always returns a fresh [`TaskId`] (ids are never reused), even on a failure
/// path, so callers never have to guess whether a slot was consumed. There is
/// no `Result` in this signature (matching the design doc's public API); a
/// failure is logged over serial and the task is simply never registered.
pub fn spawn(name: &'static str, entry: fn()) -> TaskId {
    let id = next_task_id();
    if let Err(err) = spawn_with_id(
        id,
        local_cpu() as u32,
        name,
        entry,
        hal::mm::DEFAULT_STACK_PAGES,
    ) {
        hal::serial::write_str("[sched] spawn '");
        hal::serial::write_str(name);
        hal::serial::write_str("' FAILED: ");
        hal::serial::write_str(err.label());
        hal::serial::write_str("\n");
    }
    id
}

/// Spawn a new kernel thread running `entry`, **pinned to core `cpu`** (dense
/// index; `0` = BSP), and push it onto that core's ready queue.
///
/// Allocates a [`hal::mm::DEFAULT_STACK_PAGES`]-page guard-paged kernel stack
/// ([`hal::mm::alloc_kernel_stack`]) and a zero-initialised
/// [`hal::context::XsaveArea`], fabricates the task's initial switch frame
/// (landing in [`task_shim`], which runs `entry` and then [`exit`]s), and
/// registers it as [`TaskState::Ready`] on `cpu`. If `cpu` is not the calling
/// core, a reschedule IPI wakes it (`hal::apic::send_ipi`), and its
/// [`on_resched_ipi`] switches to the new task at the ISR tail. Placement is
/// the caller's decision — there is no balancing and the task never migrates.
///
/// # Errors
///
/// [`SpawnError::CpuNotOnline`] if `cpu` is unknown or not running the
/// scheduler yet; [`SpawnError::StackAllocation`] if the frame allocator is
/// exhausted; [`SpawnError::TooManyTasks`] past [`MAX_TASKS`] live tasks. On an
/// error nothing is registered (the id is still consumed — never reused).
pub fn spawn_on(cpu: u32, name: &'static str, entry: fn()) -> Result<TaskId, SpawnError> {
    spawn_on_with_stack(cpu, name, entry, hal::mm::DEFAULT_STACK_PAGES)
}

/// Most pages [`spawn_on_with_stack`] will give one task (256 KiB).
pub const MAX_STACK_PAGES: usize = 64;

/// [`spawn_on`] with a kernel stack of `stack_pages` 4 KiB pages instead of
/// [`hal::mm::DEFAULT_STACK_PAGES`] — for a long-lived service task whose
/// call depth is known to need more (the `sfs-commit` task hashes and parses
/// 4 KiB blocks; in a debug build its frames do not fit 16 KiB). Same guard
/// page, same placement and wake-up.
///
/// # Errors
///
/// As [`spawn_on`], plus [`SpawnError::StackSize`] for `stack_pages` outside
/// `1..=MAX_STACK_PAGES`.
pub fn spawn_on_with_stack(
    cpu: u32,
    name: &'static str,
    entry: fn(),
    stack_pages: usize,
) -> Result<TaskId, SpawnError> {
    let id = next_task_id();
    spawn_with_id(id, cpu, name, entry, stack_pages).map(|()| id)
}

fn spawn_with_id(
    id: TaskId,
    cpu: u32,
    name: &'static str,
    entry: fn(),
    stack_pages: usize,
) -> Result<(), SpawnError> {
    if !cpu_is_schedulable(cpu) {
        return Err(SpawnError::CpuNotOnline(cpu));
    }
    if stack_pages == 0 || stack_pages > MAX_STACK_PAGES {
        return Err(SpawnError::StackSize(stack_pages));
    }
    let stack =
        hal::mm::alloc_kernel_stack(stack_pages).map_err(|_| SpawnError::StackAllocation)?;

    // Boot-proof only (design doc item "guard-paged kernel stacks"): a
    // read-only page-table walk confirming the guard page below this stack is
    // genuinely unmapped. Never faults, never mutates the page tables — the
    // non-destructive stand-in for an actual stack-overflow `#PF` test (see
    // `hal::mm::stack_guard_is_unmapped`).
    hal::serial::write_str("[sched] spawn '");
    hal::serial::write_str(name);
    hal::serial::write_str("': stack ok, guard-page unmapped=");
    hal::serial::write_str(if hal::mm::stack_guard_is_unmapped(&stack) {
        "true"
    } else {
        "false"
    });
    hal::serial::write_str("\n");

    // Every allocation happens HERE, before any scheduler lock is taken.
    let mut xsave = Box::new(hal::context::XsaveArea::new_init());
    let ctx = hal::context::Context::for_new_task(&stack, task_shim, id.as_usize(), &mut xsave);
    let task = Box::new(Task {
        id,
        name,
        cpu,
        state: TaskState::Ready,
        entry,
        ctx,
        stack: Some(stack),
        xsave,
        slice: TIME_SLICE_TICKS,
        permit: false,
        woken: Woken::Unparked,
        idle: false,
    });

    let placed: Result<(), Box<Task>> = with_interrupts_disabled(|| {
        // Table first (alone), then the target queue (alone) — pointer moves
        // only under each lock.
        TASKS.lock().insert(task)?;
        CPU_SCHED[cpu as usize].lock().ready.push_back(id);
        Ok(())
    });
    if let Err(rejected) = placed {
        drop(rejected); // no lock held: the heap free is safe here
        return Err(SpawnError::TooManyTasks);
    }

    // A remote core may be asleep in `sti; hlt`: tell it. The push above is
    // ordered before the IPI by the queue lock's release. Sent with `IF = 0`:
    // `unpark` may send one from IRQ context, and an IRQ must never land
    // between the two xAPIC ICR writes of a send on the same core.
    if cpu as usize != local_cpu() {
        if let Some(lapic) = crate::smp::lapic_id_of(cpu) {
            let _sent = with_interrupts_disabled(|| {
                hal::apic::send_ipi(lapic, crate::interrupts::VECTOR_RESCHED_IPI)
            });
        }
    }
    Ok(())
}

/// Voluntarily give up the CPU so another ready task can run.
///
/// A no-op if nothing else is runnable (control returns immediately, having
/// briefly toggled interrupts off then back on).
pub fn yield_now() {
    schedule();
}

/// Mark the current task exited and switch away from it forever.
///
/// Never returns: the exiting task's stack is abandoned mid-call (its id is
/// never pushed back onto `ready`, so nothing will ever switch back into it),
/// and its `Box<Task>` — stack, saved context, and vector-state area — is
/// reaped later by this core's idle task ([`idle_reap`]), never by this call.
///
/// If, structurally, nothing else were runnable (should not happen — the
/// adopted idle task is always eventually back in `ready`), park the core
/// rather than return past a `-> !` function or resume executing on an
/// about-to-be-invalid stack.
pub fn exit() -> ! {
    reschedule(true);
    hal::cpu::halt_loop()
}

/// The currently-running task's id.
#[must_use]
pub fn current_id() -> TaskId {
    with_interrupts_disabled(|| CPU_SCHED[local_cpu()].lock().current)
}

/// Debug/introspection: every task's id currently known to the scheduler, on
/// any core (`Ready`/`Running`, or briefly `Exited` and awaiting reap), in
/// ascending order.
///
/// The ids are copied into a fixed array under the lock and the `Vec` is built
/// only after it is released — no allocation under [`TASKS`].
#[must_use]
pub fn task_ids() -> alloc::vec::Vec<TaskId> {
    let mut ids = [TaskId::IDLE; MAX_TASKS];
    let count = with_interrupts_disabled(|| {
        let tasks = TASKS.lock();
        let mut n = 0;
        for t in tasks.iter() {
            ids[n] = t.id;
            n += 1;
        }
        n
    });
    let mut v: alloc::vec::Vec<TaskId> = ids[..count].to_vec();
    v.sort_unstable();
    v
}

/// Debug/introspection: the dense index of the core a task is pinned to, if it
/// still exists.
#[must_use]
pub fn task_cpu(id: TaskId) -> Option<u32> {
    with_interrupts_disabled(|| TASKS.lock().get(id).map(|t| t.cpu))
}

/// Debug/introspection: the name a task was [`spawn`]ed with, if it still
/// exists (queryable while `Ready`/`Running`, or briefly while `Exited` and
/// awaiting reap).
#[must_use]
pub fn task_name(id: TaskId) -> Option<&'static str> {
    with_interrupts_disabled(|| TASKS.lock().get(id).map(|t| t.name))
}

/// Debug/introspection: the number of 4 KiB pages in a task's kernel stack.
/// `None` for a task with no HAL-tracked stack (only the adopted idle task,
/// see [`init`]) or one that no longer exists.
#[must_use]
pub fn task_stack_pages(id: TaskId) -> Option<usize> {
    with_interrupts_disabled(|| {
        TASKS
            .lock()
            .get(id)
            .and_then(|t| t.stack.as_ref().map(hal::mm::KernelStack::pages))
    })
}

// ── Task entry shim ──────────────────────────────────────────────────────────

/// The trampoline target every spawned task's fabricated frame lands in (the
/// `entry` [`hal::context::Context::for_new_task`] was given, with `arg` = the
/// new task's [`TaskId`] as a `usize`).
///
/// Looks up and runs the task's actual body, then exits. Matches the
/// scheduler design doc's shim contract: `{ task_prologue(); (current.entry)();
/// exit(); }`.
extern "C" fn task_shim(id: usize) -> ! {
    // Look up this task's body BEFORE `task_prologue` opens the interrupt
    // window: at this point interrupts are still disabled, whether this task
    // was landed here by a voluntary switch (`reschedule` disables them
    // before the `switch` landing here) or a timer preemption (`on_tick`
    // calls `reschedule_locked` directly from interrupt-gate context, where
    // `IF` was already clear) — either way this `TASKS` lock is acquired
    // under Invariant #2 (locked only with interrupts disabled).
    let entry = TASKS.lock().get(TaskId::from_usize(id)).map(|t| t.entry);

    task_prologue();
    if let Some(f) = entry {
        f();
    }
    exit()
}

/// The baseline every task starts executing at: reset the preemption
/// critical-section depth and open the interrupt window.
///
/// Matches the baseline a *resumed* task has right after its own
/// [`hal::context::switch`] call returns inside [`reschedule`] — so a
/// first-run task and a resumed one are equally preemptible from this point
/// forward (PR-B).
///
/// **Why the unconditional `sti` here is not the same bug the PR-B
/// interrupt-flag-discipline fix addresses in [`reschedule_locked`]'s
/// callers:** this runs on a **brand-new task's own stack**, which has no
/// pending `iretq` of its own — whichever ISR frame caused this task to be
/// scheduled (if any) belongs to the *previous* task, parked on a
/// *different* stack, untouched by this `sti`. So establishing the
/// preemptible baseline here is never early relative to any interrupt
/// return, regardless of whether the switch that started this task was
/// cooperative ([`reschedule`]) or timer-driven ([`on_tick`]).
fn task_prologue() {
    PREEMPT[local_cpu()].count.store(0, Ordering::Relaxed);
    hal::cpu::enable_interrupts();
}

// ── Application-processor idle (PR-2) ───────────────────────────────────────

/// Free every task that has exited on the **calling** core — the only place a
/// `Box<Task>` (and its boxed [`hal::context::XsaveArea`], which zeroizes on
/// drop) is ever dropped. Call it from an idle loop only: kmain's (the BSP's
/// idle) and [`ap_idle_loop`] do, on every wake-up.
///
/// Each zombie is unlinked with interrupts disabled ([`take_zombie_on`]: only
/// scheduler locks, no heap), then dropped with **no lock held and interrupts
/// and preemption enabled**. The drop takes the heap lock, which another task
/// on this core may hold while preempted. A preemptible waiter is switched away
/// by the next tick and the holder runs and releases it; a waiter at `IF = 0`
/// or with preemption disabled would spin forever and freeze the core. So when
/// the caller has either disabled, this returns at once and reaps nothing (an
/// AP's very first pass, before its first `sti`, is such a call); the next
/// pass catches up.
///
/// Never frees a running stack: a task enters `zombies` inside its own exit
/// path with interrupts disabled until its final switch away, so by the time
/// this core's idle runs, every queued zombie is parked for good — and the
/// idle itself never exits.
pub fn idle_reap() {
    let cpu = local_cpu();
    let preemptible =
        hal::cpu::interrupts_enabled() && PREEMPT[cpu].count.load(Ordering::Relaxed) == 0;
    if !preemptible {
        return;
    }
    // Bounded: at most `MAX_TASKS` zombies can be queued at once; any that
    // exit while this loop runs are left to the next pass.
    for _ in 0..MAX_TASKS {
        let Some(dead) = take_zombie_on(cpu) else {
            return;
        };
        drop(dead);
    }
}

/// The application-processor idle task body: reap what exited here, then
/// `sti; hlt` until the next interrupt — a reschedule IPI, whose handler
/// ([`on_resched_ipi`]) switches this core to the placed task at the ISR tail;
/// when that task exits, this idle resumes inside that handler and returns
/// through the stub's `iretq` (interrupts back on) to here, loops, reaps it,
/// and sleeps again. The core's LAPIC-timer tick also wakes it every quantum
/// (a cheap reap + re-halt).
///
/// `hal::cpu::enable_interrupts_and_halt` is one `sti; hlt` pair so a wake-up
/// that arrives in between cannot be lost. Entered by `kernel::smp::ap_main`
/// after [`init_ap`]; the `sti` inside is the AP's first (after its
/// `simd::enable`, structurally — see `hal::smp`). Never returns.
pub fn ap_idle_loop() -> ! {
    let cpu = local_cpu();
    loop {
        idle_reap();
        PREEMPT[cpu].in_idle_halt.store(true, Ordering::Relaxed);
        hal::cpu::enable_interrupts_and_halt();
        PREEMPT[cpu].in_idle_halt.store(false, Ordering::Relaxed);
    }
}

/// A core's idle task waiting for the next interrupt: `hlt`, with this
/// core's "idle is halted" flag set around it, so [`on_tick`] may switch to a
/// task woken locally (by an [`unpark`], which sends no IPI to its own core)
/// on the next tick instead of after the idle's slice. kmain's idle loop
/// halts through this; [`ap_idle_loop`] sets the same flag around its
/// `sti; hlt`. Call with interrupts enabled, from a core's idle task only
/// (from any other task the flag has no effect: the rule needs the idle
/// current).
pub fn idle_halt() {
    let cpu = local_cpu();
    PREEMPT[cpu].in_idle_halt.store(true, Ordering::Relaxed);
    hal::cpu::halt();
    PREEMPT[cpu].in_idle_halt.store(false, Ordering::Relaxed);
}

// ── PR-A boot proof: cooperative interleave ─────────────────────────────────

/// Number of print+[`yield_now`] iterations each cooperative boot-proof task
/// performs.
///
/// Fixed and small, mostly for a short, readable raw diagnostic sequence
/// line — **not** because it makes the interleave's starting phase
/// deterministic. The proof runs with timer-driven switching suppressed
/// ([`COOP_PROOF_NO_PREEMPT`]), which is what makes the interleave itself
/// deterministic; the starting phase is still deliberately not asserted (see
/// [`validate_cooperative_sequence`]'s docs). What is deterministic and
/// asserted: each task completes exactly this many iterations, in strict
/// per-task order, alternating with the other task every step.
const PROOF_ITERATIONS: u32 = 3;

/// Total `(task letter, iteration)` entries the cooperative boot proof's two
/// tasks are expected to record between them: [`PROOF_ITERATIONS`] each.
const SEQ_LOG_EXPECTED_ENTRIES: usize = 2 * PROOF_ITERATIONS as usize;

/// Fixed capacity for [`SEQ_LOG`]. [`SEQ_LOG_EXPECTED_ENTRIES`] (6) is all
/// [`prove_cooperative`] ever needs to record; a little headroom costs
/// nothing and keeps [`record_seq_entry`] a simple bounds check rather than
/// a panic path if a future change ever over-runs it.
const SEQ_LOG_CAP: usize = 8;

/// The cooperative boot proof's recorded `(task letter, iteration)` entries,
/// in the exact order [`print_marker_atomic`] observed them — the raw
/// evidence [`validate_cooperative_sequence`] checks. A fixed-size array (no
/// `alloc`) guarded by its own [`hal::sync::SpinMutex`] (mirrors the
/// scheduler locks' own discipline). Entries are appended from inside
/// [`print_marker_atomic`]'s existing [`preempt_disable`]/[`preempt_enable`]
/// bracket, so — like that bracket's print calls — a genuine timer tick can
/// never interleave a partial append from the *other* task into the middle
/// of this one. Holds `(buffer, length)`; only the first `length` slots are
/// meaningful.
static SEQ_LOG: hal::sync::SpinMutex<([(u8, u8); SEQ_LOG_CAP], usize)> =
    hal::sync::SpinMutex::new(([(0u8, 0u8); SEQ_LOG_CAP], 0));

/// Reset [`SEQ_LOG`] to empty. [`prove_cooperative`]'s sole caller, right
/// before spawning the two proof tasks, so a stale entry from a
/// hypothetical earlier call could never leak into this run's validation.
fn reset_seq_log() {
    let mut guard = SEQ_LOG.lock();
    guard.1 = 0;
}

/// Append `(letter, iter)` to [`SEQ_LOG`], if there is room. Silently drops
/// anything past [`SEQ_LOG_CAP`] rather than panicking —
/// [`prove_cooperative`] only ever records exactly
/// [`SEQ_LOG_EXPECTED_ENTRIES`] entries in practice, so this bound is never
/// actually reached; [`validate_cooperative_sequence`]'s "exactly N
/// entries" check is what would catch a run that somehow did overflow it.
fn record_seq_entry(letter: u8, iter: u8) {
    let mut guard = SEQ_LOG.lock();
    let (buf, len) = &mut *guard;
    if let Some(slot) = buf.get_mut(*len) {
        *slot = (letter, iter);
        *len += 1;
    }
}

/// Snapshot every entry [`record_seq_entry`] has recorded so far, in order.
/// Copies out of the lock (the backing type is plain `Copy` data — no
/// allocation) so callers can inspect it without holding [`SEQ_LOG`]'s lock.
fn seq_log_snapshot() -> ([(u8, u8); SEQ_LOG_CAP], usize) {
    let guard = SEQ_LOG.lock();
    *guard
}

/// Outcome of [`validate_cooperative_sequence`] — the property-based checks
/// [`prove_cooperative`]'s verdict line reports, replacing the old
/// exact-string phase assertion (issue #21 defect 3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct CooperativeVerdict {
    /// Exactly [`SEQ_LOG_EXPECTED_ENTRIES`] entries were recorded — neither
    /// fewer (a missing print) nor more (e.g. a task's loop somehow running
    /// twice).
    entries_ok: bool,
    /// No task appeared twice in a row, from EITHER starting phase — the
    /// property this fix replaces the old phase-fixed assertion with.
    interleave_ok: bool,
    /// Every entry's task letter was recognised (`A`/`B`) and, within each
    /// task's own subsequence, its recorded iterations ran `0, 1, 2` in that
    /// exact order (no gap, repeat, or reorder).
    order_ok: bool,
    /// How many entries were attributed to task `A`.
    count_a: u8,
    /// How many entries were attributed to task `B`.
    count_b: u8,
}

impl CooperativeVerdict {
    /// Overall pass/fail: every property held AND each task completed
    /// exactly [`PROOF_ITERATIONS`] iterations.
    fn ok(&self) -> bool {
        self.entries_ok
            && self.interleave_ok
            && self.order_ok
            && self.count_a == PROOF_ITERATIONS as u8
            && self.count_b == PROOF_ITERATIONS as u8
    }
}

/// Validate the cooperative boot proof's recorded `(task letter, iteration)`
/// sequence — a **property-based** check that deliberately does NOT assert
/// which task's entry comes first.
///
/// # Why phase is not asserted (issue #21 defect 3)
///
/// This scheduler is preemptive (PR-B), not cooperative-only: a fresh
/// task's [`task_prologue`] unconditionally resets [`PreemptState::count`] to `0`
/// and enables interrupts the instant it starts running, so there is a real
/// window — between a task's switch-in and its first [`preempt_disable`]
/// (inside [`print_marker_atomic`]) — during which a timer tick can legally
/// preempt it before it ever prints. On a fast host (observed on real KVM CI)
/// a burst of PIT ticks that piled up while the guest was descheduled can
/// arrive and drain in exactly that window.
///
/// That window exists on EVERY switch-in, not just the first. Issue #21
/// defect 3 addressed only its effect on the starting phase (dropping the
/// old fixed verbatim string, which was simply wrong), leaving the mid-run
/// case: if a task is switched in and preempted before it prints, the task
/// that just yielded runs again and prints twice in a row — the schedule
/// alternated correctly, but this recorded sequence, which records *prints*,
/// does not show it. That flaked on KVM CI on 2026-07-25 (`B0 A0 A1 B1 A2 B2`).
///
/// The fix is [`COOP_PROOF_NO_PREEMPT`]: [`prove_cooperative`] now withholds
/// timer-driven switches for its own duration, so during the proof the only
/// thing that moves the CPU is [`yield_now`] and the print sequence IS the
/// schedule. Strict alternation is therefore a genuine guarantee here, not a
/// hoped-for outcome — which is what lets the check below stay strict.
///
/// The checks remain phase-AGNOSTIC even so. Suppression makes which task
/// prints first deterministic in practice, but that ordering is an artifact
/// of spawn order and pick policy rather than a property worth freezing into
/// an assertion — re-encoding it would just re-import the brittleness issue
/// #21 removed. What is asserted is what a round-robin scheduler actually
/// promises: strict alternation (Invariant #4 — `ready` never contains
/// `current`, so the *other* task is always picked next) and each task's own
/// internal ordering.
///
/// # Checks
///
/// - (a) exactly [`SEQ_LOG_EXPECTED_ENTRIES`] entries were recorded at all
///   ([`CooperativeVerdict::entries_ok`]) — catches both a missing entry and
///   a run that somehow recorded extras (e.g. a task's loop double-running).
/// - (b) no task appears twice in a row, checked over the sequence exactly
///   as recorded — i.e. from WHICHEVER phase actually occurred
///   ([`CooperativeVerdict::interleave_ok`]).
/// - (c) each task's own recorded iterations run `0, 1, 2` in exactly that
///   order, with no unrecognised task letter
///   ([`CooperativeVerdict::order_ok`]).
///
/// Pure and HAL-free (like [`pick_next`]/[`tick_slice`]), so this is
/// directly host- and Miri-testable — see the `tests` module below.
fn validate_cooperative_sequence(entries: &[(u8, u8)]) -> CooperativeVerdict {
    let entries_ok = entries.len() == SEQ_LOG_EXPECTED_ENTRIES;
    let interleave_ok = entries.windows(2).all(|pair| pair[0].0 != pair[1].0);

    let mut expect_a: u8 = 0;
    let mut expect_b: u8 = 0;
    let mut order_ok = true;
    let mut count_a: u8 = 0;
    let mut count_b: u8 = 0;
    for &(letter, iter) in entries {
        match letter {
            b'A' => {
                count_a = count_a.saturating_add(1);
                if iter == expect_a {
                    expect_a = expect_a.saturating_add(1);
                } else {
                    order_ok = false;
                }
            }
            b'B' => {
                count_b = count_b.saturating_add(1);
                if iter == expect_b {
                    expect_b = expect_b.saturating_add(1);
                } else {
                    order_ok = false;
                }
            }
            _ => order_ok = false,
        }
    }

    CooperativeVerdict {
        entries_ok,
        interleave_ok,
        order_ok,
        count_a,
        count_b,
    }
}

/// Print `"<letter><i> "` — e.g. `"A0 "` — and record the same
/// `(letter, iteration)` pair into [`SEQ_LOG`] ([`record_seq_entry`]), as one
/// scheduler-atomic unit: bracketed in [`preempt_disable`]/[`preempt_enable`]
/// so a genuine timer tick landing between the [`hal::serial::write_str`]/
/// [`hal::serial::write_dec`] calls below — or between them and the
/// [`record_seq_entry`] call — can never let the *other* proof task's own
/// print/record interleave into the middle of this one.
///
/// This closes a real combined-review defect: once PR-B wires the timer
/// live, a tick can land at any instruction boundary (observed on fast KVM,
/// where host-scheduler jitter can deliver it almost anywhere) — including
/// between this print's pieces — and without this bracket the resulting
/// preemption could run the other task's full `"B2 "` print in the gap
/// between this one's digit and its trailing space, corrupting the raw
/// diagnostic sequence line [`prove_cooperative`] prints (e.g. `"A2B2  "`
/// instead of `"A2 B2 "`) and, worse, letting the two tasks' [`SEQ_LOG`]
/// entries land out of true program order — which [`validate_cooperative_sequence`]
/// would then (correctly) flag as broken even though nothing was actually
/// wrong. A tick landing inside the bracket is never lost — [`on_tick`] just
/// defers it via [`PreemptState::need_resched`] (module docs' "Interrupt-flag discipline"
/// section) for [`preempt_enable`] to drain immediately after this function
/// returns, so this only ever delays a real preemption by a handful of
/// instructions, never skips one — the proof tasks' own explicit
/// `yield_now()` (called right after, by [`proof_task_a`]/[`proof_task_b`])
/// still hands off every iteration regardless.
///
/// During the cooperative proof no tick requests a switch at all
/// ([`COOP_PROOF_NO_PREEMPT`]), so this bracket is belt-and-braces there. It
/// is kept because it is unconditionally correct, because
/// [`print_marker_atomic`] must stay safe if the suppression is ever narrowed
/// or removed, and because the serial-output atomicity it provides is
/// independent of scheduling. Note that with suppression in place this is no
/// longer a boot-time exercise of `preempt_enable`'s deferred-drain branch —
/// that path is covered by the host unit tests and the
/// `preempt_count_nesting_never_underflows` Kani harness.
///
/// Note what this bracket does **not**, and cannot, guarantee on its own:
/// which of the two tasks' *first* call to this function happens first
/// overall — see [`validate_cooperative_sequence`]'s docs for why that
/// starting phase is deliberately left unasserted.
fn print_marker_atomic(letter: &str, i: u32) {
    preempt_disable();
    hal::serial::write_str(letter);
    hal::serial::write_dec(u64::from(i));
    hal::serial::write_str(" ");
    let letter_byte = letter.as_bytes().first().copied().unwrap_or(b'?');
    let iter_byte = u8::try_from(i).unwrap_or(u8::MAX);
    record_seq_entry(letter_byte, iter_byte);
    preempt_enable();
}

/// Boot-proof task "A": print `A<i>` then [`yield_now`], `PROOF_ITERATIONS`
/// times, then return (after which [`task_shim`] calls [`exit`]).
fn proof_task_a() {
    for i in 0..PROOF_ITERATIONS {
        print_marker_atomic("A", i);
        yield_now();
    }
}

/// Boot-proof task "B" — the sibling of [`proof_task_a`].
fn proof_task_b() {
    for i in 0..PROOF_ITERATIONS {
        print_marker_atomic("B", i);
        yield_now();
    }
}

/// Number of tasks currently in the ready queue — [`prove_cooperative`]'s and
/// [`prove_preemptive`]'s drain condition.
fn ready_len() -> usize {
    with_interrupts_disabled(|| CPU_SCHED[local_cpu()].lock().ready.len())
}

/// Run the PR-A cooperative-scheduling boot proof (scheduler design doc,
/// "Boot proofs — PR-A").
///
/// Spawns two kernel threads ("A", "B") that each print-and-record
/// ([`print_marker_atomic`]) then [`yield_now`] in a fixed, small loop, then
/// (as the adopted idle task) yields until both have exited and the ready
/// queue drains. Prints two lines:
///
/// - a **diagnostic-only** raw sequence line, e.g. `[sched] cooperative: A0
///   B0 A1 B1 A2 B2 (raw sequence above; not the pass/fail gate)` — never
///   asserted verbatim by `cargo xtask test` (see below for why),
/// - the **asserted verdict** line, computed by
///   [`validate_cooperative_sequence`] over the very same run's
///   [`SEQ_LOG`]:
///
/// ```text
/// [sched] cooperative: interleave=strict per-task-order=ok iters=3/3 ok
/// ```
///
/// # Why the raw line's starting phase is diagnostic-only (issue #21 defect 3)
///
/// This kernel is preemptive (PR-B), not cooperative-only: the timer can, in
/// principle, fire at any instant, including in the narrow window between a
/// freshly-spawned task's first switch-in and its first
/// [`preempt_disable`] (inside its first [`print_marker_atomic`] call) —
/// [`task_prologue`] unconditionally resets [`PreemptState::count`] for every
/// fresh task, so nothing the *spawning* context did with
/// `preempt_disable`/`preempt_enable` reaches across that window to cover
/// it. On real KVM hardware (this defect's origin) a burst of PIT ticks that
/// piled up while the guest was descheduled has been observed to drain
/// exactly there, preempting task "A" before its very first print and
/// letting "B" print first — a legitimate, uninvited outcome for a
/// preemptive kernel to produce, not a bug. The original implementation
/// wrongly encoded the "A always goes first" phase as part of one verbatim
/// string assertion; this version instead asserts only the properties a
/// preemptive round-robin scheduler genuinely does guarantee, regardless of
/// which task happens to go first: strict alternation and each task's own
/// internal ordering — see [`validate_cooperative_sequence`]'s docs for the
/// full reasoning and its host tests for both-phase coverage.
///
/// Uses only the `fmt`-free [`hal::serial::write_str`]/[`hal::serial::write_dec`]
/// helpers throughout — integer `println!` faults on this target (see
/// `kernel/docs/hal-tcb.md` §5e). Call once, after [`init`].
pub fn prove_cooperative() {
    // Run the proof preemption-free so strict alternation is a real guarantee,
    // not a race — see [`COOP_PROOF_NO_PREEMPT`]. Cleared before this function
    // returns, so `prove_preemptive` (which must be preemptible) is unaffected.
    COOP_PROOF_SUPPRESSED.store(0, Ordering::Relaxed);
    COOP_PROOF_NO_PREEMPT.store(true, Ordering::Relaxed);
    reset_seq_log();

    spawn("A", proof_task_a);
    spawn("B", proof_task_b);

    hal::serial::write_str("[sched] cooperative: ");
    while ready_len() > 0 {
        yield_now();
    }
    // Diagnostic only — see this function's docs for why the raw sequence's
    // starting phase is never the pass/fail gate. The verdict line below,
    // computed over this very run's `SEQ_LOG`, is.
    hal::serial::write_str("(raw sequence above; not the pass/fail gate)\n");

    // Restore normal preemption before anything else runs — in particular
    // before `prove_preemptive`, whose whole point is being preempted. Done
    // here (not at function end) so it is restored even though the verdict
    // printing below is itself preemptible.
    COOP_PROOF_NO_PREEMPT.store(false, Ordering::Relaxed);

    let (seq_buf, seq_len) = seq_log_snapshot();
    let verdict = validate_cooperative_sequence(&seq_buf[..seq_len]);

    hal::serial::write_str("[sched] cooperative: interleave=");
    hal::serial::write_str(if verdict.interleave_ok {
        "strict"
    } else {
        "broken"
    });
    hal::serial::write_str(" per-task-order=");
    hal::serial::write_str(if verdict.order_ok { "ok" } else { "fail" });
    hal::serial::write_str(" iters=");
    hal::serial::write_dec(u64::from(verdict.count_a));
    hal::serial::write_str("/");
    hal::serial::write_dec(u64::from(verdict.count_b));
    hal::serial::write_str(" ");
    hal::serial::write_str(if verdict.ok() { "ok\n" } else { "FAIL\n" });

    // Informational only — never asserted by `cargo xtask test` (the verdict
    // line above is the actual pass/fail gate). Counts the slice expiries
    // `COOP_PROOF_NO_PREEMPT` withheld during the proof: a nonzero value is
    // the evidence that real PIT ticks fired throughout, so the strict
    // interleave above came from suppression rather than from the phase
    // finishing before the timer ever got a chance to fire. Zero is not a
    // failure — on a fast host the whole proof can fit inside one quantum.
    //
    // This replaces a previous `deferred-tick-preemptions observed=N` line,
    // which reported whether a tick had landed inside one of
    // `print_marker_atomic`'s brackets and been drained through
    // `preempt_enable`'s deferred-reschedule branch. That can no longer happen
    // here (no switch is requested during the proof at all), so that path's
    // boot-time exercise is gone; it remains covered by the host unit tests
    // and the `preempt_count_nesting_never_underflows` Kani harness, and by
    // `prove_preemptive` for real timer-driven switching.
    hal::serial::write_str("[sched] cooperative: timer-preemptions suppressed=");
    hal::serial::write_dec(COOP_PROOF_SUPPRESSED.load(Ordering::Relaxed));
    hal::serial::write_str("\n");
}

// ── PR-B boot proof: timer preemption (the payoff) ──────────────────────────
//
// Per the scheduler design doc's "Boot proofs — PR-B" section: a compute
// ("gemm") task loops a fixed int8 GEMM and a "spin" task loops a cheap
// counter — **neither ever calls `yield_now`** — so the *only* thing that can
// switch either of them away is the timer (`on_tick`). Evidence: both tasks
// made progress, the GEMM checksums stayed bit-exact across every iteration
// (a per-task vector-save corruption would flip this), and at least one
// genuine timer-driven preemption occurred.

/// Dimensions for [`proof_task_gemm`]'s fixed int8 GEMM — generously past the
/// widest vector lane in play (mirrors `ml::prove`'s `N` note), so each call
/// does real, multi-instruction vector work.
const PREEMPT_PROOF_M: usize = 16;
const PREEMPT_PROOF_K: usize = 16;
const PREEMPT_PROOF_N: usize = 32;

/// Wall-clock PIT ticks [`proof_task_gemm`]/[`proof_task_spinner`] each run
/// for — comfortably more than one [`TIME_SLICE_TICKS`] quantum, so both
/// tasks are certain to be preempted at least once by the timer (never by
/// their own choice — neither ever calls [`yield_now`]) regardless of
/// host/TCG speed, since the PIT is a real-time device that fires at
/// [`hal::pit::TICK_HZ`] independent of emulation speed.
const PREEMPT_PROOF_RUN_TICKS: u64 = 40;

/// Iteration hard cap for [`proof_task_gemm`]/[`proof_task_spinner`], guarding
/// against a dead/non-advancing timer spinning either task forever (mirrors
/// `ml::prove_interrupts_on`'s identical guard).
const PREEMPT_PROOF_ITER_CAP: u64 = 20_000_000;

/// [`proof_task_gemm`]'s total completed GEMM iterations — read back by
/// [`prove_preemptive`] as "the compute task made progress" evidence.
static GEMM_ITERS: AtomicU64 = AtomicU64::new(0);
/// Whether every one of [`proof_task_gemm`]'s GEMM results matched the scalar
/// reference, bit-for-bit, for the whole run. `false` would mean a
/// preemption clobbered a live vector accumulator — the exact failure mode
/// eager per-task `xsave`/`xrstor` (req. #1 of the scheduler design doc)
/// exists to prevent.
static GEMM_EXACT: AtomicBool = AtomicBool::new(true);
/// [`proof_task_spinner`]'s total completed iterations — "the second task
/// also made progress" evidence.
static SPIN_ITERS: AtomicU64 = AtomicU64::new(0);
/// How many of the two preemption-proof tasks have finished their run — what
/// [`prove_preemptive_on`] waits for when the tasks run on **another** core
/// (the local-core variant drains its own ready queue instead).
static PROOF_TASKS_DONE: AtomicU32 = AtomicU32::new(0);
/// Upper bound on the BSP's wait for a remote core's two proof tasks: each
/// runs [`PREEMPT_PROOF_RUN_TICKS`] of wall clock and they share the core, so
/// ~2× that plus a generous margin for a descheduled TCG vCPU thread.
const PREEMPT_PROOF_REMOTE_TIMEOUT_TICKS: u64 = 3 * PREEMPT_PROOF_RUN_TICKS + 200;

/// Boot-proof task: run a fixed int8 GEMM in a tight loop for
/// [`PREEMPT_PROOF_RUN_TICKS`] wall-clock ticks, **never** calling
/// [`yield_now`] — the only thing that can switch this task away is
/// [`on_tick`]. Checksums every result against the scalar reference
/// ([`crate::ml::gemm_i8_scalar`]) computed once up front; any mismatch would
/// mean a preemption clobbered a live vector (YMM/ZMM) accumulator (see the
/// scheduler design doc's PR-B payoff proof). Records totals in
/// [`GEMM_ITERS`]/[`GEMM_EXACT`] for [`prove_preemptive`].
fn proof_task_gemm() {
    let mut a = [0i8; PREEMPT_PROOF_M * PREEMPT_PROOF_K];
    for (idx, slot) in a.iter_mut().enumerate() {
        // Small, deterministic mixed-sign fill (range -6..=6) — well within
        // i8, with no overflow risk in the reference accumulation.
        *slot = ((idx % 13) as i8) - 6;
    }
    let mut b = [0i8; PREEMPT_PROOF_K * PREEMPT_PROOF_N];
    for (idx, slot) in b.iter_mut().enumerate() {
        *slot = ((idx % 11) as i8) - 5;
    }

    let mut expected = [0i32; PREEMPT_PROOF_M * PREEMPT_PROOF_N];
    crate::ml::gemm_i8_scalar(
        &a,
        &b,
        &mut expected,
        PREEMPT_PROOF_M,
        PREEMPT_PROOF_K,
        PREEMPT_PROOF_N,
    );

    let mut c = [0i32; PREEMPT_PROOF_M * PREEMPT_PROOF_N];
    let start = crate::clock::mono_ticks();
    let mut iters: u64 = 0;
    let mut exact = true;
    while crate::clock::mono_ticks().wrapping_sub(start) < PREEMPT_PROOF_RUN_TICKS
        && iters < PREEMPT_PROOF_ITER_CAP
    {
        crate::ml::gemm_i8(
            &a,
            &b,
            &mut c,
            PREEMPT_PROOF_M,
            PREEMPT_PROOF_K,
            PREEMPT_PROOF_N,
        );
        if !c.iter().zip(expected.iter()).all(|(x, y)| x == y) {
            exact = false;
            break;
        }
        iters += 1;
    }
    GEMM_ITERS.store(iters, Ordering::Relaxed);
    GEMM_EXACT.store(exact, Ordering::Relaxed);
    PROOF_TASKS_DONE.fetch_add(1, Ordering::Release);
}

/// Boot-proof task: loop a cheap, side-effect-free counter for
/// [`PREEMPT_PROOF_RUN_TICKS`] wall-clock ticks, **never** calling
/// [`yield_now`] — the sibling of [`proof_task_gemm`], proving a second task
/// also makes progress under the same timer-preemption pressure. Records its
/// total in [`SPIN_ITERS`].
fn proof_task_spinner() {
    let start = crate::clock::mono_ticks();
    let mut iters: u64 = 0;
    while crate::clock::mono_ticks().wrapping_sub(start) < PREEMPT_PROOF_RUN_TICKS
        && iters < PREEMPT_PROOF_ITER_CAP
    {
        core::hint::spin_loop();
        iters += 1;
    }
    SPIN_ITERS.store(iters, Ordering::Relaxed);
    PROOF_TASKS_DONE.fetch_add(1, Ordering::Release);
}

/// Run the PR-B **preemptive**-scheduling boot proof (scheduler design doc,
/// "Boot proofs — PR-B"): spawn a "gemm" task and a "spin" task, **neither of
/// which ever calls [`yield_now`]**, then (as the adopted idle task) wait for
/// both to exit — driven by idle's own voluntary yields (fine: the
/// requirement is that the *compute*/*spin* tasks never yield, not idle) plus
/// genuine timer preemptions of the gemm/spin tasks themselves, which is the
/// only thing that can ever switch either of them away.
///
/// Must run with the timer already live (interrupts enabled — true by this
/// point in `kmain`, since the first spawned task's [`task_prologue`] already
/// opened the interrupt window) and after [`prove_cooperative`] has fully
/// drained (so `ready`/`tasks` start clean).
///
/// Evidence line proves three things at once:
/// - both tasks progressed (`gemm-iters`/`spin-iters` `> 0`),
/// - the GEMM checksums stayed bit-exact across every iteration
///   (`gemm-exact=yes` — a per-task vector-save corruption would flip this to
///   `no`),
/// - at least one genuine timer-driven preemption occurred (`preempted=N`,
///   counting only *actual* switches [`on_tick`] performed — see
///   [`PreemptState::events`]; on the BSP only the timer drives it).
///
/// ```text
/// [sched] preemptive: gemm-iters=<N> gemm-exact=yes spin-iters=<N> preempted=<N> ok
/// ```
///
/// Deliberately **not** an exact-string assertion target (unlike
/// [`prove_cooperative`]'s marker): the iteration/preemption counts are
/// inherently timing-dependent, so `cargo xtask test` checks the individual
/// fields (`gemm-exact=yes`, `preempted >= 1`, both iteration counts `> 0`)
/// rather than the whole line verbatim.
pub fn prove_preemptive() {
    prove_preemptive_on(local_cpu() as u32, "preemptive");
}

/// The PR-B preemption proof, run on an **application processor** (SMP phase
/// 3): both tasks are pinned to the first online AP, whose own LAPIC-timer tick
/// is the only thing that can switch them. The BSP waits for both to finish
/// and reports:
///
/// ```text
/// [sched] ap-preemptive: cpu1 gemm-iters=<N> gemm-exact=yes spin-iters=<N> tick-preempted=<N> ok
/// ```
///
/// `tick-preempted` counts **timer-driven** switches only (`PreemptState::
/// tick_events`) — the two IPI-driven switches that deliver the tasks to the
/// core are deliberately excluded, so `>= 1` is evidence of the AP's tick, not
/// of the IPIs. `cargo xtask test` asserts the fields like the BSP line's. With
/// no online AP the line reports `cpu=none skipped` (always a hard failure under
/// the tests' `-smp 4`).
pub fn prove_ap_preemptive() {
    let bsp = local_cpu() as u32;
    let target = (1..crate::smp::cpu_count() as u32).find(|&c| c != bsp && cpu_is_schedulable(c));
    match target {
        Some(cpu) => prove_preemptive_on(cpu, "ap-preemptive"),
        None => hal::serial::print_line("[sched] ap-preemptive: cpu=none (no online AP) skipped"),
    }
}

/// Run the preemption proof with both tasks pinned to `cpu`, reporting under
/// `label`. On the calling core the idle drains its own ready queue by
/// yielding (PR-B's original shape); on another core the BSP spins (bounded)
/// on [`PROOF_TASKS_DONE`], since it cannot yield on that core's behalf. The
/// evidence fields are the same in both cases, plus `tick-preempted` for a
/// remote core (see [`prove_ap_preemptive`]).
fn prove_preemptive_on(cpu: u32, label: &str) {
    let local = cpu as usize == local_cpu();
    GEMM_ITERS.store(0, Ordering::Relaxed);
    GEMM_EXACT.store(true, Ordering::Relaxed);
    SPIN_ITERS.store(0, Ordering::Relaxed);
    PROOF_TASKS_DONE.store(0, Ordering::Release);
    let events = &PREEMPT[cpu as usize].events;
    let tick_events = &PREEMPT[cpu as usize].tick_events;
    let before = events.load(Ordering::Relaxed);
    let tick_before = tick_events.load(Ordering::Relaxed);

    let spawned = spawn_on(cpu, "gemm", proof_task_gemm).is_ok()
        && spawn_on(cpu, "spin", proof_task_spinner).is_ok();
    if !spawned {
        hal::serial::write_str("[sched] ");
        hal::serial::write_str(label);
        hal::serial::write_str(": spawn FAILED on cpu");
        hal::serial::write_dec(u64::from(cpu));
        hal::serial::write_str("\n");
        return;
    }

    let timed_out = if local {
        while ready_len() > 0 {
            yield_now();
        }
        false
    } else {
        // The tasks clock themselves on the PIT, which only the BSP advances —
        // so the BSP must take interrupts while it waits (see `wait_on_other_core`).
        !wait_on_other_core(
            || PROOF_TASKS_DONE.load(Ordering::Acquire) >= 2,
            PREEMPT_PROOF_REMOTE_TIMEOUT_TICKS,
        )
    };

    let preempted = events.load(Ordering::Relaxed).wrapping_sub(before);
    let tick_preempted = tick_events
        .load(Ordering::Relaxed)
        .wrapping_sub(tick_before);
    let gemm_iters = GEMM_ITERS.load(Ordering::Relaxed);
    let gemm_exact = GEMM_EXACT.load(Ordering::Relaxed);
    let spin_iters = SPIN_ITERS.load(Ordering::Relaxed);
    let preemption_evidence = if local { preempted } else { tick_preempted };
    let ok =
        !timed_out && gemm_iters > 0 && spin_iters > 0 && gemm_exact && preemption_evidence >= 1;

    hal::serial::write_str("[sched] ");
    hal::serial::write_str(label);
    hal::serial::write_str(": ");
    if !local {
        hal::serial::write_str("cpu");
        hal::serial::write_dec(u64::from(cpu));
        hal::serial::write_str(" ");
    }
    hal::serial::write_str("gemm-iters=");
    hal::serial::write_dec(gemm_iters);
    hal::serial::write_str(" gemm-exact=");
    hal::serial::write_str(if gemm_exact { "yes" } else { "no" });
    hal::serial::write_str(" spin-iters=");
    hal::serial::write_dec(spin_iters);
    if local {
        hal::serial::write_str(" preempted=");
        hal::serial::write_dec(preempted);
    } else {
        hal::serial::write_str(" tick-preempted=");
        hal::serial::write_dec(tick_preempted);
        if timed_out {
            hal::serial::write_str(" TIMEOUT");
        }
    }
    hal::serial::write_str(" ");
    hal::serial::write_str(if ok { "ok\n" } else { "FAIL\n" });
}

// ── Waiting on another core ─────────────────────────────────────────────────

/// Spin until `done()` holds or `timeout_ticks` ticks of the core-independent
/// monotonic clock (`crate::clock::mono_ticks`) elapse; returns `done()`.
///
/// History: this used to *have* to run with interrupts enabled, because the
/// only clock was the PIT and the PIT advances only when the BSP services
/// IRQ0. A BSP spinning with `IF = 0` for work on another core froze the very
/// clock that work was timing itself against (the preemption-proof tasks run
/// for a fixed number of ticks) and its own timeout never fired either — a
/// mutual wait, observed as a silent hang the first time two timer-driven
/// tasks ran on an AP (hal-tcb invariant 4.15). Since SMP phase 3b-i both this
/// deadline and the proof tasks tick off `clock::mono_ticks`, which any ticking
/// core advances, so the wait is correct with `IF = 0` too. Interrupts are
/// still opened here on purpose: this core's own tick then also carries the
/// clock, and a tick on an empty queue is a no-op — belt and braces, not a
/// requirement.
fn wait_on_other_core(done: impl Fn() -> bool, timeout_ticks: u64) -> bool {
    let were_enabled = hal::cpu::interrupts_enabled();
    hal::cpu::enable_interrupts();
    let deadline = crate::clock::mono_ticks().saturating_add(timeout_ticks);
    while !done() && crate::clock::mono_ticks() < deadline {
        core::hint::spin_loop();
    }
    if !were_enabled {
        hal::cpu::disable_interrupts();
    }
    done()
}

// ── PR-2 boot proof: a task pinned to an application processor ──────────────

/// Dense cpu index the pinned proof task observed itself running on
/// (`u32::MAX` until it has run).
static PINNED_RAN_ON: AtomicU32 = AtomicU32::new(u32::MAX);
/// Set (`Release`) by the pinned proof task once it has recorded its core.
static PINNED_DONE: AtomicBool = AtomicBool::new(false);
/// How long the BSP waits for the pinned task: 200 PIT ticks = 2 s. Generous
/// for the same reason `kernel::smp`'s AP timeout is — a TCG vCPU thread on a
/// contended CI host can be descheduled for far longer than the ~µs the
/// IPI → switch → record → exit path needs.
const PINNED_PROOF_TIMEOUT_TICKS: u64 = 200;

/// The pinned proof task's body: record which core this is (the core's own
/// `cpuid` APIC ID mapped to its dense index by `kernel::smp`), then return
/// (→ [`task_shim`] → [`exit`] on that core). Deliberately does **not** print:
/// the BSP reports, from the atomics, after it observes `PINNED_DONE`.
fn proof_task_pinned() {
    let cpu = crate::smp::this_cpu_index().unwrap_or(u32::MAX);
    PINNED_RAN_ON.store(cpu, Ordering::Release);
    PINNED_DONE.store(true, Ordering::Release);
}

/// Run the PR-2 **per-CPU scheduler** boot proof (AP bring-up design doc,
/// "PR-2 checklist" item 9): the BSP places a task on the first online
/// application processor with [`spawn_on`] — which sends that core a
/// reschedule IPI — and the task records the core it actually ran on.
///
/// Evidence line (asserted by `cargo xtask test`, TCG and KVM alike):
///
/// ```text
/// [sched] pinned: target=cpu1 ran-on=cpu1 bsp=cpu0 distinct=yes ok
/// ```
///
/// `ok` requires all of: the task completed within the timeout, it ran on the
/// targeted core, and that core is not the BSP. This exercises the whole
/// cross-core path end to end — remote queue push, `send_ipi`, the AP waking
/// from `sti; hlt`, [`on_resched_ipi`]'s ISR-tail switch from the AP idle to
/// the task, the task's [`exit`] switching back to the idle inside the IPI
/// handler, and the idle's [`idle_reap`]. With no online AP (a single-CPU
/// machine) the line reports `target=none` and `skipped` — `cargo xtask test`
/// always boots with `-smp 4`, so there it is a hard failure.
pub fn prove_pinned() {
    let bsp = local_cpu() as u32;
    let target = (1..crate::smp::cpu_count() as u32).find(|&c| c != bsp && cpu_is_schedulable(c));
    let Some(target) = target else {
        hal::serial::write_str("[sched] pinned: target=none (no online AP) bsp=cpu");
        hal::serial::write_dec(u64::from(bsp));
        hal::serial::write_str(" skipped\n");
        return;
    };

    PINNED_DONE.store(false, Ordering::Release);
    PINNED_RAN_ON.store(u32::MAX, Ordering::Release);
    // `spawn_on` prints its own `[sched] spawn 'pinned': …` line; the verdict
    // line below is printed whole, afterwards, so the two never interleave.
    if let Err(err) = spawn_on(target, "pinned", proof_task_pinned) {
        hal::serial::write_str("[sched] pinned: target=cpu");
        hal::serial::write_dec(u64::from(target));
        hal::serial::write_str(" spawn FAILED: ");
        hal::serial::write_str(err.label());
        hal::serial::write_str("\n");
        return;
    }

    let done = wait_on_other_core(
        || PINNED_DONE.load(Ordering::Acquire),
        PINNED_PROOF_TIMEOUT_TICKS,
    );
    let ran_on = PINNED_RAN_ON.load(Ordering::Acquire);
    let distinct = done && ran_on != bsp;
    let ok = done && ran_on == target && distinct;

    hal::serial::write_str("[sched] pinned: target=cpu");
    hal::serial::write_dec(u64::from(target));
    hal::serial::write_str(" ran-on=");
    if done {
        hal::serial::write_str("cpu");
        hal::serial::write_dec(u64::from(ran_on));
    } else {
        hal::serial::write_str("TIMEOUT");
    }
    hal::serial::write_str(" bsp=cpu");
    hal::serial::write_dec(u64::from(bsp));
    hal::serial::write_str(" distinct=");
    hal::serial::write_str(if distinct { "yes" } else { "no" });
    hal::serial::write_str(if ok { " ok\n" } else { " FAIL\n" });
}

// ── Host + Miri unit tests: pure queue logic ────────────────────────────────// ── Host + Miri unit tests: pure queue logic ────────────────────────────────
//
// `pick_next` is the entire scheduling *policy* (rotation, exit bookkeeping,
// Invariant #4) with zero dependency on `Task`/`Context`/`hal`, so it is
// exercised directly here — no mock `hal::context::switch` needed, because
// nothing here ever calls the real `switch`.

#[cfg(test)]
mod tests {
    use super::{pick_next, TaskId};
    use alloc::collections::VecDeque;

    fn ids(v: &[u64]) -> VecDeque<TaskId> {
        v.iter().map(|&n| TaskId(n)).collect()
    }

    #[test]
    fn rotates_ready_queue_round_robin() {
        let mut ready = ids(&[1, 2]);
        let mut zombie = None;
        let next = pick_next(&mut ready, &mut zombie, TaskId(0), false);
        assert_eq!(next, Some(TaskId(1)));
        // The outgoing task (0) is requeued at the back.
        assert_eq!(ready, ids(&[2, 0]));
        assert_eq!(zombie, None);
    }

    #[test]
    fn ready_never_contains_the_new_current() {
        // Invariant #4 (partial): simulate several rounds and check the
        // freshly-picked `next` is never left inside `ready` afterward.
        let mut ready = ids(&[1, 2]);
        let mut current = TaskId(0);
        let mut zombie = None;
        for _ in 0..10 {
            let next = pick_next(&mut ready, &mut zombie, current, false).expect("always runnable");
            assert!(
                !ready.contains(&next),
                "ready must never contain the new current"
            );
            current = next;
        }
    }

    #[test]
    fn exiting_task_is_never_requeued_and_becomes_the_zombie() {
        let mut ready = ids(&[1]);
        let mut zombie = None;
        let next = pick_next(&mut ready, &mut zombie, TaskId(2), true);
        assert_eq!(next, Some(TaskId(1)));
        assert_eq!(zombie, Some(TaskId(2)));
        assert!(
            !ready.contains(&TaskId(2)),
            "an exiting task is never requeued"
        );
    }

    #[test]
    fn no_lost_or_duplicated_ids_across_many_steps() {
        // Invariant #4 (full): round-robin over a fixed universe of 4 ids;
        // every id must be in exactly one place (ready, or "current") at
        // every step, never both and never neither.
        let mut ready = ids(&[1, 2, 3]);
        let mut current = TaskId(0);
        let mut zombie = None;
        let universe = [TaskId(0), TaskId(1), TaskId(2), TaskId(3)];

        for _ in 0..50 {
            let next = pick_next(&mut ready, &mut zombie, current, false)
                .expect("4 tasks round-robin: always runnable");
            assert_eq!(ready.len(), universe.len() - 1);
            assert!(!ready.contains(&next));
            for id in &universe {
                let in_ready = ready.contains(id);
                let is_current = *id == next;
                assert!(
                    in_ready ^ is_current,
                    "id {:?} must be in exactly one of ready/current, never both/neither",
                    id
                );
            }
            current = next;
        }
    }

    #[test]
    fn pick_next_records_an_exit_but_never_reaps() {
        // `pick_next` alone does not reap — it only records; reaping is a
        // separate step (`idle_reap`, in the idle task). Production hands it a
        // fresh slot per pass and moves an exit into the core's zombie ring
        // (`pick_next_parking_exits`).
        let mut ready = ids(&[1]);
        let mut zombie = None;
        // Task 2 exits: recorded as zombie, not requeued.
        let next = pick_next(&mut ready, &mut zombie, TaskId(2), true);
        assert_eq!(next, Some(TaskId(1)));
        assert_eq!(zombie, Some(TaskId(2)));
        // A subsequent (non-exiting) step must NOT touch `zombie` itself.
        let next2 = pick_next(&mut ready, &mut zombie, TaskId(1), false);
        assert_eq!(next2, None); // nothing else runnable
        assert_eq!(zombie, Some(TaskId(2)), "pick_next never reaps on its own");
    }

    #[test]
    fn nothing_runnable_returns_none_and_leaves_state_unchanged() {
        let mut ready: VecDeque<TaskId> = VecDeque::new();
        let mut zombie = None;
        let next = pick_next(&mut ready, &mut zombie, TaskId(0), false);
        assert_eq!(next, None);
        assert!(ready.is_empty());
        assert_eq!(zombie, None);
    }

    #[test]
    fn preempt_disable_enable_round_trip_does_not_reschedule() {
        use super::{preempt_disable, preempt_enable, PREEMPT};
        use core::sync::atomic::Ordering;

        // No task ever requests a reschedule in this test, so `preempt_enable`
        // must not touch the (unset-up) real scheduler at all. On the host
        // `local_cpu()` is always 0.
        let count = &PREEMPT[0].count;
        preempt_disable();
        preempt_disable();
        assert_eq!(count.load(Ordering::Relaxed), 2);
        preempt_enable();
        assert_eq!(count.load(Ordering::Relaxed), 1);
        preempt_enable();
        assert_eq!(count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn preempt_state_takes_pending_only_at_zero() {
        use super::PreemptState;
        use core::sync::atomic::Ordering;

        let st = PreemptState::new();
        st.disable();
        st.disable();
        st.need_resched.store(true, Ordering::Relaxed);
        // Leaving the inner section: count 2 → 1, nothing drained yet.
        assert!(!st.enable_and_take_pending());
        assert!(st.need_resched.load(Ordering::Relaxed));
        // Leaving the outer one: count 1 → 0 with a pending flag → drain, and
        // the flag is consumed.
        assert!(st.enable_and_take_pending());
        assert!(!st.need_resched.load(Ordering::Relaxed));
        // With nothing pending, reaching zero reports nothing to drain.
        st.disable();
        assert!(!st.enable_and_take_pending());
    }

    #[test]
    fn task_ids_are_monotonic_and_never_reuse_the_idle_id() {
        use super::{next_task_id, TaskId as SchedTaskId};

        let a = next_task_id();
        let b = next_task_id();
        assert!(b.0 > a.0, "ids must be strictly increasing");
        assert_ne!(a, SchedTaskId::IDLE);
        assert_ne!(b, SchedTaskId::IDLE);
    }

    // ── PR-B: `tick_slice` (pure slice-expiry decision) ─────────────────────

    #[test]
    fn tick_slice_counts_down_and_reloads_on_expiry() {
        use super::{tick_slice, TIME_SLICE_TICKS};

        let mut slice = 3u32;
        assert!(!tick_slice(&mut slice));
        assert_eq!(slice, 2);
        assert!(!tick_slice(&mut slice));
        assert_eq!(slice, 1);
        // The tick that brings it to 0 reports expiry AND reloads a fresh
        // quantum in the same step, so the task is always ready to run again
        // regardless of whether this particular expiry triggers a switch.
        assert!(tick_slice(&mut slice));
        assert_eq!(slice, TIME_SLICE_TICKS);
    }

    /// The three slice-expiry outcomes, including the cooperative-proof
    /// suppression added to fix the KVM interleave flake (2026-07-25).
    #[test]
    fn tick_action_suppresses_only_during_the_cooperative_proof() {
        use super::{tick_action, TickAction};

        // Normal operation: switch immediately, or defer inside a
        // `preempt_disable` critical section.
        assert_eq!(tick_action(false, 0), TickAction::Switch);
        assert_eq!(tick_action(false, 1), TickAction::Defer);
        assert_eq!(tick_action(false, 7), TickAction::Defer);

        // During the cooperative proof the switch is withheld outright — at
        // ANY preempt count. Deferring instead would only postpone the same
        // preemption to the next `preempt_enable`, which is the very flake
        // the suppression exists to remove, so suppression must win over the
        // deferral branch rather than fall through to it.
        assert_eq!(tick_action(true, 0), TickAction::Suppress);
        assert_eq!(tick_action(true, 1), TickAction::Suppress);
        assert_eq!(tick_action(true, u32::MAX), TickAction::Suppress);
    }

    #[test]
    fn tick_slice_never_underflows_from_zero() {
        use super::tick_slice;

        // Defensive: `TIME_SLICE_TICKS > 0` and reload-on-expiry mean a task's
        // `slice` should never actually observe `0` going in, but
        // `saturating_sub` keeps this well-defined (never wraps to `u32::MAX`)
        // even if it did, still reporting expiry + a fresh reload.
        let mut slice = 0u32;
        assert!(tick_slice(&mut slice));
        assert_eq!(slice, super::TIME_SLICE_TICKS);
    }

    #[test]
    fn tick_slice_one_tick_expires_immediately() {
        use super::{tick_slice, TIME_SLICE_TICKS};

        let mut slice = 1u32;
        assert!(tick_slice(&mut slice));
        assert_eq!(slice, TIME_SLICE_TICKS);
    }

    // ── PR-2: `ReadyRing` (the production, allocation-free ready queue) and
    // `TaskTable` (the fixed task slab) ─────────────────────────────────────

    #[test]
    fn ready_ring_is_fifo_and_wraps_around() {
        use super::{ReadyQueue, ReadyRing};

        let mut ring: ReadyRing<4> = ReadyRing::new();
        assert_eq!(ring.len(), 0);
        assert_eq!(ring.pop_front(), None);
        ring.push_back(TaskId(1));
        ring.push_back(TaskId(2));
        ring.push_back(TaskId(3));
        assert_eq!(ring.len(), 3);
        assert_eq!(ring.get(0), Some(TaskId(1)));
        assert_eq!(ring.get(2), Some(TaskId(3)));
        assert_eq!(ring.get(3), None);
        assert_eq!(ring.pop_front(), Some(TaskId(1)));
        // Wrap: head has advanced; pushes land past the physical end.
        ring.push_back(TaskId(4));
        ring.push_back(TaskId(5));
        assert_eq!(ring.len(), 4);
        assert_eq!(ring.pop_front(), Some(TaskId(2)));
        assert_eq!(ring.pop_front(), Some(TaskId(3)));
        assert_eq!(ring.pop_front(), Some(TaskId(4)));
        assert_eq!(ring.pop_front(), Some(TaskId(5)));
        assert_eq!(ring.pop_front(), None);
        assert_eq!(ring.len(), 0);
    }

    #[test]
    fn pick_next_over_the_production_ring_rotates_and_records_exits() {
        use super::{ReadyQueue, ReadyRing};

        let mut ring: ReadyRing<8> = ReadyRing::new();
        ring.push_back(TaskId(1));
        ring.push_back(TaskId(2));
        let mut zombie = None;
        assert_eq!(
            pick_next(&mut ring, &mut zombie, TaskId(0), false),
            Some(TaskId(1))
        );
        assert_eq!(
            (ring.get(0), ring.get(1)),
            (Some(TaskId(2)), Some(TaskId(0)))
        );
        assert_eq!(
            pick_next(&mut ring, &mut zombie, TaskId(1), true),
            Some(TaskId(2))
        );
        assert_eq!(zombie, Some(TaskId(1)));
        // The exiting task was not requeued: only the idle remains.
        assert_eq!(ring.len(), 1);
        assert_eq!(ring.get(0), Some(TaskId(0)));
    }

    #[test]
    fn exits_between_idle_passes_all_wait_in_the_zombie_ring() {
        // Regression (FS-1a review): `reschedule` no longer reaps, so several
        // tasks can exit on a core before its idle task next runs
        // `idle_reap`. With the old single `zombie` slot the second exit would
        // overwrite the first, leaking its `Box<Task>` and its table slot.
        use super::{pick_next_parking_exits, ReadyQueue, ReadyRing};

        let mut ready: ReadyRing<8> = ReadyRing::new();
        for id in [1, 2, 3] {
            ready.push_back(TaskId(id));
        }
        let mut zombies: ReadyRing<8> = ReadyRing::new();
        let mut pass = |prev: u64, exiting: bool| {
            pick_next_parking_exits(&mut ready, &mut zombies, TaskId(prev), exiting)
        };
        // The idle (0) yields to 1; 1 and 2 exit back to back; 3 yields back
        // to the idle.
        assert_eq!(pass(0, false), Some(TaskId(1)));
        assert_eq!(pass(1, true), Some(TaskId(2)));
        assert_eq!(pass(2, true), Some(TaskId(3)));
        assert_eq!(pass(3, false), Some(TaskId(0)));
        // Both exits wait, oldest first; neither is runnable.
        assert_eq!(
            (zombies.len(), zombies.get(0), zombies.get(1)),
            (2, Some(TaskId(1)), Some(TaskId(2)))
        );
        assert_eq!((ready.len(), ready.get(0)), (1, Some(TaskId(3))));
        // A pass with nothing else runnable parks nothing, even if exiting.
        let mut empty: ReadyRing<8> = ReadyRing::new();
        assert_eq!(
            pick_next_parking_exits(&mut empty, &mut zombies, TaskId(9), true),
            None
        );
        assert_eq!(zombies.len(), 2);
        // The idle's drain takes them in order and then stops.
        assert_eq!(zombies.pop_front(), Some(TaskId(1)));
        assert_eq!(zombies.pop_front(), Some(TaskId(2)));
        assert_eq!(zombies.pop_front(), None);
    }

    #[test]
    fn task_table_insert_get_remove_and_full() {
        use super::{Task, TaskState, TaskTable, MAX_TASKS, TIME_SLICE_TICKS};
        use alloc::boxed::Box;

        fn mk(id: u64, cpu: u32) -> Box<Task> {
            let mut xsave = Box::new(hal::context::XsaveArea::new_init());
            let ctx = hal::context::Context::adopt_running(&mut xsave);
            Box::new(Task {
                id: TaskId(id),
                name: "t",
                cpu,
                state: TaskState::Ready,
                entry: super::idle_entry_unused,
                ctx,
                stack: None,
                xsave,
                slice: TIME_SLICE_TICKS,
                permit: false,
                woken: super::Woken::Unparked,
                idle: false,
            })
        }

        let mut table = TaskTable::new();
        assert!(table.get(TaskId(7)).is_none());
        table.insert(mk(7, 2)).ok().expect("slot free");
        table.insert(mk(9, 0)).ok().expect("slot free");
        assert_eq!(table.get(TaskId(7)).map(|t| t.cpu), Some(2));
        assert_eq!(table.get_mut(TaskId(9)).map(|t| t.cpu), Some(0));
        assert_eq!(table.iter().count(), 2);
        let removed = table.remove(TaskId(7)).expect("present");
        assert_eq!(removed.id, TaskId(7));
        assert!(table.get(TaskId(7)).is_none());
        assert!(table.remove(TaskId(7)).is_none());
        // Fill to capacity: the next insert hands the task back untouched.
        for i in 0..(MAX_TASKS as u64 - 1) {
            table
                .insert(mk(100 + i, 1))
                .ok()
                .expect("room until MAX_TASKS");
        }
        assert_eq!(table.iter().count(), MAX_TASKS);
        let rejected = table.insert(mk(999, 1)).err().expect("full");
        assert_eq!(rejected.id, TaskId(999));
    }

    // ── Defect fix (issue #21, defect 3): `validate_cooperative_sequence`
    // — property-based cooperative-proof verdict, not a fixed-phase exact
    // string. See the function's own docs for the full KVM-observed
    // scenario this replaces. ─────────────────────────────────────────────

    #[test]
    fn cooperative_sequence_passes_on_the_a_first_phase() {
        use super::validate_cooperative_sequence;

        // The "queue-policy-only" phase: task A happened to be first
        // switched into and print before any preemption could intervene.
        let seq: [(u8, u8); 6] = [
            (b'A', 0),
            (b'B', 0),
            (b'A', 1),
            (b'B', 1),
            (b'A', 2),
            (b'B', 2),
        ];
        let verdict = validate_cooperative_sequence(&seq);
        assert!(verdict.entries_ok);
        assert!(verdict.interleave_ok);
        assert!(verdict.order_ok);
        assert_eq!(verdict.count_a, 3);
        assert_eq!(verdict.count_b, 3);
        assert!(verdict.ok());
    }

    #[test]
    fn cooperative_sequence_passes_on_the_kvm_observed_b_first_phase() {
        use super::validate_cooperative_sequence;

        // Issue #21 defect 3: the exact interleave observed on KVM CI — a
        // burst of caught-up PIT ticks preempted task A between its first
        // switch-in and its first `preempt_disable`, so task B's own first
        // print won the race. Strict alternation and each task's own
        // per-task order are both still intact, so this must still pass —
        // this is the whole point of the fix (the old verbatim-string
        // marker asserted only the A-first phase and would have wrongly
        // failed this legitimate run).
        let seq: [(u8, u8); 6] = [
            (b'B', 0),
            (b'A', 0),
            (b'B', 1),
            (b'A', 1),
            (b'B', 2),
            (b'A', 2),
        ];
        let verdict = validate_cooperative_sequence(&seq);
        assert!(verdict.entries_ok);
        assert!(verdict.interleave_ok);
        assert!(verdict.order_ok);
        assert_eq!(verdict.count_a, 3);
        assert_eq!(verdict.count_b, 3);
        assert!(verdict.ok());
    }

    #[test]
    fn cooperative_sequence_fails_on_a_double_run() {
        use super::validate_cooperative_sequence;

        // Defect scenario: the proof somehow ran twice (e.g. `prove_cooperative`
        // called twice without a `reset_seq_log`, or a task's loop looping
        // twice) — 12 entries instead of 6.
        let seq: [(u8, u8); 12] = [
            (b'A', 0),
            (b'B', 0),
            (b'A', 1),
            (b'B', 1),
            (b'A', 2),
            (b'B', 2),
            (b'A', 0),
            (b'B', 0),
            (b'A', 1),
            (b'B', 1),
            (b'A', 2),
            (b'B', 2),
        ];
        let verdict = validate_cooperative_sequence(&seq);
        assert!(
            !verdict.entries_ok,
            "12 entries must not satisfy the exact-6 check"
        );
        // The second run's `(A, 0)` arrives right after the first run's
        // `(A, 2)`, where task A's own expected next iteration is `3` — a
        // mismatch, so per-task order must also be flagged broken.
        assert!(!verdict.order_ok);
        assert!(!verdict.ok());
    }

    #[test]
    fn cooperative_sequence_fails_on_out_of_order_iteration() {
        use super::validate_cooperative_sequence;

        // Defect scenario: task A's own iterations arrive out of order
        // (0, 2, 1 instead of 0, 1, 2) — interleave (no task twice in a row)
        // is still fine, but per-task order is broken.
        let seq: [(u8, u8); 6] = [
            (b'A', 0),
            (b'B', 0),
            (b'A', 2),
            (b'B', 1),
            (b'A', 1),
            (b'B', 2),
        ];
        let verdict = validate_cooperative_sequence(&seq);
        assert!(verdict.entries_ok);
        assert!(verdict.interleave_ok, "no task appears twice in a row here");
        assert!(!verdict.order_ok);
        assert!(!verdict.ok());
    }

    #[test]
    fn cooperative_sequence_fails_on_a_missing_entry() {
        use super::validate_cooperative_sequence;

        // Defect scenario: task B's final entry never got recorded (e.g. a
        // lost print, or `record_seq_entry` never reached).
        let seq: [(u8, u8); 5] = [(b'A', 0), (b'B', 0), (b'A', 1), (b'B', 1), (b'A', 2)];
        let verdict = validate_cooperative_sequence(&seq);
        assert!(
            !verdict.entries_ok,
            "5 entries must not satisfy the exact-6 check"
        );
        assert_eq!(verdict.count_a, 3);
        assert_eq!(verdict.count_b, 2, "B is missing its final iteration");
        assert!(!verdict.ok());
    }

    #[test]
    fn cooperative_sequence_fails_when_a_task_runs_twice_in_a_row() {
        use super::validate_cooperative_sequence;

        // Defect scenario: broken alternation (e.g. a `pick_next` regression)
        // — A's own iterations are still perfectly in order, so this
        // specifically isolates `interleave_ok` from `order_ok`.
        let seq: [(u8, u8); 6] = [
            (b'A', 0),
            (b'A', 1),
            (b'B', 0),
            (b'B', 1),
            (b'A', 2),
            (b'B', 2),
        ];
        let verdict = validate_cooperative_sequence(&seq);
        assert!(verdict.entries_ok);
        assert!(!verdict.interleave_ok, "A ran twice in a row");
        assert!(
            verdict.order_ok,
            "each task's own iterations are still 0,1,2 in order"
        );
        assert!(!verdict.ok());
    }

    #[test]
    fn cooperative_sequence_fails_on_an_unrecognised_task_letter() {
        use super::validate_cooperative_sequence;

        // Defensive: a corrupted/garbage entry (neither `A` nor `B`) must
        // never be silently ignored into an accidental pass.
        let seq: [(u8, u8); 6] = [
            (b'A', 0),
            (b'B', 0),
            (b'A', 1),
            (b'B', 1),
            (b'C', 0),
            (b'B', 2),
        ];
        let verdict = validate_cooperative_sequence(&seq);
        assert!(
            !verdict.order_ok,
            "an unrecognised task letter must fail per-task-order"
        );
        assert!(!verdict.ok());
    }

    #[test]
    fn cooperative_sequence_empty_is_not_ok_but_does_not_panic() {
        use super::validate_cooperative_sequence;

        let verdict = validate_cooperative_sequence(&[]);
        assert!(!verdict.entries_ok);
        assert!(verdict.interleave_ok, "vacuously true over zero pairs");
        assert!(verdict.order_ok, "vacuously true: no entry violates order");
        assert_eq!(verdict.count_a, 0);
        assert_eq!(verdict.count_b, 0);
        assert!(!verdict.ok());
    }

    #[test]
    fn record_and_reset_seq_log_round_trip() {
        use super::{
            record_seq_entry, reset_seq_log, seq_log_snapshot, validate_cooperative_sequence,
        };

        // Exercise the actual recording plumbing end-to-end (not just the
        // pure validator), mirroring how `print_marker_atomic`/
        // `prove_cooperative` drive it in production.
        reset_seq_log();
        let (_, len0) = seq_log_snapshot();
        assert_eq!(len0, 0, "reset_seq_log must clear any prior entries");

        record_seq_entry(b'B', 0);
        record_seq_entry(b'A', 0);
        record_seq_entry(b'B', 1);
        record_seq_entry(b'A', 1);
        record_seq_entry(b'B', 2);
        record_seq_entry(b'A', 2);

        let (buf, len) = seq_log_snapshot();
        assert_eq!(len, 6);
        assert!(validate_cooperative_sequence(&buf[..len]).ok());

        // A later `reset_seq_log` must not leak this run's entries into the
        // next one.
        reset_seq_log();
        let (_, len_after_reset) = seq_log_snapshot();
        assert_eq!(len_after_reset, 0);
    }
}

/// Kani proofs (PR-B, per-core since PR-2) — bounded, in-tree harnesses over
/// the same pure, HAL-free logic the host tests above exercise (`pick_next`'s
/// Invariant #4 over the production `ReadyRing`, `PreemptState`'s
/// critical-section bookkeeping). Compiled
/// only under `cargo kani` (`#[cfg(kani)]`), excluded from the stable build
/// and `cargo test` — mirrors `kernel::ml`'s existing Kani proofs (see
/// `ml.rs`). Run with `cargo kani -p kernel`.
#[cfg(kani)]
mod proofs {
    use super::{pick_next, tick_action, PreemptState, ReadyQueue, ReadyRing, TaskId, TickAction};
    use core::sync::atomic::Ordering;

    /// Kani proof — Invariant #4 over a bounded, symbolic sequence of
    /// scheduler passes: `ready` never contains the new `current`, and the
    /// live-id set is never lost or duplicated. Each of the `STEPS` passes is
    /// a nondeterministic mix of "voluntary yield" and "exit" — [`pick_next`]
    /// is the exact same pure function both [`super::yield_now`]'s cooperative
    /// path and [`super::on_tick`]'s timer-preemption path funnel through (both
    /// always call it with `exiting = false`), so this bound covers
    /// preemptive interleavings too, not just cooperative ones — matching the
    /// design doc's "N spawn/yield/exit/preempt interleavings" requirement.
    /// Mirrors the host test `no_lost_or_duplicated_ids_across_many_steps`,
    /// but Kani explores every possible `exiting` choice at every step,
    /// rather than one fixed concrete sequence.
    /// DEPTH AND WIDTH. This was pinned at `STEPS = 2` over a 4-id universe
    /// while the harness drove [`pick_next`] through a `VecDeque`: depth 2
    /// verified in ~4 s, depth 3 exhausted 15 GiB in CBMC's propositional
    /// reduction with no verdict (measured 2026-07-25). The cost was the
    /// *container*, not the policy — `RawVec`, allocation reasoning and
    /// wrap-around index arithmetic dominated the formula. Swapping in an
    /// allocation-free array queue, via the [`ReadyQueue`] trait [`pick_next`]
    /// is generic over, removed that entirely — and since PR-2 that queue,
    /// [`ReadyRing`], **is** the production container (here at capacity 6, in
    /// production at `MAX_TASKS`), so the harness now drives the real policy
    /// over the real container.
    ///
    /// This did NOT weaken the proof. The function under verification is still
    /// the real, unmodified [`pick_next`]; the container is the production
    /// type at a small capacity, and its contract is the whole of what
    /// [`ReadyQueue`] promises.
    ///
    /// The bound is chosen to SATURATE the reachable state space, not merely
    /// to be as large as CBMC tolerates. With 6 live ids (1 `current` + 5
    /// `ready`):
    ///
    /// - round-robin rotation has period 6 — after 6 non-exiting passes every
    ///   task has been `current` once and the configuration repeats, so 8
    ///   passes covers a full rotation with margin;
    /// - at most 5 tasks can exit before the queue drains and [`pick_next`]
    ///   returns `None` (the `break` below), so 8 passes covers every
    ///   exit-to-empty pattern too.
    ///
    /// Kani explores every `exiting` choice at every step, so this is all
    /// 2⁸ interleavings over that universe. Measured on the same 15 GiB
    /// machine: 4.8 s here; `STEPS = 16` also passes, in 19.5 s, but only
    /// re-walks states this bound already reaches — the extra cost buys
    /// repeats, not coverage.
    #[kani::proof]
    #[kani::unwind(9)]
    fn invariant4_no_lost_or_duplicated_ids_bounded() {
        const STEPS: usize = 8;
        // A small, fixed universe: id 0 starts `current`; 1..=3 start `ready`.
        let mut ready: ReadyRing<6> = ReadyRing::new();
        ready.push_back(TaskId::from_usize(1));
        ready.push_back(TaskId::from_usize(2));
        ready.push_back(TaskId::from_usize(3));
        ready.push_back(TaskId::from_usize(4));
        ready.push_back(TaskId::from_usize(5));
        let mut current = TaskId::from_usize(0);
        let mut zombie: Option<TaskId> = None;
        // Whether each universe id has not yet been reaped. This harness reaps
        // eagerly — the previous pass's zombie, before every pass, never the
        // departing pass itself. Production defers reaping to the idle task;
        // that schedule is proven by
        // `zombies_wait_for_the_idle_and_are_never_lost_bounded`.
        let mut alive: [bool; 6] = [true; 6];

        for _ in 0..STEPS {
            // Reap any zombie from a PREVIOUS step first (never the current
            // one).
            if let Some(z) = zombie.take() {
                alive[z.as_usize()] = false;
            }

            let exiting: bool = kani::any();
            match pick_next(&mut ready, &mut zombie, current, exiting) {
                Some(next) => {
                    // Invariant #4: `ready` never contains the new `current`.
                    // Constant-range indexed scan — NOT `contains` or any
                    // iterator: each of those leaves CBMC a loop guard it
                    // cannot refute, so the unwinding assertion fails at every
                    // bound tried (6/10/25, measured 2026-07-25 against the
                    // old `VecDeque` harness). `0..4` is a compile-time
                    // constant, so CBMC unrolls exactly 4 copies and `get`
                    // no-ops the out-of-range slots. The 4-id universe caps
                    // `ready.len()` at 3 (asserted), so the scan is exhaustive
                    // by construction.
                    let len = ready.len();
                    assert!(len <= 5);
                    let mut in_ready = false;
                    for i in 0..6usize {
                        if let Some(queued) = ready.get(i) {
                            in_ready |= queued == next;
                        }
                    }
                    assert!(!in_ready);
                    // The newly-selected task must still be alive, and must
                    // differ from an exiting `current` (an exited task is
                    // never re-selected as its own successor).
                    assert!(alive[next.as_usize()]);
                    if exiting {
                        assert_ne!(next, current);
                    }
                    current = next;
                }
                None => {
                    // Nothing else runnable: `ready` is left empty, exactly as
                    // `pick_next` documents.
                    assert!(ready.len() == 0);
                    break;
                }
            }
        }
    }

    /// Kani proof — the reaping schedule production uses (FS-1a review):
    /// [`super::pick_next_parking_exits`] parks every exit in the core's zombie ring,
    /// and only the idle task (id 0, which never exits) frees zombies, oldest
    /// first, any number at a time ([`super::idle_reap`] may be preempted
    /// between two frees, or skip a pass with `IF` clear). Over every
    /// interleaving of yields, exits and partial drains in `STEPS` passes:
    ///
    /// - every id is in exactly one of `current`/`ready`/`zombies`/freed — so
    ///   several exits between two idle passes are never lost (the old single
    ///   zombie slot would have overwritten one), and none is duplicated;
    /// - a freed id is never selected to run again;
    /// - the drain never frees the task that is running it;
    /// - when nothing is runnable, the idle is the one left running.
    ///
    /// Rings of capacity 8 (a power of two keeps CBMC's index arithmetic
    /// cheap) over 6 ids; the same `STEPS = 8` as the harness above.
    #[kani::proof]
    #[kani::unwind(9)]
    fn zombies_wait_for_the_idle_and_are_never_lost_bounded() {
        const STEPS: usize = 8;
        const IDS: usize = 6;
        let mut ready: ReadyRing<8> = ReadyRing::new();
        for i in 1..IDS {
            ready.push_back(TaskId::from_usize(i));
        }
        let mut zombies: ReadyRing<8> = ReadyRing::new();
        let mut current = TaskId::IDLE;
        let mut freed = [false; IDS];

        for _ in 0..STEPS {
            if current == TaskId::IDLE {
                // `idle_reap`: free the first `k` zombies, `k` unconstrained.
                let k: usize = kani::any();
                for i in 0..IDS {
                    if i < k {
                        if let Some(z) = zombies.pop_front() {
                            assert!(z != current);
                            freed[z.as_usize()] = true;
                        }
                    }
                }
            }
            let exiting = current != TaskId::IDLE && kani::any::<bool>();
            match super::pick_next_parking_exits(&mut ready, &mut zombies, current, exiting) {
                Some(next) => {
                    assert!(!freed[next.as_usize()]);
                    current = next;
                }
                None => assert!(current == TaskId::IDLE && ready.len() == 0),
            }
            // Count where each id is: exactly one place, every pass.
            let mut places = [0u8; IDS];
            places[current.as_usize()] += 1;
            for i in 0..8 {
                if let Some(q) = ready.get(i) {
                    places[q.as_usize()] += 1;
                }
                if let Some(z) = zombies.get(i) {
                    places[z.as_usize()] += 1;
                }
            }
            for id in 0..IDS {
                assert!(places[id] + u8::from(freed[id]) == 1);
            }
        }
    }

    /// Kani proof — a bounded nesting of [`preempt_disable`]/[`preempt_enable`]
    /// pairs (the only pattern every real caller in this crate uses) never
    /// underflows [`PreemptState::count`]: after `k` nested `preempt_disable` calls
    /// (any `k` up to the bound) the counter reads exactly `k`, and unwinding
    /// them one `preempt_enable` at a time never dips below `0` — an
    /// `AtomicU32::fetch_sub` underflow silently *wraps* to `u32::MAX` rather
    /// than panicking, exactly the silent-corruption failure mode this proof
    /// guards against. `NEED_RESCHED` is never set here, so
    /// `preempt_enable`'s deferred-reschedule branch (which would call the
    /// Kani-opaque `hal::context::switch`) is never taken.
    /// Kani proof — [`tick_action`] is total (never panics) over every
    /// `(suppressed, preempt_count)` pair, and suppression dominates: whenever
    /// the cooperative proof is running, NO slice expiry can produce a switch
    /// or a deferred switch, at any preempt count. That dominance is the
    /// property the KVM interleave fix rests on — a fall-through to
    /// [`TickAction::Defer`] would merely postpone the same preemption to the
    /// next `preempt_enable` and reintroduce the flake. Cheap: two symbolic
    /// inputs, no loops, no multiplication.
    #[kani::proof]
    fn tick_action_suppression_dominates() {
        let suppressed: bool = kani::any();
        let preempt_count: u32 = kani::any();
        let action = tick_action(suppressed, preempt_count);
        if suppressed {
            assert!(action == TickAction::Suppress);
        } else {
            assert!(action != TickAction::Suppress);
            // Outside the proof the two normal outcomes are decided solely by
            // whether we are inside a `preempt_disable` section.
            if preempt_count == 0 {
                assert!(action == TickAction::Switch);
            } else {
                assert!(action == TickAction::Defer);
            }
        }
    }

    #[kani::proof]
    #[kani::unwind(9)]
    fn preempt_count_nesting_never_underflows() {
        // One core's state, driven exactly as `preempt_disable`/
        // `preempt_enable` drive `PREEMPT[local_cpu()]`. With no deferred
        // reschedule pending, no enable ever reports a drain.
        let st = PreemptState::new();
        let depth: u32 = kani::any();
        kani::assume(depth <= 8);

        for i in 0..depth {
            st.disable();
            assert_eq!(st.count.load(Ordering::Relaxed), i + 1);
        }
        for i in (0..depth).rev() {
            assert!(!st.enable_and_take_pending());
            assert_eq!(st.count.load(Ordering::Relaxed), i);
        }
        assert_eq!(st.count.load(Ordering::Relaxed), 0);
    }

    /// `enable_and_take_pending` reports a drain exactly once — on the enable
    /// that brings the count to `0` while a reschedule is pending — and
    /// consumes the flag, for any nesting depth and any moment the flag is set.
    #[kani::proof]
    #[kani::unwind(9)]
    fn preempt_pending_is_drained_exactly_once_at_zero() {
        let st = PreemptState::new();
        let depth: u32 = kani::any();
        kani::assume((1..=8).contains(&depth));
        let set_at: u32 = kani::any();
        kani::assume(set_at < depth);

        for _ in 0..depth {
            st.disable();
        }
        let mut drains = 0u32;
        for i in (0..depth).rev() {
            if i == set_at {
                st.need_resched.store(true, Ordering::Relaxed);
            }
            if st.enable_and_take_pending() {
                drains += 1;
                // Only the final enable (count reaching 0) may drain.
                assert_eq!(i, 0);
            }
        }
        assert_eq!(drains, 1);
        assert!(!st.need_resched.load(Ordering::Relaxed));
        assert_eq!(st.count.load(Ordering::Relaxed), 0);
    }
}
