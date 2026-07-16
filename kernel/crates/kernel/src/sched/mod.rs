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
//! right there at the timer-IRQ tail ([`PREEMPT_COUNT`] `== 0`) or defers to
//! the [`preempt_enable`] that next brings [`PREEMPT_COUNT`] back to `0`
//! ([`NEED_RESCHED`]). See [`prove_preemptive`] for the payoff boot proof (a
//! GEMM task's live vector accumulators surviving genuine, uninvited timer
//! preemption bit-exact) and the "Interrupt-flag discipline" section below for
//! how this avoids the PR-A review's force-`sti` carry-item.
//!
//! # Locking discipline
//!
//! One lock ([`SCHED`]) guards all run-queue state. [`hal::sync::SpinMutex`]
//! does **not** itself disable interrupts (it is a plain spinlock — see its
//! own module docs), so `SCHED` is only ever locked with interrupts *already*
//! disabled, and is **never held across [`hal::context::switch`]** — the
//! `(prev, next)` `TaskHandle`s are copied out and the guard is dropped before
//! the switch runs, because the handles are heap-stable tokens, not
//! guard-borrows. See Invariants 1–5 in the design doc.
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
//!   pattern, used by every other `SCHED`-locking accessor
//!   (`spawn`/`current_id`/`task_ids`/`task_name`/`task_stack_pages`/`init`)
//!   so none of them can be reentered by a timer preemption mid-critical-section
//!   (a self-deadlock, since a single-core spinlock holder can never run again
//!   to release it once interrupted).
//! - **Timer preemption** ([`on_tick`]): calls [`reschedule_locked`] *directly*
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
use alloc::collections::{BTreeMap, VecDeque};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

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

// ── Task control block ──────────────────────────────────────────────────────

/// A task's scheduling state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TaskState {
    /// Runnable, waiting in [`SchedState::ready`].
    Ready,
    /// The task currently executing — exactly one, named by
    /// [`SchedState::current`].
    Running,
    /// Departed for good; its id is parked in [`SchedState::zombie`] awaiting
    /// reap on a later scheduling pass (never the pass that switched away
    /// from it — see [`reschedule`]).
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
/// **Invariant:** a `Box<Task>` is dropped only in the reap step of
/// [`reschedule`], *after* the task has been removed from
/// `current`/`ready`/`zombie` bookkeeping in a way that makes it permanently
/// unreachable as a switch target — so every `TaskHandle` minted from it
/// outlives its uses. Dropping it also drops the boxed [`hal::context::XsaveArea`],
/// which zeroizes on `Drop` (no vector-register residue outlives a task).
struct Task {
    /// This task's identifier (duplicates the `SchedState::tasks` map key —
    /// kept on the `Task` itself for self-describing introspection, see
    /// [`task_ids`]).
    id: TaskId,
    /// Name it was [`spawn`]ed with (boot-proof / debug output — see
    /// [`task_name`]).
    name: &'static str,
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
}

/// All scheduler state, guarded by one lock ([`SCHED`]).
struct SchedState {
    /// The currently-running task.
    current: TaskId,
    /// Runnable tasks, in round-robin order. Invariant: never contains
    /// `current`.
    ready: VecDeque<TaskId>,
    /// Every live task's control block, keyed by id — the single stable heap
    /// home for each `Task` (see the struct's invariant note).
    tasks: BTreeMap<TaskId, Box<Task>>,
    /// An exited task awaiting reap, if any. Reaped at the top of the *next*
    /// [`reschedule`] call (never the call that made it a zombie).
    zombie: Option<TaskId>,
}

/// The one lock guarding all scheduler state. Acquired only with interrupts
/// disabled, and never held across [`hal::context::switch`] (see
/// [`reschedule`]).
static SCHED: hal::sync::SpinMutex<SchedState> = hal::sync::SpinMutex::new(SchedState {
    current: TaskId::IDLE,
    ready: VecDeque::new(),
    tasks: BTreeMap::new(),
    zombie: None,
});

// ── Preemption state (PR-B) ─────────────────────────────────────────────────

/// Ticks per preemptive time slice, at [`hal::pit::TICK_HZ`] (100 Hz) — a
/// 100 ms quantum. Long enough that a task's own work dominates timer
/// overhead, short enough that the PR-B boot proof ([`prove_preemptive`])
/// observes several preemptions within a fraction of a second. (The design
/// doc left the exact value an open question, "start at 1 tick?"; 10 is used
/// here as the documented fallback default.)
const TIME_SLICE_TICKS: u32 = 10;

/// Per-current-task critical-section depth. The timer never switches away
/// while this is nonzero ([`on_tick`]); [`preempt_disable`]/[`preempt_enable`]
/// bracket such sections.
static PREEMPT_COUNT: AtomicU32 = AtomicU32::new(0);

/// Set when [`on_tick`] wanted to reschedule but [`PREEMPT_COUNT`] was
/// nonzero, so the switch is deferred to the [`preempt_enable`] call that
/// next brings the count back to `0`.
static NEED_RESCHED: AtomicBool = AtomicBool::new(false);

/// Count of **timer-driven** preemptions actually performed — i.e. every time
/// [`on_tick`] (directly) or a deferred [`preempt_enable`] drain called
/// [`reschedule_locked`] and it *actually switched* (never counts a no-op
/// pass where nothing else was runnable). Read by [`prove_preemptive`] as the
/// "N preemptions occurred" evidence; never touched by voluntary
/// [`yield_now`]/[`exit`].
static PREEMPT_EVENTS: AtomicU64 = AtomicU64::new(0);

/// Enter a preemption-disabled critical section.
///
/// Increments [`PREEMPT_COUNT`]; pairs with [`preempt_enable`]. While nonzero,
/// [`on_tick`] defers a slice-expiry reschedule via [`NEED_RESCHED`] instead
/// of switching immediately.
pub fn preempt_disable() {
    PREEMPT_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Leave a preemption-disabled critical section.
///
/// Decrements [`PREEMPT_COUNT`]; if it reaches `0` and a reschedule was
/// deferred while disabled ([`NEED_RESCHED`]), drains it by rescheduling
/// immediately (via the voluntary/cooperative [`schedule`] wrapper — this
/// runs in normal task context, never from inside the timer ISR, so the usual
/// interrupt-flag save/restore applies).
pub fn preempt_enable() {
    let prev = PREEMPT_COUNT.fetch_sub(1, Ordering::Relaxed);
    if prev == 1 && NEED_RESCHED.swap(false, Ordering::Relaxed) && schedule() {
        PREEMPT_EVENTS.fetch_add(1, Ordering::Relaxed);
    }
}

/// The timer-IRQ hook (PR-B): called once per PIT tick from
/// `kernel::interrupts::handle_timer`, i.e. from **interrupt-gate context**
/// (`IF` already clear on entry — see `hal::idt`'s interrupt-gate type byte).
///
/// Decrements the current task's remaining time slice ([`tick_slice`]); on
/// expiry, either switches away right here at the timer-IRQ tail (if
/// [`PREEMPT_COUNT`] `== 0`) or defers to [`NEED_RESCHED`] for the next
/// [`preempt_enable`] to drain.
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
    let expired = {
        let mut guard = SCHED.lock();
        let current = guard.current;
        match guard.tasks.get_mut(&current) {
            Some(t) => tick_slice(&mut t.slice),
            None => false,
        }
    };
    if !expired {
        return;
    }

    if PREEMPT_COUNT.load(Ordering::Relaxed) == 0 {
        if reschedule_locked(false) {
            PREEMPT_EVENTS.fetch_add(1, Ordering::Relaxed);
        }
    } else {
        NEED_RESCHED.store(true, Ordering::Relaxed);
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
/// (`with_console`) uses internally, applied here to guard [`SCHED`] against
/// a reentrant timer preemption firing mid-critical-section. Necessary
/// because [`hal::sync::SpinMutex`] does **not** itself disable interrupts
/// (see its module docs) — without this, any of these accessors holding
/// `SCHED`'s lock with interrupts enabled would be vulnerable to [`on_tick`]
/// trying to re-acquire the same lock from a nested timer IRQ and spinning
/// forever on the single core that can never release it (a self-deadlock).
///
/// Used by every `SCHED`-locking accessor **except** [`on_tick`]/
/// [`reschedule_locked`]'s bare timer-preemption call, which must never touch
/// `IF` at all — see the module docs' "Interrupt-flag discipline" section.
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
fn pick_next(
    ready: &mut VecDeque<TaskId>,
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

/// The scheduler's core reschedule step: reap any previously-exited zombie,
/// decide the next runnable task via [`pick_next`], update task states, and
/// — with the run-queue lock **dropped** first — perform the actual
/// [`hal::context::switch`]. Returns whether a switch actually happened
/// (`false` if nothing else was runnable, in which case `current`/`ready` are
/// left untouched).
///
/// # Interrupt-flag discipline
///
/// This function **never touches `IF`** — it assumes interrupts are already
/// disabled by the caller and must stay that way for its own duration (both
/// to satisfy [`hal::context::switch`]'s precondition and, per
/// [`with_interrupts_disabled`]'s docs, to prevent a reentrant [`on_tick`]
/// from deadlocking on [`SCHED`]'s lock). It has exactly two callers, each
/// with a different reason `IF` is already off:
///
/// - [`reschedule`] (the voluntary/cooperative wrapper: [`yield_now`],
///   [`exit`], the deferred drain in [`preempt_enable`]) explicitly disables
///   interrupts first and restores the caller's actual prior state after.
/// - [`on_tick`] (the timer-preemption path) calls this **directly**, with no
///   wrapper at all — it is already running in interrupt-gate context, where
///   `IF` was cleared by hardware on entry, and must return leaving it clear
///   so the ISR stub's own `iretq` restores the *interrupted* task's saved
///   `RFLAGS`. See the module docs' "Interrupt-flag discipline" section.
///
/// # Other invariants upheld
///
/// - [`SCHED`] is locked here, and the guard goes out of scope **before**
///   `switch` runs — never held across it.
/// - A task is reaped (`tasks.remove`) only on the pass *after* the one that
///   made it a zombie — never the pass departing it — so a task never frees
///   its own running stack.
fn reschedule_locked(exiting: bool) -> bool {
    let switch_pair = {
        let mut guard = SCHED.lock();
        // One real `&mut SchedState` (through `DerefMut`, taken exactly once)
        // so the borrow checker can see `state.ready`/`state.zombie`/
        // `state.tasks` as disjoint fields below — borrowing them separately
        // via `guard.foo` each time would re-invoke `DerefMut` per access,
        // which the borrow checker cannot prove disjoint.
        let state: &mut SchedState = &mut guard;

        // Reap a task that exited on a PREVIOUS pass — never the one
        // departing THIS call (it is still running on its own stack until
        // `switch` below hands control away).
        if let Some(zid) = state.zombie.take() {
            state.tasks.remove(&zid);
        }

        let prev_id = state.current;
        match pick_next(&mut state.ready, &mut state.zombie, prev_id, exiting) {
            Some(next_id) => {
                if let Some(t) = state.tasks.get_mut(&prev_id) {
                    t.state = if exiting {
                        TaskState::Exited
                    } else {
                        TaskState::Ready
                    };
                }
                if let Some(t) = state.tasks.get_mut(&next_id) {
                    t.state = TaskState::Running;
                }
                state.current = next_id;

                let prev_h = state
                    .tasks
                    .get_mut(&prev_id)
                    .map(|t| hal::context::TaskHandle::new(&mut t.ctx));
                let next_h = state
                    .tasks
                    .get_mut(&next_id)
                    .map(|t| hal::context::TaskHandle::new(&mut t.ctx));
                match (prev_h, next_h) {
                    (Some(p), Some(n)) => Some((p, n)),
                    _ => None,
                }
            }
            None => None,
        }
    }; // `guard` dropped here — never held across `switch`.

    let switched = switch_pair.is_some();
    if let Some((prev_h, next_h)) = switch_pair {
        hal::context::switch(prev_h, next_h);
    }
    switched
}

/// Voluntary/cooperative reschedule wrapper: saves the caller's actual `IF`
/// state, disables interrupts, runs [`reschedule_locked`], and restores
/// exactly the saved state afterward (via [`with_interrupts_disabled`]) —
/// **not** an unconditional `sti`, unlike PR-A's original implementation (the
/// combined-review carry-item this PR fixes). Used by [`yield_now`],
/// [`exit`], and the deferred drain in [`preempt_enable`] — every caller runs
/// in normal task context, never from inside the timer ISR (see
/// [`reschedule_locked`]'s docs for that path). Returns whether a switch
/// actually happened.
fn reschedule(exiting: bool) -> bool {
    with_interrupts_disabled(|| reschedule_locked(exiting))
}

/// Voluntarily reschedule (round-robin), keeping `current` runnable. Returns
/// whether a switch actually happened. Used by [`yield_now`] and the deferred
/// drain in [`preempt_enable`].
fn schedule() -> bool {
    reschedule(false)
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Bring up the scheduler: adopt the currently-running control flow (`kmain`)
/// as the permanent idle task, [`TaskId::IDLE`].
///
/// Call once, after the kernel heap is up (construction needs `alloc`:
/// `Box`/`BTreeMap`/`VecDeque`) and before the first [`spawn`]/[`yield_now`].
pub fn init() {
    let mut xsave = Box::new(hal::context::XsaveArea::new_init());
    let ctx = hal::context::Context::adopt_running(&mut xsave);
    let idle = Box::new(Task {
        id: TaskId::IDLE,
        name: "idle",
        state: TaskState::Running,
        entry: idle_entry_unused,
        ctx,
        stack: None,
        xsave,
        slice: TIME_SLICE_TICKS,
    });

    with_interrupts_disabled(|| {
        let mut guard = SCHED.lock();
        guard.current = TaskId::IDLE;
        guard.tasks.insert(TaskId::IDLE, idle);
    });
}

/// Placeholder `entry` for the adopted idle task.
///
/// Never actually invoked through [`task_shim`]: the idle task is *adopted*
/// ([`hal::context::Context::adopt_running`]), not spawned via
/// [`hal::context::Context::for_new_task`], so its body is whatever `kmain`
/// already runs (the rest of `kmain` + [`crate::idle_loop`]), not this.
fn idle_entry_unused() {}

/// Spawn a new kernel thread running `entry`, and push it onto the ready
/// queue.
///
/// Allocates a [`hal::mm::DEFAULT_STACK_PAGES`]-page guard-paged kernel stack
/// ([`hal::mm::alloc_kernel_stack`]) and a zero-initialised
/// [`hal::context::XsaveArea`], fabricates the task's initial switch frame
/// (landing in [`task_shim`], which runs `entry` and then [`exit`]s), and
/// registers it as [`TaskState::Ready`].
///
/// Always returns a fresh [`TaskId`] (ids are never reused), even on the
/// allocation-failure path below, so callers never have to guess whether a
/// slot was consumed.
///
/// # Errors
///
/// There is no `Result` in this signature (matching the design doc's public
/// API). A stack-allocation failure is logged over serial and the task is
/// simply never registered (it appears in neither `ready` nor `tasks`) rather
/// than panicking — this can only happen if the frame allocator is exhausted,
/// which does not occur for the fixed, small boot proof this PR ships.
pub fn spawn(name: &'static str, entry: fn()) -> TaskId {
    let id = next_task_id();
    match hal::mm::alloc_kernel_stack(hal::mm::DEFAULT_STACK_PAGES) {
        Ok(stack) => {
            // Boot-proof only (design doc item "guard-paged kernel stacks"): a
            // read-only page-table walk confirming the guard page below this
            // stack is genuinely unmapped. Never faults, never mutates the
            // page tables — the non-destructive stand-in for an actual
            // stack-overflow `#PF` test (see `hal::mm::stack_guard_is_unmapped`).
            hal::serial::write_str("[sched] spawn '");
            hal::serial::write_str(name);
            hal::serial::write_str("': stack ok, guard-page unmapped=");
            hal::serial::write_str(if hal::mm::stack_guard_is_unmapped(&stack) {
                "true"
            } else {
                "false"
            });
            hal::serial::write_str("\n");

            let mut xsave = Box::new(hal::context::XsaveArea::new_init());
            let ctx =
                hal::context::Context::for_new_task(&stack, task_shim, id.as_usize(), &mut xsave);
            let task = Box::new(Task {
                id,
                name,
                state: TaskState::Ready,
                entry,
                ctx,
                stack: Some(stack),
                xsave,
                slice: TIME_SLICE_TICKS,
            });

            with_interrupts_disabled(|| {
                let mut guard = SCHED.lock();
                guard.tasks.insert(id, task);
                guard.ready.push_back(id);
            });
        }
        Err(_e) => {
            hal::serial::write_str("[sched] spawn '");
            hal::serial::write_str(name);
            hal::serial::write_str("' FAILED: could not allocate a kernel stack\n");
        }
    }
    id
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
/// reaped on a *later* scheduling pass (never this one; see [`reschedule`]).
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
    with_interrupts_disabled(|| SCHED.lock().current)
}

/// Debug/introspection: every task's id currently known to the scheduler
/// (`Ready`/`Running`, or briefly `Exited` and awaiting reap), in ascending
/// order (`SchedState::tasks` is a `BTreeMap`).
#[must_use]
pub fn task_ids() -> alloc::vec::Vec<TaskId> {
    with_interrupts_disabled(|| SCHED.lock().tasks.values().map(|t| t.id).collect())
}

/// Debug/introspection: the name a task was [`spawn`]ed with, if it still
/// exists (queryable while `Ready`/`Running`, or briefly while `Exited` and
/// awaiting reap).
#[must_use]
pub fn task_name(id: TaskId) -> Option<&'static str> {
    with_interrupts_disabled(|| SCHED.lock().tasks.get(&id).map(|t| t.name))
}

/// Debug/introspection: the number of 4 KiB pages in a task's kernel stack.
/// `None` for a task with no HAL-tracked stack (only the adopted idle task,
/// see [`init`]) or one that no longer exists.
#[must_use]
pub fn task_stack_pages(id: TaskId) -> Option<usize> {
    with_interrupts_disabled(|| {
        SCHED
            .lock()
            .tasks
            .get(&id)
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
    // `IF` was already clear) — either way this `SCHED` lock is acquired
    // under Invariant #2 (locked only with interrupts disabled).
    let entry = {
        let guard = SCHED.lock();
        guard.tasks.get(&TaskId::from_usize(id)).map(|t| t.entry)
    };

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
    PREEMPT_COUNT.store(0, Ordering::Relaxed);
    hal::cpu::enable_interrupts();
}

// ── PR-A boot proof: cooperative interleave ─────────────────────────────────

/// Number of print+[`yield_now`] iterations each cooperative boot-proof task
/// performs.
///
/// Fixed and small: cooperative round-robin has **no** dependence on
/// wall-clock timing (there is no timer hook in PR-A), so the resulting
/// interleave is fully deterministic and [`prove_cooperative`]'s marker line
/// is reproducible byte-for-byte across runs.
const PROOF_ITERATIONS: u32 = 3;

/// Boot-proof task "A": print `A<i>` then [`yield_now`], `PROOF_ITERATIONS`
/// times, then return (after which [`task_shim`] calls [`exit`]).
fn proof_task_a() {
    for i in 0..PROOF_ITERATIONS {
        hal::serial::write_str("A");
        hal::serial::write_dec(u64::from(i));
        hal::serial::write_str(" ");
        yield_now();
    }
}

/// Boot-proof task "B" — the sibling of [`proof_task_a`].
fn proof_task_b() {
    for i in 0..PROOF_ITERATIONS {
        hal::serial::write_str("B");
        hal::serial::write_dec(u64::from(i));
        hal::serial::write_str(" ");
        yield_now();
    }
}

/// Number of tasks currently in the ready queue — [`prove_cooperative`]'s and
/// [`prove_preemptive`]'s drain condition.
fn ready_len() -> usize {
    with_interrupts_disabled(|| SCHED.lock().ready.len())
}

/// Run the PR-A cooperative-scheduling boot proof (scheduler design doc,
/// "Boot proofs — PR-A").
///
/// Spawns two kernel threads ("A", "B") that each print and [`yield_now`] in
/// a fixed, small loop, then (as the adopted idle task) yields until both have
/// exited and the ready queue drains. Because cooperative round-robin is
/// fully deterministic, the resulting interleave — and hence the printed
/// marker line — is reproducible verbatim across runs; with
/// [`PROOF_ITERATIONS`] = 3 it is:
///
/// ```text
/// [sched] cooperative: A0 B0 A1 B1 A2 B2 ok
/// ```
///
/// Uses only the `fmt`-free [`hal::serial::write_str`]/[`hal::serial::write_dec`]
/// helpers throughout — integer `println!` faults on this target (see
/// `kernel/docs/hal-tcb.md` §5e). Call once, after [`init`].
pub fn prove_cooperative() {
    spawn("A", proof_task_a);
    spawn("B", proof_task_b);

    hal::serial::write_str("[sched] cooperative: ");
    while ready_len() > 0 {
        yield_now();
    }
    hal::serial::write_str("ok\n");
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
    let start = hal::pit::ticks();
    let mut iters: u64 = 0;
    let mut exact = true;
    while hal::pit::ticks().wrapping_sub(start) < PREEMPT_PROOF_RUN_TICKS
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
}

/// Boot-proof task: loop a cheap, side-effect-free counter for
/// [`PREEMPT_PROOF_RUN_TICKS`] wall-clock ticks, **never** calling
/// [`yield_now`] — the sibling of [`proof_task_gemm`], proving a second task
/// also makes progress under the same timer-preemption pressure. Records its
/// total in [`SPIN_ITERS`].
fn proof_task_spinner() {
    let start = hal::pit::ticks();
    let mut iters: u64 = 0;
    while hal::pit::ticks().wrapping_sub(start) < PREEMPT_PROOF_RUN_TICKS
        && iters < PREEMPT_PROOF_ITER_CAP
    {
        core::hint::spin_loop();
        iters += 1;
    }
    SPIN_ITERS.store(iters, Ordering::Relaxed);
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
///   [`PREEMPT_EVENTS`]).
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
    let before = PREEMPT_EVENTS.load(Ordering::Relaxed);
    spawn("gemm", proof_task_gemm);
    spawn("spin", proof_task_spinner);

    while ready_len() > 0 {
        yield_now();
    }

    let after = PREEMPT_EVENTS.load(Ordering::Relaxed);
    let preempted = after.wrapping_sub(before);
    let gemm_iters = GEMM_ITERS.load(Ordering::Relaxed);
    let gemm_exact = GEMM_EXACT.load(Ordering::Relaxed);
    let spin_iters = SPIN_ITERS.load(Ordering::Relaxed);
    let ok = gemm_iters > 0 && spin_iters > 0 && gemm_exact && preempted >= 1;

    hal::serial::write_str("[sched] preemptive: gemm-iters=");
    hal::serial::write_dec(gemm_iters);
    hal::serial::write_str(" gemm-exact=");
    hal::serial::write_str(if gemm_exact { "yes" } else { "no" });
    hal::serial::write_str(" spin-iters=");
    hal::serial::write_dec(spin_iters);
    hal::serial::write_str(" preempted=");
    hal::serial::write_dec(preempted);
    hal::serial::write_str(" ");
    hal::serial::write_str(if ok { "ok\n" } else { "FAIL\n" });
}

// ── Host + Miri unit tests: pure queue logic ────────────────────────────────
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
    fn zombie_is_reaped_before_the_next_pick_in_practice() {
        // Mirrors `reschedule`'s ordering contract: a caller must drain
        // `zombie` (reap) BEFORE calling `pick_next` for the pass that follows
        // an exit, never during the exiting pass itself. This test documents
        // that `pick_next` alone does not reap — it only records; reaping is
        // the caller's separate, explicit step.
        let mut ready = ids(&[1]);
        let mut zombie = None;
        // Task 2 exits: recorded as zombie, not requeued.
        let next = pick_next(&mut ready, &mut zombie, TaskId(2), true);
        assert_eq!(next, Some(TaskId(1)));
        assert_eq!(zombie, Some(TaskId(2)));
        // A subsequent (non-exiting) step must NOT touch `zombie` itself —
        // that is `reschedule`'s job, taken care of before it calls
        // `pick_next` again.
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
        use super::{preempt_disable, preempt_enable, PREEMPT_COUNT};
        use core::sync::atomic::Ordering;

        // No task ever requests a reschedule in this test, so `preempt_enable`
        // must not touch the (unset-up) real scheduler at all.
        preempt_disable();
        preempt_disable();
        assert_eq!(PREEMPT_COUNT.load(Ordering::Relaxed), 2);
        preempt_enable();
        assert_eq!(PREEMPT_COUNT.load(Ordering::Relaxed), 1);
        preempt_enable();
        assert_eq!(PREEMPT_COUNT.load(Ordering::Relaxed), 0);
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
}

/// Kani proofs (PR-B) — bounded, in-tree harnesses over the same pure,
/// HAL-free logic the host tests above exercise (`pick_next`'s Invariant #4,
/// `preempt_disable`/`preempt_enable`'s `PREEMPT_COUNT` bookkeeping). Compiled
/// only under `cargo kani` (`#[cfg(kani)]`), excluded from the stable build
/// and `cargo test` — mirrors `kernel::ml`'s existing Kani proofs (see
/// `ml.rs`). Run with `cargo kani -p kernel`.
#[cfg(kani)]
mod proofs {
    use super::{pick_next, preempt_disable, preempt_enable, TaskId, PREEMPT_COUNT};
    use alloc::collections::VecDeque;
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
    #[kani::proof]
    #[kani::unwind(6)]
    fn invariant4_no_lost_or_duplicated_ids_bounded() {
        const STEPS: usize = 4;
        // A small, fixed universe: id 0 starts `current`; 1..=3 start `ready`.
        let mut ready: VecDeque<TaskId> = VecDeque::new();
        ready.push_back(TaskId::from_usize(1));
        ready.push_back(TaskId::from_usize(2));
        ready.push_back(TaskId::from_usize(3));
        let mut current = TaskId::from_usize(0);
        let mut zombie: Option<TaskId> = None;
        // Whether each of the 4 universe ids has not yet been reaped — mirrors
        // `reschedule_locked`'s "reap the PREVIOUS zombie before picking next"
        // ordering (a zombie is only removed from the live set on the pass
        // *after* the one that recorded it, never the departing pass itself).
        let mut alive: [bool; 4] = [true, true, true, true];

        for _ in 0..STEPS {
            // Reap any zombie from a PREVIOUS step first (never the current
            // one), exactly like `reschedule_locked`.
            if let Some(z) = zombie.take() {
                alive[z.as_usize()] = false;
            }

            let exiting: bool = kani::any();
            match pick_next(&mut ready, &mut zombie, current, exiting) {
                Some(next) => {
                    // Invariant #4: `ready` never contains the new `current`.
                    assert!(!ready.contains(&next));
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
                    assert!(ready.is_empty());
                    break;
                }
            }
        }
    }

    /// Kani proof — a bounded nesting of [`preempt_disable`]/[`preempt_enable`]
    /// pairs (the only pattern every real caller in this crate uses) never
    /// underflows [`PREEMPT_COUNT`]: after `k` nested `preempt_disable` calls
    /// (any `k` up to the bound) the counter reads exactly `k`, and unwinding
    /// them one `preempt_enable` at a time never dips below `0` — an
    /// `AtomicU32::fetch_sub` underflow silently *wraps* to `u32::MAX` rather
    /// than panicking, exactly the silent-corruption failure mode this proof
    /// guards against. `NEED_RESCHED` is never set here, so
    /// `preempt_enable`'s deferred-reschedule branch (which would call the
    /// Kani-opaque `hal::context::switch`) is never taken.
    #[kani::proof]
    #[kani::unwind(9)]
    fn preempt_count_nesting_never_underflows() {
        PREEMPT_COUNT.store(0, Ordering::Relaxed);
        let depth: u32 = kani::any();
        kani::assume(depth <= 8);

        for i in 0..depth {
            preempt_disable();
            assert_eq!(PREEMPT_COUNT.load(Ordering::Relaxed), i + 1);
        }
        for i in (0..depth).rev() {
            preempt_enable();
            assert_eq!(PREEMPT_COUNT.load(Ordering::Relaxed), i);
        }
        assert_eq!(PREEMPT_COUNT.load(Ordering::Relaxed), 0);
    }
}
