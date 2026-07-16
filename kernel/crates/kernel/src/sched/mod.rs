//! Cooperative kernel-thread scheduler (PR-A of
//! `docs/specs/2026-07-15-scheduler-design.md`).
//!
//! A round-robin scheduler for **kernel threads only** (one shared address
//! space, ring 0). The trusted core is [`hal::context`] — one `global_asm!`
//! register switch plus a thin safe wrapper; everything here (the run queue,
//! task lifetime, and the full public API) is safe Rust
//! (`#![forbid(unsafe_code)]`).
//!
//! # PR-A scope
//!
//! This lands the **cooperative** half only: [`init`], [`spawn`],
//! [`yield_now`], [`exit`], and [`current_id`]. [`preempt_disable`] /
//! [`preempt_enable`] and the `PREEMPT_COUNT`/`NEED_RESCHED` bookkeeping are
//! present as **PR-B scaffolding** — correct, but unused: nothing calls
//! `preempt_disable`, nothing ever sets `NEED_RESCHED`, and there is **no**
//! `on_tick`/timer hook yet (`hal::pit::on_tick` is not wired to this module).
//! PR-B adds timer preemption, per-task vector save under real contention, and
//! a security-engineer sign-off gate (see the design doc); this PR touches no
//! live IRQ path.
//!
//! # Locking discipline
//!
//! One lock ([`SCHED`]) guards all run-queue state. It is acquired only with
//! interrupts disabled ([`reschedule`]) and is **never held across
//! [`hal::context::switch`]** — the `(prev, next)` `TaskHandle`s are copied out
//! and the guard is dropped before the switch runs, because the handles are
//! heap-stable tokens, not guard-borrows. See Invariants 1–5 in the design
//! doc.

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

// ── PR-B scaffolding (unused in PR-A — see the module docs) ─────────────────

/// Per-current-task critical-section depth. **PR-B scaffolding**: nothing
/// calls [`preempt_disable`]/[`preempt_enable`] yet in PR-A, so this never
/// moves off `0`.
static PREEMPT_COUNT: AtomicU32 = AtomicU32::new(0);

/// Set when a reschedule was requested while [`PREEMPT_COUNT`] was nonzero, to
/// be drained by the [`preempt_enable`] that brings it back to `0`. **PR-B
/// scaffolding**: nothing ever sets this in PR-A (no timer hook exists), so
/// [`preempt_enable`]'s reschedule branch can never trigger today.
static NEED_RESCHED: AtomicBool = AtomicBool::new(false);

/// Enter a preemption-disabled critical section.
///
/// Increments [`PREEMPT_COUNT`]; pairs with [`preempt_enable`]. **PR-B
/// scaffolding, unused in PR-A** — present now so the timer-preemption path
/// (PR-B) has the counter ready; nothing calls this yet.
pub fn preempt_disable() {
    PREEMPT_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Leave a preemption-disabled critical section.
///
/// Decrements [`PREEMPT_COUNT`]; if it reaches `0` and a reschedule was
/// deferred while disabled ([`NEED_RESCHED`]), drains it by rescheduling
/// immediately. **PR-B scaffolding, unused in PR-A** — see [`preempt_disable`].
pub fn preempt_enable() {
    let prev = PREEMPT_COUNT.fetch_sub(1, Ordering::Relaxed);
    if prev == 1 && NEED_RESCHED.swap(false, Ordering::Relaxed) {
        schedule();
    }
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
/// [`hal::context::switch`].
///
/// # Invariants upheld
///
/// - [`SCHED`] is locked only with interrupts disabled ([`hal::cpu::disable_interrupts`]
///   at entry), and the guard goes out of scope **before** `switch` runs.
/// - A task is reaped (`tasks.remove`) only on the pass *after* the one that
///   made it a zombie — never the pass departing it — so a task never frees
///   its own running stack.
/// - `PREEMPT_COUNT` is untouched here in PR-A (nothing decrements a slice or
///   preempts); this call is always a **voluntary** reschedule.
fn reschedule(exiting: bool) {
    hal::cpu::disable_interrupts();

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

    if let Some((prev_h, next_h)) = switch_pair {
        hal::context::switch(prev_h, next_h);
    }
    hal::cpu::enable_interrupts();
}

/// Voluntarily reschedule (round-robin), keeping `current` runnable. The sole
/// internal entry point [`yield_now`] uses.
fn schedule() {
    reschedule(false);
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
    });

    let mut guard = SCHED.lock();
    guard.current = TaskId::IDLE;
    guard.tasks.insert(TaskId::IDLE, idle);
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
            });

            let mut guard = SCHED.lock();
            guard.tasks.insert(id, task);
            guard.ready.push_back(id);
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
    SCHED.lock().current
}

/// Debug/introspection: every task's id currently known to the scheduler
/// (`Ready`/`Running`, or briefly `Exited` and awaiting reap), in ascending
/// order (`SchedState::tasks` is a `BTreeMap`).
#[must_use]
pub fn task_ids() -> alloc::vec::Vec<TaskId> {
    SCHED.lock().tasks.values().map(|t| t.id).collect()
}

/// Debug/introspection: the name a task was [`spawn`]ed with, if it still
/// exists (queryable while `Ready`/`Running`, or briefly while `Exited` and
/// awaiting reap).
#[must_use]
pub fn task_name(id: TaskId) -> Option<&'static str> {
    SCHED.lock().tasks.get(&id).map(|t| t.name)
}

/// Debug/introspection: the number of 4 KiB pages in a task's kernel stack.
/// `None` for a task with no HAL-tracked stack (only the adopted idle task,
/// see [`init`]) or one that no longer exists.
#[must_use]
pub fn task_stack_pages(id: TaskId) -> Option<usize> {
    SCHED
        .lock()
        .tasks
        .get(&id)
        .and_then(|t| t.stack.as_ref().map(hal::mm::KernelStack::pages))
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
    // window: at this point interrupts are still disabled (inherited from
    // `reschedule`, which always disables them before the `switch` landing
    // here), so this `SCHED` lock is acquired under Invariant #2 (locked only
    // with interrupts disabled).
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

/// Number of tasks currently in the ready queue — [`prove_cooperative`]'s
/// drain condition.
fn ready_len() -> usize {
    SCHED.lock().ready.len()
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
}
