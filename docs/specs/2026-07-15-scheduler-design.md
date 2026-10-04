# Preemptive Kernel-Thread Scheduler — Design

Status: **proposed → implementing** · Track A (kernel core) · Author: kernel-architect
Depends on: `hal::cpu::{xsave,xrstor,xsave_area_size}` (C13/C14, shipped for this),
`hal::mm` (frame allocator + `map_page`, shipped), `hal::pit::on_tick` +
`kernel::interrupts::handle_timer` (shipped).
Escalation: PR-A touches no live IRQ path and lands cooperative-only. **PR-B adds
timer preemption + per-task vector save and requires a security-engineer gate**
(same class as the vector-state doc: silent-corruption failure mode).

## Summary

A round-robin scheduler for **kernel threads only** (one shared address space, ring 0).
The trusted core is a single `global_asm!` register switch plus a thin safe HAL
wrapper; all queue and policy logic is safe Rust in `kernel::sched`. Per-task vector
state is saved **eagerly** on every switch via the existing `xsave`/`xrstor`
primitives — never lazy `#NM`/XFD (CVE-2018-3665 class). Landed in two PRs: PR-A =
cooperative switch + spawn/yield/exit; PR-B = timer preemption + vector save.

## Framekernel classification & module layout

TCB delta is **one new asm switch + one stack-mapping helper**. Queue, policy,
fairness, and time-slicing carry zero `unsafe`; the `unsafe` in `switch` is
encapsulated behind a sealed `TaskHandle` so `kernel::sched` calls it safely.

```
hal/src/context.rs          NEW  · TCB(unsafe) · Context, TaskHandle, XsaveArea, switch(), trampoline, frame fabrication
hal/src/mm/mod.rs           EDIT · TCB(unsafe) · alloc_kernel_stack() + KernelStack + StackAllocError (guard page)
hal/src/lib.rs              EDIT · HAL(no new unsafe) · pub use sync::SpinMutex; pub use context;
kernel/src/sched/mod.rs     NEW  · safe forbid(unsafe) · Task/TaskId/TaskState, SchedState, run queue, full API
kernel/src/interrupts.rs    EDIT · safe · handle_timer -> sched::on_tick()  (PR-B)
kernel/src/lib.rs           EDIT · safe · kmain: sched::init(); spawn proofs; drive
```

## Security requirements (mandated, non-negotiable — PR-B gate)

1. **Eager save/restore only.** Every switch unconditionally `xsave`s the outgoing
   task and `xrstor`s the incoming task. **No** lazy `#NM`/XFD-triggered switching.
2. **Init-restore on first run.** A new task's `XsaveArea` is a zero image
   (`XSTATE_BV = 0`, `XCOMP_BV = 0`), so its first `xrstor` resets all vector
   registers to their architectural init state — it never inherits another task's
   registers.
3. **Zeroize on exit.** `XsaveArea::zeroize()` runs when a task's TCB is reaped
   (also on `Drop`), so no vector residue outlives a task.
4. **Zeroed + header-zeroed before first use.** `XsaveArea::new_init()` zero-fills
   the whole buffer (header included) before any `xsave`/`xrstor` touches it.
5. **Sized via `xsave_area_size`, standard format.** Fixed `XSAVE_AREA_SIZE = 4096`
   (== `VECTOR_SAVE_AREA_MAX`), asserted `>= cpuid-0xD` size at boot by
   `simd::enable` (already done); non-compacted (`XCOMP_BV = 0`).

## Task / TCB struct (`kernel::sched`)

```rust
pub struct TaskId(u64);                         // monotonic, never reused

enum TaskState { Ready, Running, Exited }

struct Task {
    id:     TaskId,
    name:   &'static str,                        // for serial proofs
    state:  TaskState,
    entry:  fn(),                                // kernel-thread body
    ctx:    hal::context::Context,               // saved rsp + xsave ptr (HAL-opaque)
    handle: hal::context::TaskHandle,            // sealed, Copy token into `ctx`
    stack:  hal::mm::KernelStack,                // owns guard-paged stack (default 4 pages)
    xsave:  alloc::boxed::Box<hal::context::XsaveArea>, // 64B-aligned, init-zeroed
    slice:  u32,                                 // remaining timer ticks (PR-B)
}
```

`ctx` and `xsave` are heap-stable inside the `Box<Task>`; `handle` is minted once
after boxing. **Invariant:** a `Box<Task>` is dropped only in the exit/reap path,
after the task is removed from `current`/`ready` and can never be a `switch` target —
so every `TaskHandle` outlives its uses.

## `hal::context` public interface (sketch)

```rust
pub const XSAVE_AREA_SIZE: usize = 4096;         // == idt::VECTOR_SAVE_AREA_MAX

#[repr(C, align(64))]
pub struct XsaveArea([u8; XSAVE_AREA_SIZE]);
impl XsaveArea {
    pub fn new_init() -> Self;                    // all-zero => init image (req. #2,#4)
    pub fn zeroize(&mut self);                    // req. #3; also called on Drop
}

#[repr(C)]
pub struct Context { rsp: u64, xsave: *mut u8 }   // fields private
impl Context {
    /// Adopt the *currently running* context (idle/kmain): rsp is filled on the
    /// first switch-OUT; `xsave` points at a live init area.
    pub fn adopt_running(xsave: &mut XsaveArea) -> Self;
    /// Fabricate a fresh task's initial frame on `stack` (see contract below).
    pub fn for_new_task(stack: &hal::mm::KernelStack,
                        entry: extern "C" fn(usize) -> !,
                        arg: usize,
                        xsave: &mut XsaveArea) -> Self;
}

#[derive(Clone, Copy)]
pub struct TaskHandle(/* NonNull<Context> */);
impl TaskHandle { pub fn new(ctx: &mut Context) -> Self; }  // safe: pointer only

/// SAFE, kernel-callable. Internally derefs both handles (unsafe, TCB).
/// Precondition (scheduling correctness, NOT memory safety): interrupts disabled,
/// PREEMPT_COUNT == 0, prev != next.
pub fn switch(prev: TaskHandle, next: TaskHandle);
```

`switch` is **safe** because `Context` is a sealed capability: its `rsp` is only ever
written by `for_new_task` (valid fabricated frame) or a prior `switch` (valid saved
frame), and the kernel upholds the outlives invariant. IF state and non-reentrancy
are *scheduling* preconditions the kernel establishes, not memory-safety obligations
— mirroring `cpu::enable_interrupts` as a safe wrapper.

## `switch(prev, next)` contract

**Register responsibility.** The asm saves/restores only SysV **callee-saved** regs
— `rbx, rbp, r12, r13, r14, r15` — plus `rsp`. Caller-saved regs and `RFLAGS` are the
compiler's problem: `switch` is a normal `extern "C"` call. No GPR snapshot struct;
the callee regs live **on the outgoing task's own stack**, `Context.rsp` points at them.

**Vector state (eager, req. #1).** The thin Rust body of `switch` brackets the GP swap:

```
xsave(prev.xsave, mask=-1)      // save outgoing task's live vectors (req. #1)
xrstor(next.xsave, mask=-1)     // load incoming task's vectors (init image for new tasks -> req. #2)
gpr_switch(&mut prev.rsp, next.rsp)   // global_asm!: push callee, swap rsp, pop callee, ret
```

The `xrstor` runs **before** the GP swap: after it the vector regs belong to `next`
while still on `prev`'s stack — safe because no vector instruction executes in that
window on this soft-float target and a mid-window IRQ's per-IRQ `isr_common`
save/restore is balanced. A task's vectors are loaded by the switch that selects it,
saved by the switch that leaves it.

**`gpr_switch` (`global_asm!` symbol `sentinel_gpr_switch`):**
`push rbp/rbx/r12/r13/r14/r15; mov [rdi], rsp; mov rsp, rsi; pop r15/r14/r13/r12/rbx/rbp; ret`.

**Fabricated initial frame** (`for_new_task`, stack top → down; `Context.rsp` = lowest):

| offset | value | consumed by |
|--------|-------|-------------|
| +48 | `sentinel_task_entry_trampoline` | final `ret` |
| +40 | rbp = 0 | `pop rbp` |
| +32 | rbx = 0 | `pop rbx` |
| +24 | r12 = `entry` (`extern "C" fn(usize)->!`) | `pop r12` |
| +16 | r13 = `arg` (`TaskId`) | `pop r13` |
| +8  | r14 = 0 | `pop r14` |
| +0  | r15 = 0 | `pop r15` ← `rsp` |

Trampoline (`global_asm!`): `mov rdi, r13; call r12; ud2` — the entry is diverging,
`ud2` traps a buggy return. The kernel's `entry` is the shim
`extern "C" fn task_shim(id) -> !` = `{ sched::task_prologue(); (current.entry)(); sched::exit(); }`;
`task_prologue` sets `PREEMPT_COUNT = 0` and enables interrupts (a new task starts
preemptible at the same baseline a resumed task has after its `switch` returns).

**HAL/kernel boundary:** asm + `switch`/`gpr_switch`/`for_new_task`/`XsaveArea` in
`hal::context` (TCB); queue, policy, `task_shim`, and all task lifetime in
`kernel::sched` (`forbid(unsafe_code)`).

## Run-queue & scheduler API (`kernel::sched`, all safe)

```rust
pub fn init();                          // adopt kmain as idle Task(0); Running
pub fn spawn(name: &'static str, entry: fn()) -> TaskId;   // build + push to ready
pub fn yield_now();                     // voluntary reschedule
pub fn exit() -> !;                     // mark Exited, reap-defer, switch away forever
pub fn on_tick();                       // PR-B: called from handle_timer
pub fn preempt_disable();               // PREEMPT_COUNT += 1
pub fn preempt_enable();                // -= 1; if 0 && NEED_RESCHED -> schedule()
pub fn current_id() -> TaskId;
fn schedule();                          // internal: select + hal::context::switch
```

State: one lock guarding everything.

```rust
struct SchedState {
    current: TaskId,
    ready:   VecDeque<TaskId>,           // round-robin
    tasks:   BTreeMap<TaskId, Box<Task>>,// stable heap homes for every TCB
    zombie:  Option<TaskId>,             // exited task awaiting reap
}
static SCHED: hal::sync::SpinMutex<SchedState>;
static PREEMPT_COUNT: AtomicU32;         // per-current-task critical-section depth
static NEED_RESCHED: AtomicBool;
```

`schedule()`: lock; reap any `zombie` (drop Box → free stack + zeroize xsave);
`next = ready.pop_front()` (else unlock + return — nothing else runnable);
`ready.push_back(current)`; set states; **copy `prev`/`next` `TaskHandle`s out**;
**drop the guard**; `hal::context::switch(prev_h, next_h)`. The lock is **not held
across the switch** (tokens are heap-stable, not guard-borrows), so the new-task
trampoline path needs no lock hand-off.

## Preemption safety & invariants (PR-B)

- **Critical sections:** `preempt_disable`/`preempt_enable` bracket a `PREEMPT_COUNT`.
  The timer never switches while `PREEMPT_COUNT > 0`.
- **need_resched consumption — exactly one primary point:** `handle_timer` (safe)
  calls `pit::on_tick()` then `sched::on_tick()`; `on_tick` decrements `current.slice`
  and, on expiry, **if `PREEMPT_COUNT == 0` calls `schedule()` right there (at the
  timer-IRQ tail)**; otherwise it sets `NEED_RESCHED` and returns. The deferred flag
  is drained by the `preempt_enable()` that brings the count back to 0.
- **Invariants:**
  1. `schedule()` is entered only with **interrupts disabled** and **`PREEMPT_COUNT == 0`**.
  2. `SCHED` is acquired only with interrupts disabled, and **never held across `switch`**.
  3. `PREEMPT_COUNT` is 0 across every `switch` (both leaving and entering sides).
  4. `ready` never contains `current`; every live `TaskId` is in `tasks`; no id is duplicated across `current`/`ready`/`zombie`.
     **Extended by park/unpark (2026-10-04):** a `Parked` task is in *none* of
     `current`/`ready`/`zombies` (only `TASKS` knows it), and has an entry in its
     core's `sleepers` set exactly when it parked with a deadline. Every other
     state names exactly one place: `Running` ⇔ `current`, `Ready` ⇔ once in
     `ready`, `Exited` ⇔ once in `zombies`. The idle is never `Parked`. Kani:
     `parked_task_is_on_no_ring_inductive` (see "Park / unpark" below).
  5. A task never frees its own running stack: `exit()` parks its TCB in `zombie`, switches away, and the *next* scheduler pass reaps it.
     **As built since the FS-1a review:** no scheduler pass reaps. A reap inside
     `schedule()` runs with interrupts disabled, and freeing takes the heap lock:
     if a task preempted on the same core held it, the next yield (or draining
     `preempt_enable`) spun forever and froze the core. `exit()` now parks the id
     in a per-core zombie *ring* (`CpuSched::zombies`, capacity `MAX_TASKS`, so
     several exits between idle passes are all kept), and only the idle task frees
     zombies — `sched::idle_reap`, called from kmain's idle loop and `ap_idle_loop`
     — dropping each `Box<Task>` with no lock held and interrupts and preemption
     enabled. Kani: `zombies_wait_for_the_idle_and_are_never_lost_bounded`.
     Consequence: kmain runs the boot proofs with `IF = 0`, where `idle_reap` is a
     no-op, so BSP tasks that exit during boot keep their `TASKS` slot and xsave box
     until kmain reaches its idle loop (4 of 64 today: the cooperative pair, gemm,
     spin). A boot proof that spawns many short-lived BSP tasks must budget for
     that or call `idle_reap` from a preemptible wait.
- **Stack sizing:** default 4 pages (16 KiB). A task preempted in the timer IRQ
  holds one `isr_common` frame + its 4 KiB per-IRQ xsave area on its stack; interrupt
  gates keep IF clear in the handler so timer nesting depth is 1 (bounded).

## Guard-paged kernel stacks (`hal::mm::alloc_kernel_stack`, PR-A)

```rust
pub struct KernelStack { top: VirtAddr, bottom: VirtAddr, pages: usize }
impl KernelStack { pub fn top(&self) -> VirtAddr; }
pub enum StackAllocError { NotInitialised, OutOfFrames, MapFailed }
pub fn alloc_kernel_stack(pages: usize) -> Result<KernelStack, StackAllocError>;
```

Allocates from a dedicated stack VA window (`STACK_WINDOW_BASE = 0xFFFF_F200_…`,
bumped like `MMIO_WINDOW_BASE`): reserves `pages + 1` pages, maps the upper `pages`
frames `PageFlags::kernel_rw()`, and **leaves the lowest page unmapped** — that
never-present page is the M1 guard (overflow ⇒ `#PF` into the existing handler, not a
silent scribble). No `unmap` primitive is needed. "Heap-allocated" = dynamically
frame-allocated at runtime; a `Box<[u8]>` on the shared heap window cannot carry a
true unmapped guard, so stacks come from this window. **Frame/VA reclamation on exit
is deferred** (needs an `mm` unmap path — open question); PR-A proof tasks are long-lived.

## Boot proofs

- **PR-A (cooperative):** `kmain` calls `sched::init()`, `spawn("A", a)`, `spawn("B", b)`
  where `a`/`b` loop N times printing `A0 B0 A1 …` and `yield_now()`, then `exit()`.
  kmain (idle task) yields until `ready` drains. Serial shows **≥2 threads
  interleaving via yield**, then both `done`, then kmain proceeds to `idle_loop`.
- **PR-B (payoff — per-task vector save proven):** with the timer live, `spawn` a
  **GEMM task** running a fixed int8 GEMM in a loop (live YMM/ZMM accumulators) and a
  **spinner task**. The PIT preempts the GEMM task **mid-computation** (need_resched →
  `schedule()`), the spinner runs, and on resume the GEMM result is **bit-exact vs the
  scalar reference** — a mismatch would mean a lost/clobbered accumulator, so bit-
  exactness proves eager per-task `xsave`/`xrstor` works. As implemented, the serial
  line is field-based rather than a single fixed marker — more rigorous than a bare
  `ok`, since `cargo xtask test` parses and asserts each field independently
  (`gemm-exact=yes`, `preempted>=1`, both iteration counts `>0`) rather than trusting
  one pass/fail token:
  `[sched] preemptive: gemm-iters=<N> gemm-exact=yes spin-iters=<N> preempted=<N> ok`.

## TCB delta (rows to add to `kernel/docs/hal-tcb.md`)

New section **§9 `hal::context` — kernel-thread context switch**:

| # | Location | Unsafe op | Why | Soundness | Verification |
|---|----------|-----------|-----|-----------|--------------|
| CX1 | `context.rs` · `sentinel_gpr_switch` (`global_asm!`) | push/pop callee regs, `mov [rdi],rsp` / `mov rsp,rsi`, `ret` | Stable-Rust register switch (no `naked_fn`/`x86-interrupt`) | Saves/restores exactly SysV callee-saved + rsp; caller-saved handled by the `extern "C"` boundary; `next.rsp` always a valid fabricated/saved frame (sealed `Context`); jumped, never data-deref'd | Reasoned + QEMU (PR-A interleave; PR-B bit-exact) |
| CX2 | `context.rs` · `sentinel_task_entry_trampoline` (`global_asm!`) | `mov rdi,r13; call r12; ud2` | Land a first-run task in its shim | r12/r13 set by the fabricated frame (CX3); entry is `-> !`, `ud2` traps a bug | Reasoned + QEMU |
| CX3 | `context.rs` · `for_new_task` | raw writes of the initial frame to `stack.top()` | Seed the fabricated switch frame | Writes only within the caller-owned, mapped `KernelStack`; frame layout matches CX1 pop order | Reasoned + QEMU |
| CX4 | `context.rs` · `switch` | deref `prev`/`next` `TaskHandle` + `cpu::xsave`/`xrstor` (C13/C14) | Save/restore per-task vector state around the GP swap | Handles are sealed tokens from live `&mut Context`; kernel outlives-invariant; single-core + IF-off ⇒ no aliasing; xsave/xrstor contracts per C13/C14 | Reasoned + QEMU + **security-engineer gate** |

Extend **§5** with:

| # | Location | Unsafe op | Why | Soundness | Verification |
|---|----------|-----------|-----|-----------|--------------|
| 5g | `mm/mod.rs` · `alloc_kernel_stack` | frame alloc + `map_page` loop of stack pages | Per-task guard-paged kernel stacks (M1) | Reuses audited `alloc_frame`/`map_page`; maps `pages` RW+NX in the stack window; leaves the page below unmapped as the guard (never present ⇒ overflow `#PF`) | Reasoned + QEMU (guard-page overflow fault test) |

Also update C13/C14 "Why needed" to note the **live** second caller (`context::switch`),
not just the boot self-test.

## What Miri/Kani can cover

- **Host tests + Miri (enforced):** `kernel::sched` queue logic compiled for the host
  with a mock `switch` — round-robin rotation, spawn/exit bookkeeping, `preempt_*`
  count transitions, and Invariant #4 (no lost/duplicated ids; `ready` excludes
  `current`). Pure data-structure logic, fully host-testable.
- **Kani (in-tree harnesses):** bounded proofs that N spawn/yield/exit interleavings
  preserve Invariant #4 and that `PREEMPT_COUNT` never underflows.
- **Opaque (QEMU boot-proof only, like all HAL asm):** `sentinel_gpr_switch`,
  the trampoline, `for_new_task`, and the `xsave`/`xrstor` bracket — Miri has no model
  for the register/stack swap or XSAVE.

## Implementation plan

1. **PR-A · hal-specialist** — `hal::mm::alloc_kernel_stack` + `KernelStack` + guard
   page (§5g); QEMU overflow-fault test.
2. **PR-A · hal-specialist** — `hal::context`: `Context`, `TaskHandle`, `XsaveArea`,
   `for_new_task`, `sentinel_gpr_switch`, trampoline, `switch` (GP path only; vector
   bracket compiled but exercised in PR-B). Re-export `hal::sync::SpinMutex`.
3. **PR-A · kernel-engineer** — `kernel::sched`: `Task`/state, `SchedState`, `init`,
   `spawn`, `yield_now`, `exit`, `schedule` (cooperative), `task_shim`,
   `preempt_disable/enable` scaffolding. Host + Miri queue tests.
4. **PR-A · kernel-engineer** — `kmain` cooperative boot proof (≥2 tasks interleave).
5. **PR-A gate** — verification-engineer: Miri green, host tests, `-D warnings`,
   clippy, boot interleave asserted in CI.
6. **PR-B · kernel-engineer** — wire `handle_timer → sched::on_tick`; time-slice +
   `NEED_RESCHED` + deferred drain in `preempt_enable`.
7. **PR-B · hal-specialist** — enable the vector `xsave`/`xrstor` bracket in `switch`;
   init-restore + zeroize-on-reap.
8. **PR-B gate** — **security-engineer** signs off requirements #1–#5; verification-
   engineer asserts the `gemm-preempted-bitexact` boot proof.

## Open questions

1. **Stack/frame reclamation on exit** needs an `mm` `unmap` + `dealloc_frame`
   teardown path (none today). Acceptable to defer for PR-A/PR-B? Proposed: yes,
   track as a follow-up; proof tasks are long-lived.
2. **Idle behaviour when `ready` is empty:** stay on the adopted idle task (kmain's
   `idle_loop`) — confirmed, or a dedicated `hlt` idle thread?
3. **`slice` length** (ticks per quantum) at 100 Hz — start at 1 tick (10 ms)?

## SMP-forward — **implemented (2026-09-18, per-CPU, no work stealing)**

Landed as PR-2 of `docs/specs/2026-07-16-smp-ap-bringup-design.md`. What the
original note predicted, and what changed in the doing:

- `SCHED`/`ready`/`current`/`zombie` → **per-core** `CPU_SCHED[cpu]`
  (`SpinMutex<CpuSched>`), indexed by the dense cpu index `kernel::smp` assigns;
  `PREEMPT_COUNT`/`NEED_RESCHED`/`PREEMPT_EVENTS` → per-core `PREEMPT[cpu]`.
  The task table became a separate lock, `TASKS`, taken **after** a queue lock.
- The "not held across `switch`" discipline and stable-`TaskHandle` ownership did
  make the split mechanical. What was *not* predicted: **no lock taken from IRQ
  context may be held across an allocation**, or an AP's IPI handler waiting on
  `TASKS` deadlocks against a BSP that holds `TASKS` and waits on the heap lock
  held by the AP's interrupted task. So `tasks: BTreeMap` became a fixed slab
  (`TaskTable`, `MAX_TASKS = 64`) and `ready: VecDeque` a fixed ring
  (`ReadyRing`) — which also retired the `reserve_ready_capacity` machinery.
- Tasks are **pinned**: `spawn_on(cpu, …)` places, nothing migrates; `spawn`
  = local core. A remote placement sends a **reschedule IPI**
  (`hal::apic::send_ipi`, vector `0xF0`); the target's `on_resched_ipi` switches
  at the ISR tail exactly like `on_tick`. So "IPI reschedule" moved from out of
  scope to the mechanism — a core idling in `sti; hlt` has no other way to learn
  it has work (no LAPIC timer yet).
- Each AP adopts its parked control flow as its idle (`init_ap`), mirroring
  `init`'s adoption of `kmain`; the AP idle loop is `idle_reap(); sti; hlt`.
- Boot proof: `prove_pinned` → `[sched] pinned: target=cpuN ran-on=cpuN bsp=cpu0
  distinct=yes ok`, asserted by `cargo xtask test` under TCG and KVM.
- Still out of scope: load balancing / work stealing, timer preemption on APs
  (phase 3: LAPIC timer + IOAPIC), TLB shootdown.

## Park / unpark — **implemented (2026-10-04, SentinelFS spec §15 A25)**

The blocking primitive the scheduler lacked: the `sfs-commit` task used to wait by
yield-polling, runnable on the BSP forever. Designed to be reused by component PR-3's
run-to-completion driver (component spec §18.4); that driver is not built here.

### API (`kernel::sched`, all safe)

```rust
pub fn park();                                // block until unparked
pub fn park_until(deadline: u64) -> Woken;    // ... or until mono_ticks() >= deadline
pub enum Woken { Unparked, Deadline }
pub fn unpark(id: TaskId) -> UnparkOutcome;   // any core; task or IRQ context
pub enum UnparkOutcome { Woke, PermitStored, Refused }
pub fn task_is_parked(id: TaskId) -> bool;    // introspection
```

- **Wake permit** (`std::thread::park` semantics): an unpark of a task that is
  running or ready sets its one, uncounted permit; its next park consumes it and
  returns at once. So a decide-then-park race cannot lose a wakeup: an unpark
  landing between the caller's check and its park is kept.
- **Deadline** — the production guarantee, precisely: `park_until(d)` returns
  `Deadline` at once if `mono_ticks() >= d`; otherwise the deadline **fires on the
  first tick of the task's own core at which `mono_ticks() >= d` — never early** —
  unless an unpark comes first (which cancels it). `mono_ticks` is the max over
  every core's tick count, so it can advance by more than one between two ticks
  of the owning core (the Kani model ties each clock advance to a tick; production
  does not — "first owning-core tick at or past `d`" is the claim, not "at `d`").
  A core
  that runs with `IF = 0` takes no ticks, so it delays its sleepers' deadlines
  until it opens interrupts — a yield does not drain deadlines, only the tick
  does. kmain's `IF = 0` boot sequence is such a span on the BSP: a pacing
  deadline of `sfs-commit` falling inside it fires once kmain opens interrupts
  (the yield-poll this replaced would have committed at kmain's next yield).
  Nothing dirties the volume during boot today, and `request_commit` unparks
  directly, so no boot path depends on it.
- **Refused, no-op**: `unpark` of an exited, reaped or never-issued id, or of a
  core's idle task (it never parks, so a stored permit could never be consumed).
  Ids come
  from one `AtomicU64::fetch_add` starting at 1 (0 is the BSP idle; AP idles take
  fresh ids too) and are never reused within a boot, so a stale id never names a
  later task.
- **Refused parks** return `Woken::Unparked` at once and change nothing: from a
  core's idle task (the fallback that must stay runnable — a non-idle task can
  always park because its core's idle is then on `ready`), with preemption
  disabled (it would hand the core on inside an open critical section), and with
  interrupts disabled (IRQ context or an `IF = 0` section). Each is a caller bug
  that a `while !done { park() }` loop would turn into a silent hot spin, so each
  is a `debug_assert!` — the kernel is built in the dev profile, so the boot faults
  loudly; a release build still returns at once rather than block a core that
  cannot be switched. Callers loop on their own condition, as with any park.
- **IRQ context**: `unpark` may be called from IRQ context. It allocates nothing
  (a ring store and an array swap-remove), takes only the two IRQ-side scheduler
  locks with `IF = 0` in queue → table order, and sends its IPI with `IF = 0`;
  `spawn_on`'s IPI is now sent with `IF = 0` as well, so an IRQ can never land
  between the two xAPIC ICR writes of a send on the same core. It never switches.
  `park`/`park_until` are task context only. No caller is in IRQ context today.
- **Local wake latency**: an unpark of a task on the caller's own core sends no
  IPI. `on_tick` therefore reschedules whenever the core's idle task is current
  and `ready` is non-empty, so a local wake while the idle runs (e.g. kmain
  calling `request_commit`, then halting) is picked up on the next tick. Measured
  at boot (informational `local-wake-ticks=`): **0–1 ticks** with the rule (four boots), **6
  ticks** without it (two boots; the rest of the idle's 10-tick slice). Otherwise the woken
  task runs at the current task's next yield, park or slice expiry.

### Data structures — fixed, per core, allocation-free

- `TaskState::Parked`; per task, `permit: bool`, `woken: Woken` (written by the
  waker, read by the task when its park returns) and `idle: bool`.
- `CpuSched::sleepers: Sleepers<MAX_TASKS>` — `(TaskId, deadline)` arrays plus a
  cached `earliest` (invariant: `earliest <=` every stored deadline; production
  keeps it exact). `on_tick` compares `now < earliest` (O(1)) and otherwise drains
  every expired entry — one pass over ≤ `MAX_TASKS` entries with a `TaskTable`
  lookup (≤ `MAX_TASKS` slots) per expired one: about 64 × 64 slot visits in the
  worst case, bounded and allocation-free, in IRQ context. `unpark` removes its
  target's entry. Can never fill: it names only parked tasks pinned to that core.
- `on_tick` reschedules (through `tick_action`, as on a slice expiry) when the
  slice expired, a deadline woke a task, or the idle is current with `ready`
  non-empty. So deadline and local-unpark wakes **preempt mid-slice**: the
  round-robin switch happens on that tick, and the woken task runs then if it is
  at the head of `ready`, otherwise in its turn. Only slice expiries count as
  `tick_events` (the AP preemption proof's evidence).
- `park_step` decides everything before it mutates anything; the two switch
  handles are then looked up under the same locks (both tasks are in the slab by
  construction — a `debug_assert!` checks it).
- The pure steps `park_step` / `unpark_step` / `expire_step` (and the existing
  `pick_next_parking_exits` for yields and exits) are generic over `ReadyQueue` and
  a `ParkTable` view, so production, the host tests and the Kani model run the same
  code.

### Cross-core wake-up

A task is resumed only by its own core. Remote `unpark` pushes it onto the target
core's `ready` under that core's lock and sends the reschedule IPI (vector `0xF0`);
the target's `on_resched_ipi` switches at the ISR tail. No core touches another's
`current`. A park leaves `current` and switches away inside one `IF = 0` section;
a remote unpark that lands between the lock release and the completed register
save only queues the task on a core that is still mid-switch with `IF = 0` — the
same argument as a yield's requeue before its switch.

### Lock order

No new lock. Park, unpark and the tick's deadline drain take
`CPU_SCHED[cpu]` → `TASKS` — the existing **queue → table** order — with `IF = 0`,
never across a switch or an allocation. `unpark` reads the target's (immutable,
pinned) core under `TASKS` alone and releases it before taking the queue lock; it
re-checks the task under both. Both locks stay on the "reachable from IRQ context,
only taken with `IF = 0`" side of hal-tcb §5e. A parked task is never suspended
inside the allocator (it parked voluntarily), so §5e's "no other task on this core
may be suspended inside the allocator" holds for it; it may again once it runs.

### Invariants (Kani, `sched::park::proofs`, induction)

Each harness is an induction step from **any** state satisfying all three
invariants (rings, sleepers — including the cached `earliest`, which is symbolic
and constrained only by `earliest <=` every entry — states, permits, ghosts and
the clock symbolic, then assumed consistent) through one symbolic operation — park (with no deadline or
`now + 0..=2`), unpark of any id (including a dead one), tick (clock + 0/1, drain,
then a switch on a wake or symbolically), or exit — over 3 tasks (the idle plus two)
and capacity-2 rings/sleepers; the base case is its own harness. So the properties
hold on every trace, not just a bounded one (bounded-trace versions, 3–5 steps from
boot, were measured at 34–170 s and dropped as subsumed).

| Harness | Property | Alone / in the full suite (shared 4-core host, load 3–6) |
|---|---|---|
| `park_invariants_hold_at_boot` | base case; `cover!` that the inductive assumption admits two parked tasks, one with a deadline | 18 s / 16 s |
| `park_transitions_are_reachable` | `cover!`s from the inductive assumption through one step: a park that switches away with a deadline; a tick whose drain wakes a task; an unpark that wakes a task and drops its sleeper entry (all satisfied) | 46 s / 39 s |
| `park_no_lost_wakeup_inductive` | (a) an unparked task is never left parked; a permit survives until a park consumes it; a park with a permit owed returns at once; unpark answers `Woke`/`PermitStored`/`Refused` by state (`Refused` for the idle) | 42 s / 42 s |
| `parked_task_is_on_no_ring_inductive` | (b) Invariant #4 extended, above; only the idle is ever refused a park; `earliest <=` every sleeper | 58 s / 55 s |
| `deadline_fires_once_never_early_inductive` | (c) a deadline fires at most once, never before its tick, is never missed; `Deadline` is answered at once only when passed; `earliest <=` every sleeper | 51 s / 50 s |

The covers live in their own harness rather than in each induction step: the
`Prop` only selects which assertions are checked and CBMC assertions never prune
paths, so reachability is the same, and inside the steps the three cover goals
pushed two of them past 60 s.

Seeded mutants, each run against the harness(es) shown — all fail as they must:

| Mutant | Fails |
|---|---|
| `Sleepers::insert` no longer lowers `earliest` (deadlines would never fire) | (b), (c) |
| `park_step` ignores the permit | (a) |
| `unpark_step` does not requeue the woken task | (b) |
| `drain_expired` fires one tick early (`at <= now + 1`) | (c) |

Review round 1 found the first mutant passing every harness: `any_valid` used to
recompute `earliest` exactly, so no harness checked it. Fixed as above.

### Boot proof (asserted exactly by `cargo xtask test`, both boots)

```text
[sched] park: target=cpu1 deadline-waited=5/5 local-wake-ticks=1 bsp-window ticks=25 halts=N switches=0
[sched] park: cross-core=ok permit-before-park=ok deadline=ok dead-unpark=refused sfs-commit=parked bsp-idles=yes ok
```

A task on the first AP: the BSP unparks it while it runs (`PermitStored`) and its
next `park` returns at once (nothing else could wake it); it parks again and the
BSP, seeing it `Parked`, unparks it (`Woke`, by IPI); its `park_until(now + 5)`
returns `Deadline` at or past the deadline; after it exits and is reaped its id is
`Refused`. Then, with `sfs-commit` parked, kmain halts until the BSP's own tick
count advances 25 (≥ two idle-slice expiries) and the BSP must perform **zero**
switches. With the old yield-poll the same window showed `switches=6
sfs-commit=runnable bsp-idles=no` (measured by reverting the commit task's park).

### As built: `sfs-commit`

The task decides under the `Sfs` lock and parks with it released: commit if a
request is pending or a dirty transaction is older than `COMMIT_INTERVAL`; else
`park_until(last_commit + COMMIT_INTERVAL)` while dirty; else `park()`.
`request_commit` unparks it, and so does `with_sfs` itself — structurally —
whenever a section turned the volume from clean to dirty (it kicks after releasing
the lock and re-enabling preemption), so no FS-1b mutation can forget to.
`sfs::service::kick` is lock-free (the task id lives in a `sched::TaskIdCell`, one
`AtomicU64`), so it is safe inside a `with_sfs` section and from IRQ context. No
periodic backstop wake: it would put a BSP wake every interval into the
`bsp-idles` window and make that proof flaky, and the structural kick makes it
unnecessary. The only waiter today is kmain's boot proof — an
idle task, which may not park — so it still yields; FS-2's blocking callers need a
waiter list the task unparks on completion.
