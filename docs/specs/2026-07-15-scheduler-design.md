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
