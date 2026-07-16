//! Kernel-thread context switch — the scheduler's trusted core.
//!
//! This is the entire `unsafe` surface of the cooperative kernel-thread
//! scheduler (`kernel::sched`, PR-A of
//! `docs/specs/2026-07-15-scheduler-design.md`): one `global_asm!` register
//! switch ([`sentinel_gpr_switch`]), a first-run trampoline
//! ([`sentinel_task_entry_trampoline`]), a fabricated-frame builder
//! ([`Context::for_new_task`]), and the eager per-task vector save/restore
//! bracket around the switch ([`switch`]). Everything else the scheduler needs
//! — the run queue, task lifetime, `spawn`/`yield_now`/`exit` — is safe Rust in
//! `kernel::sched` (`#![forbid(unsafe_code)]`).
//!
//! # Sealed capability
//!
//! [`Context`]'s fields are private: the only ways to build one are
//! [`Context::adopt_running`] (wrap the *currently executing* control flow,
//! e.g. `kmain`) and [`Context::for_new_task`] (fabricate a fresh task's
//! initial frame). [`TaskHandle`] is a `Copy` token minted from a live `&mut
//! Context` ([`TaskHandle::new`], itself fully safe — forming a `NonNull` from
//! a `&mut` cannot violate memory safety). [`switch`] is therefore a **safe**
//! function: the two `TaskHandle`s it derefs always name either a fabricated
//! frame or a frame a prior `switch` saved, and the kernel's own invariant (a
//! `Box<Task>` — and hence its heap-stable `Context`) is dropped only in the
//! exit/reap path, *after* the task can never again be a switch target — so
//! every handle outlives its uses. Scheduling correctness (interrupts
//! disabled, `prev != next`, non-reentrancy) is the caller's job, not a
//! memory-safety precondition — mirroring [`crate::cpu::enable_interrupts`] as
//! a safe wrapper over a privileged primitive.
//!
//! # Register discipline
//!
//! [`sentinel_gpr_switch`] saves/restores only the SysV **callee-saved**
//! registers (`rbx, rbp, r12–r15`) plus `rsp`; caller-saved registers and
//! `RFLAGS` are the compiler's/caller's problem (`switch` is a normal `extern
//! "C"` call, and it never touches `RFLAGS` — the interrupt flag is a single
//! CPU-wide bit unaffected by a context switch). No vector instructions appear
//! in the asm below (`cargo xtask check-no-vector` enforces this); the eager
//! `xsave`/`xrstor` bracket lives in the thin Rust body of [`switch`], gated on
//! [`crate::idt::vector_state_armed`] so it never runs before
//! [`crate::simd::enable`] has set `CR4.OSXSAVE` — exactly the same gate
//! [`crate::idt::isr_common`] uses for its per-IRQ save.

use core::arch::global_asm;
use core::ptr::{self, NonNull};

/// Size, in bytes, of the per-task `XSAVE` save area — matches
/// [`crate::idt::VECTOR_SAVE_AREA_MAX`] (the same fixed, generously-sized
/// buffer the per-IRQ save uses). `xsave`/`xrstor` need this many bytes at a
/// 64-byte-aligned address (see [`XsaveArea`]).
pub const XSAVE_AREA_SIZE: usize = crate::idt::VECTOR_SAVE_AREA_MAX;

/// Extra bytes [`XsaveArea`] reserves beyond [`XSAVE_AREA_SIZE`] so a
/// 64-byte-aligned window can always be carved out of its backing storage at
/// runtime, however that storage ends up aligned.
const XSAVE_PADDING: usize = 64;

/// A fixed-size buffer holding one task's `XSAVE` vector/FPU state, at a
/// 64-byte-aligned window computed at runtime within its own backing storage.
///
/// **Not** `#[repr(align(64))]`: `kernel::sched` (`#![forbid(unsafe_code)]`)
/// boxes this type directly (`Box::new(XsaveArea::new_init())`), and the
/// kernel heap allocator ([`crate::mm::heap`]) only honours alignments up to
/// 16 bytes (its documented ceiling — see `kernel/docs/hal-tcb.md` §5d) — a
/// type requesting 64-byte alignment from it would get back a null pointer, a
/// failed allocation. So `XsaveArea` is plain, default-aligned data
/// ([`XSAVE_AREA_SIZE`] + [`XSAVE_PADDING`] bytes, alignment 1) that computes
/// a 64-byte-aligned [`XSAVE_AREA_SIZE`]-byte window into itself on demand —
/// the same "reserve extra, align at runtime" technique
/// [`crate::idt::isr_common`]'s **on-stack** save area uses (`sub rsp,
/// area_size; and rsp, -64`), just applied to a heap allocation instead of the
/// stack, since a stack pointer can be adjusted but a `Box`'s address cannot.
///
/// Always all-zero except immediately around a live `xsave`/`xrstor` pair:
/// [`new_init`](Self::new_init) zero-fills the *entire* backing buffer
/// (superset of the window, header included) before any `xsave`/`xrstor` ever
/// touches it, so a task's first `xrstor` loads the architectural *init*
/// state (`XSTATE_BV = 0`) rather than inheriting another task's registers;
/// [`zeroize`](Self::zeroize) (also run on [`Drop`]) clears it again once the
/// owning task is reaped, so no vector residue outlives a task.
#[repr(C)]
pub struct XsaveArea([u8; XSAVE_AREA_SIZE + XSAVE_PADDING]);

impl XsaveArea {
    /// Build a fresh, all-zero save area — the architectural *init* image
    /// (`XSTATE_BV = 0`) and a zeroed, standard-format header (`XCOMP_BV = 0`),
    /// so it is safe to `xrstor` from before any `xsave` has ever written it.
    #[must_use]
    pub fn new_init() -> Self {
        Self([0u8; XSAVE_AREA_SIZE + XSAVE_PADDING])
    }

    /// Zero the whole backing buffer (a superset of the live window) so no
    /// vector-register residue survives past this call. Also run by
    /// [`Drop`], so reaping a task's `Box` always scrubs it.
    pub fn zeroize(&mut self) {
        for byte in self.0.iter_mut() {
            *byte = 0;
        }
    }

    /// Byte offset into `self.0` where a 64-byte-aligned [`XSAVE_AREA_SIZE`]-byte
    /// window begins, computed from `self`'s **current** address.
    ///
    /// Deliberately recomputed on every call rather than cached: a freshly
    /// constructed `XsaveArea` is typically moved at least once (e.g. into its
    /// final `Box` — moving a plain byte array is a bitwise copy, which
    /// changes its address), so any offset computed *before* that move would
    /// be stale. Recomputing from `self`'s address at the point of use is
    /// always correct, however many times the value has moved since
    /// construction — only the current address matters. `XSAVE_PADDING` (64)
    /// is a power of two, so `base.wrapping_neg() & (XSAVE_PADDING - 1)` is
    /// `(-base) mod 64` without a signed subtraction, and always lands in
    /// `0..XSAVE_PADDING`.
    fn window_offset(&self) -> usize {
        let base = self.0.as_ptr() as usize;
        base.wrapping_neg() & (XSAVE_PADDING - 1)
    }

    /// Raw pointer to the first byte of the 64-byte-aligned window, for
    /// [`switch`]'s `xsave`/`xrstor` calls. Private: the pointer must never
    /// outlive `self`, and only [`Context`] (via
    /// [`adopt_running`](Context::adopt_running) /
    /// [`for_new_task`](Context::for_new_task)) is allowed to capture it.
    fn as_mut_ptr(&mut self) -> *mut u8 {
        let offset = self.window_offset();
        // SAFETY: `window_offset` returns a value in `0..XSAVE_PADDING` (the
        // `& (XSAVE_PADDING - 1)` mask), and `self.0` holds `XSAVE_AREA_SIZE +
        // XSAVE_PADDING` bytes, so `offset + XSAVE_AREA_SIZE <=
        // XSAVE_PADDING - 1 + XSAVE_AREA_SIZE < self.0.len()` — the resulting
        // pointer addresses `XSAVE_AREA_SIZE` bytes fully inside `self.0`.
        // `base + offset` is a multiple of `XSAVE_PADDING` (64) by
        // construction (`window_offset`), so the pointer is 64-byte aligned —
        // exactly `xsave`/`xrstor`'s alignment/size contract.
        unsafe { self.0.as_mut_ptr().add(offset) }
    }
}

impl Drop for XsaveArea {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// A saved kernel-thread execution context: the outgoing stack pointer plus a
/// pointer to the task's [`XsaveArea`].
///
/// Fields are private. The only ways to build one are
/// [`adopt_running`](Self::adopt_running) and
/// [`for_new_task`](Self::for_new_task); the only way to advance one is
/// [`switch`]. This sealing is what makes [`switch`] a safe function — see the
/// module docs.
#[repr(C)]
pub struct Context {
    /// The outgoing stack pointer. `0` until the first `switch` *away* from
    /// this context fills it in (see [`adopt_running`](Self::adopt_running));
    /// thereafter always a value [`sentinel_gpr_switch`] itself produced, or a
    /// [`for_new_task`](Self::for_new_task)-fabricated frame.
    rsp: u64,
    /// Pointer to this task's [`XsaveArea`] (owned elsewhere — typically a
    /// `Box<XsaveArea>` alongside this `Context` inside `kernel::sched`'s
    /// `Task`), used by [`switch`]'s `xsave`/`xrstor` bracket.
    xsave: *mut u8,
}

// SAFETY: `Context` is a plain value: an integer (`rsp`) and a pointer
// (`xsave`) into a heap allocation that is always owned by the *same* task as
// this `Context` and moves with it as one unit (`kernel::sched::Task` holds
// both its `Context` and its `Box<XsaveArea>` as sibling fields) — so `xsave`
// is never a "shared" pointer in the aliasing sense, just data. Nothing reads
// or writes through it except [`switch`], which the kernel calls only on a
// single core with interrupts disabled and never re-entrantly, so there is
// never a concurrent access to race. `Send` is needed only so a `Box<Task>`
// containing a `Context` can live inside `kernel::sched`'s
// `hal::sync::SpinMutex<SchedState>` (whose `Sync` impl requires `T: Send`,
// mirroring `hal::mm::heap`'s `unsafe impl Send for Heap`, M12) — it is never
// actually sent between OS threads (the kernel is single-core in PR-A/PR-B).
unsafe impl Send for Context {}

impl Context {
    /// Adopt the *currently running* control flow (e.g. `kmain`/the idle task)
    /// as a switchable [`Context`].
    ///
    /// `rsp` starts at `0` and is filled in by the first `switch` that leaves
    /// this context (`sentinel_gpr_switch` stores the live `rsp` there); until
    /// then this `Context` must only ever be used as the `prev` side of a
    /// switch, never as `next` — `sentinel_gpr_switch` overwrites `prev.rsp`
    /// (`mov [rdi], rsp`) before it ever reads it, so a stale `0` there is
    /// harmless, whereas loading a `0` `next.rsp` into the live `rsp` register
    /// (`mov rsp, rsi`) would fault on the very next `pop`. This holds
    /// trivially for the adopted context since nothing switches into it until
    /// after it has first switched away.
    #[must_use]
    pub fn adopt_running(xsave: &mut XsaveArea) -> Self {
        Self {
            rsp: 0,
            xsave: xsave.as_mut_ptr(),
        }
    }

    /// Fabricate a fresh task's initial switch frame at the top of `stack`.
    ///
    /// Writes the exact frame [`sentinel_gpr_switch`]'s pop sequence expects
    /// (stack top → down; `rsp` ends at the lowest offset):
    ///
    /// | offset | value | consumed by |
    /// |--------|-------|-------------|
    /// | +48 | `sentinel_task_entry_trampoline` | final `ret` |
    /// | +40 | rbp = 0 | `pop rbp` |
    /// | +32 | rbx = 0 | `pop rbx` |
    /// | +24 | r12 = `entry` | `pop r12` |
    /// | +16 | r13 = `arg` | `pop r13` |
    /// | +8  | r14 = 0 | `pop r14` |
    /// | +0  | r15 = 0 | `pop r15` ← `rsp` |
    ///
    /// `stack.top()` is always a multiple of [`crate::mm::PAGE_SIZE`] (hence a
    /// multiple of 16), which is exactly the alignment the trampoline's first
    /// `call` needs (SysV requires `rsp ≡ 0 (mod 16)` immediately before a
    /// `call`; the trampoline reaches that `call` with `rsp == stack.top()`,
    /// having pushed nothing since landing there via `ret`, not `call`).
    #[must_use]
    pub fn for_new_task(
        stack: &crate::mm::KernelStack,
        entry: extern "C" fn(usize) -> !,
        arg: usize,
        xsave: &mut XsaveArea,
    ) -> Self {
        /// Number of qwords in the fabricated frame: r15, r14, r13, r12, rbx,
        /// rbp, and the return (trampoline) address.
        const FRAME_QWORDS: u64 = 7;

        let top = stack.top().as_u64();
        let base = top - FRAME_QWORDS * 8;
        let words: [u64; FRAME_QWORDS as usize] = [
            0,                                                           // r15  (+0,  = rsp)
            0,                                                           // r14  (+8)
            arg as u64,                                                  // r13  (+16)
            entry as usize as u64,                                       // r12  (+24)
            0,                                                           // rbx  (+32)
            0,                                                           // rbp  (+40)
            sentinel_task_entry_trampoline as *const () as usize as u64, // ret addr (+48)
        ];

        // SAFETY: `stack` is a freshly allocated `KernelStack` (`crate::mm`,
        // §5g) — `pages` × 4 KiB of mapped, writable memory topped at
        // `stack.top()` — owned exclusively by the caller and not yet running
        // on any core, so nothing else can observe or race this write. `base`
        // is `top - 56`; `top` is a multiple of `PAGE_SIZE` (≥ 4096) far
        // larger than 56, so `base` and every `base + 8*i` for `i < 7` stay
        // within the mapped stack region below `top` and are 8-byte-aligned
        // (`base` itself is a multiple of 8 since `top` and the subtrahend
        // both are). This seeds exactly the frame `sentinel_gpr_switch`'s pop
        // sequence expects, per the table above.
        unsafe {
            let mut p = base as *mut u64;
            for word in words {
                ptr::write(p, word);
                p = p.add(1);
            }
        }

        Self {
            rsp: base,
            xsave: xsave.as_mut_ptr(),
        }
    }
}

/// A sealed, `Copy` capability naming a live [`Context`] as a [`switch`]
/// endpoint.
///
/// Minting one ([`new`](Self::new)) is fully safe — it only forms a
/// [`NonNull`] from a `&mut Context`, which cannot violate memory safety on
/// its own. Only [`switch`] ever dereferences the pointer, and it is the
/// kernel's job (not this type's) to ensure every handle it mints outlives its
/// uses (see the module docs).
#[derive(Clone, Copy)]
pub struct TaskHandle(NonNull<Context>);

impl TaskHandle {
    /// Mint a handle from a live, heap-stable [`Context`].
    #[must_use]
    pub fn new(ctx: &mut Context) -> Self {
        Self(NonNull::from(ctx))
    }
}

extern "C" {
    /// CX1 — the register-switch primitive (see the `global_asm!` block
    /// below). Saves the SysV callee-saved registers on the *outgoing* task's
    /// own stack, stores the resulting `rsp` through `prev_rsp`, switches
    /// `rsp` to `next_rsp`, then pops the same registers back and `ret`s.
    fn sentinel_gpr_switch(prev_rsp: *mut u64, next_rsp: u64);

    /// CX2 — the trampoline a freshly-fabricated frame `ret`s into on a task's
    /// first run (see the `global_asm!` block below). Never called from Rust;
    /// only its address is taken, to seed the fabricated frame (see
    /// [`Context::for_new_task`]).
    fn sentinel_task_entry_trampoline();
}

global_asm!(
    r#"
.section .text

// CX1 — the kernel-thread register switch. Saves the SysV callee-saved
// registers (rbp, rbx, r12-r15) on the OUTGOING task's own stack, stores the
// resulting rsp through the first argument (rdi), switches rsp to the
// incoming value (rsi), then pops the same registers back (mirroring the push
// order) and `ret`s — landing either back in this function's Rust caller (a
// task resuming after an earlier switch) or in the fabricated trampoline frame
// (a task's first run). No vector registers are touched here — the eager
// XSAVE/XRSTOR bracket (req. #1 of the scheduler design doc) lives in the
// Rust `switch` wrapper, around this call, not in this asm.
.global sentinel_gpr_switch
sentinel_gpr_switch:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov [rdi], rsp
    mov rsp, rsi
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

// CX2 — lands a fresh task in its Rust shim. The fabricated frame (see
// `Context::for_new_task`) placed r12 = the shim function pointer and r13 =
// its `usize` argument (the new task's id) in the registers
// `sentinel_gpr_switch` just popped. `call` (not `jmp`) so a return address
// exists for `ud2` to catch a buggy return — the shim is `-> !`, so returning
// here is always a bug.
.global sentinel_task_entry_trampoline
sentinel_task_entry_trampoline:
    mov rdi, r13
    call r12
    ud2
"#
);

/// Save the outgoing task's execution context and load the incoming one.
///
/// **Safe** — see the module docs for why: `prev`/`next` are sealed
/// [`TaskHandle`]s minted from live `&mut Context` references that the kernel
/// guarantees outlive their use here. Scheduling preconditions (interrupts
/// disabled, `PREEMPT_COUNT == 0`, `prev != next`) are the caller's
/// responsibility, not memory-safety obligations.
///
/// Order: eagerly `xsave` the outgoing task's vector state, `xrstor` the
/// incoming task's (an all-zero [`XsaveArea`] restores the architectural init
/// state for a task's first run — never lazily, per the scheduler design
/// doc's requirement #1), *then* swap the general-purpose registers/stack via
/// [`sentinel_gpr_switch`]. The vector bracket is skipped entirely — matching
/// [`crate::idt::isr_common`]'s own gate byte-for-byte — until
/// [`crate::simd::enable`] has armed it, so it can never execute before
/// `CR4.OSXSAVE` is set (which would `#UD`).
pub fn switch(prev: TaskHandle, next: TaskHandle) {
    // SAFETY: `prev`/`next` are `TaskHandle`s minted (via `TaskHandle::new`)
    // from live `&mut Context` references that, by the kernel's documented
    // invariant (a task's `Box<Task>` — and hence its heap-stable `Context` —
    // is dropped only in the exit/reap path, after the task can never again
    // be a switch target), outlive their uses here. The kernel calls `switch`
    // only with interrupts disabled and non-reentrantly on a single core, so
    // nothing else can alias these `Context`s concurrently. Dereferencing both
    // pointers to `&mut Context` is therefore sound and unaliased.
    let (prev_ctx, next_ctx) = unsafe { (&mut *prev.0.as_ptr(), &mut *next.0.as_ptr()) };

    if crate::idt::vector_state_armed() {
        // SAFETY: `vector_state_armed()` is true only after `simd::enable` has
        // set `CR4.OSXSAVE` + `XCR0` and confirmed the `xsave`/`xrstor`
        // round-trip self-test — the exact precondition `cpu::xsave`/
        // `cpu::xrstor` require, so neither can `#UD`. `prev_ctx.xsave` /
        // `next_ctx.xsave` were captured from a live `&mut XsaveArea`
        // (`adopt_running`/`for_new_task`): 64-byte aligned,
        // `XSAVE_AREA_SIZE` bytes, header-zeroed (`new_init`/`zeroize`) —
        // exactly `xsave`/`xrstor`'s contract. `mask = !0` saves/restores
        // every `XCR0`-enabled component, intersected with `XCR0` by the
        // instruction itself.
        unsafe {
            crate::cpu::xsave(prev_ctx.xsave, !0u64);
            crate::cpu::xrstor(next_ctx.xsave, !0u64);
        }
    }

    // SAFETY: `sentinel_gpr_switch` is CX1: it saves the SysV callee-saved
    // registers onto the outgoing task's own stack, stores the resulting
    // `rsp` through `&mut prev_ctx.rsp` (a valid, unaliased, 8-byte-aligned
    // `u64` lvalue — part of the live `Context` we just derefed), switches to
    // `next_ctx.rsp` (a value only ever produced by `for_new_task` — a valid
    // fabricated frame — or a prior `switch` — a valid saved frame), pops the
    // callee-saved registers back there, and `ret`s. Calling an `extern "C"`
    // function is always `unsafe` in Rust (FFI is unverifiable), but the
    // operation itself cannot corrupt memory given the above.
    unsafe {
        sentinel_gpr_switch(&mut prev_ctx.rsp, next_ctx.rsp);
    }
}

// ── Host + Miri unit tests: the parts that don't need real hardware ────────
//
// `sentinel_gpr_switch`/`sentinel_task_entry_trampoline`/the fabricated-frame
// write in `for_new_task`/the `xsave`/`xrstor` bracket in `switch` are all
// opaque to Miri (register/stack swaps and privileged vector instructions —
// same as every other HAL asm; see `kernel/docs/hal-tcb.md` §3) and are
// verified by the QEMU boot-proof interleave instead. What *is* plain,
// host-and-Miri-checkable Rust is `XsaveArea`'s runtime alignment arithmetic
// (CX5-equivalent: the pointer offset computed in `as_mut_ptr`), exercised
// directly below.
#[cfg(test)]
mod tests {
    use super::{XsaveArea, XSAVE_AREA_SIZE};

    #[test]
    fn new_init_is_all_zero() {
        let area = XsaveArea::new_init();
        assert!(area.0.iter().all(|&b| b == 0));
    }

    #[test]
    fn as_mut_ptr_window_is_64_byte_aligned_and_in_bounds() {
        let mut area = XsaveArea::new_init();
        let base = area.0.as_ptr() as usize;
        let len = area.0.len();
        let ptr = area.as_mut_ptr() as usize;

        assert_eq!(
            ptr % 64,
            0,
            "the xsave/xrstor window must be 64-byte aligned"
        );
        assert!(
            ptr >= base,
            "the window must start at or after the backing array"
        );
        assert!(
            ptr + XSAVE_AREA_SIZE <= base + len,
            "the whole XSAVE_AREA_SIZE window must fit inside the backing array"
        );
    }

    #[test]
    fn zeroize_clears_a_dirtied_area() {
        let mut area = XsaveArea::new_init();
        for byte in area.0.iter_mut() {
            *byte = 0xAA;
        }
        area.zeroize();
        assert!(area.0.iter().all(|&b| b == 0));
    }
}
