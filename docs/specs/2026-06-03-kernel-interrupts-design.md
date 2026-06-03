# SentinelOS Kernel — Interrupts & CPU Exceptions Design Spec (#2a)

- **Date:** 2026-06-03 · **Status:** Draft for review
- **Component of:** SentinelOS · **Sub-project:** #2a of #2 (core kernel)
- **Owner agent:** kernel-architect
- **Prereq:** Sub-project #1 (boot bring-up) — complete & reviewed

## 0. Where #2a sits in sub-project #2

Sub-project #2 ("core kernel") is decomposed into five ordered, independently-buildable slices. Each slice is a tracer-bullet: it compiles, boots in QEMU, and is covered by an `xtask` test before the next slice starts.

| Slice | Scope | Depends on | Why this order |
|---|---|---|---|
| **#2a** | **GDT + IDT + CPU exception handlers** | #1 only | **Start here.** An IDT is the precondition for *every* other slice surviving its own bugs: without it, any fault (page fault, GP) is an unhandled exception → second fault → **triple fault → silent CPU reset**. #2a converts those silent resets into a serial fault report. It needs nothing from #2b–#2e. |
| **#2b** | Physical frame allocator (from the Limine memory-map response) | #2a | Paging (#2c) needs a source of physical frames for page tables. The allocator is pure bookkeeping over the Limine memory map — buildable as soon as faults are catchable (#2a), and tested by allocating/freeing frames. |
| **#2c** | Paging / virtual memory management | #2a, #2b | Building/switching page tables *requires* frames from #2b and *will* page-fault during bring-up (mis-mapped address, missing page); #2a must already report those faults. Maps the kernel higher-half, the HHDM, and MMIO. |
| **#2d** | Kernel heap allocator (`#[global_allocator]`) | #2c | A heap needs a backing virtual region that paging (#2c) has mapped, and frames (#2b) behind it. Unlocks `alloc` (`Box`/`Vec`/`BTreeMap`) for everything above. |
| **#2e** | Timer (PIT/APIC) + minimal scheduler | #2a, #2d | The timer IRQ is delivered *through the IDT* (#2a) and the scheduler's task list/run-queue needs heap allocation (#2d). This is the first slice that uses #2a for a *maskable IRQ* (not just an exception) and closes the loop into a running kernel. |

**Ordering rationale (the dependency spine):** `#2a (catch faults) → #2b (get frames) → #2c (map memory) → #2d (allocate on the heap) → #2e (schedule)`. #2a is foundational because #2b–#2e each *intentionally or accidentally* trigger CPU exceptions during development; #2a is the only slice that makes those faults debuggable instead of fatal. #2d before #2e because the scheduler's data structures want `alloc`. The rest of this spec covers **#2a** only.

## 1. Summary

Sub-project #2a installs a **Global Descriptor Table (GDT)** and an **Interrupt Descriptor Table (IDT)** and wires the x86_64 **CPU exception vectors (0–31)** to safe Rust handlers that **report the fault over serial and halt** instead of cascading into a triple fault. It is the smallest slice of the core kernel and the highest-leverage next step: during #1 a format-argument bug caused a **page fault with no IDT to catch it → triple fault → silent QEMU reset**, which is exactly the failure class #2a eliminates. After #2a, the same bug prints `EXCEPTION: PAGE FAULT … at <addr>` over serial and parks the core. It carries the **framekernel discipline** forward — the raw descriptor-table loads and ISR stubs are `unsafe` and live in `hal`; the handler dispatch and serial reporting are safe Rust in `kernel`.

## 2. Goals

- A 64-bit **GDT** (null + kernel code + kernel data; TSS slot reserved) loaded via `lgdt`, with `CS`/data segments reloaded.
- A **TSS** with an **Interrupt Stack Table (IST)** entry so double-fault (and later NMI/page-fault) handlers run on a known-good stack — preventing a fault-in-the-fault-handler triple fault.
- An **IDT** with all 32 CPU exception vectors populated, loaded via `lidt`.
- Safe Rust **exception handlers** that print the vector name, the saved `InterruptStackFrame` (RIP/CS/RFLAGS/RSP/SS), and (where the CPU pushes one) the **error code** and fault address (`CR2` for page faults), then halt.
- A **double-fault handler** on its own IST stack (the backstop that turns a would-be triple fault into a serial report).
- An `xtask` **fault test**: trigger `int3` (breakpoint) and a deliberate page fault; assert the handler's serial output via the deterministic harness; confirm **no QEMU reset loop**.
- Everything on **stable Rust, no nightly**; `kernel` stays `#![forbid(unsafe_code)]`.

## 3. Non-goals (→ later slices of #2 and beyond)

- The **PIC/APIC remap and any maskable hardware IRQ** (timer, keyboard) — that arrives in #2e (timer) / sub-project #3 (drivers). #2a handles **exceptions (vectors 0–31) only**; it leaves interrupts **masked** (`cli`) as #1 did.
- **Recovery** from faults (e.g. demand paging on a page fault) — #2a *reports and halts*; recovery logic lands with paging (#2c) and the scheduler (#2e).
- **SMP / per-CPU GDT/IDT/TSS** — single-core at this slice; per-CPU structures are a later concern.
- Frame allocation, paging, heap, scheduler — slices #2b–#2e.
- `int 0x80`/syscall vectors — sub-project #4 (userland).

## 4. Locked decisions

| Decision | Choice |
|---|---|
| Vectors covered | **CPU exceptions 0–31 only**; maskable IRQs deferred to #2e/#3 |
| GDT contents | null, kernel code (`0x08`), kernel data (`0x10`), TSS descriptor; **no userland segments yet** |
| Fault stack | a **TSS + IST[0]** dedicated stack for double-fault (extended to NMI/#PF later) |
| ISR ABI | raw `extern "x86-interrupt"`-style entry handled in `hal` (see §5); `kernel` receives a plain Rust `&InterruptStackFrame` + optional `u64` error code |
| Handler policy | **report over serial, then `hal::cpu::halt_loop()`** — never return from a fatal exception, never reboot (`-no-reboot` already set) |
| Dependencies | **hand-rolled descriptor tables in `hal`** — do **not** pull in `x86_64`-the-crate (keeps the TCB auditable and free of external `unsafe`); only `bitflags`-style consts at most |
| Framekernel boundary | `lgdt`/`lidt`/segment reload + ISR stubs = `unsafe` → `hal`; dispatch + formatting = safe → `kernel` |
| Toolchain | **stable Rust, no nightly, no `-Z build-std`** (as #1) |

> **Open question (for review):** the cleanest stable way to express ISR entry without nightly. The `x86-interrupt` ABI is a nightly feature. **Spec assumes** `hal` provides *naked-function or global_asm* ISR stubs that save scratch registers, pass a pointer to the stack frame, and `call` a Rust `extern "C"` trampoline — all `unsafe`, all inside `hal`, all in the TCB registry. (`naked_asm!`/`global_asm!` are **stable**.) This keeps `kernel` on the stable `extern "C"` side. Confirm before implementation.

## 5. Architecture

Framekernel discipline, identical boundary to #1. The slice adds two `unsafe` HAL modules and one safe `kernel` module:

- **`hal::gdt`** *(unsafe, TCB)* — builds the GDT + TSS in static storage, executes `lgdt`, reloads `CS` (via a far return / `retfq` trampoline) and the data segment registers, and loads the TSS (`ltr`). Exposes a single safe entry: `hal::gdt::init()`.
- **`hal::idt`** *(unsafe, TCB)* — builds the 256-entry IDT (only 0–31 populated now), executes `lidt`. Owns the **raw ISR entry stubs** (`global_asm!`/naked): each stub aligns the stack, pushes a synthetic error code for vectors that don't push one (so every handler sees a uniform frame), saves scratch registers, loads a pointer to the `ExceptionFrame`, and `call`s the safe Rust trampoline. Exposes a single safe entry: `hal::idt::init()`.
- **`kernel::interrupts`** *(safe, `#![forbid(unsafe_code)]`)* — the **handler logic**. Defines `#[repr(C)]` `InterruptStackFrame` / `ExceptionContext` mirrors of what the stubs push, a dispatch function per vector (or a table indexed by vector number), the human-readable vector names, and the serial reporting. Every handler ends in `hal::cpu::halt_loop()` (fatal) — no `unsafe` anywhere.

The `unsafe` is confined to *installing* the tables and the *raw register-saving stubs*; the moment control reaches Rust handler logic it is safe code operating on a `&ExceptionContext`. This preserves the invariant that `kernel` truthfully carries `#![forbid(unsafe_code)]`, and grows the TCB by exactly two well-bounded modules.

**Init order (called from `boot::_start`, before `kernel::kmain`):**
```
hal::serial::init()  →  hal::gdt::init()  →  hal::idt::init()  →  kernel::kmain()
```
GDT before IDT (the IDT's segment selectors reference the GDT's kernel-code selector); both before `kmain` so the very first fault in kernel logic is catchable.

## 6. Components / file structure

Additions to the existing `kernel/` workspace (the `boot`/`hal`/`kernel` split from #1):

```
kernel/
  crates/hal/                          ← the unsafe TCB (grows by gdt + idt)
    src/lib.rs                         + `pub mod gdt; pub mod idt;`  (+ stable API contract entries)
    src/gdt.rs        [NEW, unsafe]    GDT+TSS statics, IST stack, lgdt, CS/data reload, ltr; safe `init()`
    src/idt.rs        [NEW, unsafe]    IDT statics, lidt; raw ISR stubs (global_asm!/naked); extern "C"
                                       trampoline → kernel::interrupts; safe `init()`
    (serial.rs, cpu.rs unchanged)      cpu.rs already exposes disable/enable/halt — reused as-is

  crates/kernel/                       ← #![no_std] #![forbid(unsafe_code)]
    src/lib.rs                         + `pub mod interrupts;`  (kmain unchanged except an optional
                                       "interrupts armed" banner line)
    src/interrupts.rs [NEW, safe]      ExceptionContext (#[repr(C)]), per-vector dispatch + names,
                                       serial fault report, terminal `hal::cpu::halt_loop()`

  crates/boot/
    src/main.rs                        `_start` now calls hal::gdt::init(); hal::idt::init();
                                       between serial init and kernel::kmain (still tiny TCB shim)

  xtask/
    src/main.rs                        + `cargo xtask test-faults` (or extend `test`): build a
                                       fault-injecting variant, assert serial fault report, assert
                                       no reset loop (see §9)

  docs/hal-tcb.md                      + section "3a. hal::gdt" and "3b. hal::idt": one row per
                                       new unsafe op (lgdt/lidt/ltr/far-return/ISR stub), Reasoned + QEMU
```

No new crates; the boundary and lint posture from #1 are unchanged.

## 7. Data flow (exception path)

```
CPU raises exception (e.g. #PF on a bad load, or `int3` executed)
  → CPU consults IDT[vector]  (installed by hal::idt::init)
  → jumps to the raw ISR stub for that vector           [hal::idt, unsafe asm]
       → (if the vector pushes no error code) push a synthetic 0 for a uniform frame
       → save scratch registers; load CR2 for #PF; build pointer to ExceptionContext
       → call  kernel_exception_dispatch(vector, &ctx)   [extern "C" trampoline, hal]
            → kernel::interrupts::dispatch(vector, ctx)   [safe Rust from here]
                 → look up vector name (e.g. "PAGE FAULT", "BREAKPOINT")
                 → hal::println!("EXCEPTION: {name} (vec {n})")
                 → print RIP, CS, RFLAGS, RSP, SS, error code, CR2 (if #PF)
                 → FATAL vectors:  hal::cpu::halt_loop()        // park the core, no reboot
                 → (BREAKPOINT #3 may be made non-fatal later → iretq; out of scope to recover now)
double fault (a fault while handling a fault)
  → its IST[0] stack guarantees a valid RSP → its handler reports "DOUBLE FAULT" and halts
  → this is the backstop that replaces the #1-era triple-fault → silent reset
```

## 8. Error handling

- **Exceptions are the error-handling channel**, not an error case to recover from at this slice. Every fatal handler ends in `hal::cpu::halt_loop()` — it never returns, never unwinds (`panic = "abort"`), never reboots (`-no-reboot`).
- **Double-fault on its own IST stack** is the critical guard: if a handler itself faults (e.g. stack overflow, bad serial state), the IST stack switch keeps the double-fault handler runnable so we still get *a* serial report instead of a triple fault. This is the structural fix for the #1 incident.
- The serial report is built with the **same panic-safe discipline as #1**: no `unwrap`/`panic!` on the reporting path, and the report avoids runtime-format vtable machinery where it would itself fault (the #1 root cause) — vector names are `&'static str`, register values printed via simple hex formatting.
- `hal::gdt::init`/`hal::idt::init` are infallible by construction (they program fixed static tables); they assert their statics are sized/aligned at compile time (`const` asserts) rather than returning `Result`.

## 9. Testing

Extends the deterministic, headless `xtask` QEMU harness from #1 (build ISO → run QEMU → `-serial file:` → poll `serial.log` for markers → kill). Two new deterministic checks:

1. **Breakpoint (`int3`) test:** a test build executes `int3` after init. **Assert** the serial log contains `EXCEPTION: BREAKPOINT` (and, if #3 is made resumable, that execution continues past it to an end-marker). Proves the IDT is installed and dispatch reaches `kernel::interrupts`.
2. **Deliberate page-fault test (the headline test):** a test build dereferences an unmapped address (e.g. a non-canonical / known-unmapped pointer) **after** the IDT is installed. **Assert** the log contains `EXCEPTION: PAGE FAULT`, a faulting-address line (`CR2`), and that **QEMU does not reset** (the harness must distinguish "halted after report" from "boot banner printed twice", which would indicate a triple-fault reboot loop). This is the exact failure that silently reset in #1; here it must produce a clean serial report.
3. **Double-fault sanity (optional):** force a fault inside a handler (or overflow the IST guard) and assert `EXCEPTION: DOUBLE FAULT` appears — proving the IST backstop works.
4. **No-regression:** the existing #1 boot test still passes (banner + `boot-bringup-ok`), now with GDT/IDT armed.

Fault-injection is gated behind a cargo **feature** (e.g. `--features fault-test-int3` / `fault-test-pf`) so the normal image never faults; `xtask` builds the relevant variant per test. Markers are matched the same way `END_MARKER`/`BANNER_LINE` are in `xtask/src/main.rs`. Pure helpers (e.g. vector-name lookup, RFLAGS/error-code bit decoding) get host `cargo test` unit tests; bit-decoders are candidate **Kani** targets (verification roadmap).

## 10. Acceptance criteria

1. `cargo xtask run` boots with GDT + IDT armed and still prints the #1 banner + `boot-bringup-ok` (no regression).
2. The `int3` fault test prints `EXCEPTION: BREAKPOINT` over serial via `kernel::interrupts`.
3. The page-fault test prints `EXCEPTION: PAGE FAULT` + the faulting address and **halts with no QEMU reset loop** (the #1 incident is now caught, not silent).
4. A double-fault is handled on its **IST stack** and reported (no triple fault).
5. `crates/kernel` still compiles with `#![forbid(unsafe_code)]`; every new `unsafe` in `crates/hal` (`gdt.rs`, `idt.rs`) has a `// SAFETY:` comment **and** a row in `kernel/docs/hal-tcb.md`.
6. Builds clean with `-D warnings` and `cargo clippy` on **stable**, macOS + Linux CI; **no nightly, no `-Z build-std`**.

## 11. Open questions

- **ISR stub mechanism (§4):** confirm hand-rolled `global_asm!`/naked stubs + `extern "C"` trampoline (stable) vs. any nightly `x86-interrupt` shortcut — spec assumes the stable asm route and forbids nightly.
- **Hand-rolled tables vs. the `x86_64` crate:** spec assumes hand-rolled to keep the TCB external-`unsafe`-free; revisit only if the audit cost outweighs the dependency cost.
- **Breakpoint policy:** `int3` fatal-and-halt now, or resumable (`iretq`) to support a future debugger? Spec keeps it fatal-report at this slice; resumability is additive.
- **IST stack sizing:** size of the double-fault IST stack (a static `[u8; N]`) — pick a safe N (e.g. 4 KiB) for the report path.

## 12. Build sequence (implementation plan → agent team)

1. **toolchain-engineer:** confirm the stable ISR-stub mechanism (`global_asm!`/naked) builds for `x86_64-unknown-none`; add the `fault-test-*` cargo features and the `xtask test-faults` plumbing skeleton.
2. **hal-specialist:** `hal::gdt` (GDT+TSS+IST, `lgdt`/`ltr`/segment reload) and `hal::idt` (IDT, `lidt`, raw ISR stubs + `extern "C"` trampoline). Every `unsafe` gets `// SAFETY:` + a `kernel/docs/hal-tcb.md` row. Extend the stable API contract in `hal::lib.rs`.
3. **kernel-engineer:** `kernel::interrupts` — `ExceptionContext`, per-vector dispatch + names, serial fault report, terminal `halt_loop()`; wire `gdt::init`/`idt::init` into `boot::_start`. All safe (`#![forbid(unsafe_code)]` holds).
4. **test-engineer:** `int3`, page-fault, and double-fault QEMU tests in `xtask`; assert serial markers + **no reset loop**; keep the #1 boot test green.
5. **verification-engineer:** review the two new TCB modules in `hal-tcb.md`; mark Kani targets (bit decoders); keep the CI verification gate green.
6. **kernel-reviewer:** adversarial review of the new `unsafe` (lgdt/lidt/ltr/far-return/ISR stubs) and the safe/unsafe boundary → approve.
