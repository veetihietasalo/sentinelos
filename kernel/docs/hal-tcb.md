# HAL TCB Registry — SentinelOS

This document is the authoritative registry of **every `unsafe` operation** in
the SentinelOS Trusted Computing Base. The `hal` crate is the *only* crate
permitted to use `unsafe`; the `kernel` crate carries `#![forbid(unsafe_code)]`.
Each entry below names the unsafe primitive, why it is necessary, why it is
sound, and its formal-verification status.

- **Owner:** hal-specialist
- **Scope:** sub-project #1 (boot bring-up) — serial console + CPU primitives;
  sub-project #2 (hardware interrupts) — 8259 PIC remap + EOI (`hal::pic`),
  8254 PIT timer (`hal::pit`), and the `sti`/`int3`/`CR2` CPU primitives;
  sub-project #2a (interrupts) — GDT/TSS/IST, IDT, and the raw ISR stubs;
  sub-project #3 (input) — the PS/2 (i8042) keyboard on IRQ1 (`hal::keyboard`);
  sub-project #5 (UI, first slice) — the Limine framebuffer surface (`hal::framebuffer`)
- **Crate lints:** `#![deny(unsafe_op_in_unsafe_fn)]`,
  `#![warn(clippy::undocumented_unsafe_blocks)]` — every `unsafe` block is
  forced to carry a `// SAFETY:` comment.
- **Verification legend:** Miri / Kani / fuzz are marked **pending** — they come
  online in sub-project #2 (per design spec §9). "Reasoned" = argued sound by
  construction in the `// SAFETY:` comment and reviewed.

> Note: inline `in`/`out` and most privileged instructions are **not**
> Miri-executable (Miri has no model for x86 port I/O or `hlt`/`cli`/`sti`).
> For those, verification is by manual review + QEMU boot evidence, not Miri.

---

## 1. `hal::serial` — 16550 UART on COM1 (`0x3F8`)

The serial driver is the only source of device I/O in the bring-up TCB. All
hardware access is funnelled through two private primitives, `inb`/`outb`, each
documented with a `# Safety` rustdoc section.

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| S1 | `serial.rs` · `inb()` | `in al, dx` (port read) | Only way to read 16550 status/data registers | `unsafe fn` whose `# Safety` requires a read-safe UART port; all callers pass a COM1 register offset (`base + 0..=5`). Pure device read, `nomem`/`nostack`. | Reasoned + QEMU (Miri/Kani/fuzz **pending**) |
| S2 | `serial.rs` · `outb()` | `out dx, al` (port write) | Only way to program/transmit on the 16550 | `unsafe fn` whose `# Safety` requires a write-safe UART port; all callers pass a COM1 register offset with a defined value. Device-only effect, `nomem`/`nostack`. | Reasoned + QEMU (Miri/Kani/fuzz **pending**) |
| S3 | `serial.rs` · `Serial::init()` | block of `outb` calls | 8N1 + FIFO programming sequence | Each `outb` targets a constant COM1 register offset with a standard, well-defined value; affects only the UART device, cannot alias Rust memory. Satisfies `outb`'s contract per call. | Reasoned + QEMU (**pending**) |
| S4 | `serial.rs` · `Serial::is_transmit_ready()` | `inb(base + LSR)` | Poll Transmit-Holding-Register-Empty before writing | Reads the read-only Line Status Register; no side effect relevant to memory safety. Satisfies `inb`'s contract. | Reasoned + QEMU (**pending**) |
| S5 | `serial.rs` · `Serial::write_byte()` | `outb(base + DATA, byte)` | Transmit one byte | Reached only after the LSR reports THR empty, so no overrun; writes the data register, device-only effect. Satisfies `outb`'s contract. | Reasoned + QEMU (**pending**) |
| S6 | `serial.rs` · `interrupts_enabled()` | `pushfq; pop {}` (read RFLAGS) | Read IF so the console guard can restore prior interrupt state | Balanced push/pop reads RFLAGS into a register; `nomem`, `preserves_flags`, stack-balanced (no `nostack`). Reading flags cannot violate memory safety. | Reasoned (**pending**) |

> **Fault-path printing (no new `unsafe`).** `serial::print_labeled_hex` /
> `print_labeled_dec` / `print_line` build digits into a fixed stack buffer with
> plain arithmetic and write raw bytes through the existing (already-documented)
> `Serial::write_bytes` path — they add **no** new unsafe op. They exist because
> `core::fmt`'s *integer-argument* machinery (the `format_args!("{:#x}", n)`
> path) routes through function-pointer indirection that **page-faults on the
> `x86_64-unknown-none` target** — so an exception reporter using `{:#018x}`
> would fault *while reporting a fault*. The exception/IDT-default handlers and
> the `int3` self-test therefore report via these fmt-arg-free helpers. (String
> literals with no formatted args — the banner, status lines — are unaffected and
> still use `println!`.)

### Concurrency note

The global console (`static CONSOLE: Serial`) is shared, but `Serial` has no
interior mutability — all UART state lives in the device. Writes go through
`with_console`, which masks maskable interrupts (`cli`) for the duration of the
write and restores the prior `IF` state (`sti` only if it had been set). This
prevents an interrupt handler from re-entering the UART mid-byte. It is **not**
an SMP lock; multi-core synchronisation is a sub-project #2 concern (single-core
at bring-up).

---

## 2. `hal::cpu` — CPU primitives

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| C1 | `cpu.rs` · `disable_interrupts()` | `cli` | Mask maskable interrupts for critical sections | Clears RFLAGS.IF only; affects interrupt-delivery timing, never memory validity/aliasing. `nomem`/`nostack`; not `preserves_flags` (modifies IF). | Reasoned (**pending**) |
| C2 | `cpu.rs` · `enable_interrupts()` | `sti` | Re-open the interrupt window after a critical section | Sets RFLAGS.IF only; not itself UB. At bring-up no IDT/handlers exist, so this is for symmetry; handler safety is the IDT owner's responsibility (sub-project #2). | Reasoned (**pending**) |
| C3 | `cpu.rs` · `halt()` | `hlt` (single) | Idle the core until the next interrupt | Idles the CPU; accesses no memory/registers; `preserves_flags`. Cannot violate memory safety. | Reasoned (**pending**) |
| C4 | `cpu.rs` · `halt_loop()` | `hlt` (in a `loop`) | Terminal park for boot path + panic handler (`-> !`) | Same as C3; re-halts on every wake so the core never spins hot and never falls through. Diverging, safe wrapper. | Reasoned (**pending**) |
| C5 | `cpu.rs` · `breakpoint()` | `int3` (vector 3) | One-shot runtime self-test of the live IDT (the `[selftest]` boot line) | Software interrupt that vectors through the IDT's gate 3; touches no memory (`nomem`); the CPU's interrupt-frame push is balanced by the ISR stub. With a resumable #BP handler it returns; with none, `hal`'s default reporter halts. Cannot create UB. | Reasoned + QEMU (`int3` → #BP, resumes) |
| C6 | `cpu.rs` · `read_cr2()` | `mov {}, cr2` (read CR2) | Report the faulting linear address in the #PF handler | Pure read of the CR2 control register at CPL 0; accesses no program memory (`nomem`), no stack (`nostack`), `preserves_flags`. Observing the last faulting address cannot affect memory validity/aliasing. | Reasoned + QEMU |

---

## 2a. `hal::gdt` — GDT + TSS + IST (sub-project #2a)

Builds a 64-bit GDT (null, kernel code `0x08`, kernel data `0x10`, plus a 16-byte
TSS system descriptor `0x18`) and a TSS whose `IST[0]` points at a dedicated
16 KiB double-fault stack, then loads them. All privileged steps run inside the
single safe entry `gdt::init()`, which is documented to execute **exactly once**
on the boot core with interrupts disabled — so the `static mut` GDT/TSS/stack are
neither aliased nor concurrently accessed.

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| G1 | `gdt.rs` · `init()` | write `static mut TSS.ist[0]` / `static mut GDT[..]` via `addr_of_mut!` raw pointers | The TSS-stack top and TSS-descriptor base are runtime addresses that must be baked into the tables | Single-call, single-core, interrupts-off init; writes go through `addr_of_mut!` raw pointers (no aliasing `&mut`); each descriptor field is computed from the statics' own address/size, so the tables are self-consistent. | Reasoned + QEMU fault tests (Miri/Kani **pending**) |
| G2 | `gdt.rs` · `init()` | `lgdt [mem]` | Only way to point the CPU at the new GDT | Operand is a 10-byte pointer to our well-formed `GDT` with exact `limit`; read-only memory; loads descriptor-table base/limit without changing execution or other registers. | Reasoned + QEMU |
| G3 | `gdt.rs` · `init()` | far return (`push sel; push rip; retfq`) to reload `CS` | `mov cs, reg` is illegal in long mode; a far transfer is the canonical CS reload | Pushes the kernel-code selector and the address of the next instruction, then `retfq` pops them into `CS:RIP`; selector indexes the just-loaded present 64-bit code descriptor → valid same-privilege far return. Stack-balanced. | Reasoned + QEMU |
| G4 | `gdt.rs` · `init()` | `mov ss/ds/es/fs/gs, sel` | Make the data segment registers consistent with the new GDT | Loads the present, writable kernel-data selector (`0x10`); long-mode treats these bases as 0, so it only refreshes the selectors. Cannot corrupt memory. | Reasoned + QEMU |
| G5 | `gdt.rs` · `init()` | `ltr sel` | Arm the TSS so `IST[0]` (double-fault stack) is live | Loads the task register from the available-64-bit-TSS selector (`0x18`) pointing at our `TSS`; after this a fault routed to `IST[0]` switches to the known-good double-fault stack. Loading a valid TSS selector cannot corrupt memory. | Reasoned + QEMU (double-fault test) |

## 2b. `hal::idt` — IDT + raw ISR stubs (sub-project #2a)

Builds a 256-entry IDT and the per-vector assembly entry stubs (stable
`global_asm!`, `.altmacro` + `.rept`). Each stub normalises the stack (synthetic
`0` error code for vectors that push none), pushes the vector number, and jumps
to one shared `isr_common` tail that saves the 15 GP registers, points `rdi` at
the assembled frame, and `call`s the `extern "C"` trampoline. Error-code vectors
(8, 10–14, 17, 21, 29, 30) push only the vector (the CPU already pushed the error
code) — verified against the emitted assembly. All privileged steps run inside
the single safe entry `idt::init()` (once, single-core, interrupts off).

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| I1 | `idt.rs` · `isr_stub_*` / `isr_common` (`global_asm!`) | raw ISR entry stubs: push error-code/vector, save/restore GP regs, align stack, `call` trampoline, `iretq` | Stable Rust has no `x86-interrupt` ABI; hand-rolled stubs are the stable way to give every handler a uniform frame | Push order matches `InterruptFrame` field-for-field (r15 lowest); synthetic `0` only for no-error-code vectors (confirmed in emitted asm); 16-byte stack alignment restored before `call`; symmetric pops + `add rsp,16` + `iretq` leave the CPU frame intact. Stubs are jumped to by the CPU, never called from Rust. | Reasoned + QEMU fault tests (int3 / #PF / #DF) |
| I2 | `idt.rs` · `isr_trampoline()` | `&*frame` — form `&InterruptFrame` from the stub's `rdi` pointer | The boundary that hands the fault to safe handler code | `frame` is set by `isr_common` to the base of the stack image it just built, laid out exactly as `#[repr(C)] InterruptFrame`; the region is valid, aligned, unaliased, and stable for the whole call (the stub does not touch it until after return). | Reasoned + QEMU |
| I3 | `idt.rs` · `stub_addr()` | read `ISR_STUB_TABLE[n]` via `addr_of!` + `*const u64::read()` | Resolve each stub's link-time address as data (avoids 256 `extern fn` decls) | `ISR_STUB_TABLE` is an assembler-emitted `.rodata` array of 256 stub addresses; `n` is always `< IDT_ENTRIES` (== table length) so the read is in bounds; values are code addresses stored into gates, never dereferenced here. | Reasoned + QEMU |
| I4 | `idt.rs` · `init()` | write `static mut IDT[..]` via `addr_of_mut!` raw pointer | Each gate's handler offset is a runtime stub address | Single-call, single-core, interrupts-off init; writes via `addr_of_mut!` (no aliasing `&mut`); each gate built from a valid stub address + the present kernel-code selector; vector 8 gets `ist = DOUBLE_FAULT_IST_INDEX + 1`. | Reasoned + QEMU |
| I5 | `idt.rs` · `init()` | `lidt [mem]` | Only way to arm fault delivery through the new IDT | Operand is a 10-byte pointer to our fully-initialised `IDT` with exact `limit`; read-only memory; arms vectoring without changing registers/memory. | Reasoned + QEMU |

## 2c. `hal::interrupts` — safe registration bridge (sub-project #2a)

This module is **safe** API; it exists to let the `kernel` crate
(`#![forbid(unsafe_code)]`) register handlers without a `hal → kernel` dependency
cycle. It contains exactly **one** `unsafe` op:

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| X1 | `interrupts.rs` · `handler_for()` | `transmute::<*mut (), Handler>` | Stable Rust cannot cast a data pointer back to a `fn` pointer except via `transmute` | The `*mut ()` read from `HANDLERS` is non-null and was produced *only* by `set_handler` casting a valid `Handler` (`fn(&InterruptFrame)`) to `*mut ()`; the transmute is the exact inverse, recovering the same fn pointer; no data is dereferenced. Stored/loaded via `AtomicPtr` (no tearing). | Reasoned + QEMU (dispatch test) |

> `set_handler` itself uses only a `fn → *mut ()` cast (safe) and an atomic
> store; `init()` just calls `gdt::init()` then `idt::init()`. No other `unsafe`.

## 2d. `hal::framebuffer` — Limine linear framebuffer surface (sub-project #5)

Owns the `#[used] static FRAMEBUFFER_REQUEST: limine::request::FramebufferRequest`
so the bootloader provides a linear RGB framebuffer, and wraps the first
framebuffer's geometry + channel masks in a safe `Framebuffer` handle. The public
surface — `get`, `width`/`height`/`pitch`/`bpp`/`bytes_per_pixel`, the
`red_mask`/`green_mask`/`blue_mask` accessors, `pack_rgb`, `put_pixel`, and
`fill_rect` — is **entirely safe** and **bounds-checked** (out-of-range
coordinates are no-ops; `fill_rect` clips to the visible surface). The packed
pixel format is derived from the firmware-reported per-channel shift+size, so
`pack_rgb` is correct for any layout (not just `0x00RRGGBB`). All `unsafe` is
confined to the two ops below.

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| F1 | `framebuffer.rs` · `Framebuffer::get()` | deref the Limine framebuffer **response** (`get_response()` → `framebuffers().next()` → read `addr`/`width`/`height`/`pitch`/`bpp`/masks) | Only way to learn the bootloader-mapped framebuffer base + geometry | `get_response()` yields `Some(&FramebufferResponse)` only after Limine atomically populated our `#[used]` request before `_start`; the response/framebuffer pointers it walks were filled by the bootloader and are valid + initialised. We never mutate the request, the shared borrow is dropped before returning (only plain scalars are copied out), and a null base is rejected → `None`. | Reasoned + QEMU (Miri/Kani **pending**) |
| F2 | `framebuffer.rs` · `Framebuffer::write_pixel_at()` (called by `put_pixel`/`fill_rect`) | `ptr::write_volatile` byte stores to the framebuffer MMIO at `base + offset` | Plot a pixel; volatile so MMIO stores are never elided/coalesced | `unsafe fn` whose `# Safety` requires `offset + bytes_per_pixel <= height*pitch`; both callers reach it only via bounds-checked `byte_offset`/clipped `fill_rect`, so every byte write lands inside the mapped `height*pitch` region (`pitch >= width*bytes_per_pixel`). `base` is non-null (checked in `get`); `u8` writes are alignment-1; single-core boot path ⇒ unaliased. Byte-by-byte handles 16/24/32-bpp without an over-wide store. | Reasoned + QEMU (Miri/Kani **pending**) |

> `Framebuffer` carries `unsafe impl Send + Sync`: the base is an MMIO pointer
> valid for the program's life and the handle exposes no interior mutability; the
> geometry/mask fields are immutable. Concurrent **writes** are the caller's
> responsibility (documented on the drawing methods) — single-core at bring-up.
> `pack_rgb`, the dimension/mask getters, and the bounds/clip arithmetic are pure
> safe logic (Kani candidates).

## 2e. `hal::pic` — 8259A PIC pair remap + EOI (sub-project #2)

Remaps the cascaded master/slave 8259A PIC pair (ports `0x20/0x21` and
`0xA0/0xA1`) from their power-on vectors (which **collide** with CPU exceptions
0–31) to vectors `0x20`–`0x2F` (32–47), masks every line, and provides
per-line mask/unmask plus an End-Of-Interrupt routine. All hardware access is
funnelled through two private primitives, `inb`/`outb`, each documented with a
`# Safety` rustdoc section. The public surface (`init`, `mask_irq`,
`unmask_irq`, `end_of_interrupt`) is **safe**. `init` runs once on the boot core
with interrupts disabled; `end_of_interrupt` runs inside an interrupt handler
(interrupts already masked by the interrupt gate) — single-core, no SMP lock.

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| P1 | `pic.rs` · `inb()` | `in al, dx` (port read) | Only way to read a PIC Interrupt Mask Register before a read-modify-write | `unsafe fn` whose `# Safety` requires a read-safe PIC port; all callers pass a master/slave data port. Pure device read, `nomem`/`nostack`. | Reasoned + QEMU |
| P2 | `pic.rs` · `outb()` / `outb_wait()` | `out dx, al` (port write) | Only way to program the 8259A (ICW1–4, masks, EOI) | `unsafe fn` whose `# Safety` requires a write-safe PIC port; all callers pass a master/slave command/data port with a documented ICW/OCW/mask value. `outb_wait` adds a throwaway write to the conventional I/O-delay port `0x80`. Device-only effect, `nomem`/`nostack`. | Reasoned + QEMU |
| P3 | `pic.rs` · `init()` | ICW1–ICW4 `outb` sequence + final mask writes | Remap both PICs to `0x20`–`0x2F` in 8086 cascade mode and mask all lines | Standard, well-defined 8259A init sequence; each `outb` targets a constant PIC port with a defined value; only reconfigures where the PICs vector and which lines are masked. Runs once, boot core, interrupts off → no concurrent PIC access. | Reasoned + QEMU (timer IRQ delivered to vector 32) |
| P4 | `pic.rs` · `mask_irq()` / `unmask_irq()` | `inb` then `outb` of the IMR | Open/close a single IRQ line (e.g. IRQ0 for the PIT) | Read-modify-write of one mask bit (`line < 8`) on the master/slave IMR; device-only effect (enables/disables one line). `inb`/`outb` contracts hold. | Reasoned + QEMU |
| P5 | `pic.rs` · `end_of_interrupt()` | `outb(PIC_EOI)` to master (and slave if a slave line) | Tell the PIC the serviced interrupt is done so it delivers further IRQs | Writes the non-specific EOI (OCW2 `0x20`) to the master command port, plus the slave for vectors `0x28`–`0x2F`; vectors outside `0x20`–`0x2F` are ignored. EOI is device-only; cannot corrupt memory. | Reasoned + QEMU (sustained 100 Hz ticks) |

## 2f. `hal::pit` — 8254 PIT channel-0 timer (sub-project #2)

Programs PIT channel 0 (ports `0x40`/`0x43`) as a ~100 Hz rate generator
(mode 2, divisor 11931 of the 1.193182 MHz input), whose output drives the
master PIC's IRQ0 → vector `0x20`. A free-running `static AtomicU64 TICKS` is
incremented by the kernel's vector-32 handler via the safe `on_tick`, which also
calls `pic::end_of_interrupt`. The only privileged op is the channel-0
programming write; `TICKS` is a plain atomic (no `unsafe`), and `ticks`/`on_tick`
are safe API.

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| T1 | `pit.rs` · `outb()` | `out dx, al` (port write) | Only way to program PIT channel 0 | `unsafe fn` whose `# Safety` requires a write-safe PIT port; all callers pass `0x40`/`0x43` with a defined mode/reload value. Device-only effect, `nomem`/`nostack`. | Reasoned + QEMU |
| T2 | `pit.rs` · `init()` | mode-byte + lo/hi reload `outb` sequence | Configure channel 0 to ~100 Hz rate-generator mode | Documented 8254 channel-0 programming sequence (`0x34` then divisor low/high); only sets the PIT's mode and reload count — device-only, cannot alias Rust memory. Runs once, boot core, interrupts off. | Reasoned + QEMU (clock advances 1 s/s on the boot screen) |

> The PIT's IRQ0 handler (`hal::pit::on_tick`) does a `fetch_add` on the
> `AtomicU64 TICKS` and a `pic::end_of_interrupt` — both safe. The privileged EOI
> port write lives in `hal::pic` (P5), so the kernel's registered vector-32
> handler stays `#![forbid(unsafe_code)]`-clean.

## 2g. `hal::keyboard` — PS/2 (i8042) keyboard on IRQ1 (sub-project #3)

Captures keyboard scancodes from the legacy PS/2 controller. The IRQ1 handler
(`on_irq`, called from the kernel's registered vector-33 handler) reads one byte
from the data port `0x60` on **every** interrupt (mandatory: the i8042 will not
raise another IRQ1 until its output buffer is drained), pushes the raw byte into
a lock-free SPSC ring built from plain atomics (no `unsafe`), then EOIs via
`hal::pic`. `init` programs the i8042 configuration byte to enable the keyboard
interrupt (IRQ1) before unmasking the PIC line. **All scancode decoding** (the
`0xE0` extended-prefix state machine, make/break mapping) lives in the safe
`kernel` crate (`kernel::input`), not the TCB. All hardware access is funnelled
through two private primitives, `inb`/`outb`, each documented with a `# Safety`
section. The public surface (`init`, `on_irq`, `poll_scancode`) is **safe**;
`poll_scancode` and the ring are pure atomics. `init` runs once on the boot core
with interrupts disabled; `on_irq` runs inside the IRQ1 interrupt gate
(interrupts already masked) — single-core, no SMP lock.

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| K1 | `keyboard.rs` · `inb()` | `in al, dx` (port read) | Only way to read the i8042 data (`0x60`) and status (`0x64`) registers | `unsafe fn` whose `# Safety` requires a read-safe PS/2 port; all callers pass `0x60`/`0x64`. Pure device read (draining the scancode / reading status), `nomem`/`nostack`. | Reasoned + QEMU (keystroke → `[input]` serial line) |
| K2 | `keyboard.rs` · `outb()` | `out dx, al` (port write) | Only way to send i8042 commands (`0x64`) and write the config byte (`0x60`) | `unsafe fn` whose `# Safety` requires a write-safe PS/2 port; all callers pass `0x60`/`0x64` with documented i8042 command/config values. Device-only effect (which interrupts the controller raises / which ports are clocked), `nomem`/`nostack`. | Reasoned + QEMU |
| K3 | `keyboard.rs` · `wait_input_empty()` / `wait_output_full()` | `inb(0x64)` status poll | Gate command/data writes and the config read on the controller's buffer state | Reads the read-only status register in a **bounded** loop (so a wedged controller cannot hang boot); no side effect relevant to memory safety. `inb`'s contract holds. | Reasoned + QEMU |
| K4 | `keyboard.rs` · `init()` | read-modify-write of the i8042 config byte (`0x20` read → set IRQ1 bit, clear clock-disable → `0x60` write), then drain a stale byte | Enable IRQ1 generation; firmware may leave it disabled, in which case the keyboard never raises an interrupt | Standard i8042 config-byte programming; each `inb`/`outb` targets a constant PS/2 port with a defined value; only toggles controller interrupt/clock bits — device-only, cannot alias Rust memory. Runs once, boot core, interrupts off. | Reasoned + QEMU (after this, IRQ1 fires on keypress) |
| K5 | `keyboard.rs` · `on_irq()` | `inb(0x60)` scancode read | Drain the scancode byte (mandatory — i8042 stops raising IRQ1 until read) | Reached only from the IRQ1 interrupt gate; a single pure device read of the data port, then a `fetch`-free atomic push to the ring and a `pic::end_of_interrupt`. Cannot corrupt memory. | Reasoned + QEMU (sustained keystrokes delivered) |

> The keyboard's raw-scancode ring (`RING`/`HEAD`/`TAIL`) is built from plain
> `AtomicU8`/`AtomicUsize` (no `unsafe`); `poll_scancode` is safe API. The
> *decoding* state machine and the lock-screen logic live in `kernel::input`
> under `#![forbid(unsafe_code)]`, so the privileged surface stays tiny.

---

## 3. Verification roadmap (sub-project #2+)

| Tool | Applicable to | Status |
|------|---------------|--------|
| Manual review + adversarial review (kernel-reviewer) | all entries | scheduled (build sequence step 6) |
| QEMU boot evidence | S1–S5, C3–C4 (serial output + clean halt); F1–F2 (framebuffer plotted in QEMU once the boot screen renders) | via `cargo xtask test` (test-engineer) |
| QEMU **fault tests** (the #2a evidence) | G1–G5, I1–I5, X1 — `int3` → `EXCEPTION: BREAKPOINT`, deliberate #PF → `EXCEPTION: PAGE FAULT` + no reset loop, forced #DF on the IST stack → `EXCEPTION: DOUBLE FAULT` | via `cargo xtask test-faults` (test-engineer, build sequence step 4) — **this is the primary correctness check for the ISR/asm + descriptor-table loads** |
| Miri | pure logic helpers only (cannot model port I/O / `hlt`/`cli`/`sti` / descriptor loads / ISR stubs) | **pending** |
| Kani (bounded model checking) | bit-level helpers (e.g. IF/LSR masks, newline translation, gate/TSS descriptor bit-packing, RFLAGS/error-code decoders, **framebuffer `pack_rgb` channel packing + `byte_offset`/`fill_rect` bounds/clip arithmetic**) | **pending** |
| Fuzzing | `Serial::write_bytes` newline translation over arbitrary inputs | **pending** |

> **#2a note:** the GDT/TSS/IDT loads and the raw ISR stubs are not Miri- or
> Kani-executable (no model for `lgdt`/`lidt`/`ltr`/`iretq` or the stub asm). Their
> correctness is verified by the **QEMU fault tests** above (int3 / #PF / #DF
> serial markers + no triple-fault reboot loop), plus the emitted-assembly audit
> already performed for the per-vector error-code logic. Pure helpers (gate/TSS
> bit-packing, decoders) remain Kani candidates.

## 4. Invariants the rest of the kernel relies on

1. `serial::init()` is called exactly once before the first `print!`/`println!`.
2. No `panic!`/`unwrap` on the normal print path — `_print` drops the
   (infallible) formatting `Result` to stay panic-free (spec §8).
3. `cpu::halt_loop()` never returns and never unwinds (`panic = "abort"`).
4. The `kernel` crate touches hardware *only* through these safe wrappers; it
   never writes `unsafe` itself.
5. `interrupts::init()` (which calls `gdt::init()` then `idt::init()`, in that
   order) is called **exactly once** on the boot core with interrupts disabled,
   **before** `kmain` does anything that could fault. GDT before IDT: the IDT's
   gates reference the GDT's kernel-code selector and the IST the TSS arms.
6. Handlers registered via `interrupts::set_handler()` are plain safe
   `fn(&InterruptFrame)` and must not assume they can resume (this slice reports
   and halts); the trampoline calls the registered handler, or `hal`'s built-in
   `default_handler` (report + `halt_loop`) when none is registered — so an
   unhandled exception still produces a serial report instead of a triple fault.
7. `framebuffer::Framebuffer::get()` is the **only** place the Limine framebuffer
   response is dereferenced; it returns `None` (never UB) when no framebuffer was
   provided. All drawing through the returned handle is safe and bounds-checked
   — an off-screen coordinate is a no-op and `fill_rect` clips — so the `ui`
   crate (and `kernel`) can draw without writing `unsafe`. Write coordination is
   the caller's responsibility (single-core at bring-up); the handle exposes no
   interior mutability.
