//! Interrupt Descriptor Table (IDT) + raw ISR entry stubs — part of the TCB.
//!
//! This module builds a 256-entry IDT and the assembly **entry stubs** the CPU
//! jumps to when an interrupt or exception fires. Because the `x86-interrupt`
//! calling convention is a nightly feature and SentinelOS is stable-only
//! (spec §4), the stubs are hand-written with **stable** [`core::arch::global_asm!`]
//! and funnel into a single `extern "C"` Rust trampoline.
//!
//! # Stub strategy
//!
//! On an exception the CPU pushes (high → low address) `SS, RSP, RFLAGS, CS,
//! RIP`, and for *some* vectors an **error code** below that. To give every
//! handler a uniform frame, each stub:
//!
//! 1. pushes a **synthetic `0` error code** if (and only if) the CPU did not
//!    push one for this vector, so the layout is identical for all vectors;
//! 2. pushes the **vector number**;
//! 3. `jmp`s to one shared `isr_common` block that saves all 15
//!    general-purpose registers, points `rdi` at the assembled frame, and
//!    `call`s [`isr_trampoline`];
//! 4. on return, restores the registers, drops the vector + error code, and
//!    `iretq`s.
//!
//! The resulting stack image — saved registers, vector, error code, then the
//! CPU frame — is exactly [`crate::interrupts::InterruptFrame`], so the
//! trampoline can treat `rdi` as `&InterruptFrame` with no copying.
//!
//! The IDT and its stubs are hand-rolled (no `x86_64` crate) to keep the TCB
//! auditable (spec §4). The only public entry is the safe [`init`].

use crate::gdt::{DOUBLE_FAULT_IST_INDEX, KERNEL_CODE_SELECTOR};
use crate::interrupts::{handler_for, InterruptFrame};
use core::arch::global_asm;
use core::mem::size_of;
use core::sync::atomic::{AtomicU8, Ordering};

/// Number of IDT entries. The architecture defines 256 vectors; we install stubs
/// for the 32 CPU-exception vectors (0–31) and leave the rest pointing at a
/// catch-all stub so a stray vector still reports rather than triple-faulting.
const IDT_ENTRIES: usize = 256;

/// Bytes reserved on the interrupt stack for the per-IRQ `XSAVE` area, sized for
/// x87 + SSE + AVX + AVX-512 (~2.7 KiB) with margin, and a multiple of 64 (`XSAVE`
/// requires 64-byte alignment). [`crate::simd::enable`] validates the CPU's actual
/// `cpuid`-leaf-`0xD` size fits this before arming the save (see [`arm_vector_save`]).
pub(crate) const VECTOR_SAVE_AREA_MAX: usize = 4096;

/// Whether [`isr_common`] performs the per-IRQ vector `XSAVE`/`XRSTOR`.
///
/// `0` until [`crate::simd::enable`] turns on `CR4.OSXSAVE` + `XCR0` and validates
/// the save area, then `1`. `isr_common` reads it on entry and skips the save
/// entirely when `0` — so `xsave` is executed **only** when it is architecturally
/// legal (after `OSXSAVE`), and the interrupt path is byte-for-byte unchanged on a
/// CPU without vector state. `enable` runs in the interrupts-off boot window, so the
/// `0 → 1` transition is never observed part-way through an interrupt.
///
/// **SMP hazard — must fix before AP interrupt bring-up.** This is a single **global**
/// flag, but `CR4.OSXSAVE` is **per-core**. Once APs start, if the BSP has armed this
/// and an AP takes *any* interrupt before running its own [`crate::simd::enable`],
/// `isr_common` on that AP would execute `xsave` with `OSXSAVE` unset → `#UD`. So each
/// AP must set `OSXSAVE` (via `simd::enable`) **before enabling interrupts**, and this
/// flag must then become per-core (or the `xsave` gate a per-core check). Not
/// triggerable today (single-core; no AP handler path). See the vector-state design
/// doc. Referenced from `isr_common`'s `global_asm!` via `sym` (works with the mangled
/// name — no `#[no_mangle]` needed).
static VECTOR_SAVE_ARMED: AtomicU8 = AtomicU8::new(0);

/// Arm the per-IRQ vector save in [`isr_common`]. Called once by
/// [`crate::simd::enable`] after it has enabled vector state and confirmed both the
/// `XSAVE` area size fits [`VECTOR_SAVE_AREA_MAX`] and the `xsave`/`xrstor`
/// round-trip self-test passes. Idempotent; a plain relaxed store (single writer at
/// boot, interrupts off).
pub(crate) fn arm_vector_save() {
    VECTOR_SAVE_ARMED.store(1, Ordering::Relaxed);
}

/// Read whether the per-IRQ (and, for the cooperative scheduler, per-task)
/// vector `XSAVE`/`XRSTOR` bracket is armed.
///
/// Mirrors [`isr_common`]'s own gate for callers outside this module that need
/// the same "is it architecturally legal to `xsave`/`xrstor` right now" check —
/// currently [`crate::context::switch`] (see the scheduler design doc's TCB
/// delta, CX4), which must skip the eager per-task vector save exactly like
/// `isr_common` does before [`crate::simd::enable`] has armed it (otherwise
/// `xsave`/`xrstor` would `#UD` with `CR4.OSXSAVE` unset). A plain relaxed
/// atomic load; adds no new unsafe op.
pub(crate) fn vector_state_armed() -> bool {
    VECTOR_SAVE_ARMED.load(Ordering::Relaxed) != 0
}

/// A 64-bit IDT gate descriptor (16 bytes), hardware layout.
///
/// Splits the 64-bit handler address across three fields (`offset_low`,
/// `offset_mid`, `offset_high`) and carries the code selector, an IST index, and
/// a type/attributes byte. `#[repr(C, packed)]` pins the on-wire layout the CPU
/// reads.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct GateDescriptor {
    offset_low: u16,
    selector: u16,
    /// Bits 0..2 select the IST (0 = none); bits 3..7 are reserved/zero.
    ist: u8,
    /// Type and attributes: present, DPL, gate type (interrupt vs trap).
    type_attr: u8,
    offset_mid: u16,
    offset_high: u32,
    reserved: u32,
}

impl GateDescriptor {
    /// An all-zero (non-present) gate.
    const fn missing() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            type_attr: 0,
            offset_mid: 0,
            offset_high: 0,
            reserved: 0,
        }
    }

    /// Build a present 64-bit **interrupt gate** for `handler`, running on IST
    /// index `ist` (0 = use the current stack), at DPL 0.
    ///
    /// Type byte `0x8E` = present (`0x80`) · DPL 0 · 64-bit interrupt gate
    /// (`0x0E`). An interrupt gate clears IF on entry, so nested maskable
    /// interrupts cannot pre-empt a handler.
    fn new(handler: u64, ist: u8) -> Self {
        Self {
            offset_low: (handler & 0xFFFF) as u16,
            selector: KERNEL_CODE_SELECTOR,
            ist: ist & 0x7,
            type_attr: 0x8E,
            offset_mid: ((handler >> 16) & 0xFFFF) as u16,
            offset_high: ((handler >> 32) & 0xFFFF_FFFF) as u32,
            reserved: 0,
        }
    }
}

/// The Interrupt Descriptor Table in static storage.
///
/// `static mut` because each gate's handler-offset bits are the runtime
/// addresses of the assembly stubs; the table is filled in once by [`init`] and
/// thereafter only read by the CPU.
static mut IDT: [GateDescriptor; IDT_ENTRIES] = [GateDescriptor::missing(); IDT_ENTRIES];

/// The operand layout for `lidt`: a 16-bit limit and a 64-bit base, packed.
#[repr(C, packed)]
struct DescriptorTablePointer {
    limit: u16,
    base: u64,
}

// ── ISR stubs (stable global_asm!) ──────────────────────────────────────────
//
// We generate one tiny entry stub per vector with assembler macros, then a
// single shared `isr_common` tail. Each per-vector stub normalises the stack
// (synthetic error code where the CPU pushes none), pushes the vector number,
// and jumps to the common tail. The common tail saves registers, calls the
// Rust trampoline with a pointer to the assembled frame, restores, and `iretq`s.
//
// Vectors that push a hardware error code (per the AMD64 manual): 8, 10, 11, 12,
// 13, 14, 17, 21, 29, 30. For all others the CPU pushes no error code, so the
// `isr_noerr` macro inserts a synthetic 0 to keep the frame uniform.

global_asm!(
    r#"
.section .text

// Common tail shared by every vector stub. On entry the stack already holds
// (low -> high): vector, error_code, rip, cs, rflags, rsp, ss. We push the 15
// general-purpose registers below the vector so the full image matches
// `InterruptFrame` (r15 lowest), point rdi at it, and call the trampoline.
.global isr_common
isr_common:
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    // rdi = &InterruptFrame (points at the lowest saved reg, r15).
    mov rdi, rsp
    // rbp = frame base; the general-purpose register restore returns rsp here.
    mov rbp, rsp

    // ── Per-IRQ vector save (gated on VECTOR_SAVE_ARMED) ──────────────────────
    // Belt-and-suspenders: on this soft-float target compiled handlers contain no
    // vector instructions (CI-enforced), so they cannot clobber an interrupted
    // GEMM's YMM/ZMM state — but we also save it here so even a (guard-forbidden)
    // vector-using handler is safe. If not armed (before simd::enable, or a CPU
    // without xsave), skip: r15 = 0 marks "nothing saved" and drives the exit path
    // to skip the restore too, so save and restore are decided by the SAME value
    // and can never mismatch.
    lea rbx, [rip + {armed}]
    cmp byte ptr [rbx], 0
    jne 1f
    xor r15, r15
    jmp 2f
1:
    // Reserve a 64-byte-aligned XSAVE area on the interrupt stack.
    sub rsp, {area_size}
    and rsp, -64
    // Zero the 64-byte XSAVE header (offset 512..576): XSTATE_BV, XCOMP_BV, and the
    // reserved bytes — so the later XRSTOR reads standard (non-compacted) format and
    // does not #GP.
    mov qword ptr [rsp + 512], 0
    mov qword ptr [rsp + 520], 0
    mov qword ptr [rsp + 528], 0
    mov qword ptr [rsp + 536], 0
    mov qword ptr [rsp + 544], 0
    mov qword ptr [rsp + 552], 0
    mov qword ptr [rsp + 560], 0
    mov qword ptr [rsp + 568], 0
    // Save every XCR0-enabled component (mask edx:eax = -1, intersected with XCR0).
    mov eax, -1
    mov edx, -1
    xsave [rsp]
    // r15 = save-area pointer; callee-saved, so the trampoline preserves it.
    mov r15, rsp
2:
    // Keep the 16-byte stack alignment the SysV ABI expects at a `call`, saving the
    // pre-call rsp (frame base, or the aligned save area) in callee-saved rbx.
    mov rbx, rsp
    and rsp, -16
    call {trampoline}
    mov rsp, rbx

    // ── Per-IRQ vector restore (only if we saved above: r15 != 0) ─────────────
    test r15, r15
    jz 3f
    mov eax, -1
    mov edx, -1
    xrstor [r15]
3:
    // Return rsp to the frame base for the general-purpose register restore.
    mov rsp, rbp

    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax

    // Drop the vector number and the (real or synthetic) error code, then return
    // from the interrupt. iretq pops rip, cs, rflags, rsp, ss.
    add rsp, 16
    iretq

// Enable altmacro so `%expr` evaluates an expression to its numeric value when
// passed as a macro argument, and `\num` concatenates that value into a symbol
// name (e.g. `isr_stub_\num` -> `isr_stub_13`).
.altmacro

// Macro: stub for a vector that does NOT push a hardware error code.
// Push a synthetic 0 so the frame layout matches the error-code case.
.macro ISR_NOERR num
.global isr_stub_\num
isr_stub_\num:
    push 0
    push \num
    jmp isr_common
.endm

// Macro: stub for a vector that DOES push a hardware error code (already on the
// stack); we only push the vector number.
.macro ISR_ERR num
.global isr_stub_\num
isr_stub_\num:
    push \num
    jmp isr_common
.endm

// Generate all 256 stubs. Error-code vectors per the AMD64 manual: 8, 10-14,
// 17, 21, 29, 30. The rest are no-error-code.
.set v, 0
.rept 256
    .if (v == 8) || (v == 10) || (v == 11) || (v == 12) || (v == 13) || (v == 14) || (v == 17) || (v == 21) || (v == 29) || (v == 30)
        ISR_ERR %v
    .else
        ISR_NOERR %v
    .endif
    .set v, v + 1
.endr

.noaltmacro
"#,
    trampoline = sym isr_trampoline,
    armed = sym VECTOR_SAVE_ARMED,
    area_size = const VECTOR_SAVE_AREA_MAX,
);

/// The `extern "C"` trampoline the assembly tail calls.
///
/// `frame` points at the assembled [`InterruptFrame`] on the interrupt stack
/// (the assembly guarantees the layout matches). We hand a shared reference to
/// the registered handler for the vector, or to the default reporter if none is
/// registered. This is the boundary where control crosses from `unsafe` asm into
/// safe Rust handler logic.
///
/// # Safety
///
/// Called *only* from `isr_common` with `frame` pointing at a fully-initialised
/// `InterruptFrame` that lives for the duration of the call. It is not part of
/// the public API.
#[no_mangle]
extern "C" fn isr_trampoline(frame: *const InterruptFrame) {
    // SAFETY: `frame` is produced by `isr_common`, which set `rdi` to the base of
    // the stack image it just built; that image is laid out field-for-field as
    // `InterruptFrame` (saved regs, vector, error code, CPU frame) and remains
    // valid, properly aligned, and unaliased for the whole call (the stub does
    // not touch that memory again until after we return). So forming a shared
    // reference is sound.
    let frame: &InterruptFrame = unsafe { &*frame };
    let vector = frame.vector as u8;

    match handler_for(vector) {
        Some(handler) => handler(frame),
        None => default_handler(frame),
    }
}

/// Fallback handler used when no handler is registered for a vector.
///
/// Reports the vector and the saved instruction pointer/error code over serial,
/// then parks the core. This is the structural backstop that turns an otherwise
/// unhandled exception into a serial report instead of a triple fault. Kept in
/// `hal` (rather than `kernel`) so it works even before the kernel has
/// registered anything, and it deliberately uses only `&'static str` + simple
/// hex formatting (no allocation, no panics) on the fault path.
fn default_handler(frame: &InterruptFrame) {
    // Copy out of the packed/`#[repr(C)]` frame into locals before reporting so
    // we never take a reference into a potentially misaligned field.
    let vector = frame.vector;
    let error_code = frame.error_code;
    let rip = frame.rip;
    let rflags = frame.rflags;

    // Report via the fmt-arg-free serial helpers. The fault path must not route
    // integer arguments through `core::fmt`'s machinery, which page-faults on
    // this bare-metal target (an early fault while *reporting* a fault would be
    // catastrophic). See `crate::serial::print_labeled_hex`.
    crate::serial::print_line("");
    crate::serial::print_line("!!! UNHANDLED CPU EXCEPTION !!!");
    crate::serial::print_labeled_dec("  vector     = ", vector);
    crate::serial::print_labeled_hex("  error_code = ", error_code);
    crate::serial::print_labeled_hex("  rip        = ", rip);
    crate::serial::print_labeled_hex("  rflags     = ", rflags);
    crate::serial::print_line("[hal] no handler registered; halting core.");

    crate::cpu::halt_loop()
}

/// Read the address of ISR stub number `n`.
///
/// The stubs are emitted with names `isr_stub_0`..`isr_stub_255` by the
/// `global_asm!` block. Rather than declare 256 `extern` symbols, we resolve
/// each stub's address via a tiny per-index `global_asm!`-exported pointer table
/// (`ISR_STUB_TABLE`) so the addresses are available as data.
fn stub_addr(n: usize) -> u64 {
    // SAFETY: `ISR_STUB_TABLE` is a read-only array of 256 function-pointer-sized
    // entries emitted by the assembler, each the address of `isr_stub_<n>`. We
    // only ever index `0..IDT_ENTRIES` (== the table length), so the read is in
    // bounds. The values are code addresses we never dereference here — we only
    // store them into IDT gates. Reading a `*const u64` element is sound.
    unsafe {
        let table = core::ptr::addr_of!(ISR_STUB_TABLE) as *const u64;
        table.add(n).read()
    }
}

// A data table of stub addresses, one quadword per vector, emitted in assembly.
// Keeps Rust from needing 256 `extern fn` declarations while still resolving
// every stub's address at link time.
global_asm!(
    r#"
.altmacro
// Emit one `.quad` holding the address of `isr_stub_<num>`.
.macro STUB_ADDR num
    .quad isr_stub_\num
.endm

.section .rodata
.align 8
.global ISR_STUB_TABLE
ISR_STUB_TABLE:
.set v, 0
.rept 256
    STUB_ADDR %v
    .set v, v + 1
.endr
.noaltmacro
"#
);

extern "C" {
    /// The assembler-emitted table of 256 stub addresses (see the `global_asm!`
    /// above). Imported as an opaque symbol; addressed via [`stub_addr`].
    static ISR_STUB_TABLE: u8;
}

/// Build and load the IDT.
///
/// Installs a gate for every vector pointing at its assembly stub. The
/// double-fault vector (8) is given the dedicated IST stack
/// ([`DOUBLE_FAULT_IST_INDEX`]) so it runs on a known-good stack even if the
/// regular stack is corrupt. Then `lidt` loads the table.
///
/// Must be called **after** [`crate::gdt::init`] (the gates reference the GDT's
/// kernel-code selector and the IST the TSS provides). Idempotent and infallible
/// by construction.
pub fn init() {
    // SAFETY: We fill the `static mut IDT` and then `lidt` it. Sound because
    // `init` runs exactly once on the boot core with interrupts disabled, so no
    // concurrent access or aliasing `&mut` exists; every gate is built from a
    // valid stub address and the present kernel-code selector; and loading a
    // well-formed IDT cannot corrupt Rust memory (it only tells the CPU where to
    // vector faults). Per-instruction notes below.
    unsafe {
        let idt_ptr = core::ptr::addr_of_mut!(IDT);
        let mut vector = 0;
        while vector < IDT_ENTRIES {
            let handler = stub_addr(vector);
            // The double-fault gate runs on the dedicated IST stack; all other
            // gates use the current stack (IST index 0 = "none").
            let ist = if vector == 8 {
                (DOUBLE_FAULT_IST_INDEX as u8) + 1
            } else {
                0
            };
            (*idt_ptr)[vector] = GateDescriptor::new(handler, ist);
            vector += 1;
        }

        let idtr = DescriptorTablePointer {
            limit: (IDT_ENTRIES * size_of::<GateDescriptor>() - 1) as u16,
            base: idt_ptr as u64,
        };
        // SAFETY: `lidt [mem]` loads the IDTR from a 10-byte pointer whose `base`
        // is our fully-initialised `IDT` and whose `limit` is its exact byte
        // length − 1. The operand is read-only (`readonly`); loading a valid IDT
        // arms fault delivery without changing any register or memory.
        core::arch::asm!(
            "lidt [{ptr}]",
            ptr = in(reg) &idtr,
            options(readonly, nostack, preserves_flags),
        );
    }
}

// Compile-time sanity: a gate descriptor is exactly 16 bytes, so a 256-entry
// IDT is 4096 bytes and our `limit` arithmetic is correct.
const _: () = assert!(size_of::<GateDescriptor>() == 16);
const _: () = assert!(size_of::<InterruptFrame>() == 15 * 8 + 7 * 8);
