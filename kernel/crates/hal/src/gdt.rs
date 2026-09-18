//! Global Descriptor Table (GDT) + Task State Segment (TSS) — part of the TCB.
//!
//! In 64-bit long mode the GDT no longer carves up the address space (paging
//! does that), but a valid GDT is still mandatory: the CPU needs well-formed
//! code/data segment descriptors to run in ring 0, and — crucially for
//! sub-project #2a — a **TSS** with an **Interrupt Stack Table (IST)** so that a
//! fatal nested fault (e.g. a double fault, or a fault while the stack pointer
//! is corrupt) is delivered onto a *known-good* stack instead of cascading into
//! a triple fault and a silent CPU reset.
//!
//! This module builds, in static storage:
//!
//! - a **GDT** of four 8-byte entries (null, kernel code, kernel data) plus one
//!   16-byte **TSS descriptor** (a system descriptor occupies two GDT slots in
//!   long mode), and
//! - a **TSS** whose `IST[0]` points at a dedicated, statically-allocated
//!   double-fault stack.
//!
//! It then `lgdt`s the table, reloads `CS` via a far return, reloads the data
//! segment registers, and `ltr`s the TSS selector. The safe [`init`] does this
//! for the bootstrap processor; the crate-private [`init_ap`] does the same for
//! an application processor from its own per-AP slot of tables (a TSS goes
//! *busy* on `ltr`, so cores cannot share one). Everything privileged is
//! confined to documented `unsafe` blocks and registered in
//! `kernel/docs/hal-tcb.md`.
//!
//! Hand-rolled by design (spec §4): we deliberately do **not** pull in the
//! `x86_64` crate, so the entire descriptor-table TCB is auditable in-tree and
//! free of external `unsafe`.

use core::arch::asm;
use core::mem::size_of;

/// Selector (byte offset into the GDT) of the kernel code segment.
///
/// The kernel code descriptor is GDT entry 1, so its selector is `1 * 8 = 0x08`
/// with RPL 0. This is the value the IDT's gate descriptors reference, so it is
/// re-exported for [`crate::idt`].
pub const KERNEL_CODE_SELECTOR: u16 = 0x08;

/// Selector (byte offset into the GDT) of the kernel data segment.
///
/// Kernel data is GDT entry 2 → selector `2 * 8 = 0x10`, RPL 0.
pub const KERNEL_DATA_SELECTOR: u16 = 0x10;

/// Selector of the TSS descriptor.
///
/// The TSS descriptor begins at GDT entry 3 → selector `3 * 8 = 0x18`, RPL 0.
/// `ltr` loads this selector into the task register.
pub const TSS_SELECTOR: u16 = 0x18;

/// Index into the TSS's Interrupt Stack Table used for the double-fault stack.
///
/// IST entries are 1-based in the IDT gate's `ist` field but 0-based in the TSS
/// layout; this constant is the **TSS-array index** (0). The matching IDT gate
/// stores `ist = DOUBLE_FAULT_IST_INDEX + 1` (see [`crate::idt`]).
pub const DOUBLE_FAULT_IST_INDEX: usize = 0;

/// Size of the dedicated double-fault stack (16 KiB).
///
/// Generous for the report-and-halt path (spec §11 suggests ≥4 KiB); 16 KiB
/// leaves head-room for the serial-formatting call chain even if the regular
/// kernel stack was the thing that overflowed.
const IST_STACK_SIZE: usize = 16 * 1024;

/// 64-bit-aligned backing storage for the double-fault IST stack.
///
/// Wrapped in a `#[repr(C, align(16))]` newtype so the stack top is 16-byte
/// aligned (the x86-64 SysV ABI's stack-alignment requirement at a `call`
/// boundary). The stack grows downward, so the *top* is the address one past the
/// last byte of this array.
#[repr(C, align(16))]
struct IstStack([u8; IST_STACK_SIZE]);

/// The double-fault stack itself, in `.bss` (zero-initialised static storage).
///
/// `static mut` is required because the address-of the top must be a runtime
/// value baked into the TSS, and the region is genuinely a CPU-owned stack (the
/// CPU writes to it on a double fault). It is written by the CPU, never aliased
/// by Rust code after [`init`] records its top in the TSS.
static mut DOUBLE_FAULT_STACK: IstStack = IstStack([0; IST_STACK_SIZE]);

/// A 64-bit Task State Segment, hardware layout (`#[repr(C, packed)]`).
///
/// In long mode the TSS no longer holds a task context; the fields the CPU
/// actually consults are the privilege-level stack pointers (`rsp0..2`) and the
/// **Interrupt Stack Table** (`ist1..7`). We only populate `ist[0]`
/// (the double-fault stack). `iomap_base` is set past the segment limit to
/// indicate "no I/O permission bitmap".
#[repr(C, packed)]
struct TaskStateSegment {
    reserved_0: u32,
    /// Stack pointers for privilege levels 0–2 (`rsp0`, `rsp1`, `rsp2`).
    privilege_stack_table: [u64; 3],
    reserved_1: u64,
    /// The Interrupt Stack Table: `ist[0]`..`ist[6]` map to IST1..IST7.
    interrupt_stack_table: [u64; 7],
    reserved_2: u64,
    reserved_3: u16,
    /// Offset to the I/O permission bitmap; set beyond the limit to disable it.
    iomap_base: u16,
}

impl TaskStateSegment {
    /// A zeroed TSS with the I/O map disabled.
    const fn new() -> Self {
        Self {
            reserved_0: 0,
            privilege_stack_table: [0; 3],
            reserved_1: 0,
            interrupt_stack_table: [0; 7],
            reserved_2: 0,
            reserved_3: 0,
            // No I/O bitmap: point past the TSS limit (its own size).
            iomap_base: size_of::<Self>() as u16,
        }
    }
}

/// The bootstrap processor's Task State Segment.
///
/// `static mut` because its `ist[0]` field is filled in at runtime with the
/// address of [`DOUBLE_FAULT_STACK`]'s top, and the CPU references it by
/// physical/linear address via the TSS descriptor after `ltr`. Application
/// processors get their own (see [`init_ap`]): a TSS descriptor is marked *busy*
/// by `ltr`, so one TSS cannot be loaded on two cores, and each core's
/// double-fault IST stack must be distinct anyway.
static mut TSS: TaskStateSegment = TaskStateSegment::new();

// ── Per-application-processor descriptor tables (SMP) ────────────────────────

/// Number of application-processor table slots: every CPU but the BSP.
pub(crate) const MAX_APS: usize = crate::smp::MAX_CPUS - 1;

/// Size of each AP's double-fault IST stack (8 KiB).
///
/// Half the BSP's: the AP double-fault path is the same report-and-halt chain,
/// and 8 KiB × [`MAX_APS`] keeps the static footprint modest.
const AP_IST_STACK_SIZE: usize = 8 * 1024;

/// 16-byte-aligned backing storage for one AP's double-fault IST stack.
#[repr(C, align(16))]
struct ApIstStack([u8; AP_IST_STACK_SIZE]);

/// Per-AP double-fault stacks (`.bss`), indexed by AP slot. CPU-written only.
static mut AP_DOUBLE_FAULT_STACKS: [ApIstStack; MAX_APS] =
    [const { ApIstStack([0; AP_IST_STACK_SIZE]) }; MAX_APS];

/// Per-AP Task State Segments, indexed by AP slot (`ist[0]` filled by [`init_ap`]).
static mut AP_TSS: [TaskStateSegment; MAX_APS] = [const { TaskStateSegment::new() }; MAX_APS];

/// Per-AP GDTs, indexed by AP slot. Same layout as [`GDT`]; only the TSS
/// descriptor (entries 3/4) differs per core.
static mut AP_GDT: [[u64; GDT_ENTRIES]; MAX_APS] = [[0; GDT_ENTRIES]; MAX_APS];

/// Number of 8-byte slots in the GDT: null + code + data + 2 for the TSS.
const GDT_ENTRIES: usize = 5;

/// The Global Descriptor Table: an array of raw 8-byte descriptors.
///
/// Layout:
/// - `[0]` null descriptor (required to be all-zero),
/// - `[1]` kernel code (`0x08`),
/// - `[2]` kernel data (`0x10`),
/// - `[3]`,`[4]` the 16-byte TSS system descriptor (`0x18`).
///
/// `static mut` because the TSS descriptor's base-address bits are only known at
/// runtime (the address of [`TSS`]); the rest are compile-time constants.
static mut GDT: [u64; GDT_ENTRIES] = [0; GDT_ENTRIES];

/// The operand layout for the `lgdt` instruction: a 16-bit limit followed by a
/// 64-bit base, packed with no padding.
#[repr(C, packed)]
struct DescriptorTablePointer {
    /// Size of the table in bytes, minus one.
    limit: u16,
    /// Linear base address of the table.
    base: u64,
}

// ── Code/data descriptor access-byte and flag bits ──────────────────────────
//
// A long-mode code/data descriptor packs the access byte into bits 40..47 and
// the flags nibble into bits 52..55 of the 64-bit descriptor. Base and limit are
// ignored by the CPU for long-mode code/data (paging governs addressing), so we
// set only the bits that matter.

/// Access byte: segment present (P).
const ACCESS_PRESENT: u64 = 1 << 47;
/// Access byte: descriptor type = code/data (S), not a system segment.
const ACCESS_USER_SEGMENT: u64 = 1 << 44;
/// Access byte: executable (this is a code segment).
const ACCESS_EXECUTABLE: u64 = 1 << 43;
/// Access byte: readable code / writable data.
const ACCESS_RW: u64 = 1 << 41;
/// Flags: long-mode (64-bit) code segment (the `L` bit).
const FLAG_LONG_MODE: u64 = 1 << 53;

/// Build a long-mode kernel **code** segment descriptor.
const fn code_descriptor() -> u64 {
    ACCESS_PRESENT | ACCESS_USER_SEGMENT | ACCESS_EXECUTABLE | ACCESS_RW | FLAG_LONG_MODE
}

/// Build a kernel **data** segment descriptor.
///
/// Data segments are not executable and do not set the `L` bit; `RW` here means
/// "writable".
const fn data_descriptor() -> u64 {
    ACCESS_PRESENT | ACCESS_USER_SEGMENT | ACCESS_RW
}

/// Build the two 8-byte halves of a 64-bit TSS **system** descriptor for a TSS
/// at linear address `base` with byte length `limit` (length − 1).
///
/// Returns `(low, high)` where `low` goes in `GDT[3]` and `high` in `GDT[4]`.
/// The type nibble `0x9` marks an available 64-bit TSS; the present bit is set;
/// DPL is 0.
const fn tss_descriptor(base: u64, limit: u32) -> (u64, u64) {
    // Low half: limit[0:15], base[0:23], type/access, limit[16:19], base[24:31].
    let mut low: u64 = 0;
    low |= (limit as u64) & 0xFFFF; // limit 0..15
    low |= (base & 0xFF_FFFF) << 16; // base 0..23
    low |= 0x9 << 40; // type = available 64-bit TSS
    low |= 1 << 47; // present
    low |= ((limit as u64 >> 16) & 0xF) << 48; // limit 16..19
    low |= ((base >> 24) & 0xFF) << 56; // base 24..31

    // High half: base[32:63] in the low 32 bits, rest reserved (zero).
    let high: u64 = (base >> 32) & 0xFFFF_FFFF;
    (low, high)
}

/// Install the GDT + TSS and switch the CPU onto them.
///
/// Steps, in order:
/// 1. Fill the TSS's `ist[0]` with the top of the double-fault stack.
/// 2. Compose the GDT (code, data, and the TSS descriptor built from `&TSS`).
/// 3. `lgdt` the new table.
/// 4. Reload `CS` to the kernel-code selector via a far return.
/// 5. Reload the data segment registers to the kernel-data selector.
/// 6. `ltr` the TSS selector so `ist[0]` is live.
///
/// Idempotent and infallible by construction (it programs fixed static tables).
/// Must be called exactly once, on the boot path, **before** [`crate::idt::init`]
/// (the IDT's gates reference [`KERNEL_CODE_SELECTOR`], which only becomes valid
/// once this GDT is loaded).
pub fn init() {
    // SAFETY: We take raw pointers to the BSP's `static mut` TSS/stack/GDT and
    // hand them to `install`. Sound because `init` is documented to run exactly
    // once on the boot core before interrupts are enabled, so there is no
    // concurrent access to these statics and no aliasing `&mut` exists elsewhere;
    // the stack top is computed from the static's own address/size (one past the
    // end of the array — the stack grows down), so `install`'s preconditions
    // (exclusively-owned table storage for this core, a valid IST stack top,
    // interrupts masked) all hold.
    unsafe {
        let stack_bottom = core::ptr::addr_of_mut!(DOUBLE_FAULT_STACK) as *mut u8;
        let stack_top = stack_bottom.add(IST_STACK_SIZE) as u64;
        install(
            core::ptr::addr_of_mut!(GDT),
            core::ptr::addr_of_mut!(TSS),
            stack_top,
        );
    }
}

/// Build and load a **private** GDT + TSS (with its own double-fault IST stack)
/// for application processor `slot` (`0..MAX_APS`), on the calling AP.
///
/// The code/data descriptors are identical to the BSP's — the selectors
/// [`KERNEL_CODE_SELECTOR`] / [`KERNEL_DATA_SELECTOR`] / [`TSS_SELECTOR`] mean the
/// same thing on every core, which is what lets the **shared** IDT (whose gates
/// name [`KERNEL_CODE_SELECTOR`]) be loaded unchanged on each AP. Only the TSS
/// differs per core: `ltr` marks a TSS descriptor *busy*, so a second core cannot
/// load the BSP's, and each core's IST stack must be its own memory.
///
/// Returns `false` (doing nothing) if `slot` is out of range. Must be called
/// **once per AP**, on that AP, with interrupts masked — which is exactly how
/// `hal::smp::ap_entry` calls it (slot = dense cpu index − 1, unique per AP).
pub(crate) fn init_ap(slot: usize) -> bool {
    if slot >= MAX_APS {
        return false;
    }
    // SAFETY: `slot < MAX_APS` (checked), so each `.add(slot)` stays inside its
    // static array. Each slot is used by exactly one AP (the kernel hands out
    // dense cpu indices uniquely and starts APs serially), and that AP is the
    // only core that ever touches its slot — so the table storage is exclusively
    // owned by the calling core, unaliased, and never concurrently accessed. The
    // IST stack top is one past the end of that slot's `ApIstStack` (the stack
    // grows down). Interrupts are masked on an AP until after `ap_entry`'s
    // privileged sequence. These are `install`'s preconditions.
    unsafe {
        let stacks = core::ptr::addr_of_mut!(AP_DOUBLE_FAULT_STACKS) as *mut ApIstStack;
        let stack_bottom = stacks.add(slot) as *mut u8;
        let stack_top = stack_bottom.add(AP_IST_STACK_SIZE) as u64;
        let gdt = (core::ptr::addr_of_mut!(AP_GDT) as *mut [u64; GDT_ENTRIES]).add(slot);
        let tss = (core::ptr::addr_of_mut!(AP_TSS) as *mut TaskStateSegment).add(slot);
        install(gdt, tss, stack_top);
    }
    true
}

/// Program `gdt_ptr`/`tss_ptr` and switch the **calling core** onto them.
///
/// Steps, in order:
/// 1. Fill the TSS's `ist[0]` with `ist_top`.
/// 2. Compose the GDT (code, data, and the TSS descriptor built from `tss_ptr`).
/// 3. `lgdt` the new table.
/// 4. Reload `CS` to the kernel-code selector via a far return.
/// 5. Reload the data segment registers to the kernel-data selector.
/// 6. `ltr` the TSS selector so `ist[0]` is live.
///
/// # Safety
///
/// `gdt_ptr` and `tss_ptr` must point at `'static` table storage owned
/// exclusively by the calling core (no other core or reference accesses it, ever);
/// `ist_top` must be the 16-byte-aligned top of a valid, otherwise-unused stack;
/// and interrupts must be masked on the calling core for the duration. Call once
/// per core.
unsafe fn install(gdt_ptr: *mut [u64; GDT_ENTRIES], tss_ptr: *mut TaskStateSegment, ist_top: u64) {
    // SAFETY: We program the caller-owned tables through raw pointers, then load
    // them into this CPU. This is sound because:
    //   * By this function's contract the tables are exclusively owned by the
    //     calling core and interrupts are masked, so there is no concurrent
    //     access and no aliasing `&mut` exists elsewhere.
    //   * We compute the TSS base/limit from the table's own address/size and take
    //     `ist_top` from a valid stack, so every descriptor field is
    //     self-consistent.
    //   * The descriptor bit-layouts (`code_descriptor`/`data_descriptor`/
    //     `tss_descriptor`) follow the AMD64 manual; loading well-formed
    //     descriptors cannot corrupt Rust-managed memory.
    // Each individual privileged instruction has its own SAFETY note below.
    unsafe {
        // (1) Record the double-fault stack top in IST[0], via the raw pointer's
        // field (no intermediate reference to the static, avoiding any aliasing
        // question).
        (*tss_ptr).interrupt_stack_table[DOUBLE_FAULT_IST_INDEX] = ist_top;

        // (2) Compose the GDT. Entries 1/2 are compile-time constants; the TSS
        // descriptor (entries 3/4) is built from the runtime address of the TSS.
        let tss_base = tss_ptr as u64;
        let tss_limit = (size_of::<TaskStateSegment>() - 1) as u32;
        let (tss_low, tss_high) = tss_descriptor(tss_base, tss_limit);

        (*gdt_ptr)[0] = 0; // null
        (*gdt_ptr)[1] = code_descriptor();
        (*gdt_ptr)[2] = data_descriptor();
        (*gdt_ptr)[3] = tss_low;
        (*gdt_ptr)[4] = tss_high;

        // (3) Load the GDT register.
        let gdtr = DescriptorTablePointer {
            limit: (GDT_ENTRIES * size_of::<u64>() - 1) as u16,
            base: gdt_ptr as u64,
        };
        // SAFETY: `lgdt [mem]` loads the GDTR from a 10-byte `DescriptorTablePointer`
        // whose `base` points at our well-formed `GDT` array and whose `limit` is
        // its exact byte length − 1. Loading a valid GDT does not by itself change
        // execution; the active selectors are only refreshed by the reloads below.
        // The operand is read-only memory (`readonly`); no other registers change.
        asm!(
            "lgdt [{ptr}]",
            ptr = in(reg) &gdtr,
            options(readonly, nostack, preserves_flags),
        );

        // (4) Reload CS. `mov cs, reg` is illegal in long mode; the canonical way
        // to reload CS is a far transfer. We push the new selector and a return
        // address, then `retfq` (far return) which pops RIP and CS together.
        //
        // SAFETY: We push the target selector (kernel code, `0x08`) and the
        // address of label `2:` (the very next instruction), then `retfq`, which
        // pops them into CS:RIP. Control lands at `2:` with CS reloaded. The
        // selector indexes our just-loaded GDT's present 64-bit code descriptor,
        // so this is a valid same-privilege far return. We touch the stack
        // (push/retf), so no `nostack`. (Labels `0`/`1` are avoided per the
        // `binary_asm_labels` lint — an LLVM x86 ambiguity with binary literals.)
        asm!(
            "push {sel}",
            "lea {tmp}, [rip + 2f]",
            "push {tmp}",
            "retfq",
            "2:",
            sel = in(reg) KERNEL_CODE_SELECTOR as u64,
            tmp = lateout(reg) _,
            options(preserves_flags),
        );

        // (5) Reload the data segment registers to the kernel-data selector.
        //
        // SAFETY: loads SS/DS/ES/FS/GS with the kernel-data selector (`0x10`),
        // which indexes our present, writable data descriptor. In long mode the
        // segment bases for these are treated as 0; this simply makes the
        // selectors consistent with the new GDT. `ax` is clobbered as a scratch.
        asm!(
            "mov ss, {sel:x}",
            "mov ds, {sel:x}",
            "mov es, {sel:x}",
            "mov fs, {sel:x}",
            "mov gs, {sel:x}",
            sel = in(reg) KERNEL_DATA_SELECTOR,
            options(nostack, preserves_flags),
        );

        // (6) Load the task register with the TSS selector so IST[0] is active.
        //
        // SAFETY: `ltr` loads the task register from the TSS selector (`0x18`),
        // which indexes the available-64-bit-TSS descriptor we built in entries
        // 3/4 pointing at this core's TSS (never loaded on any other core, so it
        // is *available*, not *busy*). After this, a fault routed to IST[0] (the
        // double-fault gate) switches to this core's double-fault stack. Loading
        // a valid TSS selector cannot corrupt memory; it only arms the IST
        // mechanism.
        asm!(
            "ltr {sel:x}",
            sel = in(reg) TSS_SELECTOR,
            options(nostack, preserves_flags),
        );
    }
}
