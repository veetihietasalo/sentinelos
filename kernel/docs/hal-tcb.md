# HAL TCB Registry — SentinelOS

This document is the authoritative registry of **every `unsafe` operation** in
the SentinelOS Trusted Computing Base. The `hal` crate is the *only* crate
permitted to use `unsafe`; the `kernel` crate carries `#![forbid(unsafe_code)]`.
Each entry below names the unsafe primitive, why it is necessary, why it is
sound, and its formal-verification status.

- **Owner:** hal-specialist
- **Scope:** sub-project #1 (boot bring-up) — serial console + CPU primitives;
  sub-project #2a (interrupts) — GDT/TSS/IST, IDT, and the raw ISR stubs;
  sub-project #2 part 1 (memory) — frame allocator, paging, kernel heap +
  `#[global_allocator]` (`hal::mm`, §5);
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

---

## 5. `hal::mm` — memory management (sub-project #2 part 1)

Brings the kernel from "no heap" to a working `#[global_allocator]`: a physical
frame allocator over the firmware memory map, virtual page mapping **on top of**
Limine's already-active 4-level paging + HHDM, and a free-list kernel heap. The
public API is **entirely safe** — `mm::init()` returns a `Result`, the frame
allocator and heap expose safe `alloc`/`dealloc`, and the `kernel` crate only
*declares* the `#[global_allocator]` static (declaring a static is not `unsafe`),
so `kernel` stays `#![forbid(unsafe_code)]`. The single `unsafe impl GlobalAlloc`
and every raw page-table / frame / heap-header access live here, below.

The pipeline (`mm::init` → frame allocator seed → heap-page mapping → install
global allocator) is single-call, single-core, interrupts already armed. Page
tables and free frames are reached through the HHDM (`virt = phys + hhdm`), which
Limine maps over all physical RAM and keeps live (we never replace CR3).

### 5a. `hal::mm::bootinfo` — Limine memory-map + HHDM requests

Owns `#[used] static MEMORY_MAP_REQUEST: MemoryMapRequest` and `#[used] static
HHDM_REQUEST: HhdmRequest` (same `#[used]` pattern as `FRAMEBUFFER_REQUEST`). The
safe accessors `usable_regions()` (USABLE entries only) and `hhdm_offset()` are
the only places these responses are dereferenced.

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| M1 | `mm/bootinfo.rs` · `hhdm_offset()` | deref the Limine **HHDM response** (`get_response()` → read `offset()`) | Only way to learn the `virt = phys + offset` direct-map offset used to reach page-table/frame memory | `get_response()` yields `Some(&HhdmResponse)` only after Limine atomically populated our `#[used]` request before `_start`; we never mutate the request, copy out the plain `u64` offset, and drop the borrow in-expression. | Reasoned + QEMU (Miri/Kani **pending**) |
| M2 | `mm/bootinfo.rs` · `usable_regions()` | deref the Limine **memory-map response** (`get_response()` → `entries()` slice → read `base`/`length`/`entry_type`) | Only way to learn which physical RAM the frame allocator may use | Response populated by Limine before `_start` (as M1); `entries()` reconstructs a slice from the bootloader-filled array; the borrow stays in the function and each `base`/`length` scalar is copied out into a `UsableRegion`. No response ⇒ empty iterator (never UB). Only `EntryType::USABLE` is surfaced, so reserved/ACPI/framebuffer/loader/kernel regions can never be handed out. | Reasoned + QEMU (Miri/Kani **pending**) |

### 5b. `hal::mm::frame` — physical frame allocator (intrusive free list)

A LIFO free list of 4 KiB frames seeded from the USABLE regions. Each free frame
stores the physical address of the next free frame in its own first 8 bytes,
reached through the HHDM. Safe API: `alloc_frame()` / `dealloc_frame()` /
`free_frames()`. Frame 0 and unaligned addresses are rejected, so a null-like
physical address can never be returned. State lives behind a `SpinMutex` (§5e).

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| M3 | `mm/frame.rs` · `FrameAllocator::init()` | `ptr::write((frame + hhdm) as *mut u64, next)` — store the next-pointer into each free frame | Build the intrusive free list without side metadata | `frame` is a 4 KiB-aligned address inside a USABLE region (so real, unowned RAM); Limine HHDM-maps all RAM, so `frame + hhdm` is a valid, writable, 8-byte-aligned virtual address; the frame is being placed on the list for the first time ⇒ unaliased. Frame 0 is skipped. Single-call, interrupts-armed, single-core. | Reasoned + QEMU |
| M4 | `mm/frame.rs` · `FrameAllocator::alloc_frame()` | `ptr::read((head + hhdm) as *const u64)` — read the next-pointer back | Pop the list head | `head` is a frame the allocator itself pushed (so real, aligned RAM, HHDM-mapped); the read recovers exactly the next-pointer written by M3/M6; it is the last access to the link field before the frame leaves the list ⇒ unaliased. | Reasoned + QEMU |
| M5 | `mm/frame.rs` · `FrameAllocator::dealloc_frame()` | `ptr::write((phys + hhdm) as *mut u64, head)` — push a frame back | Return a frame to the list | `phys` is 4 KiB-aligned (checked) and non-zero (checked); the caller has relinquished it, so `phys + hhdm` is a valid, writable, 8-byte-aligned, unaliased HHDM address for the link write. | Reasoned + QEMU |

### 5c. `hal::mm::paging` — virtual mapping on top of Limine's paging

Reaches the active PML4 via `CR3` + HHDM and installs new 4 KiB leaf mappings,
allocating + zeroing intermediate tables from the frame allocator. Safe API:
`ActivePageTable::map_page(virt, phys, flags, frames)`. We build **on** Limine's
tables (never replace CR3); `map_page` floors `virt`/`phys` to frames, refuses to
silently overwrite a present leaf (`MapError::AlreadyMapped`), and flushes the
TLB. `PageFlags` is a safe value type over the leaf permission bits.

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| M6 | `mm/paging.rs` · `ActivePageTable::pml4_phys()` | `mov {}, cr3` (read CR3) | Locate the active top-level page table | Privileged-but-side-effect-free register read; ring 0; `nomem`/`nostack`/`preserves_flags`. The PML4 base is masked out with `ADDR_MASK` (bits 12..51). Cannot violate memory safety. | Reasoned + QEMU |
| M7 | `mm/paging.rs` · `read_entry()` / `write_entry()` | `ptr::read` / `ptr::write` of a `u64` at `(table + hhdm) + index*8` | Read/insert page-table entries | `unsafe fn`s whose contract requires `table` to be a live table frame and `index < 512`; upheld by `map_page` (passes the CR3 PML4 or a child from `next_table_create`, plus 9-bit indices). Target is within the 4 KiB frame, 8-byte-aligned, HHDM-mapped (writable — RAM is writable and our table frames are USABLE RAM). Single-core/caller-serialised ⇒ no concurrent writer. | Reasoned + QEMU |
| M8 | `mm/paging.rs` · `new_table()` | manual `ptr::write(ptr.add(i), 0u64)` loop zeroing a fresh table frame | A new intermediate/leaf table must start all-non-present | The frame is freshly `alloc_frame`d (4 KiB-aligned USABLE RAM, HHDM-mapped, exclusively owned); each `ptr.add(i)` for `i < 512` is within the frame, 8-byte-aligned, writable, unaliased. **Deliberately a `u64` loop, not `ptr::write_bytes`** — `write_bytes` lowers to a `memset` libcall that *faults* on this higher-half static-relocation target (the `.got`/`.rela` sections it needs are discarded by the linker script; confirmed via QEMU). | Reasoned + QEMU (memset-libcall fault reproduced and avoided) |
| M9 | `mm/paging.rs` · `flush_tlb()` | `invlpg [mem]` | Drop any stale TLB entry for a newly-mapped page | Invalidates one page's cached translation; reads no Rust-modelled memory, no stack, preserves flags. Flushing a stale translation can only make accesses more correct — never UB. | Reasoned + QEMU |

### 5d. `hal::mm::heap` — free-list kernel heap + `GlobalAlloc`

A first-fit free list of variable-size blocks over a fixed higher-half window
(`HEAP_START = 0xFFFF_F000_0000_0000`, `HEAP_SIZE = 4 MiB`) that `mm::init` maps
to physical frames before use. Free-block headers live inside the free memory
itself. `LockedHeap` (a `SpinMutex<Heap>`) is the `#[global_allocator]` type the
`kernel` crate declares as a `static`. Alignments above 16 fail with null (the
kernel never requests more); `dealloc` coalesces with the adjacent free block.

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| M10 | `mm/heap.rs` · `Heap::install` / `alloc` / `dealloc` / `coalesce_from` | `ptr::write` / `ptr::read` of `FreeBlock` headers at block addresses inside the heap window | Maintain the free list with in-band metadata | All pointers are `ALIGN`(16)-aligned addresses inside the `[HEAP_START, HEAP_START+HEAP_SIZE)` region that `mm::init` mapped writable to real frames; headers are written only into free/just-freed blocks (unaliased); split/coalesce arithmetic keeps every header within its mapped block; the list is serialised by the enclosing `SpinMutex`. `dealloc` reconstructs the same block size from the `Layout` the runtime passes back. | Reasoned + QEMU (heap `Vec`/`Box` allocation proven at boot) |
| M11 | `mm/heap.rs` · `unsafe impl GlobalAlloc for LockedHeap` | implement `alloc` / `dealloc` | Install a `#[global_allocator]` so `alloc` (`Box`/`Vec`/`String`) works | Delegates to the free-list `Heap` under its `SpinMutex` (exclusive access per op). `alloc` returns null or a ≥`layout.size()`-byte block carved from the mapped heap, `ALIGN`-aligned (larger alignments → null, which `GlobalAlloc` permits); blocks are removed from the list on `alloc` and only re-added on `dealloc`, so no two live allocations overlap. `dealloc` is only ever called with a pointer/layout this allocator returned. | Reasoned + QEMU (boot proof: `[mem] heap ok: allocated NNN bytes`) |
| M12 | `mm/heap.rs` · `unsafe impl Send for Heap` | mark the free-list state `Send` | Let `SpinMutex<Heap>` be `Sync` and back the global-allocator `static` | `Heap`'s only non-`Send` field is the `head` raw pointer, which is null or points into the fixed heap window (valid for the program's life); it is never shared outside the `SpinMutex` that serialises all access. Moving a `Heap` does not invalidate the pointer. | Reasoned |

### 5e. `hal::mm::sync` — minimal spin mutex

A tiny `AtomicBool` compare-exchange spinlock so `mm`'s statics are `Sync`. At
bring-up the kernel is single-core, so it never actually spins; it exists to make
the types `Sync` and be correct under future SMP.

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| M13 | `mm/sync.rs` · `SpinGuard` `Deref`/`DerefMut` | `&*self.mutex.data.get()` / `&mut *…` — form a reference to the `UnsafeCell` interior | A mutex must hand out `&`/`&mut` to the guarded value while locked | Holding a `SpinGuard` proves the lock is acquired and is the unique guard (only one passes the `compare_exchange`), so forming the shared/exclusive reference is sound and cannot alias another guard's. Released on `Drop`. | Reasoned |
| M14 | `mm/sync.rs` · `unsafe impl Send + Sync for SpinMutex<T>` | mark the mutex `Send`/`Sync` (for `T: Send`) | Allow the guarded value to be shared/sent behind the lock | Mutual exclusion via the `locked` atomic means the inner `T` is never accessed by two threads at once — exactly the `Sync` invariant; sending the owned mutex is sound for `T: Send`. | Reasoned |

> **`fmt`-free serial helpers.** `mm`'s boot proof needs to print dynamic numbers,
> but `println!("{}", n)` *faults* on this target — `core::fmt`'s argument path
> needs `.got`/`.rela` relocations the linker script discards (same root cause as
> the `memset` fault in M8; both reproduced in QEMU). So `hal::serial` gained two
> **safe**, `fmt`-free helpers — `write_str(&str)` and `write_dec(u64)` (digits
> generated into a stack buffer, emitted with interrupts masked) — which the
> `kernel` crate uses to print `[mem] heap ok: allocated NNN bytes …`. No new
> `unsafe`: they reuse the existing `Serial::write_bytes` path (S1–S5).

---

## 3. Verification roadmap (sub-project #2+)

| Tool | Applicable to | Status |
|------|---------------|--------|
| Manual review + adversarial review (kernel-reviewer) | all entries | scheduled (build sequence step 6) |
| QEMU boot evidence | S1–S5, C3–C4 (serial output + clean halt); F1–F2 (framebuffer plotted in QEMU once the boot screen renders); **M1–M14 (`cargo xtask test` boots, maps the heap, and allocates: `[mem] heap ok: allocated NNN bytes` — `Box`/`Vec` through the global allocator — before the banner + `boot-bringup-ok`)** | via `cargo xtask test` (test-engineer) |
| QEMU **fault tests** (the #2a evidence) | G1–G5, I1–I5, X1 — `int3` → `EXCEPTION: BREAKPOINT`, deliberate #PF → `EXCEPTION: PAGE FAULT` + no reset loop, forced #DF on the IST stack → `EXCEPTION: DOUBLE FAULT` | via `cargo xtask test-faults` (test-engineer, build sequence step 4) — **this is the primary correctness check for the ISR/asm + descriptor-table loads** |
| Miri | pure logic helpers only (cannot model port I/O / `hlt`/`cli`/`sti` / descriptor loads / ISR stubs / CR3 / `invlpg` / raw page-table writes) | **pending** |
| Kani (bounded model checking) | bit-level helpers (e.g. IF/LSR masks, newline translation, gate/TSS descriptor bit-packing, RFLAGS/error-code decoders, **framebuffer `pack_rgb` channel packing + `byte_offset`/`fill_rect` bounds/clip arithmetic**, **`mm` address-index decomposition `VirtAddr::table_indices`, frame-align math, `PageFlags` bit-packing, and `align_up`/free-block split arithmetic**) | **pending** |
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
8. `mm::init()` is called **exactly once**, early in `kmain` (after
   `interrupts::init()`, before any heap allocation), and builds **on top of**
   Limine's active paging + HHDM — it never reloads CR3. It returns a `Result`;
   the global allocator is installed only on `Ok`, so no allocation must occur
   before a successful `init`. The frame allocator only ever yields
   `EntryType::USABLE` RAM (never reserved/ACPI/framebuffer/loader/kernel), is
   4 KiB-aligned, and never returns physical frame 0. The `kernel` crate only
   *declares* the `#[global_allocator]` static (`hal::mm::LockedHeap`) — declaring
   a static is **not** `unsafe`, so `kernel` stays `#![forbid(unsafe_code)]`.
9. On this higher-half, statically-relocated target, the `core::fmt` argument path
   and the `memset`/`memcpy` compiler libcalls **fault** (they need `.got`/`.rela`
   relocations the linker script discards). Therefore `mm` zeroes page-table
   frames with an explicit `u64` loop (never `ptr::write_bytes`), and dynamic
   boot output uses the `fmt`-free `hal::serial::write_str`/`write_dec` helpers
   rather than `println!("{}", …)`. Both are reproduced + avoided (see M8 / §5e).
