//! HAL — Hardware Abstraction Layer (the SentinelOS TCB).
//!
//! This is the **only** crate in `crates/` permitted to use `unsafe`; it is the
//! entire Trusted Computing Base for kernel bring-up (sub-project #1). Every
//! capability that needs a privileged instruction or raw device access is
//! confined here and re-exported behind a **safe** API, so that the `kernel`
//! crate can carry `#![forbid(unsafe_code)]`.
//!
//! `hal` is a pure library of safe primitives: it deliberately does **not**
//! define `_start` or a `#[panic_handler]`. The boot entry point and panic
//! handler live in the `kernel` crate, which keeps the dependency edge
//! one-directional (`kernel` → `hal`) and avoids a cycle.
//!
//! # Modules
//!
//! - [`serial`] — a 16550 UART driver on COM1 (`0x3F8`) with a global console
//!   and the [`print!`] / [`println!`] macros.
//! - [`cpu`] — safe wrappers over `hlt`, `cli`, `sti`, and the `CR2` read.
//! - [`cpuid`] — a safe wrapper over the `cpuid` instruction returning the CPU
//!   vendor/brand strings, family/model/stepping, and feature flags
//!   ([`cpuid::info`]) for the shell's `cpuinfo` command.
//! - [`framebuffer`] — the Limine linear framebuffer wrapped as a safe,
//!   bounds-checked drawing surface ([`framebuffer::Framebuffer`]).
//! - [`gdt`] — the 64-bit GDT + TSS with an IST double-fault stack (`lgdt`/`ltr`).
//! - [`idt`] — the 256-entry IDT and the raw ISR entry stubs (`lidt`).
//! - [`interrupts`] — the **safe** registration API ([`interrupts::init`],
//!   [`interrupts::set_handler`], [`interrupts::InterruptFrame`]) the `kernel`
//!   crate uses to hook exception handlers without a `hal → kernel` cycle.
//! - [`pic`] — the 8259A PIC pair remapped to vectors 32–47 ([`pic::init`],
//!   [`pic::unmask_irq`], [`pic::end_of_interrupt`]) so hardware IRQs don't
//!   collide with CPU exceptions.
//! - [`pit`] — the 8254 PIT channel-0 timer at ~100 Hz ([`pit::init`],
//!   [`pit::ticks`], [`pit::on_tick`]) driving the monotonic [`pit::TICKS`].
//! - [`keyboard`] — the PS/2 keyboard on IRQ1 ([`keyboard::init`],
//!   [`keyboard::on_irq`], [`keyboard::poll_scancode`]): the IRQ1 handler drains
//!   the scancode byte from port `0x60` into a lock-free ring the safe kernel
//!   polls and decodes (no decoding lives in the TCB).
//! - [`mouse`] — the PS/2 mouse (i8042 aux device) on IRQ12 ([`mouse::init`],
//!   [`mouse::on_irq`], [`mouse::poll_event`]): the IRQ12 handler reassembles the
//!   3-byte packet from port `0x60` and pushes a decoded `MouseEvent` into a
//!   lock-free ring the safe kernel polls (cursor/window policy lives in `kernel`).
//! - [`mm`] — memory management: the physical frame allocator, virtual page
//!   mapping over Limine's paging, and the kernel heap behind a
//!   `#[global_allocator]` ([`mm::init`], [`mm::LockedHeap`]).
//! - [`ata`] — a legacy ATA (IDE) PIO disk driver on the primary channel
//!   (`0x1F0..=0x1F7` + control `0x3F6`) with [`ata::identify`],
//!   [`ata::read_sectors`], [`ata::write_sectors`] (512-byte sectors, LBA28,
//!   no DMA/IRQ): the backing store for `kernel::fs` reboot persistence.
//!
//! # `unsafe` discipline
//!
//! Every `unsafe` block in this crate carries a `// SAFETY:` comment, and every
//! distinct `unsafe` operation is registered in `kernel/docs/hal-tcb.md` with
//! its justification and verification status. The crate denies any *implicit*
//! unsafety lints so that new unsafe code is always a deliberate, documented act.
//!
//! # Stable API contract (consumed by the `kernel` crate)
//!
//! - [`println!`] / [`print!`]
//! - [`serial::init`]
//! - [`cpu::halt_loop`]
//! - [`cpu::halt`] — single `hlt` (build an idle loop on top).
//! - [`cpu::disable_interrupts`] / [`cpu::enable_interrupts`] (`cli` / `sti`).
//! - [`cpu::read_cr2`] — faulting linear address for a `#PF` handler.
//! - [`pic::init`] / [`pic::unmask_irq`] / [`pic::end_of_interrupt`].
//! - [`pit::init`] / [`pit::ticks`] / [`pit::on_tick`] / [`pit::TICK_HZ`].
//! - [`interrupts::init`] — load GDT+TSS+IDT (call once at boot).
//! - [`interrupts::set_handler`] — register a `fn(&InterruptFrame)` for a vector.
//! - [`interrupts::InterruptFrame`] — the `#[repr(C)]` fault view passed to a
//!   handler (vector, error code, saved registers, `rip`/`cs`/`rflags`/…).
//! - [`interrupts::Handler`] — the handler function-pointer type.
//! - [`framebuffer::Framebuffer::get`] — acquire the boot framebuffer (or `None`).
//! - [`framebuffer::Framebuffer`] — `width`/`height`/`pitch`/`bpp`, the channel
//!   masks, `pack_rgb`, `put_pixel`, and `fill_rect` (all safe, bounds-checked).
//! - [`mm::init`] — bring up the frame allocator + heap; install the global
//!   allocator (call once at boot, after `interrupts::init`).
//! - [`mm::LockedHeap`] — the `#[global_allocator]` type the `kernel` crate
//!   declares as a `static` (declaring a static is not `unsafe`).
//! - [`ata::identify`] / [`ata::read_sectors`] / [`ata::write_sectors`] /
//!   [`ata::DiskInfo`] / [`ata::AtaError`] — block-level disk access for the
//!   filesystem persistence layer.

#![no_std]
// `unsafe` is permitted in this crate (and only this crate), but it must always
// be explicit and documented. These lints make undocumented or accidental
// unsafety a hard error rather than a silent allowance.
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
#![warn(clippy::undocumented_unsafe_blocks)]

pub mod ata;
pub mod cpu;
pub mod cpuid;
pub mod e1000;
pub mod framebuffer;
pub mod gdt;
pub mod idt;
pub mod interrupts;
pub mod keyboard;
pub mod mm;
pub mod mouse;
pub mod pci;
pub mod pic;
pub mod pit;
pub mod serial;
