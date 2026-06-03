//! Kernel memory bring-up — the `#[global_allocator]` and its one-shot init.
//!
//! This module owns the kernel's global allocator **static** and a thin safe
//! [`init`] wrapper around [`hal::mm::init`]. The actual allocator implementation
//! (frame allocator, page mapping, the `unsafe impl GlobalAlloc`) lives entirely
//! in the `hal` crate (the TCB); here we only *declare* the static and forward
//! to `hal`, both of which are ordinary safe Rust — so the `kernel` crate keeps
//! `#![forbid(unsafe_code)]`.
//!
//! Declaring a `#[global_allocator]` static is **not** an `unsafe` operation
//! (the `unsafe` is in the `GlobalAlloc` *impl*, which is in `hal`), so this
//! compiles fine under `forbid(unsafe_code)`.

/// The kernel's global heap allocator.
///
/// Backed by `hal`'s free-list [`hal::mm::LockedHeap`] over a higher-half virtual
/// window that [`init`] maps to physical frames. Until [`init`] runs, any
/// allocation would find an empty heap and return null (so `init` must be called
/// before the first `Box`/`Vec`/`String`).
#[global_allocator]
static ALLOCATOR: hal::mm::LockedHeap = hal::mm::LockedHeap::new();

/// Bring up the kernel heap and install the global allocator.
///
/// Call **once**, early in `kmain` (after `interrupts::init`, before any heap
/// allocation). Delegates to [`hal::mm::init`], which seeds the physical frame
/// allocator from the firmware memory map, maps the heap window, and installs it
/// into [`ALLOCATOR`]. On success, returns a [`hal::mm::MemoryInfo`] summary;
/// after it, `alloc` (`Box`/`Vec`/`String`) works.
///
/// # Errors
///
/// Propagates [`hal::mm::InitError`] when Limine gave no HHDM offset / no usable
/// RAM, or a heap page could not be mapped.
pub fn init() -> Result<hal::mm::MemoryInfo, hal::mm::InitError> {
    hal::mm::init(&ALLOCATOR)
}

/// Bring up the heap, then **prove** the global allocator works by actually
/// heap-allocating and reporting over serial.
///
/// This is the single call `kmain` makes. After [`init`] succeeds, it allocates a
/// heap-backed `alloc::vec::Vec<u8>` through the freshly-installed
/// `#[global_allocator]`, fills it, and prints
/// `[mem] heap ok: allocated NNN bytes ...` — concrete evidence that `Box`/`Vec`/
/// `String` now work. The number is emitted with `hal`'s `fmt`-free serial
/// helpers ([`hal::serial::write_dec`]) because `println!("{}", n)` faults on this
/// higher-half target (its `core::fmt` path needs `.got`/`.rela` relocations the
/// linker script discards). On failure it reports the error and continues
/// (headless), leaving the global allocator uninstalled.
pub fn init_and_prove() {
    match init() {
        Ok(info) => {
            // PROOF: allocate on the heap via the global allocator. A `Vec` that
            // grows from empty exercises the allocator's `alloc` path directly.
            let mut proof: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
            proof.extend(0u8..=255);
            // A second, boxed allocation, to exercise `Box` too.
            let boxed = alloc::boxed::Box::new(0xA5u8);
            let allocated = proof.len() + core::mem::size_of_val(&*boxed);

            // `[mem] heap ok: allocated NNN bytes (frames=…, heap=… KiB)` — built
            // without `core::fmt` (which faults here); see this fn's docs.
            hal::serial::write_str("[mem] heap ok: allocated ");
            hal::serial::write_dec(allocated as u64);
            hal::serial::write_str(" bytes (frames=");
            hal::serial::write_dec(info.total_frames as u64);
            hal::serial::write_str(", heap=");
            hal::serial::write_dec((info.heap_bytes / 1024) as u64);
            hal::serial::write_str(" KiB)\n");
        }
        Err(_) => {
            hal::serial::write_str("[mem] heap init FAILED\n");
        }
    }
}
