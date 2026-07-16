//! Kernel heap — a free-list allocator behind a `#[global_allocator]`.
//!
//! This module provides [`LockedHeap`], the type the `kernel` crate installs as
//! its `#[global_allocator]` so that `alloc` (`Box`, `Vec`, `String`, …) works.
//! The heap is a classic **first-fit free list** of variable-size blocks over a
//! contiguous virtual region that [`super::init`] backs with physical frames.
//!
//! ## Design
//!
//! * The managed region is a fixed window of higher-half virtual address space
//!   ([`HEAP_START`] … `HEAP_START + HEAP_SIZE`) that `mm::init` maps to fresh
//!   physical frames via [`super::paging`] before the heap is used.
//! * Free blocks form a singly-linked list; each free block header
//!   ([`FreeBlock`]) stores its size and the next free block, stored *inside* the
//!   free memory itself (so the allocator needs no side metadata).
//! * Allocation is first-fit with splitting; deallocation pushes the block back
//!   and coalesces with the immediately-adjacent free block when possible.
//! * Every allocation is rounded up so headers stay [`ALIGN`]-aligned and the
//!   minimum block can always hold a [`FreeBlock`] header.
//!
//! All `unsafe` (the raw header reads/writes and the `GlobalAlloc` impl) is
//! confined here and documented in `kernel/docs/hal-tcb.md` (§5d).

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;

use crate::sync::SpinMutex;

/// Base virtual address of the kernel heap window.
///
/// A higher-half address well clear of the kernel image (`0xFFFFFFFF8000_0000`),
/// the HHDM region, and the framebuffer. `0xFFFF_F000_0000_0000` sits in an
/// otherwise-unused PML4 slot, so mapping pages here cannot collide with
/// Limine's existing mappings.
pub const HEAP_START: u64 = 0xFFFF_F000_0000_0000;

/// Size of the kernel heap window, in bytes (4 MiB).
pub const HEAP_SIZE: u64 = 4 * 1024 * 1024;

/// Allocation alignment / minimum granularity (16 bytes covers `u128`/`max_align_t`).
const ALIGN: usize = 16;

/// A free-block header, stored at the start of each free block.
///
/// `size` is the total size of the block in bytes (header included). `next` is
/// the next free block, or null for the list tail. Headers live *inside* the
/// managed region, so the allocator carries no external metadata.
#[repr(C)]
struct FreeBlock {
    /// Total block size in bytes (including this header).
    size: usize,
    /// Next free block, or null.
    next: *mut FreeBlock,
}

/// Round `value` up to the next multiple of `align` (a power of two).
const fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

/// The free-list allocator state (not itself `Sync`; wrapped by [`LockedHeap`]).
struct Heap {
    /// Head of the free list, or null when empty / before `init`.
    head: *mut FreeBlock,
    /// Whether the heap region has been installed.
    initialised: bool,
}

// SAFETY: `Heap`'s only non-`Send` field is the `head` raw pointer, which always
// either is null or points at a `FreeBlock` header inside the kernel heap window
// (a fixed higher-half region valid for the whole life of the program). Moving a
// `Heap` between threads does not invalidate that pointer. `Heap` is never shared
// directly; it lives inside a `SpinMutex` (`LockedHeap`) that serialises every
// access, so there is never concurrent use of the inner pointer. Marking it
// `Send` is what lets `SpinMutex<Heap>` be `Sync` and back the global-allocator
// `static`.
unsafe impl Send for Heap {}

// The minimum size a block must have to hold a `FreeBlock` header, aligned.
const MIN_BLOCK: usize = {
    let header = core::mem::size_of::<FreeBlock>();
    align_up(header, ALIGN)
};

impl Heap {
    const fn new() -> Self {
        Self {
            head: ptr::null_mut(),
            initialised: false,
        }
    }

    /// Install a contiguous, already-mapped region `[start, start+size)` as the
    /// single initial free block.
    ///
    /// # Safety
    ///
    /// `[start, start + size)` must be a valid, writable, currently-unused
    /// virtual range backed by real physical frames (mapped by `mm::init`),
    /// `size >= MIN_BLOCK`, and `start` must be [`ALIGN`]-aligned. Called once.
    unsafe fn install(&mut self, start: u64, size: usize) {
        let block = start as *mut FreeBlock;
        // SAFETY: by this function's contract `start` is `ALIGN`-aligned (so it is
        // aligned for `FreeBlock`, whose alignment is `align_of::<usize>() <=
        // ALIGN`) and `[start, start+size)` is a mapped, writable, unaliased
        // region of at least `MIN_BLOCK` bytes. Writing one `FreeBlock` header at
        // `start` is therefore in bounds and sound.
        unsafe {
            ptr::write(
                block,
                FreeBlock {
                    size,
                    next: ptr::null_mut(),
                },
            );
        }
        self.head = block;
        self.initialised = true;
    }

    /// Allocate `layout.size()` bytes with at least `layout.align()` alignment,
    /// first-fit. Returns a data pointer or null on failure.
    ///
    /// # Safety
    ///
    /// The heap must have been [`install`](Self::install)ed. The returned pointer
    /// (if non-null) is valid for `layout.size()` bytes.
    unsafe fn alloc(&mut self, layout: Layout) -> *mut u8 {
        // Block must hold the requested bytes and be re-usable as a `FreeBlock`
        // when freed, so size is at least `MIN_BLOCK`, and we honour alignment by
        // over-aligning the requested size up to `ALIGN` (>= header align). We do
        // not support alignments larger than `ALIGN`; callers in the kernel never
        // request more (the largest is `u128` at 16). Larger requests fail (null).
        if layout.align() > ALIGN {
            return ptr::null_mut();
        }
        let need = align_up(layout.size().max(1), ALIGN).max(MIN_BLOCK);

        let mut prev: *mut FreeBlock = ptr::null_mut();
        let mut cur = self.head;
        while !cur.is_null() {
            // SAFETY: `cur` is a non-null free-block pointer that was placed on the
            // list by `install`/`dealloc`, so it points at a live, mapped
            // `FreeBlock` header in the heap region; reading its fields is sound.
            let (cur_size, cur_next) = unsafe { ((*cur).size, (*cur).next) };
            if cur_size >= need {
                // Decide whether to split the remainder into a new free block.
                let remainder = cur_size - need;
                if remainder >= MIN_BLOCK {
                    // SAFETY: `cur` block spans `cur_size` mapped bytes; the split
                    // point `cur + need` is within it (`need < cur_size`) and
                    // `ALIGN`-aligned (both `cur` and `need` are), so taking the
                    // interior pointer and writing a `FreeBlock` header there is in
                    // bounds and aligned, and the region is unaliased (it is part
                    // of the block we are removing from the free list).
                    let split = unsafe { (cur as *mut u8).add(need) as *mut FreeBlock };
                    // SAFETY: `split` points at `cur + need`, which is inside the
                    // `cur_size`-byte block (`need < cur_size`), `ALIGN`-aligned,
                    // mapped, and currently unused, so writing one `FreeBlock`
                    // header there is in bounds, aligned, and unaliased.
                    unsafe {
                        ptr::write(
                            split,
                            FreeBlock {
                                size: remainder,
                                next: cur_next,
                            },
                        );
                    }
                    self.unlink(prev, cur, split);
                } else {
                    // Use the whole block (remainder too small to be a block).
                    self.unlink(prev, cur, cur_next);
                }
                return cur as *mut u8;
            }
            prev = cur;
            cur = cur_next;
        }
        ptr::null_mut()
    }

    /// Replace `cur` in the list with `replacement` (its successor), updating
    /// either the head or `prev.next`.
    fn unlink(&mut self, prev: *mut FreeBlock, cur: *mut FreeBlock, replacement: *mut FreeBlock) {
        let _ = cur;
        if prev.is_null() {
            self.head = replacement;
        } else {
            // SAFETY: `prev` is non-null here and is a live free-block header on
            // the list (it was `cur` on a previous loop iteration), so writing its
            // `next` field is in bounds and sound.
            unsafe {
                (*prev).next = replacement;
            }
        }
    }

    /// Return a block of `layout`-sized memory to the free list, coalescing with
    /// an immediately-following adjacent free block when possible.
    ///
    /// # Safety
    ///
    /// `ptr` must have come from a previous [`alloc`](Self::alloc) with the same
    /// `layout`, and must not be used after this call.
    unsafe fn dealloc(&mut self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() {
            return;
        }
        let size = align_up(layout.size().max(1), ALIGN).max(MIN_BLOCK);
        let block = ptr as *mut FreeBlock;
        // SAFETY: `ptr` was returned by `alloc` for a block of exactly `size`
        // bytes (recomputed identically from `layout`), so `[ptr, ptr+size)` is a
        // mapped, now-unused region in the heap, `ALIGN`-aligned. Writing a fresh
        // `FreeBlock` header at its start is in bounds and sound; we push it to the
        // list head, then attempt forward coalescing.
        unsafe {
            ptr::write(
                block,
                FreeBlock {
                    size,
                    next: self.head,
                },
            );
        }
        self.head = block;
        // SAFETY: `block` is the live list head we just wrote; coalescing only
        // reads/writes `FreeBlock` headers reachable from the list, all of which
        // are live mapped headers in the heap region.
        unsafe {
            self.coalesce_from(block);
        }
    }

    /// If `block` is immediately followed in memory by another free block, merge
    /// them into one larger free block (forward coalescing only).
    ///
    /// # Safety
    ///
    /// `block` must be a live free-block header currently on the list.
    unsafe fn coalesce_from(&mut self, block: *mut FreeBlock) {
        // SAFETY: `block` is a live header (caller's contract); reading its size
        // is sound.
        let block_size = unsafe { (*block).size };
        let block_end = block as usize + block_size;

        // Scan the list for a free block that starts exactly at `block_end`.
        let mut prev: *mut FreeBlock = ptr::null_mut();
        let mut cur = self.head;
        while !cur.is_null() {
            if cur as usize == block_end && cur != block {
                // SAFETY: `cur` is a live header on the list; reading its
                // size/next is sound. It is physically adjacent to `block`, so we
                // can absorb it.
                let (cur_size, cur_next) = unsafe { ((*cur).size, (*cur).next) };
                // Remove `cur` from the list.
                self.unlink(prev, cur, cur_next);
                // SAFETY: `block` is a live header; growing its recorded size to
                // cover the now-absorbed adjacent region is sound (the region
                // `[block, block_end + cur_size)` is one contiguous mapped span).
                unsafe {
                    (*block).size = block_size + cur_size;
                }
                return;
            }
            prev = cur;
            // SAFETY: `cur` is a live header; reading `next` to advance is sound.
            cur = unsafe { (*cur).next };
        }
    }
}

/// The `#[global_allocator]`-installable kernel heap.
///
/// `LockedHeap` wraps the free-list [`Heap`] in a [`SpinMutex`] so it is `Sync`
/// and can back a `static`. The `kernel` crate writes:
///
/// ```ignore
/// #[global_allocator]
/// static ALLOCATOR: hal::mm::LockedHeap = hal::mm::LockedHeap::new();
/// ```
///
/// Declaring that static is **not** `unsafe`, so the `kernel` crate stays
/// `#![forbid(unsafe_code)]`; the one `unsafe impl GlobalAlloc` lives here.
pub struct LockedHeap {
    inner: SpinMutex<Heap>,
}

impl LockedHeap {
    /// Create an empty heap. `const`, so it can back a `static`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inner: SpinMutex::new(Heap::new()),
        }
    }

    /// Install the mapped region `[HEAP_START, HEAP_START + HEAP_SIZE)` as the
    /// heap. Called once by [`super::init`] after the frames are mapped.
    ///
    /// # Safety
    ///
    /// The whole `[start, start+size)` range must be mapped, writable, and unused
    /// by anything else, with `start` [`ALIGN`]-aligned and `size >= MIN_BLOCK`.
    pub(crate) unsafe fn init(&self, start: u64, size: usize) {
        // SAFETY: forwards the caller's `init` contract (range mapped/writable/
        // unused, aligned, big enough) directly to `Heap::install`, which is the
        // sole consumer of that guarantee.
        unsafe {
            self.inner.lock().install(start, size);
        }
    }
}

impl Default for LockedHeap {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: `LockedHeap` implements `GlobalAlloc` by delegating to the free-list
// `Heap` under its `SpinMutex`, which guarantees exclusive access during each
// operation. `alloc` returns either null or a pointer to a block of at least
// `layout.size()` bytes carved from the mapped heap region, aligned to `ALIGN`
// (>= every alignment the kernel requests; larger alignments fail with null, as
// `GlobalAlloc` permits). `dealloc` is only ever called by the runtime with a
// pointer/layout pair previously returned by this allocator's `alloc`, so the
// block size it reconstructs matches and the freed region is back inside the
// heap. No allocation hands out overlapping memory (blocks are removed from the
// free list on `alloc` and only re-added on `dealloc`), satisfying the
// `GlobalAlloc` safety contract.
unsafe impl GlobalAlloc for LockedHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the heap is installed before the global allocator is used (the
        // proof allocation in `kmain` runs after `mm::init`). The lock gives
        // exclusive access; `Heap::alloc`'s precondition (installed heap) holds.
        unsafe { self.inner.lock().alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr`/`layout` were produced by this allocator's `alloc` (the
        // `GlobalAlloc` contract guarantees it), so `Heap::dealloc`'s precondition
        // holds. The lock gives exclusive access for the list manipulation.
        unsafe { self.inner.lock().dealloc(ptr, layout) }
    }
}
