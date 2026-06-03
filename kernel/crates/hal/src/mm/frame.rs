//! Physical frame allocator — an intrusive free-list of 4 KiB frames.
//!
//! The allocator is seeded from the firmware's **usable** memory-map regions
//! (see [`super::bootinfo::usable_regions`]) and hands out / takes back single
//! 4 KiB physical frames. It is an *intrusive* free list: each free frame stores
//! the physical address of the next free frame in its own first 8 bytes. We can
//! write there because Limine higher-half-direct-maps all physical RAM, so a
//! free frame at physical `p` is reachable (read/write) at virtual `p + hhdm`.
//!
//! # Concurrency model
//!
//! At bring-up the kernel is single-core. The free-list head and the HHDM offset
//! live behind a [`super::sync::SpinMutex`] inside the global [`FrameAllocator`]
//! so the *type* is `Sync`, but no real contention exists yet. All linked-list
//! pointer writes are confined to two `unsafe` blocks documented below and in
//! `kernel/docs/hal-tcb.md` (§5b).

use core::ptr;

use super::addr::{PhysAddr, PAGE_SIZE};
use super::bootinfo;
use super::sync::SpinMutex;

/// Sentinel value for "end of free list" (a physical address no frame can have).
const NIL: u64 = u64::MAX;

/// Inner, lock-protected state of the frame allocator.
struct Inner {
    /// Physical address of the first free frame, or [`NIL`] if exhausted.
    free_head: u64,
    /// HHDM offset: `virt = phys + hhdm` for any physical RAM address.
    hhdm: u64,
    /// Whether [`FrameAllocator::init`] has run (a second init is ignored).
    initialised: bool,
    /// Count of frames currently on the free list (diagnostics).
    free_count: usize,
}

/// A single-frame physical allocator over the usable memory-map regions.
///
/// Construct the global instance with [`FrameAllocator::new`] (a `const fn`, so
/// it can back a `static`) and seed it once with [`FrameAllocator::init`].
/// Thereafter [`alloc_frame`](FrameAllocator::alloc_frame) /
/// [`dealloc_frame`](FrameAllocator::dealloc_frame) are the safe API.
pub struct FrameAllocator {
    inner: SpinMutex<Inner>,
}

impl FrameAllocator {
    /// Create an empty, uninitialised allocator suitable for a `static`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inner: SpinMutex::new(Inner {
                free_head: NIL,
                hhdm: 0,
                initialised: false,
                free_count: 0,
            }),
        }
    }

    /// Seed the free list from the firmware's usable RAM regions.
    ///
    /// `hhdm` is the higher-half direct-map offset (from
    /// [`bootinfo::hhdm_offset`]). Each usable region is sliced into 4 KiB frames
    /// and pushed onto the free list. Call **once**, early, on the boot core;
    /// a second call is a no-op. Returns the number of frames made available.
    ///
    /// Physical frame `0` is deliberately skipped so a null-like physical address
    /// can never leak out of [`alloc_frame`](Self::alloc_frame). The free-list
    /// terminator is [`NIL`] (`u64::MAX`), which no real frame address collides
    /// with, so the empty-list sentinel is unambiguous.
    pub fn init(&self, hhdm: u64) -> usize {
        let mut inner = self.inner.lock();
        if inner.initialised {
            return inner.free_count;
        }
        inner.hhdm = hhdm;

        for region in bootinfo::usable_regions() {
            // Frame-align the region to whole 4 KiB frames inside its bounds.
            let start = region.base.frame_ceil().as_u64();
            let end = PhysAddr::new(region.base.as_u64() + region.length)
                .frame_floor()
                .as_u64();
            // Skip degenerate regions (smaller than one frame after alignment),
            // which would otherwise underflow `frame + PAGE_SIZE <= end`.
            if end < start + PAGE_SIZE {
                continue;
            }
            let mut frame = start;
            // `frame + PAGE_SIZE <= end` guarantees a whole 4 KiB frame fits and
            // (since `PAGE_SIZE > 0`) implies `frame < end`.
            while frame + PAGE_SIZE <= end {
                // Skip physical frame 0 so a null-like physical address can never
                // be returned by `alloc_frame`.
                if frame != 0 {
                    // SAFETY: `frame` is a 4 KiB-aligned physical address inside a
                    // region the firmware marked USABLE, so the frame is real RAM
                    // not owned by anything else. Limine HHDM-maps all physical
                    // RAM, so `frame + hhdm` is a valid, writable virtual address
                    // for the whole 4 KiB frame; writing the 8-byte next-pointer
                    // into its first bytes is in bounds and aligned (frame is
                    // 4 KiB-aligned ⇒ 8-byte-aligned). No other code references
                    // this frame yet (it is being placed on the free list for the
                    // first time), so the write is unaliased.
                    unsafe {
                        let node = (frame + inner.hhdm) as *mut u64;
                        ptr::write(node, inner.free_head);
                    }
                    inner.free_head = frame;
                    inner.free_count += 1;
                }
                frame += PAGE_SIZE;
            }
        }

        inner.initialised = true;
        inner.free_count
    }

    /// Allocate one 4 KiB physical frame, or `None` if memory is exhausted.
    ///
    /// The returned [`PhysAddr`] is 4 KiB-aligned and non-zero. The frame's
    /// contents are unspecified (the caller must zero it before use as a page
    /// table — [`super::paging`] does so). Safe: it only unlinks a frame the
    /// allocator itself previously placed on the list.
    #[must_use]
    pub fn alloc_frame(&self) -> Option<PhysAddr> {
        let mut inner = self.inner.lock();
        let head = inner.free_head;
        if head == NIL {
            return None;
        }
        // SAFETY: `head` is a physical frame address the allocator placed on the
        // free list (so it is real, 4 KiB-aligned USABLE RAM), and we stored its
        // successor's physical address in its first 8 bytes at `head + hhdm`.
        // That virtual address is HHDM-mapped, readable, and 8-byte-aligned, so
        // reading the next-pointer back is in bounds and sound. The frame is
        // about to leave the free list, so this read is the last access to its
        // link field and is unaliased.
        let next = unsafe { ptr::read((head + inner.hhdm) as *const u64) };
        inner.free_head = next;
        inner.free_count -= 1;
        Some(PhysAddr::new(head))
    }

    /// Return a 4 KiB physical frame to the free list.
    ///
    /// # Panics
    ///
    /// Does not panic. The caller must pass a frame previously obtained from
    /// [`alloc_frame`](Self::alloc_frame) (or otherwise known-free, 4 KiB-aligned
    /// usable RAM); passing a non-frame address would corrupt the list, so this
    /// is a logical precondition enforced by construction (the heap only ever
    /// frees frames it allocated). Frame 0 and unaligned addresses are ignored.
    pub fn dealloc_frame(&self, frame: PhysAddr) {
        let phys = frame.as_u64();
        // Reject obviously-invalid frames rather than corrupting the list.
        if phys == 0 || (phys & (PAGE_SIZE - 1)) != 0 {
            return;
        }
        let mut inner = self.inner.lock();
        // SAFETY: `phys` is a 4 KiB-aligned (checked above) physical RAM frame the
        // caller is handing back, so `phys + hhdm` is its valid, writable,
        // 8-byte-aligned HHDM virtual address. Writing the current free-list head
        // into the frame's first 8 bytes is in bounds for the 4 KiB frame and
        // unaliased (the caller has relinquished the frame). We then publish the
        // frame as the new head.
        unsafe {
            let node = (phys + inner.hhdm) as *mut u64;
            ptr::write(node, inner.free_head);
        }
        inner.free_head = phys;
        inner.free_count += 1;
    }

    /// Number of frames currently available on the free list (diagnostics).
    #[must_use]
    pub fn free_frames(&self) -> usize {
        self.inner.lock().free_count
    }
}

impl Default for FrameAllocator {
    fn default() -> Self {
        Self::new()
    }
}
