//! A counting global allocator for **host tests only** (SentinelFS spec
//! §5 principle 7, amendments A23/A31).
//!
//! [`Counting`] forwards every call to the system allocator and keeps, per
//! thread, the live byte count since the last [`reset`] and its peak. A test
//! resets, runs filesystem work on its own thread, and reads [`peak`]: other
//! test threads' allocations never mix in. Bytes freed that were allocated
//! before the reset drive the live count below zero, which only makes the
//! peak conservative (it is measured from the reset point).
//!
//! This is the only `unsafe` the heap-cap test needs, and it lives here, not
//! in the `kernel` crate (`#![forbid(unsafe_code)]`). On the bare-metal
//! target the crate is empty.

#![no_std]

#[cfg(not(target_os = "none"))]
extern crate std;

#[cfg(not(target_os = "none"))]
mod imp {
    use core::alloc::{GlobalAlloc, Layout};
    use core::cell::Cell;
    use std::alloc::System;

    std::thread_local! {
        static LIVE: Cell<isize> = const { Cell::new(0) };
        static PEAK: Cell<isize> = const { Cell::new(0) };
    }

    /// The counting allocator: install with `#[global_allocator]`.
    pub struct Counting;

    fn grow(n: usize) {
        let n = isize::try_from(n).unwrap_or(isize::MAX);
        // `try_with`: during thread teardown the slots may be gone; then the
        // allocation simply is not counted.
        let _ = LIVE.try_with(|live| {
            let v = live.get().saturating_add(n);
            live.set(v);
            let _ = PEAK.try_with(|peak| {
                if v > peak.get() {
                    peak.set(v);
                }
            });
        });
    }

    fn shrink(n: usize) {
        let n = isize::try_from(n).unwrap_or(isize::MAX);
        let _ = LIVE.try_with(|live| live.set(live.get().saturating_sub(n)));
    }

    // SAFETY: every method forwards to `System` with the caller's arguments
    // unchanged, so `System`'s `GlobalAlloc` contract is this impl's
    // contract; the bookkeeping touches only `const`-initialised
    // thread-local `Cell`s, which never allocate (no re-entry) and never
    // unwind.
    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // SAFETY: forwarded unchanged; the caller upholds `alloc`'s
            // contract (non-zero size).
            let p = unsafe { System.alloc(layout) };
            if !p.is_null() {
                grow(layout.size());
            }
            p
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            // SAFETY: as `alloc`.
            let p = unsafe { System.alloc_zeroed(layout) };
            if !p.is_null() {
                grow(layout.size());
            }
            p
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            // SAFETY: forwarded unchanged; the caller guarantees `ptr` came
            // from this allocator (hence from `System`) with `layout`.
            unsafe { System.dealloc(ptr, layout) };
            shrink(layout.size());
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            // SAFETY: forwarded unchanged; the caller upholds `realloc`'s
            // contract for `ptr`, `layout` and `new_size`.
            let p = unsafe { System.realloc(ptr, layout, new_size) };
            if !p.is_null() {
                shrink(layout.size());
                grow(new_size);
            }
            p
        }
    }

    /// Start measuring on this thread: live and peak back to zero.
    pub fn reset() {
        let _ = LIVE.try_with(|l| l.set(0));
        let _ = PEAK.try_with(|p| p.set(0));
    }

    /// Highest live byte count on this thread since [`reset`].
    #[must_use]
    pub fn peak() -> isize {
        PEAK.try_with(Cell::get).unwrap_or(0)
    }

    /// Live bytes allocated on this thread since [`reset`] and not freed.
    #[must_use]
    pub fn live() -> isize {
        LIVE.try_with(Cell::get).unwrap_or(0)
    }
}

#[cfg(not(target_os = "none"))]
pub use imp::{live, peak, reset, Counting};
