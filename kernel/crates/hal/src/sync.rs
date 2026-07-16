//! A minimal spin mutex, shared by `mm` and `context` (the scheduler's TCB).
//!
//! `mm`'s global statics (the frame allocator and the kernel heap) and
//! `kernel::sched`'s run-queue state (`hal::sync::SpinMutex<SchedState>`, see the
//! scheduler design doc) both need interior mutability behind a `Sync` type so
//! they can live in a `static` and be shared. At bring-up (and through the PR-A
//! cooperative scheduler) the kernel is single-core, so this lock never actually
//! spins; it exists to make the *types* `Sync` and to be correct if/when SMP
//! arrives.
//!
//! It is a tiny, self-contained implementation (no external `spin` crate) using
//! [`AtomicBool`] compare-exchange. The only `unsafe` is forming the `&mut` to
//! the guarded data while the lock is held, which is the standard mutex pattern;
//! see `kernel/docs/hal-tcb.md` (§5e). Promoted from `mm::sync` to a crate-level
//! module so `hal::context`/`kernel::sched` can reuse it too — no new `unsafe`.

use core::cell::UnsafeCell;
use core::hint;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

/// A spinlock-guarded value.
///
/// `lock()` busy-waits until it acquires the lock, then returns a [`SpinGuard`]
/// giving `&mut T` access; the lock is released when the guard is dropped.
pub struct SpinMutex<T> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

// SAFETY: `SpinMutex` provides mutual exclusion via the `locked` atomic: only one
// `SpinGuard` can exist at a time, and that guard is the only path to the inner
// `UnsafeCell`. Therefore the inner `T` is never accessed by two threads at once,
// which is exactly the invariant `Sync` requires (given `T: Send`).
unsafe impl<T: Send> Sync for SpinMutex<T> {}
// SAFETY: moving the mutex moves its owned `data`; nothing observes the old
// location, so sending it across threads is sound when `T: Send`.
unsafe impl<T: Send> Send for SpinMutex<T> {}

impl<T> SpinMutex<T> {
    /// Create a new, unlocked mutex. `const`, so it can back a `static`.
    #[must_use]
    pub const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(value),
        }
    }

    /// Acquire the lock, spinning until it is free, and return a guard.
    pub fn lock(&self) -> SpinGuard<'_, T> {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            // Spin until the lock looks free, hinting the CPU we are busy-waiting.
            while self.locked.load(Ordering::Relaxed) {
                hint::spin_loop();
            }
        }
        SpinGuard { mutex: self }
    }
}

/// RAII guard that releases a [`SpinMutex`] on drop and derefs to the guarded `T`.
pub struct SpinGuard<'a, T> {
    mutex: &'a SpinMutex<T>,
}

impl<T> Deref for SpinGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: holding this guard proves the lock is acquired, so we have
        // exclusive access to the inner value for the guard's lifetime; forming a
        // shared reference to it is sound and cannot alias another `&mut`.
        unsafe { &*self.mutex.data.get() }
    }
}

impl<T> DerefMut for SpinGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: holding this guard (by `&mut self`) proves the lock is acquired
        // and that this is the unique guard, so we have exclusive access to the
        // inner value; forming the unique `&mut` is sound and unaliased.
        unsafe { &mut *self.mutex.data.get() }
    }
}

impl<T> Drop for SpinGuard<'_, T> {
    fn drop(&mut self) {
        // Release the lock so the next `lock()` can acquire it.
        self.mutex.locked.store(false, Ordering::Release);
    }
}
