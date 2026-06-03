//! Memory management — physical frames, virtual mapping, and the kernel heap.
//!
//! This module is part of the TCB. It brings the kernel from "no heap" to a
//! working `#[global_allocator]` so the safe `kernel`/`ui` crates can use `alloc`
//! (`Box`, `Vec`, `String`). It is built **on top of** the address space Limine
//! hands us: 4-level paging is already enabled and all physical RAM is
//! higher-half-direct-mapped (HHDM). We never replace that; we only *add* new
//! mappings for the heap.
//!
//! # Pipeline ([`init`])
//!
//! 1. **Boot info** ([`bootinfo`]) — own the Limine `MemoryMapRequest` +
//!    `HhdmRequest`, exposing the usable-RAM regions and the HHDM offset.
//! 2. **Frame allocator** ([`frame`]) — a free list of 4 KiB physical frames
//!    seeded from the usable regions (`alloc_frame`/`dealloc_frame`).
//! 3. **Paging** ([`paging`]) — reach the active page tables (CR3 + HHDM) and
//!    `map_page(virt, phys, flags)`, allocating intermediate tables as needed.
//! 4. **Heap** ([`heap`]) — map a few MiB at a fixed higher-half window and run a
//!    free-list allocator over it, installed as the `#[global_allocator]`.
//!
//! # `unsafe` discipline
//!
//! Every `unsafe` op in `mm` is registered in `kernel/docs/hal-tcb.md` (§5).
//! The public API here is **safe**: `init()` returns a [`Result`] and the
//! `kernel` crate stays `#![forbid(unsafe_code)]` — it only *declares* the
//! global-allocator static (declaring a static is not `unsafe`).

mod addr;
mod bootinfo;
mod frame;
mod heap;
mod paging;
mod sync;

pub use addr::{PhysAddr, VirtAddr, PAGE_SIZE};
pub use bootinfo::{hhdm_offset, usable_regions, UsableRegion};
pub use frame::FrameAllocator;
pub use heap::{LockedHeap, HEAP_SIZE, HEAP_START};
pub use paging::{ActivePageTable, MapError, PageFlags};

/// The global physical frame allocator, seeded by [`init`].
///
/// Public so callers (and tests) can query [`FrameAllocator::free_frames`]; the
/// heap maps its pages from this instance.
pub static FRAME_ALLOCATOR: FrameAllocator = FrameAllocator::new();

/// Why [`init`] could not bring memory management up.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InitError {
    /// Limine did not provide the higher-half direct-map offset.
    NoHhdm,
    /// No usable RAM regions were reported, so no frames could be allocated.
    NoUsableMemory,
    /// A heap page could not be mapped (out of frames or an unexpected clash).
    MapFailed(MapError),
}

impl From<MapError> for InitError {
    fn from(e: MapError) -> Self {
        Self::MapFailed(e)
    }
}

/// A short summary of what [`init`] set up, for the boot log.
#[derive(Clone, Copy, Debug)]
pub struct MemoryInfo {
    /// HHDM offset in use.
    pub hhdm: u64,
    /// Frames placed on the free list at boot.
    pub total_frames: usize,
    /// Bytes of kernel heap mapped and made allocatable.
    pub heap_bytes: usize,
}

/// Bring up memory management: frame allocator → heap mapping → global allocator.
///
/// Call **once**, early in `kmain`, after `interrupts::init()` and before any
/// heap allocation. On success the `#[global_allocator]` is live and `alloc`
/// (`Box`/`Vec`/`String`) works. The `allocator` argument is the kernel's
/// `#[global_allocator]` static (`&hal::mm::LockedHeap`), which this installs
/// over the freshly-mapped heap window.
///
/// Steps:
/// 1. Read the HHDM offset; seed [`FRAME_ALLOCATOR`] from usable RAM.
/// 2. Map [`HEAP_SIZE`] bytes at [`HEAP_START`] to fresh frames as kernel RW.
/// 3. Install the heap region into `allocator`.
///
/// # Errors
///
/// Returns [`InitError`] if Limine gave no HHDM offset, no usable RAM, or a heap
/// page could not be mapped (e.g. the frame allocator was exhausted). On error
/// the global allocator is left uninstalled and no allocation must be attempted.
pub fn init(allocator: &LockedHeap) -> Result<MemoryInfo, InitError> {
    // 1. HHDM offset + seed the frame allocator.
    let hhdm = hhdm_offset().ok_or(InitError::NoHhdm)?;
    let total_frames = FRAME_ALLOCATOR.init(hhdm);
    if total_frames == 0 {
        return Err(InitError::NoUsableMemory);
    }

    // 2. Map the heap window to fresh physical frames.
    let table = ActivePageTable::new(hhdm);
    let flags = PageFlags::kernel_rw();
    let pages = HEAP_SIZE / PAGE_SIZE;
    for i in 0..pages {
        let virt = VirtAddr::new(HEAP_START + i * PAGE_SIZE);
        let phys = FRAME_ALLOCATOR
            .alloc_frame()
            .ok_or(InitError::MapFailed(MapError::OutOfFrames))?;
        table.map_page(virt, phys, flags, &FRAME_ALLOCATOR)?;
    }

    // 3. Install the now-mapped region as the heap.
    // SAFETY: the entire `[HEAP_START, HEAP_START + HEAP_SIZE)` range was just
    // mapped page-by-page to fresh, exclusively-owned physical frames as kernel
    // read-write (loop above), so it is valid, writable, and used by nothing
    // else. `HEAP_START` is 4 KiB-aligned (hence `ALIGN`-aligned) and `HEAP_SIZE`
    // (4 MiB) far exceeds the minimum block size. This is the single install
    // call. These are exactly `LockedHeap::init`'s preconditions.
    unsafe {
        allocator.init(HEAP_START, HEAP_SIZE as usize);
    }

    Ok(MemoryInfo {
        hhdm,
        total_frames,
        heap_bytes: HEAP_SIZE as usize,
    })
}
