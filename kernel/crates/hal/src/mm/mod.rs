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

use core::sync::atomic::{AtomicUsize, Ordering};

mod addr;
mod bootinfo;
mod frame;
mod heap;
mod paging;
// `sync` is the project's only sanctioned interior-mutability primitive
// (`SpinMutex`). It stays a *private* module; its types are re-exported at the
// `mm` level (below) so safe kernel subsystems that need shared global state
// (e.g. `kernel::security::audit`'s global log) can reuse it rather than inventing
// their own — mirroring how `addr`'s types are re-exported. This exposes the
// *existing* types only — no new code, no new `unsafe`, no new TCB surface;
// `sync.rs`'s `unsafe` is already documented in `kernel/docs/hal-tcb.md` (§5e).
mod sync;

pub use addr::{PhysAddr, VirtAddr, PAGE_SIZE};
pub use bootinfo::{hhdm_offset, usable_regions, UsableRegion};
pub use frame::FrameAllocator;
pub use heap::{LockedHeap, HEAP_SIZE, HEAP_START};
pub use paging::{ActivePageTable, MapError, PageFlags};
pub use sync::{SpinGuard, SpinMutex};

// `DmaFrame`, `MmioError`, and `map_mmio` are defined below in this module and
// are part of the public `hal::mm` API consumed by device drivers (the NIC).

/// Base of the higher-half virtual window reserved for device MMIO mappings.
///
/// Chosen well clear of the kernel-heap window ([`HEAP_START`] =
/// `0xFFFF_F000_…`) so the two never overlap. [`map_mmio`] lays successive
/// mappings out from here, bumping [`MMIO_NEXT`] by the (page-rounded) size of
/// each region.
const MMIO_WINDOW_BASE: u64 = 0xFFFF_F100_0000_0000;

/// Bump pointer for the next free MMIO virtual address (see [`map_mmio`]).
static MMIO_NEXT: AtomicUsize = AtomicUsize::new(MMIO_WINDOW_BASE as usize);

/// Why [`map_mmio`] could not map a device register window.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MmioError {
    /// Memory management was not initialised (no HHDM offset available).
    NotInitialised,
    /// A page in the region could not be mapped (out of frames or a clash).
    MapFailed(MapError),
}

impl From<MapError> for MmioError {
    fn from(e: MapError) -> Self {
        Self::MapFailed(e)
    }
}

/// Map a physical device-MMIO region into the kernel address space, **uncached**.
///
/// Limine's HHDM only covers RAM, so a device's BAR (e.g. a NIC's register
/// window in the `0xFEB…` hole) is **not** reachable until we map it ourselves.
/// This maps the page-aligned span covering `[phys, phys + len)` into the
/// higher-half MMIO window ([`MMIO_WINDOW_BASE`]) with [`PageFlags::mmio`]
/// (PCD+PWT, so reads/writes always reach the device), and returns the
/// [`VirtAddr`] corresponding to `phys` (preserving the in-page offset).
///
/// Mappings are laid out by bumping a global cursor, so repeated calls never
/// overlap. Must be called after [`init`] (it needs the HHDM offset and the
/// frame allocator). Single-core at bring-up; not re-entrant-safe across cores.
///
/// # Errors
///
/// Returns [`MmioError::NotInitialised`] if `init` has not run, or
/// [`MmioError::MapFailed`] if a page could not be mapped.
pub fn map_mmio(phys: PhysAddr, len: usize) -> Result<VirtAddr, MmioError> {
    let hhdm = hhdm_offset().ok_or(MmioError::NotInitialised)?;

    // Page-align the physical span: floor the base, ceil the end, so the whole
    // region is covered by whole 4 KiB pages.
    let phys_base = phys.frame_floor().as_u64();
    let offset_in_page = phys.as_u64() - phys_base;
    let phys_end = PhysAddr::new(phys.as_u64() + len as u64)
        .frame_ceil()
        .as_u64();
    let span = (phys_end - phys_base) as usize;
    let pages = span / PAGE_SIZE as usize;

    // Reserve a contiguous virtual span from the MMIO bump cursor.
    let virt_base = MMIO_NEXT.fetch_add(span, Ordering::Relaxed) as u64;

    let table = ActivePageTable::new(hhdm);
    let flags = PageFlags::mmio();
    for i in 0..pages {
        let virt = VirtAddr::new(virt_base + (i * PAGE_SIZE as usize) as u64);
        let frame = PhysAddr::new(phys_base + (i * PAGE_SIZE as usize) as u64);
        table.map_page(virt, frame, flags, &FRAME_ALLOCATOR)?;
    }

    Ok(VirtAddr::new(virt_base + offset_in_page))
}

/// A single 4 KiB physical frame reserved for device DMA (descriptor rings /
/// packet buffers), reachable by the CPU through the HHDM.
///
/// A device that does DMA needs the **physical** address of its buffers, while
/// the CPU needs a virtual pointer to read/write them. Since Limine
/// higher-half-direct-maps all RAM, a frame at physical `p` is reachable at
/// `p + hhdm` (cached, ordinary RAM — fine for DMA on x86, where the device
/// snoops the caches). [`DmaFrame::alloc`] grabs one frame from the global
/// [`FRAME_ALLOCATOR`], zeroes it, and records both addresses.
///
/// The frame is **leaked** (never returned to the allocator): NIC rings live for
/// the lifetime of the kernel, so there is no free path to get wrong.
#[derive(Clone, Copy, Debug)]
pub struct DmaFrame {
    phys: PhysAddr,
    virt: VirtAddr,
}

impl DmaFrame {
    /// Allocate and zero one 4 KiB DMA-capable frame, or `None` if out of frames.
    ///
    /// The frame is zeroed with an explicit `u64` loop (never `write_bytes`,
    /// which lowers to a `memset` libcall that faults on this target — see the
    /// `mm` paging notes), so it is allocation-clean and panic-free.
    #[must_use]
    pub fn alloc() -> Option<Self> {
        let hhdm = hhdm_offset()?;
        let phys = FRAME_ALLOCATOR.alloc_frame()?;
        let virt = VirtAddr::new(phys.as_u64() + hhdm);
        let ptr = virt.as_u64() as *mut u64;
        // SAFETY: `phys` was just handed out by the frame allocator, so it is a
        // 4 KiB-aligned USABLE-RAM frame owned exclusively by us; Limine
        // HHDM-maps all RAM, so `virt = phys + hhdm` is a valid, writable,
        // 8-byte-aligned (4 KiB-aligned) virtual address for the whole frame.
        // Each `ptr.add(i)` for `i < 512` is within the 4 KiB frame
        // (`8 * 512 == 4096`). We zero with a `u64` loop, not `write_bytes`,
        // because the `memset` libcall faults on this higher-half target (see the
        // `mm` notes / HAL TCB §5 M8). The frame is freshly allocated ⇒ unaliased.
        unsafe {
            let mut i = 0usize;
            while i < (PAGE_SIZE as usize / 8) {
                core::ptr::write(ptr.add(i), 0u64);
                i += 1;
            }
        }
        Some(Self { phys, virt })
    }

    /// Physical base address of the frame (what a DMA descriptor must reference).
    #[must_use]
    pub const fn phys(&self) -> PhysAddr {
        self.phys
    }

    /// Virtual base address of the frame (the CPU's HHDM view of it).
    #[must_use]
    pub const fn virt(&self) -> VirtAddr {
        self.virt
    }
}

/// The global physical frame allocator, seeded by [`init`].
///
/// Public so callers (and tests) can query [`FrameAllocator::free_frames`]; the
/// heap maps its pages from this instance.
pub static FRAME_ALLOCATOR: FrameAllocator = FrameAllocator::new();

/// Total physical frames seeded onto the free list at boot, recorded by [`init`]
/// before the heap mapping consumes any. Read live via [`stats`]; `0` until
/// `init` has run. A plain `AtomicUsize` so it is read/written without `unsafe`
/// and never tears.
static TOTAL_FRAMES: AtomicUsize = AtomicUsize::new(0);

/// A live snapshot of kernel memory usage, for the shell's `mem` command.
///
/// All three fields are read with no `unsafe`: `total_frames`/`free_frames`
/// from the frame allocator (the latter behind its `SpinMutex`), and
/// `heap_bytes` from the compile-time [`HEAP_SIZE`] constant. Returned by
/// [`stats`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemStats {
    /// Total 4 KiB frames the allocator was seeded with at boot.
    pub total_frames: usize,
    /// Frames currently on the free list (i.e. not yet handed out).
    pub free_frames: usize,
    /// Size of the kernel heap window, in bytes.
    pub heap_bytes: usize,
}

/// A live snapshot of physical-frame and heap usage.
///
/// Safe to call any time after [`init`] has run (before that, `total_frames` and
/// `free_frames` read as `0`). Cheap: one atomic load plus one short spin-lock to
/// read the frame allocator's free count. Used by the kernel shell's `mem`
/// command to print heap size and frames free/total.
#[must_use]
pub fn stats() -> MemStats {
    MemStats {
        total_frames: TOTAL_FRAMES.load(Ordering::Relaxed),
        free_frames: FRAME_ALLOCATOR.free_frames(),
        heap_bytes: HEAP_SIZE as usize,
    }
}

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
    // Record the boot-time frame total so the shell's `mem` command can report
    // "free / total" live (the free count drops as the heap mapping below and
    // later allocations consume frames). Recorded before any heap mapping runs.
    TOTAL_FRAMES.store(total_frames, Ordering::Relaxed);

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
