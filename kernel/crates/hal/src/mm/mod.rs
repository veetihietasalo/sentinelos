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

pub use addr::{PhysAddr, VirtAddr, PAGE_SIZE};
pub use bootinfo::{hhdm_offset, overlaps_kernel_owned, usable_regions, UsableRegion};
pub use frame::FrameAllocator;
pub use heap::{LockedHeap, HEAP_SIZE, HEAP_START};
pub use paging::{ActivePageTable, MapError, PageFlags};

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
    map_window(phys, len, PageFlags::mmio())
}

/// Map a physical **firmware-table** region (ACPI RSDP/RSDT/XSDT/MADT) into the
/// same higher-half window, **read-only, non-executable, cache-attribute from
/// the MTRRs** (`PageFlags::kernel_ro()`: no PCD/PWT, so a table in RAM that the
/// HHDM may also map write-back is not aliased with a conflicting UC mapping,
/// and a table in BIOS ROM gets whatever the MTRRs declare for it).
///
/// Limine base revision 3 no longer guarantees that the HHDM covers ACPI or
/// reserved memory, so `hal::acpi` cannot simply add the HHDM offset. Returns
/// the [`VirtAddr`] for `phys` (in-page offset preserved). The caller
/// (`hal::acpi::read_phys`) has already refused ranges that overlap
/// kernel-owned RAM ([`overlaps_kernel_owned`]).
///
/// # Errors
///
/// As [`map_mmio`].
pub fn map_firmware_ro(phys: PhysAddr, len: usize) -> Result<VirtAddr, MmioError> {
    map_window(phys, len, PageFlags::kernel_ro())
}

/// The shared body of [`map_mmio`] / [`map_firmware_ro`]: bump-allocate a
/// virtual span in the MMIO window and map every page of `[phys, phys + len)`
/// with `flags`.
fn map_window(phys: PhysAddr, len: usize, flags: PageFlags) -> Result<VirtAddr, MmioError> {
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

// ── §5g: guard-paged kernel-thread stacks (`kernel::sched`, PR-A) ──────────────
//
// Per-task kernel stacks for the cooperative scheduler. Reuses the same
// bump-window pattern as `map_mmio` (§5f) but for a dedicated VA range, and
// deliberately leaves one page unmapped below each stack as an M1 guard: a
// stack overflow walks straight into a never-present page and `#PF`s into the
// existing fault handler instead of silently corrupting whatever comes next in
// the window. See `docs/specs/2026-07-15-scheduler-design.md`.

/// Base of the higher-half virtual window reserved for per-task kernel-thread
/// stacks (guard-paged; see [`alloc_kernel_stack`]).
///
/// Bumped like [`MMIO_WINDOW_BASE`], and chosen well clear of both the heap
/// ([`HEAP_START`]) and the MMIO window so none ever overlap.
const STACK_WINDOW_BASE: u64 = 0xFFFF_F200_0000_0000;

/// Bump pointer for the next free stack-window virtual address (see
/// [`alloc_kernel_stack`]).
static STACK_WINDOW_NEXT: AtomicUsize = AtomicUsize::new(STACK_WINDOW_BASE as usize);

/// Default number of 4 KiB pages in a kernel-thread stack (16 KiB), **not**
/// counting the guard page below it. Chosen generously: a task preempted deep
/// in the timer IRQ (PR-B) holds one `isr_common` frame plus its on-stack
/// `XSAVE` area, and interrupt gates keep IF clear in the handler so nesting
/// depth is bounded at 1.
pub const DEFAULT_STACK_PAGES: usize = 4;

/// Why [`alloc_kernel_stack`] could not allocate a guard-paged kernel stack.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StackAllocError {
    /// Memory management was not initialised (no HHDM offset available).
    NotInitialised,
    /// The frame allocator ran out of physical frames.
    OutOfFrames,
    /// A stack page could not be mapped (an unexpected clash — the stack
    /// window is exclusively bump-allocated, so this should not occur).
    MapFailed(MapError),
}

impl From<MapError> for StackAllocError {
    fn from(e: MapError) -> Self {
        match e {
            MapError::OutOfFrames => Self::OutOfFrames,
            other => Self::MapFailed(other),
        }
    }
}

/// A dynamically frame-allocated, guard-paged kernel-thread stack.
///
/// `[bottom, top)` is [`pages`](Self::pages) × 4 KiB of mapped, writable,
/// non-executable memory (the stack grows *down* from [`top`](Self::top) on
/// `x86_64`); the single page immediately below `bottom` is deliberately left
/// **unmapped** — the M1 guard page.
///
/// No `unmap` primitive exists yet, so the VA/frames a `KernelStack` holds are
/// currently **leaked** on drop rather than reclaimed (same posture as
/// [`DmaFrame`] — see the scheduler design doc's open questions); acceptable
/// for PR-A/PR-B because the tasks that own one are long-lived, and reclaiming
/// a *running* task's own stack is never safe anyway (a task never frees the
/// stack it is executing on).
#[derive(Debug)]
pub struct KernelStack {
    top: VirtAddr,
    bottom: VirtAddr,
    pages: usize,
}

impl KernelStack {
    /// The top of the stack: one past the highest valid byte, and (since
    /// `x86_64` stacks grow down) where a fresh switch frame is fabricated.
    /// Always a multiple of [`PAGE_SIZE`] (hence 16-byte aligned), which is
    /// exactly the alignment `hal::context::Context::for_new_task`'s
    /// fabricated frame relies on at the trampoline's first `call`.
    #[must_use]
    pub const fn top(&self) -> VirtAddr {
        self.top
    }

    /// The lowest mapped address — the guard page starts exactly one page
    /// below this.
    #[must_use]
    pub const fn bottom(&self) -> VirtAddr {
        self.bottom
    }

    /// Number of mapped 4 KiB pages (excludes the guard page below `bottom`).
    #[must_use]
    pub const fn pages(&self) -> usize {
        self.pages
    }
}

/// Allocate a `pages`-page (4 KiB each) kernel-thread stack with an unmapped
/// guard page directly below it.
///
/// Reserves `pages + 1` pages from the dedicated stack VA window
/// ([`STACK_WINDOW_BASE`], bumped like [`MMIO_WINDOW_BASE`]): the upper
/// `pages` are mapped [`PageFlags::kernel_rw`], and the lowest page is left
/// **unmapped** (never present ⇒ a stack overflow into it `#PF`s into the
/// existing fault handler rather than corrupting adjacent memory). Must be
/// called after [`init`] (it needs the HHDM offset and the frame allocator).
///
/// # Errors
///
/// Returns [`StackAllocError::NotInitialised`] if `init` has not run, or
/// [`StackAllocError::OutOfFrames`] / [`StackAllocError::MapFailed`] if a page
/// could not be mapped.
pub fn alloc_kernel_stack(pages: usize) -> Result<KernelStack, StackAllocError> {
    let hhdm = hhdm_offset().ok_or(StackAllocError::NotInitialised)?;

    // Reserve pages+1 (guard + the usable stack) from the bump cursor.
    let span = (pages + 1) * PAGE_SIZE as usize;
    let base = STACK_WINDOW_NEXT.fetch_add(span, Ordering::Relaxed) as u64;

    let table = ActivePageTable::new(hhdm);
    let flags = PageFlags::kernel_rw();
    // The guard page is [base, base + PAGE_SIZE) — deliberately left unmapped.
    let bottom = base + PAGE_SIZE;
    for i in 0..pages {
        let virt = VirtAddr::new(bottom + (i as u64) * PAGE_SIZE);
        let phys = FRAME_ALLOCATOR
            .alloc_frame()
            .ok_or(StackAllocError::OutOfFrames)?;
        table.map_page(virt, phys, flags, &FRAME_ALLOCATOR)?;
    }

    Ok(KernelStack {
        top: VirtAddr::new(bottom + (pages as u64) * PAGE_SIZE),
        bottom: VirtAddr::new(bottom),
        pages,
    })
}

/// Confirm the guard page directly below `stack` is genuinely unmapped.
///
/// A read-only page-table walk ([`ActivePageTable::is_mapped`]) with **no**
/// side effect — it never maps, unmaps, or faults anything. This is the
/// non-destructive stand-in for an actual stack-overflow `#PF` test: rather
/// than deliberately recursing a boot task into its guard page (which would
/// turn every boot into a fault demonstration), the boot proof calls this to
/// verify the invariant [`alloc_kernel_stack`] establishes. Returns `false`
/// (never "unmapped") if memory management was not initialised.
#[must_use]
pub fn stack_guard_is_unmapped(stack: &KernelStack) -> bool {
    let Some(hhdm) = hhdm_offset() else {
        return false;
    };
    let guard = VirtAddr::new(stack.bottom().as_u64() - PAGE_SIZE);
    !ActivePageTable::new(hhdm).is_mapped(guard)
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
