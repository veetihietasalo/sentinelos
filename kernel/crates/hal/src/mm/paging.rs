//! Virtual-memory mapping on top of Limine's 4-level paging.
//!
//! Limine enters the kernel with 4-level paging already enabled and **all**
//! physical RAM higher-half-direct-mapped (HHDM). We do not replace that; we map
//! *new* virtual pages (for the kernel heap) into the **already-active** address
//! space by walking the live page tables and inserting entries, allocating any
//! missing intermediate tables from the physical [frame allocator].
//!
//! Page tables are physical frames; we reach them through the HHDM (`virt =
//! phys + hhdm`). [`map_page`] walks PML4 → PDPT → PD → PT, creating any absent
//! table along the way, and installs a 4 KiB leaf mapping `virt → phys` with the
//! requested [`PageFlags`]. After installing a mapping it invalidates the TLB for
//! that page (`invlpg`).
//!
//! All `unsafe` (reading CR3, dereferencing page-table frames, the `invlpg`) is
//! confined to this module and documented in `kernel/docs/hal-tcb.md` (§5c).
//!
//! [frame allocator]: super::frame

use core::arch::asm;
use core::ptr;

use super::addr::{PhysAddr, VirtAddr, ENTRY_COUNT, PAGE_SIZE};
use super::frame::FrameAllocator;

// ── Page-table entry flag bits ────────────────────────────────────────────────
const PRESENT: u64 = 1 << 0;
const WRITABLE: u64 = 1 << 1;
const USER: u64 = 1 << 2;
const NO_EXECUTE: u64 = 1 << 63;

/// Mask selecting the physical frame address out of a page-table entry.
///
/// Bits 12..=51 hold the next-level table / leaf frame physical address; the low
/// 12 bits are flags and bits 52..63 are flags / reserved.
const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Flags controlling a virtual→physical mapping installed by [`map_page`].
///
/// A safe, value-type description of the page-table leaf permission bits, so the
/// caller never touches raw bit positions. `PRESENT` is always set by
/// [`map_page`]; these select the rest.
#[derive(Clone, Copy, Debug)]
pub struct PageFlags {
    writable: bool,
    user_accessible: bool,
    no_execute: bool,
}

impl PageFlags {
    /// Kernel read-only, non-executable data (e.g. metadata pages).
    #[must_use]
    pub const fn kernel_ro() -> Self {
        Self {
            writable: false,
            user_accessible: false,
            no_execute: true,
        }
    }

    /// Kernel read-write, non-executable data — the kernel-heap default.
    #[must_use]
    pub const fn kernel_rw() -> Self {
        Self {
            writable: true,
            user_accessible: false,
            no_execute: true,
        }
    }

    /// Make this mapping user-accessible (sets the U/S bit).
    #[must_use]
    pub const fn user_accessible(mut self) -> Self {
        self.user_accessible = true;
        self
    }

    /// The raw leaf-entry flag bits (always including `PRESENT`).
    const fn bits(self) -> u64 {
        let mut bits = PRESENT;
        if self.writable {
            bits |= WRITABLE;
        }
        if self.user_accessible {
            bits |= USER;
        }
        if self.no_execute {
            bits |= NO_EXECUTE;
        }
        bits
    }

    /// Flag bits for an *intermediate* table entry pointing at `self`'s leaf.
    ///
    /// Intermediate entries must be present and writable; we also set USER if the
    /// final mapping is user-accessible (the most-restrictive of the levels wins
    /// at translation time, so a permissive parent is fine).
    const fn intermediate_bits(self) -> u64 {
        let mut bits = PRESENT | WRITABLE;
        if self.user_accessible {
            bits |= USER;
        }
        bits
    }
}

/// Errors that can occur while installing a mapping.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MapError {
    /// The frame allocator was out of physical frames for a new page table.
    OutOfFrames,
    /// The target virtual page is already mapped to a (different) frame.
    AlreadyMapped,
}

/// The active 4-level page-table hierarchy, reached via CR3 + the HHDM offset.
///
/// Construct with [`ActivePageTable::new`] (passing the HHDM offset). It does not
/// own the tables — they belong to the running address space Limine built — it is
/// a thin, lock-free *view* used to edit them. Map operations are serialised by
/// the caller ([`super::heap`] grows the heap once during `init`, single-core).
pub struct ActivePageTable {
    /// HHDM offset: `virt = phys + hhdm` for any physical address.
    hhdm: u64,
}

impl ActivePageTable {
    /// Create a view over the currently-active page tables.
    ///
    /// `hhdm` is the higher-half direct-map offset (from
    /// [`super::bootinfo::hhdm_offset`]). The PML4's physical base is read from
    /// CR3 on demand inside [`map_page`].
    #[must_use]
    pub const fn new(hhdm: u64) -> Self {
        Self { hhdm }
    }

    /// Physical base address of the active top-level table (PML4), from CR3.
    fn pml4_phys(&self) -> PhysAddr {
        let cr3: u64;
        // SAFETY: `mov rax, cr3` reads the page-table base register into a GP
        // register. It accesses no memory (`nomem`), no stack (`nostack`), and
        // does not alter flags (`preserves_flags`). Reading CR3 is a privileged
        // but side-effect-free move; we are in ring 0 (kernel) so it is allowed.
        unsafe {
            asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        }
        // The low 12 bits of CR3 are flags (PCD/PWT/PCID); the PML4 base is the
        // 4 KiB-aligned address above them.
        PhysAddr::new(cr3 & ADDR_MASK)
    }

    /// Mutable pointer to a page-table frame, via its HHDM mapping.
    ///
    /// `phys` must be the 4 KiB-aligned physical base of a real page-table frame.
    /// The returned pointer addresses the 512-entry (`[u64; 512]`) table.
    fn table_ptr(&self, phys: PhysAddr) -> *mut u64 {
        (phys.as_u64() + self.hhdm) as *mut u64
    }

    /// Read entry `index` of the table at physical base `table`.
    ///
    /// # Safety
    ///
    /// `table` must be the 4 KiB-aligned base of a live page-table frame and
    /// `index < 512`. The frame must be HHDM-mapped (always true for tables
    /// Limine created or that we allocated from usable RAM).
    unsafe fn read_entry(&self, table: PhysAddr, index: usize) -> u64 {
        // SAFETY: by this function's contract `table` is a valid table frame and
        // `index < 512`, so `table_ptr(table).add(index)` is within the 512-entry
        // (`8 * 512` byte) frame, 8-byte-aligned (table is 4 KiB-aligned), and
        // HHDM-mapped (readable). The caller upholds these preconditions.
        unsafe { ptr::read(self.table_ptr(table).add(index)) }
    }

    /// Write `value` into entry `index` of the table at physical base `table`.
    ///
    /// # Safety
    ///
    /// Same preconditions as [`read_entry`](Self::read_entry). The write must not
    /// race another writer (single-core / caller-serialised at bring-up).
    unsafe fn write_entry(&self, table: PhysAddr, index: usize, value: u64) {
        // SAFETY: as in `read_entry`, `table` is a valid table frame and
        // `index < 512`, so the target is within the frame, 8-byte-aligned, and
        // HHDM-mapped (writable — Limine maps RAM writable and our own table
        // frames are usable RAM). The caller guarantees no concurrent writer.
        unsafe { ptr::write(self.table_ptr(table).add(index), value) }
    }

    /// Allocate and zero a fresh page-table frame.
    ///
    /// Returns its physical base, or `None` if the frame allocator is empty.
    fn new_table(&self, frames: &FrameAllocator) -> Option<PhysAddr> {
        let frame = frames.alloc_frame()?;
        let ptr = self.table_ptr(frame);
        // SAFETY: `frame` came from the frame allocator, so it is a 4 KiB-aligned
        // usable-RAM frame, HHDM-mapped at `ptr`, and owned exclusively by us
        // (just allocated). We zero it one `u64` at a time — deliberately *not*
        // `ptr::write_bytes`, which lowers to a `memset` libcall that faults on
        // this higher-half static-relocation target (the `.got`/`.rela` sections
        // it would need are discarded by the linker script). Each `ptr.add(i)`
        // for `i < ENTRY_COUNT` is within the 4 KiB frame (`8 * 512 == 4096`
        // bytes), 8-byte-aligned, writable, and unaliased. A zeroed table has
        // every entry non-present — the correct empty initial state.
        unsafe {
            let mut i = 0;
            while i < ENTRY_COUNT {
                ptr::write(ptr.add(i), 0u64);
                i += 1;
            }
        }
        Some(frame)
    }

    /// Walk to the next level, creating the intermediate table if absent.
    ///
    /// Reads entry `index` of `table`; if present, returns the referenced child
    /// table's physical base; otherwise allocates a zeroed child table, links it
    /// with `intermediate` flags, and returns it.
    ///
    /// # Safety
    ///
    /// `table` must be a live table frame and `index < 512`.
    unsafe fn next_table_create(
        &self,
        table: PhysAddr,
        index: usize,
        intermediate: u64,
        frames: &FrameAllocator,
    ) -> Option<PhysAddr> {
        // SAFETY: `table`/`index` validity is this function's precondition,
        // upheld by `map_page` which only ever passes the active PML4 (from CR3)
        // or a child returned by a previous `next_table_create`, plus a 9-bit
        // index. So reading the entry is sound.
        let entry = unsafe { self.read_entry(table, index) };
        if entry & PRESENT != 0 {
            return Some(PhysAddr::new(entry & ADDR_MASK));
        }
        let child = self.new_table(frames)?;
        // SAFETY: same `table`/`index` validity as the read above; we link the
        // freshly-allocated, zeroed `child` frame with present+writable
        // intermediate flags. Single-core/caller-serialised ⇒ no concurrent
        // writer. `child` is 4 KiB-aligned so its address occupies only the
        // ADDR_MASK bits and does not collide with the flag bits.
        unsafe {
            self.write_entry(table, index, child.as_u64() | intermediate);
        }
        Some(child)
    }

    /// Map a single 4 KiB virtual page to a physical frame with `flags`.
    ///
    /// Walks PML4→PDPT→PD→PT from the active CR3, creating any missing
    /// intermediate tables from `frames`, then installs the leaf entry and
    /// invalidates the TLB for `virt`. `virt` and `phys` are floored to their
    /// 4 KiB frame. Returns [`MapError::AlreadyMapped`] if the leaf was already
    /// present, or [`MapError::OutOfFrames`] if a table could not be allocated.
    pub fn map_page(
        &self,
        virt: VirtAddr,
        phys: PhysAddr,
        flags: PageFlags,
        frames: &FrameAllocator,
    ) -> Result<(), MapError> {
        let virt = VirtAddr::new(virt.as_u64() & !(PAGE_SIZE - 1));
        let phys = phys.frame_floor();
        let [i4, i3, i2, i1] = virt.table_indices();
        let intermediate = flags.intermediate_bits();

        let pml4 = self.pml4_phys();
        // SAFETY: `pml4` is the active top-level table (read from CR3) — a live,
        // HHDM-mapped table frame — and each `i*` is a 9-bit index (`< 512`) from
        // `table_indices`. So every `next_table_create` below sees a valid table
        // + index; each returns a live child table frame (allocated zeroed or
        // already present) which is the valid input to the next level. The final
        // `read_entry`/`write_entry` target the leaf PT with a valid index.
        unsafe {
            let pdpt = self
                .next_table_create(pml4, i4, intermediate, frames)
                .ok_or(MapError::OutOfFrames)?;
            let pd = self
                .next_table_create(pdpt, i3, intermediate, frames)
                .ok_or(MapError::OutOfFrames)?;
            let pt = self
                .next_table_create(pd, i2, intermediate, frames)
                .ok_or(MapError::OutOfFrames)?;

            if self.read_entry(pt, i1) & PRESENT != 0 {
                return Err(MapError::AlreadyMapped);
            }
            self.write_entry(pt, i1, phys.as_u64() | flags.bits());
        }

        flush_tlb(virt);
        Ok(())
    }
}

/// Invalidate the TLB entry for a single virtual page (`invlpg`).
fn flush_tlb(virt: VirtAddr) {
    // SAFETY: `invlpg [mem]` invalidates any cached TLB translation for the page
    // containing the operand address. It reads no program memory we model in Rust
    // (`nomem` is appropriate — it only consults the TLB/operand address), uses no
    // stack (`nostack`), and does not affect flags (`preserves_flags`). Flushing a
    // stale translation can only make subsequent accesses *more* correct; it can
    // never introduce UB.
    unsafe {
        asm!(
            "invlpg [{}]",
            in(reg) virt.as_u64(),
            options(nostack, preserves_flags),
        );
    }
}
