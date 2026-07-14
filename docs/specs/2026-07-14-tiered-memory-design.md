# Tiered-memory / CXL abstraction — Design

Status: **proposed** · cross-cutting (memory subsystem) · design only, no code yet.
References (design pointers, not endorsements): adaptive tiered-memory tuning
[arXiv:2604.12165], fair multi-tenant CXL tiering [arXiv:2602.08800], CXL-hybrid
memory for LLM inference / KV cache [arXiv:2606.12556, arXiv:2606.19746],
stall-aware allocation for mixed-criticality [arXiv:2511.19991]. See the strategy
note `docs/research/2026-07-14-sentinelos-strategy-and-roadmap.md` (decision #2).

## Goal

Give the physical memory manager a **tier** concept from the start, so that when
memory stops being uniform — CXL-attached expansion memory, HBM, persistent
memory — the kernel already has the abstraction to place data by speed/capacity
class instead of retrofitting it. This is one of the two "get-it-right-once"
decisions: the frame-allocator API shape is cheapest to change **now**.

Explicitly **not** in scope here: the placement *policy* (hot/cold classification,
promotion/demotion), tier *discovery* from firmware (ACPI SRAT/HMAT — that rides
Track B), and multi-tenant fairness (needs userland). This doc reserves the
abstraction those will plug into.

## Background

**CXL** (Compute Express Link) lets a CPU attach cache-coherent memory beyond its
local DIMM slots — much more capacity, higher latency. The OS consequence: there
is no longer "memory", there are **tiers** with different latency/bandwidth/
capacity, and the allocator must decide what lives where. AI workloads are the
canonical driver: model weights + KV-cache state are tens of GiB but not all hot
at once, so a tiering-aware manager keeps the working set in fast local DRAM and
spills the rest to CXL — the bridge between our memory manager and Track C
(inference). That is why this small (32-paper) corner of the literature matters
disproportionately for us.

## Current state (accurate)

`hal::mm::frame::FrameAllocator` is a **single flat pool**: `init` threads every
usable 4 KiB frame from Limine's memory map onto one intrusive free list;
`alloc_frame() -> Option<PhysAddr>` pops the head; `dealloc_frame` pushes. There
is **no** notion of tier, source, or speed class anywhere in the type — and no way
to even *ask* for a fast vs. slow frame.

All callers today are **inside `hal::mm`** (a tiny blast radius):
- `paging::ActivePageTable::new_table` — page-table frames.
- `mm::{map_page helpers}` — heap growth, MMIO, and DMA-frame mapping.

That is the whole surface that a signature change touches — a handful of internal
sites, not a cross-kernel refactor. It will not stay that small once storage
caches, a compositor, and userland all allocate.

## Proposed design

### 1. A `MemoryTier` classification

```rust
pub enum MemoryTier {
    Local,      // CPU-local DRAM — the fast tier (all memory today)
    Expansion,  // CXL / far / capacity tier — higher latency
    // (HBM, PMem, etc. added as hardware and discovery land)
}
```

Today, with QEMU and no CXL, **every** frame is `Local` — the abstraction degrades
to exactly current behaviour, zero runtime change. Tier discovery (ACPI SRAT
proximity domains + HMAT latency/bandwidth; CXL memory appears as its own domain)
is future work; until then a stub reports a single `Local` tier.

### 2. Tier-aware allocation, back-compatible by default

```rust
pub enum TierPref { PreferLocal, PreferExpansion, RequireLocal }

impl FrameAllocator {
    // New primary API. Falls back across tiers unless Require* forbids it.
    pub fn alloc_frame_in(&self, pref: TierPref) -> Option<PhysAddr>;
    // Kept as `alloc_frame_in(PreferLocal)` so existing callers are unchanged.
    pub fn alloc_frame(&self) -> Option<PhysAddr>;
}
```

Internally, one free list per known tier (today: just `Local`). `dealloc_frame`
returns a frame to the tier it came from — which requires knowing a frame's tier;
with one tier that is trivial, with several it comes from the discovery map
(address-range → tier), not from per-frame metadata.

### 3. Threading a hint through `map_page`

`PageFlags` (or a sibling `MapHint`) gains an optional tier preference so callers
express intent: page tables and hot kernel structures → `RequireLocal`/
`PreferLocal`; large cold buffers (a future model-weight arena, KV spill) →
`PreferExpansion`. `map_page` forwards the hint to `alloc_frame_in`. Callers that
don't care keep the defaulted `PreferLocal`.

### 4. Policy is a later, separable layer

Hot/cold tracking (via PTE Accessed bits), promotion/demotion, and a tuning
control loop ([arXiv:2604.12165]) sit **above** this mechanism and are out of
scope here. Multi-tenant fairness ([arXiv:2602.08800]) waits for userland/tenants.
The point of this doc is that the *mechanism* (tier tag + tier-aware alloc + map
hint) is in place so those policies attach without an allocator rewrite.

## Testing

- **No-regression (today):** with one `Local` tier, `alloc_frame()` behaves
  exactly as now; the boot test (`make test`) must stay green.
- **Future tier test:** recent QEMU can emulate a CXL type-3 device
  (`-device cxl-type3,…`); a later boot test can attach one, confirm the allocator
  discovers a second (`Expansion`) tier, and that a `PreferExpansion` allocation
  lands there while page tables stay `Local`.
- Unit-testable pieces (address-range → tier lookup, fallback ordering) are pure
  logic — Kani/Miri candidates under the new Verify workflow.

## Phasing

1. **This doc's implementation:** `MemoryTier` + `TierPref`, per-tier free lists
   (one tier populated), `alloc_frame` preserved, `map_page` hint plumbed. All
   callers keep working; behaviour identical on non-CXL hardware.
2. **Discovery (with Track B / ACPI):** parse SRAT/HMAT → an address-range→tier
   map; populate real tiers.
3. **Policy:** hot/cold + promotion/demotion + tuning loop; then multi-tenant
   fairness once there are tenants.

## Open questions

- Per-tier free lists (chosen above) vs. a single list with a per-frame tier tag?
  Per-tier lists make "allocate from tier X" O(1) and keep `dealloc` cheap via the
  range→tier map; revisit if tier count grows large.
- Does tier discovery belong in `hal` (ACPI parse in the TCB) or a safe layer
  above it consuming a raw table? Leaning: minimal ACPI table access in `hal`,
  parsing/policy in safe kernel code — consistent with the framekernel split.
- Should `RequireLocal` failures be hard errors (e.g. for DMA that a device can't
  reach on the far tier) or silent fallbacks? Proposal: hard `None` for `Require*`.
