# SentinelFS — a copy-on-write, content-addressed, Merkle-verified filesystem

Status: **proposed · review round 1 complete (2026-09-18) · FS-1a implemented (2026-10-03),
code-review round 1 addressed (2026-10-03) · FS-1b implemented (2026-10-04)** — four-role verdicts and the amendment table in
§15; A1–A16 applied inline in this revision, the rest owned by the PR named there. **Re-staged 2026-10-03 (Veeti):** the
storage-capability lattice moves out of FS-1a into **FS-1c**, on top of component PR-2's
`kernel::cap` (§9, §11, A13); FS-1a's as-built notes — corrected group arithmetic, the
coexistence window, what `flush` means on today's ATA — and FS-1b's (the tree, the
torn-commit proof and its test-control sector, the deviations) are in §11 · Track A (kernel core) + D
(security subsystem) · Author: kernel-architect
Depends on: `hal::ata` (PIO block I/O incl. `FLUSH CACHE`, TCB; FS-1b split `flush()` out of
`write_sectors`, row A2 amended, zero new rows), `kernel::hash`
(SHA-256, component PR-1), `kernel::clock` (commit pacing), the component-model design
(`docs/specs/2026-09-18-component-model-design.md`: §6 content-addressed identity, §10 state
objects, §13 `kernel::state` / `kernel::secrets` "persistence via `kernel::fs`", §19 review
conditions), and the identity/login spec (to be written) for every key this design wraps.
Escalation: **architectural.** Replaces `kernel::fs`'s on-disk format outright (no migration:
the image is a dev artefact under `target/`). **Zero new `hal` rows**: the one this spec first
claimed (`FLUSH CACHE`) already exists (`hal::ata` row A2); FS-1b amends that row's text.
Direction from Veeti (2026-09-18): "the filesystem the most efficient possible in the modern
world … we aim for perfection" — this spec says what that means here and what it does not.

## 1. Summary

SentinelFS never overwrites a live block. Every write allocates fresh blocks, every block
pointer carries the SHA-256 of what it points to, and a commit is one atomic superblock
switch between two generation-numbered slots. A crash at any instant leaves the previous
root intact and verifiable: **no journal, no replay, no fsck**. The superblock's hash is a
32-byte summary of the entire filesystem state (root, blobs, snapshots, free space,
generation), which the IntegrityLog signs and a paired device can verify — the filesystem
becomes something the Sentinel subsystem can *attest*, not just store into.

Blobs are content-addressed (a second tree keyed by hash within a **domain**), so components
(already identified by `H(code ‖ params)`), model weights and state-object snapshots are
stored exactly once per domain and the host's "the kernel knows what it runs" check is also
"the disk knows what it holds". Snapshots are free (an old root kept alive), which gives
rollback after a bad update — and rollback is a **privileged, logged operation**, because it
also resurrects revoked capabilities and pruned findings. Small files live inline in the
tree; larger ones in extents with a hash per block; the whole thing runs in a bounded block
cache well inside the 4 MiB heap and never materialises the image in memory.

"Most efficient in the modern world" splits into two things. The *format* is designed for
the modern world: 4 KiB blocks, extents, CoW B+tree, inline small files, dedup, no journal
double-write. The *transport* is not: `hal::ata` is 16-bit PIO with polling, so throughput is
bounded by the CPU pushing words through a port. DMA (NVMe queues, or virtio-blk under
QEMU) is new `hal` territory — MMIO doorbells, DMA-coherent buffers, MSI-X — and gets its own
spec **after** the format proves itself on ATA (§13). The block-device trait is shaped for
DMA now (multi-block transfers, explicit flush) so the format never has to change for it.
Perfection is sequenced, not claimed.

## 2. Goals and non-goals

Goals (v1, FS-1a…FS-5):

1. **Crash consistency by construction.** Under the durability model of §8 — the device may
   have applied *any subset* of the writes issued since the last flush — every crash mounts
   the last fully committed generation, scrubs clean, and has no live block marked free
   (host property test over write indices and torn superblock sectors; QEMU torn-commit
   proof for the two cases the host cannot reach).
2. **Integrity everywhere.** Every metadata and data block is hashed; a flipped bit anywhere is
   detected at read and named in the scrub. The superblock hash is attestable.
3. **Content addressing.** `put_blob(domain, bytes) -> Hash`, deduplicated within a domain;
   components and state objects live there.
4. **Snapshots and rollback** as first-class, O(1), *privileged* operations.
5. **Bounded memory.** One 64-block cache slab (256 KiB) that includes the dirty set; no path
   that allocates proportional to the image size; a counting allocator proves it on the host.
6. **Same shell and Files-app behaviour** through the `kernel::fs` API — with the two API
   changes §3 names, because a block cache cannot serve a borrow into a heap tree.
7. **Deterministic.** Replaying the same operation sequence on the same image yields the same
   superblock hash; the same key set reached by different orders yields the same tree items.

Non-goals (v1): POSIX semantics (permissions, links, mtime beyond a generation number),
encryption at rest (§10 places it; the identity spec supplies keys), multiple devices,
compression, quotas beyond the per-capability ones in §9, rollback *protection* against a
full-disk adversary (§12, anchor field reserved), DMA (§13, separate spec), **atomicity of a
single bulk data write** larger than the dirty budget (it spans commits; metadata operations
are always atomic — §8), and erasure: **deletion is not erasure** while a snapshot holds the
data (crypto-shred arrives with per-object keys, §10).

## 3. What we have, honestly

`kernel::fs` today: a heap tree of `Vec<(name, Node)>` directories and `Vec<u8>` files,
serialised as **one blob** behind a superblock (`"SNTLFS01"`, payload length, one CRC-32),
**rewritten whole on every mutating operation** over ATA PIO. `MAX_PAYLOAD = 64 KiB`. A power
cut mid-write corrupts the image; the CRC catches it on the next boot and the code falls back
to the seeded tree — data loss by design. No per-block checksums, no allocation, no
directories on disk (the tree is the payload), no snapshots, nothing addressable by content.
It did its job (prove persistence exists) and it is the right thing to replace rather than
evolve: none of its on-disk decisions survive contact with the goals above.

What survives: the `FileSystem` API shape the shell and the Files app use (`list`,
`write_file`, `mkdir`, `remove`, `change_dir`, `cwd`, `is_persistent`), `FsError` with a stable
`message()`, "no panics on bad user input", the fmt-free discipline, `prove_persistence`'s
reboot-survival proof, and `hal::ata`'s safe surface.

What changes in the facade (FS-2), stated now because callers depend on it:

- `read_file(&self, path) -> Result<&[u8]>` becomes `read_file(&mut self, path, out: &mut
  Vec<u8>) -> Result<usize>` (and a `read_into(&mut [u8], offset)` for the Files app's
  bounded view). A borrow into the tree cannot be served from a 64-entry cache; pinning would
  be unbounded. `shell.rs` (`cat`) and `app/files.rs` (preview) change at their two call sites.
- `FsError` gains `Corrupt`, `NoSpace`, `Io`, `ReadOnly`. The old contract "disk errors never
  fail a user operation" is **retired**: there is no authoritative in-memory tree any more. A
  read can fail `Corrupt`/`Io`; a write can fail `NoSpace`/`Io`/`ReadOnly`. Each has a
  `message()` the shell prints.
- `stat(path) -> { kind, size, gen }` (FS-2); `rename` and the `snapshot` / `rollback`
  built-ins arrive with FS-4.

## 4. Vocabulary

| Term | Meaning |
|---|---|
| **Block** | 4 KiB = 8 ATA sectors, the unit of allocation, hashing and caching. `BlockNo(u32)`: up to 16 TiB. |
| **Pointer** | `{ block: BlockNo, hash: [u8; 32], gen: u64 }` — where, what it must hash to, when written. Every reference between blocks is a Pointer. |
| **Block hash** | Metadata: SHA-256 over the whole 4 KiB with the 32-byte hash field zeroed — the header (`kind`, `gen`, `tree_id`, `fs_uuid`) is *inside* the hash. Data: SHA-256 over the whole 4 KiB. `Pointer.hash == header.hash` always. |
| **Superblock** | Two fixed slots (blocks 0 and 1). Each: magic, format version, generation, root Pointers, geometry, keys-in-the-clear, own hash. Mount takes the valid slot with the higher generation. |
| **Generation** | Monotonic u64, +1 per commit. Also the "mtime" of everything (no wall clock on disk). Mount compares superblock `gen` (off 88); a block's header `gen` is informational (which commit wrote it). |
| **Tree** | A CoW B+tree of items keyed by `Key { obj: u64, kind: u8, off: u64 }`; nodes are blocks; children are Pointers. |
| **Key** | 17 bytes, packed little-endian at fixed offsets `[0..8) obj, [8] kind, [9..17) off`; no alignment assumed; parsed with explicit offsets. Sorts by `(obj, kind, off)`. |
| **Object** | A file, directory, blob or snapshot record: a range of keys with the same `obj`. |
| **Extent** | `{ start: BlockNo, len: u32 ≤ 32, hashes: [[u8; 32]; len] }` — a contiguous run of ≤ 32 data blocks (128 KiB) with **one hash per block**, so any block is verified alone. Longer runs are several extents. |
| **Inline data** | File bytes stored inside the leaf item when ≤ `INLINE_MAX = 1024` (so two inline items always share a leaf and split/merge stays well-defined). |
| **Blob** | Content-addressed data: `(domain, Hash) → extents`, refcounted per domain. Domains: `Public` (components, weights: keyed by plain SHA-256) and `User(n)` (per-user keyed hash, §10). |
| **Snapshot** | A retained root Pointer with a name and generation, in the roots tree. Creating or rolling back to one is a distinct capability op, not `Write`. |
| **Transaction** | The in-memory dirty set between two commits. Commits happen only at **quiescent points** (between operations). |
| **Scrub** | Read every reachable block, verify every hash, report; `bad > 0` ⇒ the affected objects are marked `Corrupt` and the mount goes read-only (§12). |

## 5. Principles (each maps to a boot proof in §11)

1. **Never overwrite a live block.** Allocation only from blocks free in the *committed* root
   and not referenced by any retained snapshot. Proof: torn-commit recovers the previous root.
2. **Every pointer carries a hash, and the hash covers the whole block.** Reads verify before
   returning; a mismatch is `Corrupt`, never silently served; a kind-confused or foreign block
   fails the hash because `kind` and `fs_uuid` are inside it. Proof: scrub finds an injected bit
   flip in a header field as well as in data.
3. **One root, two slots.** A commit is: write all dirty blocks → flush → write the new
   superblock into the *other* slot → flush. Mount picks the higher valid generation. Proof:
   `mount: gen=N slot=1 verified=yes`.
4. **Deterministic shape and deterministic history.** Split and merge points depend only on
   the key set, so the same key set reached by different operation orders yields the same
   tree *items* (host test: A-then-B vs B-then-A, churn back to the same set). Allocation
   depends only on committed state and the operation sequence — never on cache state — so
   replaying a sequence on the same image yields the same superblock hash (host test). Two
   filesystems with the same logical content do **not** share a superblock hash: pointers
   embed placement, and the attestation in §9 attests *this disk*, not abstract content.
   Content identity lives in the blob tree, where the key *is* the hash.
5. **Content is addressed by what it is, within a domain.** `put_blob` returns the domain's
   hash; a second `put` of the same bytes in the same domain allocates nothing. Proof:
   `cas: dedup=yes`.
6. **Snapshots are pointers; rollback is history, never rewriting.** `snapshot()` writes one
   item; `rollback()` writes a *new* generation whose roots are the snapshot's, and logs it.
   Proof: `snapshot=ok rollback=ok logged=yes`.
7. **Bounded memory, always.** No operation allocates proportional to image size. Proof: host
   test formats a 1 GiB `MemDevice` and runs the suite under a **counting allocator** cap.
8. **A full disk can always free space.** CoW needs fresh blocks to write the bitmaps and
   superblock that *free* blocks, so a **metadata reserve** (`RESERVE = 64` blocks per group,
   usable only by `remove`/reclaim commits) is held back from data allocation. Proof: host
   test fills the disk, then deletes successfully.
9. **Nothing above the facade changes but the two API points §3 names.** Proof: the existing
   `[fs] persistence` proof line keeps passing, now against SentinelFS.

## 6. Architecture

```
┌───────────────────────────────────────────────────────────────────────────────┐
│  shell · Files app · kernel::state (state objects) · kernel::host (components) │
├───────────────────────────────────────────────────────────────────────────────┤
│  kernel::fs        the FileSystem API — a facade over sfs (FS-2, §3 changes)   │
│  kernel::sfs       SentinelFS: superblocks · CoW B+tree · extents · blobs ·    │
│                    snapshots · transactions · scrub          (safe Rust)       │
│  kernel::blk       block layer: BlockDevice trait · verified read/write ·      │
│                    one 64-block cache slab · allocator (group bitmaps)         │
│  sfs-commit task   the ONLY thread that touches the device; owns commit pacing │
├───────────────────────────────────────────────────────────────────────────────┤
│  hal::ata          PIO sectors + FLUSH CACHE (TCB, rows A1–A4, text amended)   │
│  later: hal::nvme / hal::virtio_blk — DMA queues, own spec (§13)               │
└───────────────────────────────────────────────────────────────────────────────┘
```

- **`kernel::blk::BlockDevice`**, shaped for DMA now:
  `fn blocks(&self) -> u64; fn read_blocks(&mut self, start: BlockNo, out: &mut [Block]) ->
  Result; fn write_blocks(&mut self, start: BlockNo, data: &[Block]) -> Result; fn flush(&mut
  self) -> Result;`. Implemented by `AtaDevice` (8 sectors per block; `write_blocks` is
  *unflushed* once FS-1b splits `hal::ata`'s API, §11) and by `MemDevice` on the host (a
  `Vec<u8>` with crash-at-write-index, torn-sector and **unflushed-subset** hooks, §8).
- **Verified reads**: `blk` checks the Pointer's hash before a block enters the cache; a cache
  entry is **immutable while resident and verified** — parsers read the cached copy, never
  the device, so hash-then-parse has no window (the TOCTOU the review named). Dirty blocks
  are **unevictable**; the slab is `CACHE_BLOCKS = 64` entries including at most
  `DIRTY_MAX = 48` dirty ones — one budget, 256 KiB, stated once.
- **Locking.** `SpinMutex<Sfs>` guards the in-memory state (cache index, dirty set, tree
  cursors) and is held only for bounded in-memory work — **never across device I/O**
  (`hal::sync::SpinMutex` does not mask interrupts, hal-tcb §5e; a holder preempted mid-PIO
  would make every other core spin). All I/O is done by the **`sfs-commit` task**, a pinned
  kernel thread (`spawn_on(0, …)`): a caller's read miss enqueues a request and blocks on a
  completion flag; the task reads with the lock released, then takes the lock to publish.
  Commits (§8) are the task's alone. Nothing about the FS runs in IRQ context — the interval
  commit is the task waking on `clock::mono_ticks`, never `on_tick`.
- **`kernel::sfs`** is pure logic over `blk`: never touches ports, never allocates unbounded,
  never panics on disk contents (every parse is `&[u8] -> Result`; every loop driven by an
  on-disk count is bounded by the block size, not by the field).
- **`kernel::fs`** keeps its API shape and becomes a thin path resolver over `sfs` (FS-2);
  the old serialiser is deleted.
- Components reach the FS only through a **storage capability** (§9).

## 7. On-disk format

All integers little-endian. Block size `BLOCK = 4096`. Hashes are SHA-256 (32 bytes).
Every metadata block begins with a 64-byte header:

```text
off len field
 0   32  hash           SHA-256 of the WHOLE block with these 32 bytes zeroed — covers
                        kind, gen, tree_id, fs_uuid and the payload (A1)
32    8  gen            generation that wrote this block (informational)
40    4  kind           1 superblock · 2 tree node · 3 bitmap · 5 group index
                        (6 keyring: reserved for the identity spec, §7.1; refused in v2)
44    4  tree_id        which tree: 0 none (superblock) · 1 root · 2 blobs · 3 roots ·
                        4 free (bitmaps and the group index)
48   16  fs_uuid        the filesystem this block belongs to (stray-block detection)
```

Data blocks (kind 4) have **no** header: their hash lives in the extent item (one per
block), so a 4 KiB file block is 4 KiB of user data and is verifiable alone.

A `Pointer` is `{ block u32, pad u32 = 0, hash [32], gen u64 }` (48 bytes). `Pointer::NULL`
is all-zero; block 0 is a superblock slot and never a pointer target, so the null encoding
is unambiguous.

### 7.1 Superblock (slots: block 0 and block 1)

```text
 64    8  magic "SNTLFS02"     72   4  version = 2       76   4  block_size = 4096
 80    8  total_blocks         88   8  gen               96  32  fs_uuid (dup)
128   48  root: Pointer{block u32, pad u32, hash [32], gen u64}   — the metadata tree
176   48  blobs: Pointer        — the content-addressed tree
224   48  roots: Pointer        — the snapshots tree
272   48  free: Pointer         — the allocation-group index block (§7.4, one level)
320    8  next_obj             328   8  committed_at (mono ticks; informational, per boot)
336   16  dirent_key            key for the dirent name hash (§7.2) — not secret, defeats
                                offline-precomputed collision floods; derived per §10 later
352   32  kdf_params            reserved for the identity spec (§10): alg u16 | ver u16 |
                                m_kib u32 | t u32 | p u32 | salt [16] — inside the signed
                                superblock so they cannot be downgraded offline
384    8  reserve_blocks_per_group (§5.8)
392   48  keys: Pointer          reserved: the keyring block (kind 6) holding every wrapped key
440   …   zero
```

Mount: read both slots; a slot is valid iff its hash matches, `magic`/`version` do, and
`total_blocks ≤ device blocks`; take the valid slot with the higher `gen`; if neither is
valid: **`Corrupt`** if either carries the magic (a filesystem was here — never auto-format
over it; mount read-only-empty and report), **`Unformatted`** only if both slots are all-zero
or carry a foreign magic. The kernel formats a disk only when it is `Unformatted`, and the
shell gains an explicit `format` built-in for the other case. A torn superblock write fails
its own hash and is ignored, which is the whole recovery story.

FS-1a pins what the table leaves open (`kernel::sfs::superblock`, all checked at mount — a
slot that breaks one is invalid, and still "carries the magic"):

- `fs_uuid (dup)` is the header's 16-byte uuid followed by 16 zero bytes; header `kind` = 1,
  `tree_id` = 0, header `gen` = superblock `gen` ≥ 1; `total_blocks` ≥ 128; `free` non-null and
  every tree pointer null or inside `[2, total_blocks)` with a `gen` in `1..=gen`; reserve ≤ one
  group; bytes `[392, 4096)` zero. Generation `g` is written to slot `g % 2` (format writes
  generation 1 to slot 1), so on a healthy disk `slot = gen % 2` always. Two valid slots with
  the **same** generation (which the writer never produces) resolve to slot `gen % 2`, the
  one the writer would have used. `next_obj` and `committed_at` are **not** validated at
  mount (`committed_at` is per boot and informational; `next_obj` is FS-2's to police).
- **`kdf_params` and `keys` must be zero in v2** until the identity spec defines them: a
  non-zero byte is refused, so a kernel that cannot unwrap a key never mounts an encrypted tree
  as plaintext. Their layout is reserved now (named constants in `kernel::sfs::superblock`,
  still validated as zero): the KDF parameters are exactly the 32 bytes at `[352, 384)`,
  `alg u16 | ver u16 | m_kib u32 | t u32 | p u32 | salt [16]`. Wrapped keys do **not** fit
  there (an AEAD-wrapped 256-bit key alone is ≥ 48 bytes) and do **not** go into the zero tail
  either — key material past byte 512 would break the first-sector torn-write argument below.
  They live in a copy-on-write **keyring** metadata block (new kind 6: the tree key, the
  KeyAgent key, later recovery and per-user slots), named by the `keys: Pointer` reserved at
  `[392, 440)` — null in v2, so v2's zero-tail check is unchanged. Superblock content stays
  below byte 512.
- Every field — the reserved `keys` pointer included — ends by offset 440, inside the
  block's **first 512-byte sector**; sectors 1–7 are zero. Format zeroes both slots (and flushes) before it writes anything else, and a commit
  only ever overwrites an older superblock, so a torn superblock write leaves either the old
  first sector or the new one — it can make a slot stale, never `Corrupt`. The host crash
  matrix checks exactly this (format: `Unformatted` or generation 1; commit: the previous or
  the new generation).

### 7.2 Tree nodes (kind 2) — a CoW B+tree

```text
 64   1  level (0 = leaf)   65  1  pad   66  2  nitems   68  4  pad
 72  …   internal: nitems × { Key (17 B), Pointer (48 B) }
         leaf:     nitems × { Key, data_off u16, data_len u16 } then item data packed
                   from the end of the block backwards (btrfs-style)
```

Decoding a leaf checks, for every item, `72 + 21·nitems ≤ data_off`, `data_off + data_len
≤ 4096`, and that item ranges do not overlap; failure is `Corrupt`. Item kinds:

| kind | key `off` | item data |
|---|---|---|
| `INODE` (0x01) | 0 | `{ size u64, kind u8 (dir/file/blob-ref), nlink u32, gen u64, flags u32 }` |
| `DIRENT` (0x10) | `H64_k(name)` | `{ child_obj u64, name_len u16, name… }` — keyed hash with `dirent_key`; collisions chain by `off+1`; **deletion re-chains** (the successor of the removed item moves down) so lookups never stop early (Kani, FS-2) |
| `INLINE` (0x20) | 0 | file bytes, `≤ INLINE_MAX = 1024` |
| `EXTENT` (0x21) | byte offset | `{ start u32, len u32 ≤ 32, flags u32, hashes [32]×len }` |
| `XATTR` (0x30) | `H64_k(key)` | small key/value, used by `kernel::state` for object metadata |

Fan-out: internal nodes hold ~60 children; a leaf holds ~30 dirents or three inline files
plus a few items. Three levels address millions of objects; the shell will see two. Nodes
are CoW'd from leaf to root on every mutation within a transaction (path copying, done once
per transaction per path thanks to the dirty set). Split at half, merge below a quarter,
deterministically, so the tree shape depends only on the key set (principle 4). The tree
algebra is written over `Node<const CAP: usize>` with the block encoding separate, so Kani
proves it at `CAP = 4` (§11) and the host round-trips the 4 KiB encoding.

### 7.3 Blobs — content addressing, per domain

The `blobs` tree is keyed by `obj = domain (u16) ‖ first 6 bytes of the hash`, kind `BLOB`
(0x40), `off = next 8 bytes`; item `{ full_hash [32], size u64, refs u32, extents… }` (or
inline). `Public` blobs hash the plaintext with plain SHA-256 — components, weights — and
the host loads a component from the blob store by its `ComponentId` directly: the id **is**
the storage key, and the FS verified the hash on the way in and again on the way out.
`User(n)` blobs (state snapshots, secrets' ciphertext, user files) use a keyed hash (§10),
so dedup never spans users and never reveals cross-domain equality. A file may *reference* a
blob (`EXTENT` with a `BLOB_REF` flag) instead of owning extents — zero-copy storage for
data that is also a file. `put_blob` from a non-root caller does not distinguish hit from
miss in its result or (as far as the design can make it) its timing: the store path always
runs the same steps and the refcount bump is per domain (FS-4, §12).

FS-1a pins the encoding (A12, `kernel::sfs::key`): the domain is a `u16` — `0` = `Public`,
`n ≥ 1` = `User(n)` — and `obj`/`off` take the domain and hash bytes **big-endian**, so the
numeric key order is domain-major, then hash-lexicographic. The 17-byte key itself is packed
little-endian at fixed offsets (§4, A10).

### 7.4 Allocation — per-group bitmaps, one index level

The image is divided into **allocation groups** of 32 256 blocks (≈126 MiB). Each group has
one bitmap block (kind 3): the 4032 bytes after its 64-byte header = 32 256 bits. The `free`
Pointer names **one** index block (kind 5) of group Pointers: (4096 − 64) / 48 = **84 groups**
≈ 10.3 GiB. (FS-1a corrected the first draft's 32 768 bits / 85 groups, which forgot the
header every metadata block carries.) Larger devices are refused at mount with
`TooLarge` — a second level is a format-version bump, not a v1 feature (the dev image's
SentinelFS window is 3 840 blocks, an eighth of one group, §11). Bitmaps are CoW like everything else. Allocation
policy is **deterministic given committed state**: first-fit within the group of the
object's last extent, else the group with the most free blocks by the *committed* counts
(ties to the lowest index) — never a function of what is cached. Extents prefer runs of ≥ 8
blocks. Blocks freed in a transaction become allocatable **only after** the commit that
frees them (they may be referenced by the still-live previous root) and never while a
retained snapshot references them. Each group keeps `RESERVE = 64` blocks that only
reclaim commits may use (principle 8). Snapshot deletion walks the snapshot's exclusive
extents incrementally: at most `RECLAIM_PER_COMMIT = 256` blocks freed per commit, counted
and asserted in the boot line (FS-4).

FS-1a format rules (`kernel::blk::allocator`, checked at mount; a break is `Corrupt`): bit
`i` of a group is bit `i % 8` — **least significant first** — of byte `i / 8` of the bitmap
payload, set = in use; a group's bitmap lives **inside its own group** and the index **in
group 0**; group 0's bitmap marks both superblock slots and the index; bits past the end of a partial last group are
**set** (padding is never free); index entries past the last group, and the rest of the block,
are zero; every free-space pointer's block is ≥ 2 and its `gen` is in `1..=` the superblock's,
equal to the target header's. The reserve exactly: `Normal` allocations leave `reserve` free
blocks in every group, plus two in group 0 for the commit's own index and group-0 bitmap
copies; `Reclaim` allocations may use the reserve but never a group's last block (the next
transaction's copy of that group's bitmap needs it); the allocator's own copy-on-write may
borrow from the reserve because it is net-zero across a commit (the commit that writes the
new copy frees the old). Frees are deferred: a freed block stays set until the seal of the
commit that frees it, and nothing allocates between that seal and the commit's end.

**Deferred frees are bounded.** One transaction may defer at most `PENDING_MAX = 512` frees,
and its own copy-on-write and seal take a few of those slots (one per copied bitmap, plus the
old index and group 0's bitmap), so about 509 caller frees fit; past that a free is refused
with `NeedCommit`. A remove larger than that cannot be one transaction, so to keep "metadata
operations are always atomic" for large removes **FS-2 needs a persistent orphan / reclaim
list**: the remove commits the unlink and records the object as an orphan in one transaction,
and reclaim frees its blocks across later commits (the same bounded-reclaim shape FS-4 uses
for snapshot deletion).

### 7.5 Snapshots

The `roots` tree holds `{ name, gen, root: Pointer, blobs: Pointer }` items. `snapshot(name)`
writes one item at the current committed root. `rollback(name)` writes a new superblock
whose `root`/`blobs` are the snapshot's (a new generation — history is never rewritten) and
appends a record to the IntegrityLog naming the generations. Retention is bounded:
`MAX_SNAPSHOTS = 16`; the shell's `snapshot` built-in refuses beyond that. Reading a
snapshot mounts it read-only through the same code.

## 8. Transactions, durability model and commit

**Durability model.** Between two `flush()` calls the device may persist *any subset* of the
writes issued, in any order; a single 512-byte sector write is atomic; `flush()` makes every
earlier write durable before it returns. `MemDevice` implements exactly this (random subset
drop on crash, torn-sector variants for blocks 0 and 1) and the property test in §11 runs
against it. Real drives with write caches behave this way; QEMU with `cache=writeback` does
too and is what xtask pins (never `cache=unsafe`).

```
mutate (any thread, under the Sfs lock, bounded): CoW path copies into the dirty set
commit (the sfs-commit task, only at a quiescent point between operations):
  1. write every dirty block to its fresh location (hash computed once, stored in the
     parent Pointer and the block header)              — unflushed writes
  2. flush
  3. write superblock(gen+1) into the inactive slot
  4. flush
  5. dirty set → clean; freed-in-this-txn blocks → allocatable
```

**Dirty budget.** Every *metadata* operation has a worst-case dirty footprint: path copy ≤ 4
(depth), splits ≤ 4, dirent/xattr leaf ≤ 1, bitmaps ≤ 2, group index 1, superblock 1 —
**≤ 13 blocks**, asserted in the host tests per operation kind. The task commits when the
dirty set would exceed `DIRTY_MAX = 48` **before** starting the next operation, so an early
commit never publishes a half-applied metadata mutation. Bulk data writes larger than the
remaining budget are chunked across commits: filesystem consistency is kept, single-call
atomicity for bulk data is not (a non-goal, §2), and the facade documents it.

**Pacing.** Commit at the end of every shell/Files-app mutating call (as today), or when the
`sfs-commit` task wakes after `COMMIT_INTERVAL = 50` mono ticks (0.5 s) with a dirty set, or
at the budget boundary above. Reads inside a transaction see the dirty set first. Nothing
allocates under the `Sfs` lock except the fixed slabs.

Cost on ATA PIO (per commit, small change): ~4–6 metadata blocks + data + 1 superblock =
~10 block writes ≈ 80 sectors, **two** flushes instead of today's one-per-sector-write. The
old design rewrote up to 64 KiB (128 sectors) for a one-byte change and had no upper bound.

## 9. Integration with the component model

- **Storage is a native service behind a capability.** `cap::Target::Storage` carries an
  attenuation lattice with a decidable `⊑` (Kani, FS-1c — after component PR-2 lands
  `kernel::cap`: a delegate never amplifies; whatever a child grants, its parent grants):
  `{ tree: Live | SnapshotRo(name), prefix: path *components* (never a byte prefix — `/app/foo`
  must not grant `/app/foobar`), blobs: None | Domain(d) | RefSet(hashes) (never List), ops ⊆
  {Read, Write, Snapshot, Rollback, Format}, quota { bytes, inodes, blob_bytes }, expires:
  Option<mono tick> }`. `Snapshot`/`Rollback` are distinct from `Write` because rollback
  resurrects revoked capabilities, removed components and pruned findings. Denials are
  logged (component amendment A8). The shell and Files app are first-party and hold the root
  cap; no non-first-party component runs before the memory gate (component §16), so the
  enforcement can land with FS-4 and the type with FS-1c — the on-disk fields it needs
  (domains, `dirent_key`) cannot wait and are in FS-1a.
- **Components live in the `Public` blob domain** keyed by `ComponentId`; `Manifest.code`
  becomes "the blob with this hash", and instantiation is `get_blob` + the existing verify
  (which now cannot fail unless the disk lies — and then the FS said so first).
- **State objects** (`kernel::state`) persist as `User` blobs referenced from an
  `XATTR`-carrying object per state object; `summarize_state` can be the blob hash for the
  mergeable class.
- **Attestation (FS-5).** The IntegrityLog record is the **superblock hash** — it already
  commits root, blobs, roots, free, gen and uuid, so an adversary cannot retarget the
  snapshot tree unseen — framed with `signing_key_id` (component A6), `prev_record_hash`,
  `gen`, and `anchor: None | Tpm(counter) | PairedDevice(counter)` (reserved; §12).
  `committed_at` ticks are per boot and never mean freshness. Under the ephemeral KeyAgent key
  (component §18.1) the signature verifies only within the boot that made it, so FS-5 waits
  for the identity spec's persistent, user-secret-wrapped device key; until then the
  `sentinel-core` filesystem vector reports **Unavailable, never Clear**.
- **Secrets** (`kernel::secrets`, component PR-3) store ciphertext in a `User` domain; the FS
  never sees a key.

## 10. Where encryption goes (not v1, placed now)

Integrity is the FS's job; confidentiality is layered above it so the two can be reasoned
about separately — but the on-disk fields it needs exist from FS-1a:

1. **Now (component PR-3):** `kernel::secrets` encrypts its own blobs (AEAD, KeyAgent key,
   nonce = generation ‖ counter). The FS stores opaque bytes with real hashes.
2. **With login (identity spec):** `Argon2id(user secret) → unlock_key → tree_key → HKDF
   labels {name-hash, name-enc, data, dedup}`. Encrypted: **data blocks, inline items, dirent
   names and xattr values** (all leaf *payload*, so ordering, split points and canonical
   shape are unchanged); `H64_k` uses the derived name-hash key. In the clear: keys, pointers,
   hashes, bitmaps, superblock. **KDF parameters and the wrapped key sit inside the signed
   superblock** (§7.1) or they can be downgraded offline. Residual leak, stated: tree shape,
   object count, sizes, write timing. Per-**object** data keys (not per-tree) so that deleting
   an object can crypto-shred it even while snapshots hold its ciphertext — the only real
   answer to "deletion is not erasure". The cache holds plaintext: **zeroize on eviction,
   flush and zeroize on lock** (component A9). The same `unlock_key` wraps the KeyAgent key,
   which resolves component §18.1 and unblocks FS-5.
3. **Never:** keys on the same disk in the clear (refused 4/4 in the component review).

**Constraint the identity spec must solve:** Argon2id at OWASP parameters (≥ 19 MiB) does not
fit a 4 MiB heap under an infallible allocator with `panic = "abort"`. The KDF needs a
pre-reserved arena from the frame allocator outside the heap (a `hal::mm` question), or
parameters chosen for this machine with the trade-off written down. Not this spec's call.

## 11. Boot proofs and PR staging

Each PR is independently bootable and adds hard assertions to `cargo xtask test`. Order
revised by the review: the flush split and the torn-commit proof move **into** the tree PR,
FS-1 splits in two, and attestation waits for the identity spec.

| PR | Lands | Boot-proof line (asserted) |
|---|---|---|
| **FS-1a** block layer + superblocks | `kernel::blk` (`BlockDevice` with multi-block I/O + `flush`, `AtaDevice`, `MemDevice` with crash-index / torn-sector / unflushed-subset hooks, verified reads, the 64-block slab, group bitmaps + one-level index, reserve), superblock format/mount/`Corrupt`-vs-`Unformatted` with the A12 fields, the `sfs-commit` task. Kani: superblock selection over decoded `(valid, gen)` candidates; 64-bit bitmap ops; extent arithmetic; header decode totality. Host: adversarial mount corpus (deterministic, fuzz-shaped, lifts into the lane unchanged). | `[sfs] mount: gen=N slot=S sb=<8 hex> verified=yes groups=1 free=N/N reserve=64 ok` (shape exact, `slot = gen % 2`) then `[sfs] commit: gen=N+1 slot=1-S sb=<8 hex> blocks=B flushes=2 ok` |
| **FS-1b** tree + transactions + durability | CoW B+tree (`Node<CAP>` algebra + 4 KiB encoding), items, transactions with the ≤ 13-block bound, scrub; `hal::ata` API split: `write_sectors` unflushed + public `flush()` (**row A2 text amended**, new §4 invariant naming the command-serialising lock, and the pre-existing `issue_command(CMD_FLUSH)`-without-`wait_not_busy` fixed). Kani: `Node<4>` split/merge (sorted, occupancy, key-set preservation, separators); leaf packing totality over a shrunken block. Host: crash-point property test (shadow map advanced at commit; write-index × torn-sector × unflushed-subset; seeded PRNG, delta-debugging shrinker, 20 seeds < 30 s); order-independence and replay-determinism tests (principle 4, 7); counting-allocator cap on a 1 GiB `MemDevice`. QEMU: **torn-commit** — xtask runs QEMU with `cache=writeback`, the kernel halts after the k-th block write of a commit under a boot flag, xtask SIGKILLs and reboots; the next boot must mount `gen-1` intact. **Shipped 2026-10-04** (as built below). | `[sfs] torn-commit: cut-after=K recovered-gen=N-1 data-intact=yes ok` and `[sfs] scrub: blocks=N hashed=N bad=0 ok` — as printed: `[sfs] torn-commit: cut-after=2 recovered-gen=3 data-intact=yes ok`, `[sfs] scrub: blocks=10 hashed=10 bad=0 ok`; plus `[sfs] ledger: gen=M items=K data-intact=yes ok` every boot |
| **FS-1c** storage-cap lattice | Split out of FS-1a (Veeti, 2026-10-03): the storage-cap lattice type + `⊑` + Kani "never amplifies", on top of component PR-2's `kernel::cap` (`cap::Target::Storage`, §9, A13). Lands after PR-2; enforcement and denial logging stay in FS-4. | — (a type and its proofs; the enforcement line is FS-4's) |
| **FS-2** files + facade | `INODE`/`DIRENT` (re-chaining delete, Kani)/`INLINE`/`EXTENT`; `kernel::fs` facade with the §3 API changes; `stat`; old serialiser deleted; `Corrupt`/`NoSpace`/`Io`/`ReadOnly`. Fuzz lane lands here at the latest (own workspace like `xtask`, so `kernel/Cargo.lock` stays at 6 packages). | existing `[fs] persistence … ok` line (adapted), plus `[sfs] full-disk: filled=yes delete=ok ok` |
| **FS-4** blobs + snapshots + caps | domains, `put_blob`/`get_blob` with per-domain refcounts and hit/miss-indistinguishable path, `BLOB_REF` extents, snapshots (`MAX_SNAPSHOTS`), rollback as a logged privileged op, bounded reclaim, storage-cap enforcement + denial logging; the host loads `hello` from the `Public` domain by `ComponentId`. | `[sfs] cas: put=2 stored=1 dedup=yes component-from-cas=verified snapshot=ok rollback=ok logged=yes reclaim<=256 ok` |
| *(identity spec, then component PR-3 with a persistent key)* | | |
| **FS-5** attestation | superblock hash signed by the KeyAgent into the IntegrityLog with `signing_key_id`, `prev_record_hash`, `anchor`; mount policy on mismatch (§12); `sentinel-core` filesystem vector. | `[sfs] attest: sb=<8 hex> logged=yes signed=yes verified=yes anchor=none ok` |

**FS-1a as built (2026-10-03).**

- *Coexistence with the old `kernel::fs`.* The toy FS owns the IDE disk from LBA 0 (its
  `SNTLFS01` sector plus ≤ 128 payload sectors) until FS-2 deletes its serialiser, so
  `AtaDevice` is a **block window** `{ base_lba, blocks }` and SentinelFS lives from LBA 2048
  (1 MiB) to the end of the disk — 3 840 blocks, one group, on the 16 MiB dev image. Zero
  `hal` delta, no xtask disk change; "blocks 0 and 1" (§7.1) are blocks 0 and 1 of the
  window. FS-2 moves the window to LBA 0 when the old serialiser goes (a dev image: no
  migration — the old sector reads as foreign, so the disk is `Unformatted` and formatted).
  Both users of the channel take one kernel-side lock per `hal::ata` command, waiting by
  yielding, because `hal::ata` relies on its callers never interleaving commands:
  `kernel::blk::ata` wraps `identify`/`read_sectors`/`write_sectors` with it and is the only
  kernel file allowed to name `hal::ata` (`cargo xtask check-ata-callers`, a CI step).
- *Boot.* A fresh image is `Unformatted` → formatted → mounted at generation 1 in slot 1.
  Every boot then mounts what is there (never formatting over the magic) and asks the
  `sfs-commit` task for one empty commit, so the slot alternates on every boot. xtask asserts
  the mount line's exact shape plus `slot = gen % 2`, and that the commit line is generation
  `N + 1` in the other slot with `blocks=1 flushes=2` over the image's 3 840 blocks. The boot
  tests own their disk: `make test` / `make test-kvm` (and `boot-timing`) recreate
  `target/sentinelos-test-disk.img` at the start of every run (`SENTINELOS_KEEP_TEST_DISK=1`
  keeps it for local multi-boot work; `make run`'s dev image is never touched) and boot
  **twice**, asserting every boot line on both boots and the chain between them: boot 1
  `format: … (was unformatted)`, `mount: gen=1 slot=1`, `commit: gen=2 slot=0`; boot 2
  `mount: gen=2 slot=0 sb=<boot 1's commit sb>`, `commit: gen=3 slot=1`; and the old toy FS's
  `first boot` line on boot 1 and `persistence PROVEN` on boot 2. CI caches no disk image: each
  job's last step deletes both images before the cache's post-job save (a `!` exclusion cannot
  reach a file inside the cached `kernel/target` directory).
- *`flush` on today's ATA.* `hal::ata::write_sectors` already ends every command with
  `FLUSH CACHE`, and `hal` has no separate flush, so every `AtaDevice` write is as durable as
  `hal` makes it when it returns and `AtaDevice::flush` is a no-op that returns `Ok`. The §8
  protocol still issues it where it belongs, so FS-1b's API split changes nothing above
  `blk::ata`. The A2 weakness (FLUSH issued without waiting for BSY) is unchanged until then.
- *The task.* `sfs-commit` is pinned to the BSP with a **64 KiB** stack
  (`sched::spawn_on_with_stack`, added for it): in the dev profile every temporary keeps its
  own stack slot, and the mount path measured ~14 KiB deep — a 16 KiB stack overflowed into
  its guard page at boot (a double fault, before the frames were trimmed). It opens the device
  itself and keeps it on its own stack, so no other thread can reach it. The `Sfs` lock is
  taken with preemption disabled for bounded in-memory work only; a commit is sealed under it,
  written with it released, and published under it again. From the boot proof on, the task
  stays runnable on the BSP (it polls for requests and the pacing deadline each time it is
  scheduled): nothing after it in `kmain` may wait for the BSP's ready queue to drain.
- *Failures go read-only.* A commit whose I/O fails, or whose seal needs a committed block
  that cannot be read back intact (an I/O error, or a block that no longer matches its
  pointer's hash), leaves the volume read-only and the task stops committing — it does not
  re-read the bad block every `COMMIT_INTERVAL`. The previous generation stays intact on disk.
- *`Corrupt` at boot (a deviation from §7.1 / A9).* §7.1 has a `Corrupt` disk mount
  read-only-empty and report. FS-1a's task reports
  (`[sfs] mount: corrupt (<damage>; never formatted over) FAIL`) and exits, leaving both slots
  untouched; the read-only-empty mount and the shell's explicit `format` arrive with FS-2's
  facade, the first code that could use them.
- *A23's counting allocator.* A process-wide counting `#[global_allocator]` needs an
  `unsafe impl GlobalAlloc`, which the kernel crate forbids. FS-1a asserts the property
  instead: every FS structure is a fixed-size heap block built at mount (the slab, the
  allocator tables, the commit plan, the caller's workspace — nothing grows, nothing is sized
  by the device), and the host test shows the footprint is identical for the 16 MiB window
  and a 1 GiB device (≤ 300 KiB) and unchanged across 40 commits. A true counting allocator
  (which would also catch a stray temporary) needs a test-only crate outside the forbid
  boundary; it moves to FS-1b (A23, A31).

**FS-1b as built (2026-10-04).**

- *The tree.* `kernel::sfs::tree`: the `Node<V, CAP>` algebra (`node`, entries in inline
  arrays so Kani stays cheap at `CAP = 4`; kernel nodes are built on the heap one at a time),
  the 4 KiB encoding (`codec`, over any block length) and the item payloads (`item`). Every
  mutation is **planned in memory** on a fixed ~50 KiB workspace (path, siblings, splits; leaf
  bytes copied, so nothing depends on a cache entry staying resident), **preflighted** —
  `Allocator::check_ops` simulates exactly the allocs and frees the plan needs plus its new
  dirty entries against every budget (dirty, pending, the cache's non-dirty entries, so no
  bitmap the operation needs can be evicted midway) — then **applied**, where nothing can be
  refused. So every refusal (`Miss`, `NeedCommit`, `NoSpace`, `TooBig`, `TreeFull`) changes
  nothing, and "commit before an operation that would exceed `DIRTY_MAX`" is exact rather than a
  fixed reserve. Path copying via the dirty set; split at half, merge-or-recut below a quarter;
  `MAX_LEVEL = 3`; the empty tree is the null pointer. Removes allocate as `Reclaim` (§5.8).
- *Invariants beyond §7.2, checked on every walk and by the scrub.* Every internal entry's key
  is **exactly** its child's lowest key (not merely a separator), and leaves are **canonically
  packed** (item 0's data ends at the block end, each next item's where the previous one starts,
  the gap zero) — stricter than "no overlap", and it makes the encoding a function of the items.
- *Footprint (§8's ≤ 13).* Asserted per operation kind (insert, replace, remove, maximal
  insert) on a two-level tree of large items, as the blocks the commit of a one-operation
  transaction writes: worst 7/7/7/8 on the dev window, 8/8/8/9 on a 1 GiB (9-group) device.
- *Scrub.* `sfs::scrub`, on the `sfs-commit` task with the lock released: the superblock as it
  is on disk, the group index (canonical re-encode), every bitmap, every node (hash, header,
  §7.2 decode, levels, exact-min keys), every item payload for its kind, every extent block
  against its own hash, and every reachable block **marked in use** in its bitmap. Damage names
  up to eight objects (`what=tree-node obj=…`, `data`, `item`, `marked-free`, …) and leaves the
  volume read-only.
- *Durability, host.* The crash-point property test records every commit's I/O and replays it
  into a crash at **every** write index × {nothing, everything, two PRNG subsets with torn slot
  sectors}: 20 seeds, 126 commits, 2 744 crash points, ~13 s in a debug build; every one mounts
  the previous or the new generation, holds exactly that generation's shadow map (advanced only
  at completed commits, forced ones included) and scrubs clean. A failure is shrunk by
  delta debugging before it is reported (checked by removing the pre-superblock flush: caught,
  shrunk to two operations).
- *Determinism (principle 4, as built).* Replaying an operation sequence yields the same
  superblock hashes and the same image — also with a cold remount between commits, so cache
  state is not an input. The same key set by different orders (and with churn) yields the same
  **items**; it does not yield the same node boundaries — no insert-split B+tree does, and the
  host test checks items. Principle 4's "shape depends only on the key set" holds per node (split
  and merge points are pure functions of the node's entries), not for the whole tree.
- *Heap cap (A23/A31).* A host-only crate `test-alloc` (one `Cargo.lock` entry, empty on the
  bare-metal target) holds the one `unsafe impl GlobalAlloc`; `#[global_allocator]` itself is
  safe and sits in the kernel's test kit. Peak per-thread heap of format + mount + 1 800 puts +
  600 removes over 12 commits + scrub: **435 636 bytes** on both the dev window and a 1 GiB
  device (cap 512 KiB), and the session frees everything.
- *Race model (A21).* `sfs::race`: std threads around the real `Volume` — a task thread owning
  the `MemDevice` (miss reads and commits, never I/O under the lock), three callers on disjoint
  keys, reads during an in-flight commit, the cache dropped cold every third commit. It found a
  real protocol bug: a caller's miss can go **stale** before it is served (another caller copies
  the node, a commit frees the block, a later transaction reuses it), and resolving it then
  turned a dirty conflict or a rewritten block into read-only. Misses now carry the commit
  **epoch** they were reported in; a failed resolve is damage only within that epoch
  (`Volume::resolve_tree_miss`). Miri runs a shortened version.
- *The kernel's ops.* Tree operations run under the `Sfs` lock on any thread; a `Miss` is
  posted to the task (one ticketed slot), which reads with the lock released and inserts
  verified under it. `hold_commits` keeps the interval commit from splitting a group of
  operations that must commit together. The boot proof is a **ledger** (`sfs::proof`): six
  900-byte items per generation, a four-generation window, and a metadata xattr naming the first
  and last generation, verified byte for byte every boot and extended by the boot's commit
  (`[sfs] ledger: gen=M items=K data-intact=yes ok`; the commit line's `blocks=` is now the
  ledger commit's, 6–7 on the dev image, where FS-1a's empty commit wrote 1).
- *The torn-commit proof — a deviation in how the flag reaches the kernel.* Not a Limine
  `cmdline`: that needs a new `hal` request row (a Limine response deref, like M1) and a second
  ISO, against this spec's "zero new `hal` rows". The flag is a **test-control sector** on the
  test disk (LBA 1024, between the toy FS image and the window; magic `SFSCTL01`, zero on every
  other disk) that `xtask` writes before a boot and the task reads through `blk::ata` before
  mounting. `make test` (and `test-kvm`) run the stage after the persistence chain on the same
  disk: cut after 2 block writes (`[sfs] torn-commit: cut-after=2 gen=4 dirty=6 halting`, the
  machine halted with interrupts off), SIGKILL under `cache=writeback`, then xtask checks that
  **exactly 2** window blocks changed and neither superblock slot; the recovery boot must pass
  every boot assertion, mount exactly the previous commit (generation, slot and superblock hash)
  and print `[sfs] torn-commit: cut-after=2 recovered-gen=3 data-intact=yes ok`. +2 boots,
  ~10 s of CI.
- *`flush` on ATA, now.* `hal::ata::write_sectors` is unflushed and `flush()` waits for BSY
  before `FLUSH CACHE` (row A2 amended, invariant 16); `AtaDevice::flush` is the real barrier
  and the toy `kernel::fs` flushes once per save through `blk::ata`. Status waits end at a TSC
  deadline (not a count of reads, which QEMU's asynchronous completion under host write
  pressure outlasted), and a timed-out command resets the channel before `Timeout` returns.
- *Kani (A19), each measured alone.* `Node<4>`: split occupancy/order/separator 37.3 s, split
  key-set preservation 17.7 s, append preservation 24.7 s, merge 44.0 s, re-cut 39.3 s / 41.2 s
  (left / right underflow); codec over shrunken blocks: leaf decode totality 7.0 s, internal
  decode totality 18.8 s, one-item leaf packing round trip 45.8 s. Getting there changed code,
  not only harnesses: `Node` stores entries in inline arrays and every node and codec loop runs
  over a constant bound (the capacity, or the block length) and stops early at the count — the
  first versions sat in CBMC for minutes or ran out of 16 GB on symbolic-length moves. **Not
  gating:** the two-item packing harness verifies but takes ~195 s; it is behind
  `cfg(kani_slow)` and the host round-trip tests cover multi-item packing. `Node<6>` was not
  attempted (the `Node<4>` harnesses already needed splitting to fit), so the real fan-out
  bound is not earned yet (§15 "minds change on").
- *Not done here.* A27 (fall back to the older slot when the newer tree is damaged) stays open:
  the scrub now names the damage and goes read-only, but mount still takes the newer valid slot.
  A30 is bounded, not measured: an operation hashes nothing under the lock; a seal hashes its
  dirty set (≤ 48 blocks) under it; a resolved miss hashes one block under it.

Every PR: the entire FS runs on `MemDevice` on the host — this is where the real coverage
is; Miri on `sfs::codec` and `blk` (scoped step; honest value on a `forbid(unsafe_code)`
crate is the threaded host model of the cache/task hand-off, which is the race model the
component review asked for and did not get); Kani harnesses are **merge conditions**, each
discharged locally and hard-capped at 60 s measured; fmt-free console output; `hal-tcb.md`
unchanged except FS-1b's amendment to row A2 and one invariant.

## 12. Threat model

**Assumption (Kerckhoffs):** the adversary knows the format and the code.

*Detected, always:* bit rot, torn writes, a truncated image, a block from another
filesystem (uuid, inside the hash), kind confusion (inside the hash), any modification of
any block (hash mismatch, named by the scrub). Response: the object is `Corrupt`, the mount
goes **read-only** (evidence preserved; refuse-to-mount is a brick and gets the check
disabled), and the shell can `rollback` to a snapshot.

*Recovered, always:* a crash at any point in a commit under the §8 model (previous root); a
bad update *after* a snapshot (rollback, logged).

*Detected once FS-5 lands:* offline modification of the whole tree by an adversary who
re-hashes consistently — the superblock hash no longer matches the signed attestation.
Three cases: hash/uuid failure = `Corrupt` (above); `gen` **greater** than the last signed =
drift (records were written after the last attestation; no finding); `gen` **less than or
equal** with a different hash = **rollback** → read-only mount, a `Threat` finding, the
PolicyAgent must consent before read-write, and the KeyAgent refuses to unwrap the tree key.

*Not defended (open, §14):* **rollback by a full-disk adversary** to an older, internally
consistent, previously signed state. Needs a monotonic counter the disk does not control
(TPM NV index, or the paired device's copy of the IntegrityLog via IdentityDir sync). The
`anchor` field is reserved for it.

*Confirmation oracles:* a non-root `put_blob` must not reveal whether the bytes already
existed (result and, as far as possible, timing — per-domain refcounts, same code path;
FS-4). There is no attacker for this before the memory gate; the on-disk domain field is
what cannot wait.

*Deletion is not erasure* while any snapshot references the data; crypto-shred (§10) is the
answer, and the shell says so.

*Not the FS's job:* confidentiality (§10), a malicious first-party component (component
§16: authority boundary only until the gate), the ATA controller lying about completion
(the TCB assumption we already make).

## 13. Efficiency, honestly, and the road to DMA

| Path | Today (`kernel::fs`) | SentinelFS on ATA PIO | SentinelFS on NVMe/virtio-blk (later spec) |
|---|---|---|---|
| 1-byte write | rewrite whole tree, ≤ 128 sectors, 128 flushes | ~10 blocks, 80 sectors, 2 flushes, no data rewrite | same blocks, DMA, µs |
| Read a 1 KiB file | deserialise everything at boot, then heap | 1 leaf (inline), cache hit after first | same |
| Read 4 KiB of a 10 MiB file | impossible (64 KiB cap) | 1 data block, 1 hash | same |
| Store a 10 MiB model | impossible | extents, ~2560 blocks, seconds under PIO (measured, not gated) | ~ms |
| Boot mount | parse whole payload | 2 superblocks + root path | same |
| Memory | whole tree on heap | one 256 KiB slab, dirty ≤ 48 of its 64 blocks | same, larger slab when the heap grows |
| Crash | data loss to seed | previous generation | same |

The hash cost is reported as deterministic counters, never as a wall-clock gate on a shared
CI runner: the commit line's `blocks=B` (§11 — every block a commit writes is hashed exactly
once, when it is sealed) and `hashed=N` in FS-1b's scrub line; throughput is recorded
non-gating for three runs before any floor is considered. PIO is the transport bottleneck:
every sector is 256 `outw`/`inw` with status polling. The format never asks PIO for more than
it must, but throughput stays CPU-bound until DMA. The DMA spec will add `hal::pci`
bus-mastering (present), MMIO doorbells, DMA-safe buffers (identity-mapped, never on the
heap), MSI or polling completion, and its own Kani/Miri lane — the sharpest `hal` work since
SMP, which is why it is *after* the format is proven, not before. `BlockDevice` already has
the shape it needs.

## 14. Open questions

1. **Hash primitive per block.** SHA-256 in-tree costs ~5 µs per 4 KiB block scalar; fine on
   PIO, dominant on DMA. A hardware SHA-256 tier (`sha_ni`, a `hal::simd` sibling) changes
   nothing on disk. A different primitive (BLAKE3, a dependency) **is** a format change —
   every stored hash differs — and v2 has no field naming the algorithm, so it needs a future
   `hash_alg` field (a reserved superblock field read as `0 = SHA-256`, or a version bump);
   `kernel::hash::Hasher` keeps the code agile, not the format (corrected in the FS-1a review,
   A29).
2. **Rollback protection** (§12): TPM NV vs paired device. Decide with the identity spec;
   the `anchor` field is reserved.
3. **KDF memory** (§10): Argon2id's ≥ 19 MiB vs the 4 MiB heap — arena from the frame
   allocator, or tuned parameters. Identity spec.
4. **Recovery console before unlock** would need filenames in the clear — the one fact the
   security seat said would change §10's split. Decide with the identity spec.
5. **`kernel::fs` API growth** beyond §3: `rename` (FS-4), snapshot list in the Files app.
6. **Second index level** (> 10 GiB) is a format-version bump; not before a real disk needs it.

## 15. Review round 1 (2026-09-18): verdicts and amendments

Four roles read the draft independently (kernel-architect, kernel-reviewer,
security-engineer, verification-engineer). Where they agreed, the change is applied above;
where they set conditions, the PR that owns them is named.

| Question | architect | reviewer | security | verification | **Consensus** |
|---|---|---|---|---|---|
| Layering / staging | blk-sfs-facade right; FS-1 too big → split; fold FS-3 into the tree PR; FS-5 last | — | FS-5 only after a persistent key: sequence FS-1..4 → identity → FS-5 | host `MemDevice` is where coverage lives | **FS-1a / FS-1b / FS-2 / FS-4 / identity / FS-5** (applied, §11) |
| `hal` delta | `FLUSH CACHE` already in-tree (A2); "one new row" is wrong | same; FS-3 is an API split that *removes* a per-write flush, and that weakening is what torn-commit must prove; `cache=writeback` + SIGKILL for evidence; fix the BSY wait | — | — | **zero new rows; A2 text amended in FS-1b** (applied) |
| Format | header fields outside the hash; `INLINE_MAX` 2 KiB breaks splits; one index level is enough | extent hash over the whole run kills partial verified reads; hash domain undefined | dedup-domain and dirent-key fields must be on disk from day one | tree algebra must be separable from encoding for Kani | **whole-block hash with field zeroed; per-block extent hashes; inline 1 KiB; one index level; domains + `dirent_key` in the superblock; `Node<CAP>`** (applied) |
| Locking / memory | — | PIO under `SpinMutex` and interval commit from the tick both blocked; early commit mid-mutation blocked; two cache budgets contradict | plaintext cache must zeroize | threaded host model of the cache is the race model still owed | **`sfs-commit` task does all I/O; commits at quiescent points with a ≤ 13-block metadata bound; one 64-block budget; zeroize (identity)** (applied) |
| Principle 4 | pointers embed placement → not content-canonical; make allocation deterministic or drop | — | attestation attests *this disk* | test order-independence of the key set | **split into deterministic shape + deterministic history; content identity lives in the blob tree** (applied) |
| Parsing / fuzz | — | hash-before-parse is tamper detection, not well-formedness; DoS not UB ⇒ lane not a gate; totality harnesses + block-bounded loops before FS-1 | — | same; lane by FS-2 in its own workspace; TOCTOU unless parse sees an immutable copy | **totality Kani per parser is an FS-1 merge condition; fuzz lane by FS-2; immutable verified cache entries** (applied) |
| Attestation | — | — | sign the superblock hash, framed with key id / prev hash / anchor; three mismatch cases; read-only not refuse; vector `Unavailable` under ephemeral key | deterministic `hashed=N` counter, no wall-clock gate | (applied, §9, §12, §13) |
| Encryption | — | — | encrypt dirent names + xattr values too; per-object keys for crypto-shred; KDF params inside the signed root; Argon2id does not fit the heap | — | (applied, §10; KDF memory → identity spec) |

**Amendments.**

| # | Where | Finding | Status |
|---|---|---|---|
| A1 | §7 | Header self-hash excluded `kind`/`gen`/`tree_id`/`fs_uuid` — a kind-confusion flip survives verification. Hash the whole block with the hash field zeroed. | applied |
| A2 | §1/§6/§11/§13 | "One new `hal` row (`FLUSH CACHE`)" — already in-tree, row A2. FS-1b amends the row text and adds a `flush()` API split plus an invariant for the ATA command lock; fix `issue_command(CMD_FLUSH)` issued without `wait_not_busy`. | **done (FS-1b)**: `flush()` split out, BSY wait before `FLUSH CACHE`, row A2 + invariant 16 |
| A3 | §4/§7.2 | `Extent.hash` over the whole run: reading 4 KiB of 10 MiB hashes 10 MiB. Per-block hashes, extents ≤ 32 blocks. | applied |
| A4 | §7.2 | `INLINE_MAX = 2048` in a 4 KiB leaf: two inline items can never share a leaf. 1 KiB. | applied |
| A5 | §7.4 | Two-level group index over-designed for v1. One level, `TooLarge` beyond ~10 GiB. | applied |
| A6 | §5.4/§7.4 | Canonical-root-hash principle contradicted placement-dependent pointers and cache-dependent allocation. Deterministic allocation from committed state; principle split; attestation attests this disk. | applied |
| A7 | §6/§8 | PIO under a non-IRQ-masking `SpinMutex` for up to seconds; interval commit unassigned (must not be the tick); early commit mid-mutation could publish a structurally invalid root; two cache budgets. `sfs-commit` task, quiescent-point commits, ≤ 13-block metadata bound, one 64-block slab, dirty unevictable. | applied; **FS-1b**: exact preflight per operation, ≤ 13 asserted per op kind (worst 9) |
| A8 | §3 | "Disk errors never fail a user operation" impossible without an authoritative heap tree; `read_file(&self) -> &[u8]` cannot be served from a cache (two call sites). Contract retired; API changes named. | applied; code in FS-2 |
| A9 | §7.1/§12 | Mount on `Corrupt` vs `Unformatted`: never auto-format over a disk carrying the magic; scrub `bad > 0` had no response. Read-only + rollback; explicit `format`. | applied |
| A10 | §4 | `Key` had no parse/alignment rule. 17 bytes packed LE at fixed offsets. | applied |
| A11 | §6 | `read(BlockNo, &mut Block)` would cap future DMA. `read_blocks`/`write_blocks` + `flush`. | applied |
| A12 | §7.3/§9/§10 | On-disk fields that cannot be added later: blob **domains** (dedup never spans users; `Public` vs `User(n)`), `dirent_key`, KDF-params + wrap slot inside the signed superblock, metadata reserve. | applied (FS-1a) |
| A13 | §9 | Storage attenuation must be a lattice with decidable `⊑`: path *components*, `blobs` never `List`, `Snapshot`/`Rollback` distinct from `Write`, quotas, expiry; Kani "never amplifies". | type + Kani in FS-1c (after component PR-2); enforcement FS-4 |
| A14 | §9/§12 | Attestation record = superblock hash, framed with `signing_key_id`, `prev_record_hash`, `anchor`; mismatch has three cases; response is read-only + finding + PolicyAgent consent + KeyAgent refusal; vector `Unavailable` under an ephemeral key. | applied |
| A15 | §10 | Encrypt dirent names and xattr values (leaf payload, no shape change); per-object keys for crypto-shred; residual leak stated; cache zeroize. | applied |
| A16 | §8/§11 | "Every prefix" is the wrong durability model. Unflushed-subset model in `MemDevice`; shadow map advanced at commit; torn variants at sector granularity for blocks 0/1; seeded PRNG + shrinker; 20 seeds < 30 s. | **done (FS-1b)**: 2 744 crash points, ~13 s, ddmin shrinker |
| A17 | §7.2 | Dirent chain-by-`off+1` deletion truncated lookups. Re-chaining delete + Kani. | FS-2 |
| A18 | §7.3/§12 | `put_blob` hit/miss oracle (result and timing) for non-root callers. Per-domain refcounts, same path. | FS-4 |
| A19 | §11 | Kani only over shrunken generics (`Node<4>`, 64-bit bitmaps, decoded superblock candidates); never SHA-256 or 4 KiB blocks; each harness ≤ 60 s measured; the split/merge harness at `CAP = 6` would earn the real fanout bound. | FS-1a done; FS-1b: `Node<4>` + codec totality done (times in the PR); `CAP = 6` not attempted |
| A20 | §11 | Fuzz lane: not a gate for FS-1 (first-party, `forbid(unsafe_code)`, DoS not UB) but required by FS-2, in its own workspace; one kind-selected parser target + one whole-image mount/scrub/list/read target. | FS-2 |
| A21 | §11 | Race model: threaded host model of the cache / `sfs-commit` hand-off — the gap the component review (A7 there) already named. | **done (FS-1b)** — found the stale-miss bug (epoch fix) |
| A22 | §10 | Argon2id at ≥ 19 MiB does not fit the 4 MiB heap under an infallible allocator. | identity spec |
| A23 | §11 | Counting allocator for the heap-cap test; asserted `reclaim<=N` and `hashed=N` counters; adversarial mount corpus as an FS-1a deliverable. | corpus: FS-1a (done); counting allocator: **done (FS-1b, A31)**; `hashed=N`: **done (FS-1b scrub)**; `reclaim<=N`: FS-4 |
| A24 | — | `docs/security/` still does not exist (component A10). | component PR-2 |

**FS-1a code review, round 1 (2026-10-03): follow-ups, each owned.** Fixed in the round
itself: CI's cached disk image (the boot tests now own and recreate theirs), a scheduler reap
that could spin on the heap lock with interrupts off, read-only on a failed miss, an
`alloc_run` refusal that changed state, the first-fit Kani proof, and the ATA channel lock
being enforceable only by convention. Recorded above: the slot tie rule, LSB-first bitmaps,
the `tree_id` values, `Pointer::NULL`, the unvalidated fields, the KDF / keyring layout, the
deferred-free bound, and the `Corrupt`-at-boot deviation (§11; deviation 8 of the FS-1a
report). Still open:

| # | Where | Finding | Owner |
|---|---|---|---|
| A25 | §6/§8 | `sfs-commit` waits by yield-polling (it stays runnable on the BSP forever). `sched` needs park/unpark with a wake permit and an optional mono-tick deadline, designed together with component PR-2's blocking bus receive, replacing the poll. | sched, before FS-2 |
| A26 | §7.1/§10 | The format seed — `fs_uuid` and `dirent_key` — comes from the tick counters: low entropy. It needs a real entropy source before anything writes dirents, since `dirent_key` exists to defeat precomputed collision floods. | before FS-2 |
| A27 | §7.1/§12 | Mount never falls back to the older slot: if the newer valid superblock's tree turns out damaged, the volume is `Corrupt` though the previous generation may be intact. Decide the fallback policy (and how it interacts with rollback protection). | open — FS-1b's scrub names and fences the damage; the fallback itself moves to FS-2 / FS-5 |
| A28 | §7.3 | The blob key carries 112 bits of the hash (6 bytes in `obj`, 8 in `off`): two blobs in one domain can share a key with different full hashes. FS-4 must chain such collisions or refuse the second blob — never treat an equal key as an equal blob. | FS-4 |
| A29 | §14.1 | Hash agility was claimed for free ("behind `Hasher`, the format does not change"); a new primitive needs a `hash_alg` field. Claim corrected in §14.1. | whoever changes the hash (a format change) |
| A30 | §8/§13 | Hashing runs under the `Sfs` lock (seal, verified inserts) with preemption off. Measure the worst case per commit and per mutating operation, and move hashing out from under the lock if it is not small. | FS-1b: bounded (ops hash nothing; a seal ≤ 48 blocks; a miss 1 block), **not measured** — open |
| A31 | §11 | The real counting allocator for the heap-cap test (A23): a test-support crate outside the `forbid(unsafe_code)` boundary. | **done (FS-1b)**: `test-alloc`, peak 435 636 B on 16 MiB and 1 GiB |

**Minds change on.** Architect: FS-1b's torn-commit harness not drivable without the facade
(then FS-2 moves up); shell files mostly > 1 KiB (then inline grows). Reviewer: a proven
≤ 13-block bound is what unblocks quiescent early commits (now stated; the host asserts it).
Security: a pre-unlock recovery console that must list filenames (then names stay clear); the
identity spec shipping a user-secret-wrapped device key before FS-5 (then FS-5 moves up).
Verification: a `Node<6>` split/merge harness under 60 s locally (then the real fanout bound
is asked for); every parser Kani-total at realistic bounds (then the lane may slip to FS-4).

## 16. References

- O. Rodeh, *B-trees, Shadowing, and Clones* (CoW B+trees; the basis of btrfs).
- btrfs on-disk format (leaf item packing, generation numbers, checksummed pointers);
  ZFS (two-slot uberblock ring, space maps, Merkle-verified block pointers); bcachefs.
- dm-verity (Merkle-verified block devices) for the read-verification discipline.
- `docs/specs/2026-09-18-component-model-design.md` §6, §10, §13, §16, §19 (review conditions
  reused here: pure parsers, Kani-bounded invariants, fuzz lane before third-party code).
- `kernel/docs/hal-tcb.md` §7 (`hal::ata` rows A1–A4, incl. `FLUSH CACHE` under A2).
