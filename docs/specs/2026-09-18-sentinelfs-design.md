# SentinelFS — a copy-on-write, content-addressed, Merkle-verified filesystem

Status: **proposed** · Track A (kernel core) + D (security subsystem) · Author: kernel-architect
Depends on: `hal::ata` (PIO block I/O, TCB), `kernel::hash` (SHA-256, PR-1 of the component
model), `kernel::clock` (commit pacing), the component-model design
(`docs/specs/2026-09-18-component-model-design.md`: §6 content-addressed identity, §10 state
objects, §13 `kernel::state` / `kernel::secrets` "persistence via `kernel::fs`").
Escalation: **architectural.** Replaces `kernel::fs`'s on-disk format outright (no migration:
the image is a dev artefact under `target/`). One new `hal` row (ATA `FLUSH CACHE`) in FS-3,
none before. Direction from Veeti (2026-09-18): "the filesystem the most efficient possible in
the modern world … we aim for perfection" — this spec says what that means here and what it
does not.

## 1. Summary

SentinelFS never overwrites a live block. Every write allocates fresh blocks, every block
pointer carries the SHA-256 of what it points to, and a commit is one atomic superblock
switch between two generation-numbered slots. A crash at any instant leaves the previous
root intact and verifiable: **no journal, no replay, no fsck**. The Merkle root of the
metadata tree is a 32-byte summary of the entire filesystem state, which the IntegrityLog
can sign and a paired device can verify — the filesystem becomes something the Sentinel
subsystem can *attest*, not just store into.

Blobs are content-addressed (a second tree keyed by hash), so components (already identified
by `H(code ‖ params)`), model weights and state-object snapshots are stored exactly once and
the host's "the kernel knows what it runs" check is also "the disk knows what it holds".
Snapshots are free (an old root kept alive), which gives rollback after tamper or a bad
update. Small files live inline in the tree; larger ones in extents; the whole thing runs in
a bounded block cache well inside the 4 MiB heap and never materialises the image in memory.

"Most efficient in the modern world" splits into two things. The *format* is designed for
the modern world: 4 KiB blocks, extents, CoW B-tree, inline small files, dedup, no journal
double-write. The *transport* is not: `hal::ata` is 16-bit PIO with polling, so throughput is
bounded by the CPU pushing words through a port. DMA (NVMe queues, or virtio-blk under
QEMU) is new `hal` territory — MMIO doorbells, DMA-coherent buffers, MSI-X — and gets its own
spec **after** the format proves itself on ATA (§13). Perfection is sequenced, not claimed.

## 2. Goals and non-goals

Goals (v1, FS-1…FS-5):

1. **Crash consistency by construction.** Any prefix of the block-write sequence mounts to a
   consistent, verified state (host property test over every crash point; QEMU torn-commit
   proof).
2. **Integrity everywhere.** Every metadata and data block is hashed; a flipped bit anywhere is
   detected at read and named in the scrub. The root hash is attestable.
3. **Content addressing.** `put_blob(bytes) -> Hash`, deduplicated; components and state
   objects live there.
4. **Snapshots and rollback** as first-class, O(1) operations.
5. **Bounded memory.** Block cache ≤ 256 KiB, dirty set bounded per transaction, no path that
   allocates proportional to the image size.
6. **Same shell and Files-app behaviour** through the existing `kernel::fs` API, so nothing
   above notices except that it stops losing data.

Non-goals (v1): POSIX semantics (permissions, links, mtime beyond a generation number),
encryption at rest (§10 places it; the KeyAgent and login work supply the keys), multiple
devices, compression, quotas, rollback *protection* against a full-disk adversary (§12,
open), DMA (§13, separate spec).

## 3. What we have, honestly

`kernel::fs` today: a heap tree of `Vec<(name, Node)>` directories and `Vec<u8>` files,
serialised as **one blob** behind a superblock (`"SNTLFS01"`, payload length, one CRC-32),
**rewritten whole on every mutating operation** over ATA PIO. `MAX_PAYLOAD = 64 KiB`. A power
cut mid-write corrupts the image; the CRC catches it on the next boot and the code falls back
to the seeded tree — data loss by design. No per-block checksums, no allocation, no
directories on disk (the tree is the payload), no snapshots, nothing addressable by content.
It did its job (prove persistence exists) and it is the right thing to replace rather than
evolve: none of its on-disk decisions survive contact with the goals above.

What *does* survive: the `FileSystem` API the shell and the Files app use (`list`,
`read_file`, `write_file`, `mkdir`, `remove`, `change_dir`, `cwd`, `is_persistent`), the
`FsError` contract ("no panics on bad user input, disk errors never fail a user operation"),
the fmt-free discipline, `prove_persistence`'s reboot-survival proof, and `hal::ata`'s safe
`read_sectors` / `write_sectors` surface.

## 4. Vocabulary

| Term | Meaning |
|---|---|
| **Block** | 4 KiB = 8 ATA sectors, the unit of allocation, hashing and caching. `BlockNo(u32)`: up to 16 TiB. |
| **Pointer** | `{ block: BlockNo, hash: [u8; 32], gen: u64 }` — where, what it must hash to, when written. Every reference between blocks is a Pointer. |
| **Superblock** | Two fixed slots (blocks 0 and 1). Each: magic, format version, generation, root Pointers, geometry, own hash. Mount takes the valid slot with the higher generation. |
| **Generation** | Monotonic u64, +1 per commit. Also the "mtime" of everything (no wall clock on disk). |
| **Tree** | A CoW B+tree of items keyed by `Key { obj: u64, kind: u8, off: u64 }`; nodes are blocks; children are Pointers. |
| **Object** | A file, directory, blob or snapshot record: a range of keys with the same `obj`. |
| **Extent** | `{ start: BlockNo, len: u32, hash }` — a contiguous run of data blocks with the hash of the whole run. |
| **Inline data** | File bytes stored inside the leaf item when ≤ `INLINE_MAX` (2 KiB). |
| **Blob** | Content-addressed data: `Hash → extents`, refcounted. |
| **Snapshot** | A retained root Pointer with a name and generation, in the roots tree. |
| **Transaction** | The in-memory dirty set between two commits. One commit per shell command, or every `COMMIT_INTERVAL` ticks of `clock::mono_ticks` if dirty, whichever first. |
| **Scrub** | Read every reachable block, verify every hash, report. |

## 5. Principles (each maps to a boot proof in §11)

1. **Never overwrite a live block.** Allocation only from blocks free in the *committed* root
   and not referenced by any retained snapshot. Proof: torn-commit recovers the previous root.
2. **Every pointer carries a hash.** Reads verify before returning; a mismatch is `Corrupt`,
   never silently served. Proof: scrub finds an injected bit flip.
3. **One root, two slots.** A commit is: write all dirty blocks → flush → write the new
   superblock into the *other* slot → flush. Mount picks the higher valid generation. Proof:
   `mount: gen=N slot=1 verified=yes`.
4. **The root hash is the state.** Same content ⇒ same root hash (the tree is canonical:
   sorted keys, deterministic split points). Proof: format + same writes twice ⇒ same root
   hash on the host.
5. **Content is addressed by what it is.** `put_blob` returns SHA-256; a second `put` of the
   same bytes allocates nothing. Proof: `cas: dedup=yes`.
6. **Snapshots are pointers.** `snapshot()` writes one item; `rollback()` switches the root.
   Proof: `snapshot=ok rollback=ok`.
7. **Bounded memory, always.** No operation allocates proportional to image size. Proof:
   host test formats a 1 GiB mock image and runs the suite under a heap cap.
8. **Nothing above the API changes.** Shell and Files app unchanged. Proof: the existing
   `[fs] persistence` proof line keeps passing, now against SentinelFS.

## 6. Architecture

```
┌───────────────────────────────────────────────────────────────────────────────┐
│  shell · Files app · kernel::state (state objects) · kernel::host (components) │
├───────────────────────────────────────────────────────────────────────────────┤
│  kernel::fs        the existing FileSystem API — a facade over sfs (FS-2)      │
│  kernel::sfs       SentinelFS: superblocks · CoW B+tree · extents · blobs ·    │
│                    snapshots · transactions · scrub          (safe Rust)       │
│  kernel::blk       block layer: BlockDevice trait · verified read/write ·      │
│                    bounded cache · allocator (per-group bitmaps) (safe Rust)   │
├───────────────────────────────────────────────────────────────────────────────┤
│  hal::ata          PIO sectors (TCB, unchanged) + FLUSH CACHE (one row, FS-3)  │
│  later: hal::nvme / hal::virtio_blk — DMA queues, own spec (§13)               │
└───────────────────────────────────────────────────────────────────────────────┘
```

- **`kernel::blk`** owns the only path to the device. `trait BlockDevice { fn blocks(&self)
  -> u64; fn read(&mut self, BlockNo, &mut Block) -> Result; fn write(&mut self, BlockNo,
  &Block) -> Result; fn flush(&mut self) -> Result; }` — implemented by `AtaDevice` (8
  sectors per block) in the kernel and by `MemDevice` (a `Vec<u8>` with an injectable
  crash point and bit-flip hook) on the host. `VerifiedRead` checks the Pointer's hash
  before handing a block out. The cache is a fixed slab of `CACHE_BLOCKS = 64` entries
  (256 KiB), LRU by generation, write-back within a transaction, write-through at commit.
- **`kernel::sfs`** is pure logic over `blk`: it never touches ports, never allocates
  unbounded, never panics on disk contents (every parse is `&[u8] -> Result`).
- **`kernel::fs`** keeps its API and becomes a thin path resolver over `sfs` (FS-2); the
  old serialiser is deleted.
- Concurrency: one `SpinMutex<Sfs>`; the lock is never held across a device I/O that can
  block for long — PIO is synchronous, so operations are short and thread-context only
  (never from an IRQ). Components reach the FS only through a **storage capability** (§9).

## 7. On-disk format

All integers little-endian. Block size `BLOCK = 4096`. Hashes are SHA-256 (32 bytes).
Every block begins with a 64-byte header:

```text
off len field
 0   32  hash           SHA-256 of bytes [32..4096) — the block's own hash, so a block
                        can be verified standalone during scrub
32    8  gen            generation that wrote this block
40    4  kind           1 superblock · 2 tree node · 3 bitmap · 4 data (raw, no header)
44    4  tree_id / pad
48   16  fs_uuid        the filesystem this block belongs to (stray-block detection)
```

Data blocks (kind 4) have **no** header: their hash lives in the extent item, so a 4 KiB
file block is 4 KiB of user data. Headers are for metadata only.

### 7.1 Superblock (slots: block 0 and block 1)

```text
 64    8  magic "SNTLFS02"     72   4  version = 2       76   4  block_size = 4096
 80    8  total_blocks         88   8  gen               96  32  fs_uuid (dup)
128   48  root: Pointer{block u32, pad u32, hash [32], gen u64}   — the metadata tree
176   48  blobs: Pointer        — the content-addressed tree
224   48  roots: Pointer        — the snapshots tree
272   48  free: Pointer         — the allocation-group index (§7.4)
320    8  next_obj             328   8  committed_at (mono ticks; informational)
336  …    zero
```

Mount: read both slots; a slot is valid iff its header hash matches and `magic`/`version`
do; take the valid slot with the higher `gen`; if neither is valid → `Unformatted`. Commit
writes the slot **not** currently active. A torn superblock write fails its own hash and is
ignored, which is the whole recovery story.

### 7.2 Tree nodes (kind 2) — a CoW B+tree

```text
 64   1  level (0 = leaf)   65  1  pad   66  2  nitems   68  4  pad
 72  …   internal: nitems × { Key (17 B: obj u64, kind u8, off u64), Pointer (48 B) }
         leaf:     nitems × { Key, data_off u16, data_len u16 } then item data packed
                   from the end of the block backwards (btrfs-style)
```

Keys sort by `(obj, kind, off)`. Item kinds:

| kind | key `off` | item data |
|---|---|---|
| `INODE` (0x01) | 0 | `{ size u64, kind u8 (dir/file/blob), nlink u32, gen u64, flags u32 }` |
| `DIRENT` (0x10) | `H64(name)` | `{ child_obj u64, name_len u16, name… }` (collisions chain by `off+1`) |
| `INLINE` (0x20) | 0 | file bytes, `≤ INLINE_MAX = 2048` |
| `EXTENT` (0x21) | byte offset | `{ start u32, len_blocks u32, hash [32] }` |
| `XATTR` (0x30) | `H64(key)` | small key/value, used by `kernel::state` for object metadata |

Fan-out: internal nodes hold ~60 children; a leaf holds ~30 dirents or ~1 inline file plus
a few items. Three levels address millions of objects; the shell will see two. Nodes are
CoW'd from leaf to root on every mutation within a transaction (path copying, done once per
transaction per path thanks to the dirty set). Split at half, merge below a quarter,
deterministically, so the tree shape depends only on the key set (principle 4).

### 7.3 Blobs — content addressing

The `blobs` tree is keyed by `obj = first 8 bytes of SHA-256`, kind `BLOB` (0x40), `off =
next 8 bytes`; item `{ full_hash [32], size u64, refs u32, extents… }` (or inline). `put_blob`
hashes the bytes (`kernel::hash`), looks up, bumps `refs` or writes extents. A file may
*reference* a blob (`EXTENT` with a `BLOB_REF` flag) instead of owning extents — a
zero-copy way to store components, weights and state snapshots that are also files. The
host loads a component from the blob store by its `ComponentId` directly: the id **is** the
storage key, and the FS verified the hash on the way in and again on the way out.

### 7.4 Allocation — per-group bitmaps

The image is divided into **allocation groups** of 32 768 blocks (128 MiB). Each group has
one bitmap block (kind 3): 4 KiB = 32 768 bits. The `free` Pointer names an index block of
group Pointers (one block indexes 85 groups ≈ 10 GiB; a second level covers LBA28's 128
GiB). Bitmaps are CoW like everything else: allocating from a group dirties its bitmap
block, which is written to a fresh location and re-pointed. Allocation policy: first-fit
within the group of the object's last extent, else the emptiest cached group; extents
prefer runs of ≥ 8 blocks. Blocks freed in a transaction become allocatable **only after**
the commit that frees them (they may be referenced by the still-live previous root) and
never while a retained snapshot references them (snapshot deletion walks its exclusive
extents — bounded by that snapshot's size, done incrementally across commits).

### 7.5 Snapshots

The `roots` tree holds `{ name, gen, root: Pointer, blobs: Pointer }` items. `snapshot(name)`
writes one item at the current committed root. `rollback(name)` writes a new superblock
whose `root`/`blobs` are the snapshot's (a new generation — history is never rewritten).
Reading a snapshot mounts it read-only through the same code.

## 8. Transactions and commit

```
begin (implicit) → mutate: CoW path copies into the dirty set (bounded: DIRTY_MAX = 48
blocks; exceeding it forces an early commit) → commit:
  1. write every dirty block to its fresh location (verified write: hash computed once,
     stored in the parent Pointer and the block header)
  2. flush
  3. write superblock(gen+1) into the inactive slot
  4. flush
  5. dirty set → clean; freed-in-this-txn blocks → allocatable
```

Commit pacing: at the end of every shell/Files-app mutating call (as today), or every
`COMMIT_INTERVAL = 50` mono ticks (0.5 s) if dirty, or when `DIRTY_MAX` is hit. Reads inside
a transaction see the dirty set first. Nothing allocates under the `Sfs` lock except the
fixed slabs; no I/O happens from IRQ context.

Cost on ATA PIO (per commit, small change): ~4–6 metadata blocks + data + 1 superblock =
~10 block writes ≈ 80 sectors ≈ a few hundred microseconds under KVM, milliseconds under
TCG. The old design rewrote up to 64 KiB (128 sectors) for a one-byte change and had no
upper bound design.

## 9. Integration with the component model

- **Storage is a native service behind a capability.** `cap::Target::Storage { tree, prefix }`:
  a component holding it can read/write under that path prefix (or that blob namespace)
  and nothing else; attenuation narrows the prefix or drops `Write`. Denials are logged
  (component amendment A8). The shell and Files app are first-party and hold the root cap.
- **Components live in the blob store** keyed by `ComponentId`; the host's `Manifest.code`
  becomes "the blob with this hash", and instantiation is `get_blob(id)` + the existing
  verify (which now cannot fail unless the disk lies — and then the FS said so first).
- **State objects** (`kernel::state`) persist as blobs referenced from an `XATTR`-carrying
  object per state object; `summarize_state` can literally be the blob hash for the
  mergeable class.
- **IntegrityLog** is an append-only object whose records reference blobs; the FS root hash
  is itself a record: *"at generation N the filesystem was X"*, signed by the KeyAgent — the
  attestation the Sentinel subsystem sweeps against (FS-5).
- **Secrets** (`kernel::secrets`, component PR-3) store ciphertext blobs; the FS never sees a
  key. Full-tree encryption (§10) comes when login supplies a user secret.

## 10. Where encryption goes (not v1, placed now)

Integrity is the FS's job; confidentiality is layered above it so the two can be reasoned
about separately:

1. **Now (component PR-3):** `kernel::secrets` encrypts its own blobs (AEAD, KeyAgent key,
   nonce = generation ‖ counter). The FS stores opaque bytes with real hashes.
2. **With login (identity spec):** a per-tree data key wrapped by a key derived from the
   user secret (Argon2id) — data blocks and inline items encrypted, **metadata keys and
   hashes in the clear** (so scrub, dedup-by-hash-of-plaintext-with-a-keyed-hash, and
   attestation keep working; hash of ciphertext would hide dedup and tie identity to nonces).
3. **Never:** keys on the same disk in the clear (refused 4/4 in the component review).

## 11. Boot proofs and PR staging

Each PR is independently bootable and adds hard assertions to `cargo xtask test`.

| PR | Lands | Boot-proof line (asserted) |
|---|---|---|
| **FS-1** block layer + tree | `kernel::blk` (BlockDevice, AtaDevice, MemDevice, verified I/O, cache, allocator), `kernel::sfs` (superblocks, CoW B+tree, transactions, format, mount, scrub). Host: property tests over random op sequences vs a reference model, **every crash point** mounts consistently, bit-flip → `Corrupt`. Kani: superblock selection, key ordering, node split/merge invariants, bitmap ops, extent arithmetic. The kernel formats the dev image if it is not SentinelFS. | `[sfs] mount: gen=N slot=S root=<8 hex> verified=yes groups=N free=N/N ok` |
| **FS-2** files + facade | `INODE`/`DIRENT`/`INLINE`/`EXTENT`; `kernel::fs` becomes a facade; old serialiser deleted; shell and Files app unchanged. | existing `[fs] persistence … ok` line, plus `[sfs] scrub: blocks=N bad=0 ok` |
| **FS-3** durability | ATA `FLUSH CACHE` (**one `hal` row**, `FL1`, with its hal-tcb entry); commit protocol as in §8; a QEMU **torn-commit** proof: with a boot flag the kernel halts after the k-th block write of a commit, the next boot must mount the previous generation with its data intact (xtask drives two boots). | `[sfs] torn-commit: cut-after=K recovered-gen=N-1 data-intact=yes ok` |
| **FS-4** blobs + snapshots | `put_blob`/`get_blob` with dedup, `BLOB_REF` extents, snapshots and rollback; the host loads `hello` from the blob store by `ComponentId`. | `[sfs] cas: put=2 stored=1 dedup=yes component-from-cas=verified snapshot=ok rollback=ok ok` |
| **FS-5** attestation | FS root hash recorded in the IntegrityLog and signed by the KeyAgent (needs component PR-3/PR-4); scrub compares against the last signed root. | `[sfs] attest: root=<8 hex> logged=yes signed=yes verified=yes ok` |

Every PR: host tests for the pure parts (the entire FS runs on `MemDevice` on the host —
this is where the real coverage is), Miri on the codec/tree, Kani where named, fmt-free
console output, `hal-tcb.md` unchanged except FS-3's single row.

## 12. Threat model

**Assumption (Kerckhoffs):** the adversary knows the format and the code.

*Detected, always:* bit rot, torn writes, a truncated image, a block from another
filesystem (uuid), any modification of any block (hash mismatch, named by the scrub).

*Recovered, always:* a crash at any point in a commit (previous root); a bad update or
tamper *after* a snapshot (rollback).

*Detected once FS-5 lands:* offline modification of the whole tree by an adversary who
re-hashes consistently — the root no longer matches the signed attestation.

*Not defended (open, §14):* **rollback by a full-disk adversary** to an older, internally
consistent, previously signed state. Needs a monotonic counter the disk does not control
(TPM NV index, or the paired device's copy of the IntegrityLog via IdentityDir sync — the
component review already noted that sync forces a persistent device key).

*Not the FS's job:* confidentiality (§10), a malicious first-party component (§16 of the
component spec: authority boundary only until the gate), the ATA controller lying about
completion (the TCB assumption we already make).

## 13. Efficiency, honestly, and the road to DMA

| Path | Today (`kernel::fs`) | SentinelFS on ATA PIO | SentinelFS on NVMe/virtio-blk (later spec) |
|---|---|---|---|
| 1-byte write | rewrite whole tree, ≤ 128 sectors | ~10 blocks, 80 sectors, no data rewrite | same blocks, DMA, µs |
| Read a 1 KiB file | deserialise everything at boot, then heap | 1 leaf (inline), cache hit after first | same |
| Store a 10 MiB model | impossible (64 KiB cap) | extents, ~2560 blocks, ~1.3 s PIO under KVM | ~ms |
| Boot mount | parse whole payload | 2 superblocks + root path | same |
| Memory | whole tree on heap | ≤ 256 KiB cache + ≤ 48 dirty blocks | same, larger cache when the heap grows |
| Crash | data loss to seed | previous generation | same |

PIO is the transport bottleneck: every sector is 256 `outw`/`inw` with status polling. The
format never asks PIO for more than it must (no journal double-write, no read-modify-write
of live blocks, cache), but throughput stays CPU-bound until DMA. The DMA spec will add
`hal::pci` bus-mastering (present), MMIO doorbells, DMA-safe buffers (identity-mapped,
never on the heap), MSI or polling completion, and its own Kani/Miri lane — the sharpest
`hal` work since SMP, which is why it is *after* the format is proven, not before.

## 14. Open questions

1. **Hash primitive per block.** SHA-256 in-tree costs ~5 µs per 4 KiB block scalar; fine on
   PIO, dominant on DMA. BLAKE3 (dependency) or a hardware-SHA tier (`sha_ni`, a `hal::simd`
   sibling) later — behind `kernel::hash::Hasher` so the format does not change.
2. **Block size** 4 KiB vs 512 B: 4 KiB wastes up to 3.5 KiB on the smallest files; inline
   items (§7.2) cover that. Decided 4 KiB unless the review objects.
3. **Rollback protection** (§12): TPM NV vs paired device. Decide with the identity spec.
4. **Encryption granularity** (§10): per-tree vs per-object. Decide with the identity spec.
5. **Dirent hashing** `H64(name)`: SipHash-style keyed hash (needs a per-fs key in the
   superblock — fine, it is not secret, it only defeats collision floods) vs truncated
   SHA-256. Start with truncated SHA-256 + chaining.
6. **Free-space reclamation from deleted snapshots** is the one operation whose cost is
   proportional to the snapshot's exclusive size; incremental across commits, bounded per
   commit. Verify the bound holds in the host model before FS-4.
7. **`kernel::fs` API growth:** `stat`, `rename`, and `snapshot`/`rollback` shell built-ins
   arrive with FS-2/FS-4; the Files app gains a snapshot list.

## 15. References

- O. Rodeh, *B-trees, Shadowing, and Clones* (CoW B+trees; the basis of btrfs).
- btrfs on-disk format (leaf item packing, generation numbers, checksummed pointers);
  ZFS (two-slot uberblock ring, space maps, Merkle-verified block pointers); bcachefs.
- dm-verity (Merkle-verified block devices) for the read-verification discipline.
- `docs/specs/2026-09-18-component-model-design.md` §6, §10, §13, §19 (review conditions
  reused here: pure parsers, Kani-bounded invariants, fuzz lane before third-party code).
- `kernel/docs/hal-tcb.md` §7 (`hal::ata` rows) — FS-3 adds `FLUSH CACHE`.
