# SentinelOS — Kernel-Native Tamper-Evident Audit Log Design Spec (#S1)

- **Date:** 2026-06-04 · **Status:** Draft for review
- **Component of:** SentinelOS · **Sub-project:** #S1 — first kernel-native security subsystem
- **Owner agent:** kernel-architect
- **Prereq:** sub-projects #1 (boot), #2 (core kernel: IDT/heap/PIT), storage (ATA + `kernel::fs`) — all complete & reviewed
- **Escalate to:** `security-engineer` (hash choice / threat model), `kernel-reviewer` (no-new-`unsafe` boundary, append-only invariant)

## 0. Where #S1 sits in the north-star direction

This spec designs the **first primitive** of SentinelOS's new "agent-native, reversible, tamper-evident" direction: a **kernel-native, append-only, tamper-evident audit log**. It is the *substrate* under three of the north-star goals; this spec is explicit about that so the schema is built to generalize, not retrofitted later:

| North-star goal | Role the audit log plays | What this spec ships in the seed |
|---|---|---|
| **#1 Agent-native OS** — autonomous agents as first-class, bounded, revocable, fully-audited principals | The audit log is **where every agent action is recorded**. The record's `principal` field is the audit trail of "who did what." | A `Principal` enum that today only names *kernel-internal* actors (shell, fs, app-spawn) but is shaped to grow an `Agent { id, .. }` variant + capability-decision events. |
| **#2 Reversible OS** — whole-system "undo" | The audit log is the **transaction journal**: the ordered, gap-free record an undo engine replays/inverts. | A reserved `inverse`/`snapshot` reference field on each record (encoded, today always "none") so the journal shape is fixed now and the undo engine is purely additive later. |
| **#4 Tamper-evidence / provable attack surface** | A **hash-chained, structurally append-only** record, small enough to eventually Kani/Miri-verify. | The hash chain + the append-only-by-construction API + a `verify_chain()` invariant, with the chain core sized to be a tractable verification target. |

**Honesty up front (set the expectations the rest of the doc keeps):** this is a *seed*. It delivers tamper-**evidence** (you can *detect* that the on-disk log was rewritten), not tamper-**prevention** (nothing here stops a privileged writer from rewriting the disk). It records *kernel-internal* actors only — there are no real agents, processes, capabilities, or undo engine yet, because the kernel has no scheduler/syscalls/userland (single-core monolithic kernel). It picks a hash and an encoding now so the three north-star subsystems plug in without reshaping the record.

## 1. Summary

#S1 adds a **kernel-native, append-only, hash-chained audit log** as the first component of the kernel's security subsystem. Every security-relevant kernel action (a shell command, a filesystem mutation, an app spawn) is recorded as an immutable `AuditRecord` carrying a monotonic sequence number, a PIT-tick timestamp, the acting `Principal`, an `Action`/target/summary, and a **hash-chain field** = `H(prev_hash ‖ this_record)`. The log is **append-only by construction** (the public API has `append` but *no* mutate/delete), persisted to the primary ATA disk reusing `kernel::fs`'s exact superblock+CRC+`hal::ata` pattern, and verifiable with `verify_chain()`. It is written **entirely in safe Rust** and adds **zero new `unsafe`** — it lives in `crates/kernel` under a new `security/` module, leans on the existing safe `hal::ata`/`hal::pit` surfaces, and carries the crate's `#![forbid(unsafe_code)]`. It carries the **framekernel discipline** forward unchanged: the TCB does not grow by one line.

## 2. Goals

- An **`AuditRecord`** schema with: monotonic `seq: u64`, `tick: u64` (PIT), `principal: Principal` (extensible), `action: Action`, a bounded `target` + `summary`, and `entry_hash: [u8; 32]` = `H(prev_hash ‖ serialized-record-without-hash)`.
- An **append-only `AuditLog`** with `append(...) -> Seq`, `verify_chain() -> Result<(), ChainError>`, and read-only iteration/query — and **no** API to edit or delete a record.
- **On-disk persistence** that survives reboot, reusing the `kernel::fs` `disk` pattern verbatim in shape: a superblock (magic + len + CRC-32) on sector 0, records appended after it, loaded/validated on boot.
- A **dependency-light, pure-safe-Rust hash** (recommendation: a compact SHA-256) so the chain is *adversarially* tamper-evident, with an honest statement of the trade-off and an upgrade path.
- **First emit sites** wired into existing code (`shell.rs` command execution, `fs.rs` mutations, `wm.rs` `log_spawn`), so the log is non-empty on first boot.
- A way to **view** the log: an `audit` shell command and/or an Audit app (per the `App` trait framework).
- **Extension points** designed in (not built) for #1 agents, #2 reversibility, #4 verification.
- Everything on **stable Rust**; `crates/kernel` stays `#![forbid(unsafe_code)]`; clippy-clean, `-D warnings`.

## 3. Non-goals (seed scope — explicitly deferred)

- **Cryptographic signing** of the log (HMAC/Ed25519 over the head hash). The seed gives a *hash chain*, not a *signed* chain — a rewriter who recomputes the whole chain from a tampered point forward defeats it (see §3-hash). Signing is the named upgrade path, deferred to a follow-up once a key-management story exists. **(Escalate the threat model to `security-engineer`.)**
- **Real agents / capabilities.** There is no scheduler, no syscalls, no userland, no process table — so there are no real principals to bind beyond kernel-internal actors. The `Principal` enum is *shaped* for agents; binding them is goal #1's later work.
- **Reversibility engine.** No undo/redo, no snapshots, no inverse application. The seed reserves the journal fields; building the engine is goal #2's later work.
- **Tamper-PREVENTION.** Nothing here prevents a privileged kernel path (or an attacker with disk access) from rewriting sectors. The seed *detects* rewrites that fail to reconstruct a consistent chain; it does not stop them. (See §6.4.)
- **Log rotation / compaction / retention policy** beyond a simple bounded on-disk region. A full-disk log is a follow-up.
- **Multi-core / concurrent appends.** Single-core monolithic kernel; the log is driven from the single-threaded kernel path, same concurrency model as `hal::ata`/`kernel::fs`.
- **`sentinel-core` integration.** `sentinel-core` is `std` + `serde` today (not `no_std`) and models *findings*, not *journal entries*. The seed does **not** depend on it (see §7).

## 4. Locked decisions

| Decision | Choice |
|---|---|
| Framekernel classification | **Safe kernel code, zero new `unsafe`.** Lives in `crates/kernel`, inherits `#![forbid(unsafe_code)]`. TCB unchanged. |
| Module placement | A **new module** `crates/kernel/src/security/{mod.rs, audit.rs}`, *not* a new crate (see §5 rationale). |
| Hash function | **A compact, hand-rolled, pure-safe-Rust SHA-256** (no external crate). FNV/CRC are integrity-only; SHA-256 gives real adversarial tamper-evidence. Seed picks SHA-256 (see §3-hash). |
| Chain rule | `entry_hash = SHA256(prev_hash ‖ encode(record_without_hash))`; genesis `prev_hash = [0u8; 32]`. |
| Append-only | The public type exposes `append`, `verify_chain`, and iteration **only** — no `&mut record`, no `remove`, no `truncate`. Append-only is an *API* property in RAM; the chain gives tamper-*evidence* on disk. |
| Persistence | Reuse the `kernel::fs::disk` pattern: superblock (magic `b"SNTLLOG1"` + `u32 len` + `u32 crc`) on sector 0, encoded records after it, via the safe `hal::ata` block API. CRC-32 detects accidental corruption; the hash chain detects rewrites. |
| Timestamp source | `hal::pit::ticks()` — the monotonic PIT counter (100 Hz). Recorded raw as `tick: u64`; wall-clock derivation is a display concern. |
| Encoding | Little-endian, length-prefixed, tag-byte framed — the **same byte-discipline as `kernel::fs`** (`u32` LE lengths, bounded reads, `Option`-returning deserialisers, depth/size caps). |
| `core::fmt` | **Avoided** on this target (it faults — the documented bare-metal constraint). Numbers go to serial via `hal::serial::write_dec` and to the console via the existing `push_dec` helper pattern. |
| Toolchain | **stable Rust, no nightly, no `-Z build-std`.** |

> **Open question (for review):** SHA-256 in pure safe Rust on this target adds compute per append. Appends are *rare* (a command, a file write — human-rate, not hot-path), so this is acceptable for the seed; confirm with `kernel-reviewer`/`security-engineer` before locking. The fallback if compute is a concern is "FNV-1a now, SHA-256 behind the same `entry_hash` field later" — but that ships *integrity-only*, not tamper-evidence, so the spec recommends SHA-256 from the seed.

## 3-hash. Hashing choice (honest trade-off)

The hash-chain field is the load-bearing part of goal #4, so the choice deserves a frank treatment:

| Option | Pure safe Rust? | Detects accidental corruption? | Detects adversarial rewrite? | Cost |
|---|---|---|---|---|
| **CRC-32** (already in `fs.rs`) | yes | yes | **no** — trivially forgeable; a rewriter recomputes it | ~free |
| **FNV-1a / DJB2** | yes | yes | **no** — not collision-resistant, trivially forgeable | ~free |
| **SHA-256** (hand-rolled) | yes | yes | **yes** — pre-image/collision resistant; a rewriter cannot cheaply forge a chain that re-links | bounded, per-append |

**Recommendation: SHA-256, hand-rolled in safe Rust, in the seed.**

Rationale: the *entire point* of goal #4 is a record that is "structurally un-rewritable" enough to be *evidence*. CRC/FNV give you "the disk didn't bit-rot" — useful, but a one-line forgery for an attacker. SHA-256 makes the chain *cryptographically* hard to rewrite without detection: to alter record *k* you must recompute `entry_hash` for *k, k+1, … head*, which is possible on disk (see the honesty note below) but **not** forgeable against an out-of-band copy of the head hash, and is exactly what a future *signature over the head* turns into prevention.

SHA-256 is ~250 lines of pure integer arithmetic (the eight working variables, the message schedule, the round constants) — **no `unsafe`, no external crate, no `core::fmt`**. It is also an excellent, well-bounded **Kani/Miri target** (fixed-size buffers, no allocation in the compression function) — which directly serves goal #4. We keep CRC-32 *as well*, for the superblock, reusing `fs.rs`'s `crc32` to detect accidental media corruption cheaply on load before we spend SHA work verifying the chain.

**The honest limit (must be stated wherever this is described):** a hash chain on disk gives tamper-**evidence relative to a trusted head hash**, not tamper-**prevention**. An attacker who can rewrite the disk *and* knows the chain rule can recompute a fully self-consistent chain from any tampered point to the head. The chain only catches them if a copy of the head hash (or an earlier record's hash) is held somewhere they cannot rewrite. The seed does **not** ship that out-of-band anchor or a signature — so the seed's honest claim is: *"detects accidental corruption and naive in-place edits; full tamper-evidence requires the deferred signing/anchoring step."* Escalate the precise claim wording to `security-engineer`.

## 5. Architecture & module placement

### 5.1 Framekernel classification

The audit log is **safe kernel code**. Every operation it performs — serialise records, hash bytes, call `hal::ata::read_sectors`/`write_sectors`, read `hal::pit::ticks()` — is already available through **safe** HAL surfaces. There is **no privileged instruction** the log needs that isn't already wrapped by the TCB. Therefore:

- **TCB (`crates/hal`): unchanged.** No new module, no new `unsafe`, no new `hal-tcb.md` row. This is a hard requirement and an acceptance criterion (§10).
- **Safe kernel (`crates/kernel`): grows by one module** (`security/`), carrying the crate-level `#![forbid(unsafe_code)]`.

This is the framekernel thesis working as designed: a security-critical subsystem implemented with **zero TCB growth** because the dangerous primitives (port I/O for ATA/PIT) were already minimised into `hal`. Challenge any reviewer suggestion to push hashing or journal logic into `hal` — it has no need of `unsafe` and must stay out of the TCB.

### 5.2 Module vs. new crate

**Recommendation: a new *module* `crates/kernel/src/security/`, not a new crate — for the seed.**

| Consideration | Module (chosen) | New `crates/security` crate |
|---|---|---|
| `#![forbid(unsafe_code)]` | inherited from `kernel` | would need its own (fine) |
| Depends on `hal` (ata/pit) | already a `kernel` dep | new dep edge to declare |
| Depends on `kernel::fs` byte helpers | same crate, trivial reuse | would need to export/duplicate them |
| Workspace graph / cycle risk | none (it's inside `kernel`) | must not depend back on `kernel` |
| Future: many security components | promote to a crate when ≥2 land | premature now |

The seed is one file plus a `mod.rs`; a crate is overhead with no payoff yet. **When the security subsystem grows a second component** (capability engine, the reversibility journal-replayer, a `sentinel-core` port), promote `security/` to `crates/security` — at which point the byte-helpers it shares with `fs.rs` should move to a small shared `crates/kernel`-internal `serde`-free codec module. Flag this promotion as a future architecture review.

### 5.3 Module layout

```
kernel/crates/kernel/
  src/lib.rs                       + `pub mod security;`
  src/security/
    mod.rs        [NEW, safe]      `pub mod audit;`  + a one-line subsystem doc; the
                                   future home of capability/reversibility submodules
    audit.rs      [NEW, safe]      AuditRecord, Principal, Action, AuditLog, ChainError;
                                   the append-only API, the SHA-256 chain, the on-disk
                                   codec (a private `disk` submodule mirroring fs.rs)
    sha256.rs     [NEW, safe]      hand-rolled SHA-256 (pure integer arithmetic, no
                                   alloc in the compression fn) — a Kani/Miri target
```

### 5.4 Data flow (append path)

```
kernel action occurs (e.g. shell runs `mkdir /x`, fs writes a file, wm spawns an app)
  → call site builds an AuditRecord-in-flight (principal, action, target, summary)   [safe kernel]
  → AuditLog::append(record_fields)                                                  [security::audit]
       → seq      = self.next_seq         (monotonic; ++)
       → tick     = hal::pit::ticks()      (safe HAL read)
       → body     = encode(seq, tick, principal, action, target, summary)            (LE, length-prefixed)
       → entry_hash = sha256(self.head_hash ‖ body)                                  [security::sha256]
       → push AuditRecord { ..body.., entry_hash } into the in-RAM Vec
       → self.head_hash = entry_hash
       → disk::save(&self.records)    (best-effort write-through, like fs.rs::save)  [via hal::ata]
       → return seq
verify (on demand, e.g. `audit verify`)
  → AuditLog::verify_chain()
       → h = [0u8;32]
       → for rec in records: expect rec.entry_hash == sha256(h ‖ encode(rec_body)); h = rec.entry_hash
       → first mismatch → Err(ChainError { at_seq })   (the record where the chain broke)
load (on boot)
  → disk::load() reads sector 0 superblock (magic+len+crc32), validates CRC, decodes records,
    then runs verify_chain(); a broken chain or bad CRC → start an empty log + emit a "tamper/
    corruption detected at seq N" audit event of its own (honesty: report, don't hide)
```

## 6. Public interface (Rust sketches, not implementations)

> Sketches only — field/method shapes for review, not final code. All types are `#![forbid(unsafe_code)]` safe Rust, `no_std` + `alloc`, no `serde`, no `core::fmt` on the hot path.

### 6.1 Record schema & encoding

```rust
/// A monotonic, gap-free sequence number identifying a record's position in the log.
/// Genesis is 0. Never reused, never decreases.
pub type Seq = u64;

/// Who performed the action. EXTENSIBLE: today only kernel-internal actors exist
/// (no scheduler/userland), but the enum is shaped so an `Agent`/`Process` variant
/// drops in for goal #1 without changing the record layout. Encoded as a u8 tag
/// (+ payload for variants that carry an id), so adding a variant is forward-only.
#[non_exhaustive]
pub enum Principal {
    /// The kernel itself (boot, self-tests, the log reporting on itself).
    Kernel,
    /// The interactive shell acting on a user's typed command line.
    Shell,
    /// The in-kernel filesystem performing a mutation.
    FileSystem,
    /// The window manager / launcher spawning or closing an app window.
    WindowManager,
    // --- reserved for goal #1 (do NOT encode yet; documented intent) ---
    // Agent { id: u32 },     // an autonomous agent principal (bounded capability holder)
    // Process { pid: u32 },  // a future userland process
}

/// What kind of action was recorded. Coarse, stable verbs; the `target`/`summary`
/// carry the specifics. Encoded as a u8 tag. EXTENSIBLE the same way as `Principal`.
#[non_exhaustive]
pub enum Action {
    Boot,            // kernel/subsystem came up
    Command,         // a shell command was executed
    FsCreate,        // mkdir / new file
    FsWrite,         // file content written/overwritten
    FsRemove,        // file/dir removed
    AppSpawn,        // a window/app was launched
    AppClose,        // a window/app was closed
    SecurityEvent,   // the log reporting on itself (e.g. chain-break detected)
    // --- reserved for goal #1 ---
    // CapabilityGrant / CapabilityDeny / CapabilityRevoke
}

/// One immutable entry. Field order here is the canonical encoding order; the
/// `entry_hash` is computed over everything BEFORE it and is itself never part of
/// the hashed body (it IS the chain output for this record).
pub struct AuditRecord {
    pub seq: Seq,                 // u64 LE
    pub tick: u64,                // u64 LE — hal::pit::ticks() at append time
    pub principal: Principal,     // u8 tag (+ optional id payload)
    pub action: Action,          // u8 tag
    pub target: BoundedStr,       // u32 LE len + bytes (e.g. "/home/notes.txt", "mkdir")
    pub summary: BoundedStr,      // u32 LE len + bytes (a compact param/result note)
    /// RESERVED for goal #2 (reversibility). Encoded NOW as a 1-byte tag that is
    /// always `0 = None` in the seed, so the on-disk shape is fixed and the undo
    /// engine is purely additive. Future: `Inverse { kind, blob }` or `SnapshotRef(u64)`.
    pub reversal: Reversal,       // u8 tag (seed: always None)
    pub entry_hash: [u8; 32],     // SHA-256(prev_hash ‖ encode(all fields above))
}

/// Bounded so a single record can never balloon the early-boot heap or a sector
/// budget (mirrors fs.rs's MAX_PAYLOAD/MAX_DEPTH discipline). Truncated-with-marker
/// rather than rejected, so logging an event can never fail the action it records.
pub struct BoundedStr(/* len-capped String */);

/// The reversibility hook (goal #2). Seed only ever constructs `None`.
#[non_exhaustive]
pub enum Reversal { None /*, Inverse { .. }, SnapshotRef(u64) */ }
```

**On-disk layout** (mirrors `kernel::fs::disk` exactly in structure):

```text
sector 0  : superblock
            [0..8)   magic        = b"SNTLLOG1"
            [8..12)  payload_len  = u32 LE   (encoded-records byte count)
            [12..16) payload_crc  = u32 LE   (CRC-32 of payload — reuse fs.rs crc32)
            [16..48) head_hash    = [u8;32]  (the chain head — a fast integrity anchor;
                                              honest note: still rewritable on disk)
            [48..512) reserved (zero)
sector 1+ : payload — encoded records back-to-back, zero-padded to a sector boundary

record encoding (LE, length-prefixed; same byte discipline as fs.rs node encoding):
  u64 seq | u64 tick | u8 principal_tag [| u32 id] | u8 action_tag
         | u32 target_len | target_bytes
         | u32 summary_len | summary_bytes
         | u8 reversal_tag (0 in seed)
         | 32 bytes entry_hash
```

The deserialiser is a cursor over a borrowed slice returning `Option<AuditRecord>`, with the **same hardening as `fs.rs`**: bounded `take_slice`/`take_u32` helpers, a `MAX_PAYLOAD` cap, a `MAX_RECORD_LEN` cap, and a `MAX_RECORDS` cap so a corrupt-but-CRC-passing superblock length cannot exhaust the heap. Reuse `fs.rs`'s `crc32`, `read_u32`/`write_u32`, `take_u32`/`take_slice` idioms (lift them to a shared internal helper when `security/` is promoted to a crate — §5.2).

### 6.2 The append-only API

```rust
/// The kernel's append-only, hash-chained audit log. There is DELIBERATELY no
/// method to mutate or delete a record: append-only BY CONSTRUCTION.
pub struct AuditLog { /* records: Vec<AuditRecord>, head_hash: [u8;32], next_seq: Seq, persistent: bool */ }

impl AuditLog {
    /// Load the log from the primary ATA disk (validating CRC + chain) or start a
    /// fresh one. Mirrors `FileSystem::seeded`: probe disk → load+verify → else empty.
    /// A failed verify starts empty AND records a `SecurityEvent` noting the break.
    pub fn boot() -> Self;

    /// Append one record. Stamps `seq` (monotonic) and `tick` (PIT), computes the
    /// chain hash, write-through-persists (best-effort, like fs::save), returns the
    /// assigned `Seq`. This is the ONLY mutating method. Cannot fail the caller's
    /// action: a disk error is logged and swallowed (in-RAM log stays authoritative).
    pub fn append(&mut self, principal: Principal, action: Action,
                  target: &str, summary: &str) -> Seq;

    /// Re-walk the chain from genesis; `Ok(())` if every `entry_hash` re-links,
    /// else `Err(ChainError { at_seq })` naming the first record that fails.
    pub fn verify_chain(&self) -> Result<(), ChainError>;

    /// Read-only iteration (newest-first and oldest-first variants) and a count.
    /// Returns borrows / copies of records; NO `&mut` is ever handed out.
    pub fn iter(&self) -> impl Iterator<Item = &AuditRecord>;
    pub fn len(&self) -> usize;
    pub fn head_hash(&self) -> [u8; 32];
}

/// The single failure mode of the integrity check: the chain broke at `at_seq`.
pub struct ChainError { pub at_seq: Seq }
```

> **What "append-only" does and does not mean (state this in the rustdoc):** in RAM, append-only is an *API* property — no caller can get a `&mut AuditRecord` or a `remove`, so the running kernel cannot edit history. On disk, the bytes are just bytes: a privileged writer can rewrite a sector. The **hash chain** turns such a rewrite into a *detectable* event (`verify_chain` fails), which is tamper-**evidence**. It is **not** "un-rewritable." Do not claim prevention.

### 6.3 Global access

A single kernel-global log instance, accessed the same way the rest of the kernel reaches shared state on this single-core target (a `spin`-free, single-threaded cell pattern consistent with how `Shell`/`WindowManager` are owned in `kmain`/`idle_loop`). **Open question for `kernel-reviewer`:** the cleanest ownership — (a) a global behind the existing safe sync primitive used elsewhere, or (b) passed by `&mut` through the call chain like `Shell` owns its `FileSystem`. The spec leans (a) for the log because emit sites are scattered (fs, shell, wm), and a borrow-threaded log would touch every signature. Confirm the safe global pattern (must remain `#![forbid(unsafe_code)]`-compatible — e.g. the same approach `hal::pit::TICKS` uses for shared state, lifted to the safe side).

## 6.4 Honest tamper model (one place, plainly)

- **In-RAM, this boot:** append-only **by construction** (no mutate/delete API). Strong.
- **On-disk, CRC-32:** detects **accidental** corruption (bit-rot, partial write). Not adversarial.
- **On-disk, SHA-256 chain:** detects **in-place edits and naive rewrites** — *if* you have a trusted reference (an out-of-band head hash). Without an anchor, a full recompute by a disk-level attacker is undetected. This is **evidence, conditioned on an anchor**, not prevention.
- **Deferred (named upgrade path → prevention-ish):** sign the head hash (HMAC with a kernel-held key, or Ed25519) and/or anchor the head off-box. Only then can you claim tamper-evidence against a disk-level attacker. **Escalated to `security-engineer`.**

## 7. Relationship to `sentinel-core`

`sentinel-core` (`/home/user/sentinelos/sentinel-core/src/model.rs`) is the cross-platform security model: `Severity`, `VectorStatus`, `Finding`, `Snapshot`. It is **`std` + `serde`** today and is **not** referenced by the kernel workspace. The audit log models **journal entries** (who/when/what/chain), which is an *orthogonal* concern to `sentinel-core`'s **findings** (what's suspicious on a host).

**Decision: the seed does NOT depend on `sentinel-core`.** Reasons: (1) it is not `no_std`/`serde`-free, so it cannot be pulled into `crates/kernel` as-is; (2) coupling a low-level journal to a host-scanner model is premature. **Future relationship (documented intent, not seed work):** when `sentinel-core` is ported to `no_std` (a separate effort), a `Finding` raised inside the kernel becomes a *source* of `Action::SecurityEvent` audit records, and `Severity` can ride along in the `summary`. The audit log is the *substrate*; `sentinel-core` becomes one of its *producers*. Keep `Action`/`Principal` general enough to carry that later (they are). Flag the `no_std` port of `sentinel-core` as a separate architecture task.

## 8. Extension points (designed now, built later)

### 8.1 Goal #1 — Agent-native principals & logged capabilities

- The `Principal` enum gains `Agent { id: u32 }` (and `Process { pid: u32 }`) — already reserved in §6.1, encoded as a tagged variant so the on-disk format is forward-compatible.
- New `Action` variants `CapabilityGrant` / `CapabilityDeny` / `CapabilityRevoke`: **every capability decision for every agent is an audit record.** "Bounded, revocable, fully-audited capabilities" means *the audit log is the audit*. The grant/deny/revoke flow writes here before the action proceeds.
- The `summary` carries the capability name + the decision rationale (compact, bounded).
- **Boundary:** when a scheduler/process model lands, the principal is bound from the *current actor* at the syscall boundary — the log never trusts a caller-supplied principal (the kernel stamps it). Note this invariant now so it isn't violated later.

### 8.2 Goal #2 — Reversibility (the log AS the undo journal)

- The reserved `Reversal` field (§6.1) carries either an **inverse** (the operation that undoes this one — e.g. `FsWrite` records the *prior* bytes or a content-hash reference) or a **snapshot id** (a reference into a future snapshot store).
- **Undo flow sketch** (future engine, additive — no schema change):
  ```
  user/agent requests "undo last N"
    → engine walks the log NEWEST-first for N records
    → for each: read its Reversal hook
         Inverse{..}    → apply the inverse op (e.g. restore prior file bytes)
         SnapshotRef(s) → roll the affected subsystem back to snapshot s
         None           → record is informational/irreversible → skip + note
    → each undo is ITSELF appended as a new record (Action::* with a "undo of seq K"
      summary) — the journal never rewrites history; reversal moves FORWARD.
  ```
- This is why the log must be **gap-free and ordered** (monotonic `seq`) and why undo *appends* rather than *deletes*: reversibility and append-only are compatible precisely because "undo" is a new forward entry, preserving #4's chain. **This is the key design insight to preserve through review.**
- Seed ships `Reversal::None` everywhere; the engine, the inverse-capture, and the snapshot store are goal #2's later sub-projects.

### 8.3 Goal #4 — Verification (what's tractable for Kani/Miri)

- **`sha256.rs`** — fixed-size buffers, no allocation in the compression function, pure integer arithmetic: a strong **Kani** target. Verify (a) it matches the known SHA-256 test vectors (host `cargo test`), and (b) Kani-bounded properties: padding length arithmetic never overflows, the message-schedule index stays in range, output is always 32 bytes.
- **The chain invariant** — `verify_chain()` is the spec's central property: *for all i>0, `records[i].entry_hash == sha256(records[i-1].entry_hash ‖ encode(records[i].body))`, and `records[0]` links to genesis `[0;32]`*. Express as a **Kani harness over a bounded number of records** (e.g. ≤4): appending then verifying always succeeds; mutating any byte of any record's body makes `verify_chain` fail at that record. This is small and decidable — exactly the "small enough to verify" goal.
- **The codec** — `encode` then `decode` round-trips (a **Miri**-clean, **Kani**-bounded property), and `decode` never panics / never reads out of bounds on arbitrary input (reuse the `fs.rs` deserialiser-hardening test pattern, which already proves truncation/bad-tag/over-depth rejection).
- **The append-only invariant** is a *type-level* property (no mutate/delete API) reinforced by a test that the public surface exposes no `&mut AuditRecord` — partly a review/clippy concern, partly a doc-test.

## 9. Integration points in current code (where to emit the first events)

These are the *exact* call sites to wire, all in `crates/kernel` (all safe):

1. **Boot** — `kernel/crates/kernel/src/lib.rs::kmain` (after `memory::init_and_prove`, alongside `fs::prove_persistence`): construct the global `AuditLog` via `AuditLog::boot()` and append one `Principal::Kernel / Action::Boot` record ("sentinelos boot, version X"). This makes the log non-empty and exercises load/verify on every boot.
2. **Shell commands** — `kernel/crates/kernel/src/shell.rs::execute` (the `match cmd` at line ~313): append a `Principal::Shell / Action::Command` record with `target = cmd`, `summary = rest` (bounded). One emit at the top of `execute` covers every command uniformly.
3. **Filesystem mutations** — `kernel/crates/kernel/src/fs.rs`: the three mutating ops `mkdir` (line ~359), `write_file` (~378), `remove` (~403). Emit `Principal::FileSystem / Action::FsCreate|FsWrite|FsRemove` with `target = path`. **Design note:** `fs.rs` is a self-contained module that today knows nothing of the log; rather than make `fs.rs` depend on `security`, prefer emitting from the **shell's fs command wrappers** (`cmd_mkdir`/`cmd_write`/`cmd_rm`, lines ~603/616/634) where the principal is unambiguously `Shell`, *and* emit from `fs.rs` itself only once a non-shell caller exists. **Open question for `kernel-reviewer`:** emit at the `fs.rs` op (captures *all* callers, future-proof for agents, but couples `fs`→`security`) vs. at the shell wrapper (clean layering now, misses non-shell writers). Spec leans: emit at the **shell wrapper for the seed**, move into `fs.rs` when a second caller (agent/process) appears — and at that point the `Principal` is passed *in* by the caller, never assumed.
4. **App spawn/close** — `kernel/crates/kernel/src/wm.rs::log_spawn` (line ~853) and `log_close` (~861). **Decision: the audit log subsumes `log_spawn`.** Today `log_spawn`/`log_close` write a one-line serial string (`"[wm] spawned <label>"`). The seed keeps that serial line (it's a useful boot trace) **and** appends a `Principal::WindowManager / Action::AppSpawn` record (`target = kind.label()`), so `log_spawn` becomes the *first real producer* feeding the audit log. This is the cleanest demonstration that "structural events already logged informally" graduate to "first-class auditable events."

## 10. Acceptance criteria

1. `cargo xtask run` boots with the audit log armed; serial shows the log loaded/seeded (mirroring `[fs] …` lines) and at least the `Action::Boot` record present.
2. Running shell commands and `mkdir`/`write`/`rm` and spawning an app each produce audit records (visible via the `audit` command / Audit app, §11).
3. `verify_chain()` returns `Ok(())` on a clean log; a unit test that flips a byte of a record makes it return `Err(ChainError { at_seq })` at that record.
4. The log **persists across reboot**: a record written on boot N is present and chain-valid on boot N+1 (a QEMU two-boot proof, mirroring `fs::prove_persistence`).
5. `crates/hal` is **unchanged** — no new module, no new `unsafe`, no new `hal-tcb.md` row. `crates/kernel` still compiles with `#![forbid(unsafe_code)]`.
6. SHA-256 matches the published NIST test vectors (host `cargo test`).
7. Builds clean with `-D warnings` + `cargo clippy` on **stable**; no nightly, no `-Z build-std`.

## 11. Testing strategy

- **Hash-chain unit tests** (`sha256.rs` + `audit.rs`, host `cargo test`): SHA-256 NIST vectors; `append` then `verify_chain` is `Ok`; flipping any byte of any record's body → `Err(ChainError{at_seq})` at that record; the genesis record links to `[0;32]`.
- **Append-only invariant**: a compile-level/doc test asserting the public API exposes no mutate/delete and no `&mut AuditRecord` (clippy + review backstop, plus a doc-test).
- **Persistence round-trip** (host `cargo test`, mirroring `fs.rs`'s `serialise_roundtrips_*`): encode a log → decode → structurally identical and chain-valid; truncated payload → `None`; bad tag → `None`; oversized `payload_len`/record count → rejected before alloc; CRC mismatch → rejected.
- **A viewer**: add an `audit` shell command (`audit` = list recent records, `audit verify` = run `verify_chain` and report `Ok`/`at_seq`) wired into `shell.rs::execute`'s `match cmd` and listed in `cmd_help`. **And/or** an **Audit app**: a new `AppKind::Audit` variant (`crates/kernel/src/app/audit.rs`) implementing the `App` trait — a read-only, self-refreshing panel like `SystemPanel`/`Net`, appearing automatically in the launcher via `AppKind::ALL`. Seed ships the `audit` shell command (cheaper); the Audit app is a fast follow.
- **QEMU boot proof**: extend the `xtask` harness (the `serial.log` end-marker poll, `END_MARKER = "boot-bringup-ok"` pattern in `kernel/xtask/src/main.rs`): assert an `[audit] log ready (N records)` line on first boot and an `[audit] chain verified ok` line, mirroring how `fs::prove_persistence` proves storage. A second boot proves persistence + cross-boot chain validity.

## 12. Open questions

- **Hash cost vs. tamper-evidence** (§4 open question): confirm SHA-256-per-append is acceptable (appends are human-rate). → `kernel-reviewer` / `security-engineer`.
- **Tamper claim wording** (§3-hash, §6.4): exact honest phrasing for "evidence not prevention" and whether to ship a head-hash anchor or signing in the *next* milestone. → `security-engineer`.
- **Global ownership of the log** (§6.3): safe global cell vs. borrow-threading. → `kernel-reviewer`.
- **Emit site for fs mutations** (§9.3): `fs.rs` op vs. shell wrapper for the seed. → `kernel-reviewer`.
- **`security/` → `crates/security` promotion trigger** (§5.2) and the shared `serde`-free codec extraction from `fs.rs`. → architecture review when component #2 lands.
- **`sentinel-core` `no_std` port** (§7) as the future producer path. → separate architecture task.
- **Log capacity / rotation** when the on-disk region fills (out of seed scope, but the superblock should reserve a version/flags byte now so rotation is forward-compatible).

## 13. Build sequence (implementation plan → agent team)

> Hand-off: **do not begin implementation from this doc until §12 hash-cost + global-ownership questions are confirmed by `kernel-reviewer`/`security-engineer`.** Then, in order:

1. **kernel-engineer:** `crates/kernel/src/security/sha256.rs` — hand-rolled SHA-256 (pure safe Rust, no alloc in the compression fn), with NIST test-vector unit tests. *(Foundation; nothing else links without it.)*
2. **kernel-engineer:** `crates/kernel/src/security/audit.rs` — `AuditRecord`/`Principal`/`Action`/`Reversal`/`ChainError`/`AuditLog`; the append-only API (`append`/`verify_chain`/`iter`); the private `disk` codec submodule (reusing `fs.rs`'s CRC + bounded-read discipline); host unit tests for chain + round-trip + hardening. `mod.rs` + `pub mod security;` in `lib.rs`.
3. **kernel-engineer:** global log ownership (per the §6.3 decision) + the `AuditLog::boot()` call in `kmain`, and the emit sites: `shell.rs::execute` (commands), the shell fs-command wrappers (fs mutations), `wm.rs::log_spawn`/`log_close` (app spawn/close — subsuming the existing serial line).
4. **kernel-engineer:** the `audit` / `audit verify` shell command in `shell.rs` (+ `cmd_help` entry); optionally the `AppKind::Audit` Audit app (`app/audit.rs`) as a fast follow.
5. **test-engineer:** extend `kernel/xtask` with the audit boot proof (`[audit] log ready`, `[audit] chain verified ok`) and a two-boot persistence + cross-boot chain-validity check; keep the existing boot test green.
6. **verification-engineer:** Kani harnesses for `sha256` (bounds/padding) and the bounded chain invariant (≤4 records); Miri over the codec round-trip; confirm no new `unsafe` anywhere → the verification gate stays green.
7. **kernel-reviewer:** adversarial review — confirm **zero TCB growth**, the append-only invariant holds at the type level, the honest tamper claim is not overstated, and the `fs`/`security` layering decision. Approve.
8. **security-engineer:** sign off on the hash choice + the "evidence not prevention" claim, and scope the deferred signing/anchoring milestone.
