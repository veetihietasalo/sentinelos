//! The kernel-native, append-only, hash-chained **audit log** — the first
//! component of SentinelOS's security subsystem.
//!
//! Implements the seed defined in
//! `docs/specs/2026-06-04-audit-log-and-agent-native-architecture.md`. Every
//! security-relevant kernel action (a boot, a shell command, a filesystem
//! mutation, an app spawn/close) is recorded as an immutable [`AuditRecord`]
//! carrying a monotonic [`Seq`], a PIT-tick timestamp, the acting [`Principal`],
//! an [`Action`]/target/summary, and a SHA-256 **chain hash**
//! `entry_hash = SHA256(prev_hash ‖ encode(record_body))`.
//!
//! This module carries the crate's `#![forbid(unsafe_code)]`; it adds **zero**
//! new `unsafe` and grows the TCB by not one line (spec §5.1). All disk access is
//! delegated to the safe [`hal::ata`] block API, the timestamp to
//! [`hal::pit::ticks`], and shared global state lives behind the project's only
//! sanctioned interior-mutability primitive, [`hal::mm::SpinMutex`].
//!
//! # What "append-only" does and does not mean (honest framing)
//!
//! * **In RAM, this boot:** append-only **by construction**. The public API
//!   exposes [`AuditLog::append`], [`AuditLog::verify_chain`], and read-only
//!   iteration — and *no* method to mutate or delete a record, and never hands
//!   out `&mut AuditRecord`. The running kernel therefore cannot rewrite history.
//! * **On disk, CRC-32:** detects **accidental** corruption (bit-rot, a partial
//!   write) cheaply on load, before any SHA work — exactly as `kernel::fs` does.
//! * **On disk, SHA-256 chain:** detects **in-place edits and naive rewrites**
//!   *relative to a trusted reference* (an out-of-band head hash). This is
//!   tamper-**EVIDENCE**, not tamper-**PREVENTION**: a privileged writer who knows
//!   the chain rule can recompute a self-consistent chain from any tampered point
//!   to the head, and nothing here stops a disk-level rewrite. The seed ships
//!   neither a signature over the head nor an off-box anchor; those are the named
//!   upgrade path (spec §3-hash, §6.4). **Do not claim prevention.**
//!
//! # Resolved design decisions (spec §12 open questions)
//!
//! * **Global ownership (spec §6.3):** the single kernel-global log lives in a
//!   `static AUDIT_LOG: SpinMutex<AuditLog>` initialised with `AuditLog::new()`
//!   (both `SpinMutex::new` and `Vec::new` are `const`, so this is
//!   const-constructible). This mirrors how `hal::mm` holds the frame
//!   allocator/heap and how `net/mod.rs` holds global stack state — the
//!   established kernel pattern — rather than borrow-threading a `&mut AuditLog`
//!   through every emit site (`fs`, `shell`, `wm`).
//! * **Hash (spec §4):** SHA-256, hand-rolled in pure safe Rust ([`super::sha256`]).
//! * **fs-mutation emit site (spec §9.3):** for the seed, emit at the *shell*
//!   wrappers where the principal is unambiguously [`Principal::Shell`]; move into
//!   `fs.rs` (with the principal passed *in*) when a non-shell caller appears.

use alloc::string::String;
use alloc::vec::Vec;

use hal::mm::SpinMutex;

use super::sha256;

/// A monotonic, gap-free sequence number identifying a record's position in the
/// log. Genesis is `0`; never reused, never decreases.
pub type Seq = u64;

/// The genesis predecessor hash: the chain's first record links to all-zero.
const GENESIS_HASH: [u8; 32] = [0u8; 32];

/// Cap on a single [`BoundedStr`]'s byte length, mirroring `fs.rs`'s
/// `MAX_PAYLOAD`/`MAX_DEPTH` discipline: a log entry can never balloon the heap or
/// a sector budget, and logging an event can never fail the action it records
/// (over-long input is truncated with a marker, not rejected).
const MAX_STR_LEN: usize = 256;

/// The ASCII marker appended when a [`BoundedStr`] is truncated, so a reader can
/// tell a clipped field from a naturally short one.
const TRUNC_MARKER: &str = "...[truncated]";

/// Who performed the action.
///
/// **EXTENSIBLE** (`#[non_exhaustive]`): today only *kernel-internal* actors
/// exist, because the single-core kernel has no scheduler/syscalls/userland and
/// thus no real agents or processes. The enum is *shaped* so an `Agent`/`Process`
/// variant drops in for north-star goal #1 without changing the record layout: it
/// is encoded as a `u8` tag (plus a `u32` id payload for variants that carry one),
/// so adding a variant is forward-only. See the reserved tags in [`disk`].
///
/// **Invariant for goal #1 (documented now so it is not violated later):** when a
/// scheduler/process model lands, the principal is stamped by the kernel from the
/// *current actor* at the syscall boundary — the log never trusts a caller-supplied
/// principal.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Principal {
    /// The kernel itself (boot, self-tests, the log reporting on itself).
    Kernel,
    /// The interactive shell acting on a user's typed command line.
    Shell,
    /// The in-kernel filesystem performing a mutation.
    FileSystem,
    /// The window manager / launcher spawning or closing an app window.
    WindowManager,
    // --- reserved for goal #1 (not encoded yet; tags 4/5 are held in `disk`) ---
    // Agent { id: u32 },     // an autonomous agent principal (bounded capability holder)
    // Process { pid: u32 },  // a future userland process
}

/// What kind of action was recorded.
///
/// Coarse, stable verbs; the `target`/`summary` carry the specifics. Encoded as a
/// `u8` tag and **EXTENSIBLE** (`#[non_exhaustive]`) the same forward-only way as
/// [`Principal`]. The reserved goal-#1 capability verbs are documented here and
/// hold tags `100+` in [`disk`].
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// The kernel/a subsystem came up.
    Boot,
    /// A shell command was executed.
    Command,
    /// A directory or new file was created (`mkdir` / new `write`).
    FsCreate,
    /// File content was written/overwritten.
    FsWrite,
    /// A file/directory was removed.
    FsRemove,
    /// A window/app was launched.
    AppSpawn,
    /// A window/app was closed.
    AppClose,
    /// The security subsystem reporting on itself (e.g. a chain-break detected on
    /// load, or a boot self-check result).
    SecurityEvent,
    // --- reserved for goal #1 ---
    // CapabilityGrant / CapabilityDeny / CapabilityRevoke
}

/// The reversibility hook for north-star goal #2 (the log as the undo journal).
///
/// **EXTENSIBLE** (`#[non_exhaustive]`). The seed only ever constructs
/// [`Reversal::None`], encoded as a single tag byte (`0`), so the on-disk shape is
/// fixed now and the future undo engine is purely additive — it will add
/// `Inverse { .. }` / `SnapshotRef(u64)` variants without reshaping the record
/// (spec §8.2). Undo *appends* a new forward record rather than rewriting history,
/// which is precisely why append-only and reversibility are compatible.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reversal {
    /// No inverse captured: the record is informational/irreversible (the only
    /// variant in the seed).
    None,
    // Inverse { kind: u8, blob: Vec<u8> },  // goal #2
    // SnapshotRef(u64),                     // goal #2
}

/// A length-bounded UTF-8 string field (`target` / `summary`).
///
/// Bounded to [`MAX_STR_LEN`] bytes so a single record can never balloon the
/// early-boot heap or a sector budget. Construction *truncates* over-long input
/// (appending [`TRUNC_MARKER`]) rather than rejecting it, so logging an event can
/// never fail the action it records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundedStr(String);

impl BoundedStr {
    /// Build a bounded string from `s`, truncating on a char boundary to at most
    /// [`MAX_STR_LEN`] bytes (with a `...[truncated]` marker when clipped).
    #[must_use]
    pub fn new(s: &str) -> Self {
        if s.len() <= MAX_STR_LEN {
            return Self(String::from(s));
        }
        // Find the largest char boundary <= the budget that leaves room for the
        // marker, so the stored string is always valid UTF-8 and <= MAX_STR_LEN.
        let budget = MAX_STR_LEN - TRUNC_MARKER.len();
        let mut cut = budget.min(s.len());
        while cut > 0 && !s.is_char_boundary(cut) {
            cut -= 1;
        }
        let mut out = String::with_capacity(MAX_STR_LEN);
        out.push_str(&s[..cut]);
        out.push_str(TRUNC_MARKER);
        Self(out)
    }

    /// Borrow the field as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One immutable audit-log entry.
///
/// The field order here is the **canonical encoding order**; the [`entry_hash`]
/// is computed over an encoding of every field *before* it (the "body") chained
/// with the previous record's hash, and is itself never part of the hashed body —
/// it *is* the chain output for this record.
///
/// [`entry_hash`]: AuditRecord::entry_hash
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditRecord {
    /// Monotonic position in the log (`u64` LE on disk).
    pub seq: Seq,
    /// `hal::pit::ticks()` sampled at append time (`u64` LE on disk).
    pub tick: u64,
    /// Who acted (`u8` tag on disk, plus a future id payload).
    pub principal: Principal,
    /// What kind of action (`u8` tag on disk).
    pub action: Action,
    /// The object acted on (e.g. `/home/notes.txt`, `mkdir`, `Terminal`).
    pub target: BoundedStr,
    /// A compact parameter/result note.
    pub summary: BoundedStr,
    /// The reversibility hook (always [`Reversal::None`] in the seed).
    pub reversal: Reversal,
    /// `SHA256(prev_hash ‖ encode(body))` — the chain link for this record.
    pub entry_hash: [u8; 32],
}

impl AuditRecord {
    /// Encode this record's **body** (every field except `entry_hash`) into `out`,
    /// in canonical order. This is exactly the byte string the chain hash is
    /// computed over, so it must be deterministic and stable.
    fn encode_body(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.seq.to_le_bytes());
        out.extend_from_slice(&self.tick.to_le_bytes());
        out.push(disk::principal_tag(self.principal));
        // (Reserved: a future Agent/Process variant appends its u32 id here.)
        out.push(disk::action_tag(self.action));
        disk::encode_str(self.target.as_str(), out);
        disk::encode_str(self.summary.as_str(), out);
        out.push(disk::reversal_tag(self.reversal));
    }

    /// The body bytes as a fresh `Vec` (used by hashing and verification).
    fn body_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode_body(&mut buf);
        buf
    }
}

/// The integrity-check failure: the chain broke at record [`at_seq`].
///
/// [`at_seq`]: ChainError::at_seq
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainError {
    /// The `seq` of the first record whose `entry_hash` failed to re-link.
    pub at_seq: Seq,
}

/// The kernel's append-only, hash-chained audit log.
///
/// There is **deliberately no** method to mutate or delete a record:
/// append-only by construction. Construct the kernel-global instance via the
/// module-level [`boot`]/[`append`]/[`with_log`] helpers; this type is public so
/// it can be unit-tested directly on the host.
pub struct AuditLog {
    /// Records in append order; index 0 is genesis. Never edited or removed.
    records: Vec<AuditRecord>,
    /// The chain head: the `entry_hash` of the last record, or [`GENESIS_HASH`]
    /// when empty. A fast integrity anchor written to the superblock and
    /// re-checked against the decoded records on the next load (`disk::load`).
    head_hash: [u8; 32],
    /// The next sequence number to assign (== `records.len()` as a `u64`).
    next_seq: Seq,
    /// Whether a persistence-capable ATA disk was detected. When `false` (no disk,
    /// or host unit tests) the log is a pure in-RAM structure and never touches
    /// hardware — degrading gracefully exactly like `kernel::fs`.
    persistent: bool,
}

impl AuditLog {
    /// Create an empty, **non-persistent** in-RAM log. `const`, so it can back the
    /// `static AUDIT_LOG` (spec §6.3 resolution). Used by tests and as the base
    /// the [`AuditLog::boot`] constructor upgrades to persistent.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            records: Vec::new(),
            head_hash: GENESIS_HASH,
            next_seq: 0,
            persistent: false,
        }
    }

    /// Load the log from the primary ATA disk (validating CRC + chain) or start a
    /// fresh one. Mirrors [`crate::fs::FileSystem::seeded`]:
    ///
    /// 1. Probe the primary-master disk.
    /// 2. A disk holding a **valid** SentinelOS log image → load it and re-verify
    ///    the chain. A passing chain → restore those records (persistent).
    /// 3. A disk that is blank/unformatted in the log region → start an empty
    ///    persistent log (the first append will write the superblock).
    /// 4. No disk → an empty in-RAM log (boot never fails for lack of a disk).
    ///
    /// # Tamper/corruption → preserve the suspect image (forensics)
    ///
    /// A *failed* chain (tamper evidence) or a `Corrupt` load outcome
    /// (CRC/length/format/structure failure) means the on-disk bytes are
    /// untrustworthy *and* possible evidence. In that case `boot` does **not**
    /// start a fresh persistent log — that would `save()` over the suspect region
    /// and destroy the evidence. Instead it returns an empty, **non-persistent**
    /// in-RAM log (so no subsequent append ever calls `save()` and clobbers the
    /// suspect bytes) carrying a single in-RAM [`Action::SecurityEvent`] recording
    /// the detection, and emits a clear serial warning. The suspect image stays on
    /// disk for offline analysis until an operator deliberately re-seeds it
    /// (honesty: report and *preserve*, don't hide — spec §5.4).
    #[must_use]
    pub fn boot() -> Self {
        match disk::probe() {
            Some(geo) => match disk::load(geo) {
                disk::LoadOutcome::Loaded(records) => {
                    let log = Self::from_records(records, true);
                    if let Err(e) = log.verify_chain() {
                        // A loaded-but-broken chain is tamper evidence: do NOT
                        // trust it and do NOT overwrite the suspect on-disk bytes.
                        hal::serial::write_str("[audit] WARNING: on-disk chain broke at seq ");
                        hal::serial::write_dec(e.at_seq);
                        hal::serial::write_str("\n");
                        return Self::preserving_in_ram_log(
                            "on-disk chain verification failed on load (suspect image preserved)",
                        );
                    }
                    hal::serial::write_str("[audit] loaded log from disk (");
                    hal::serial::write_dec(log.records.len() as u64);
                    hal::serial::write_str(" records)\n");
                    log
                }
                disk::LoadOutcome::Empty => {
                    hal::serial::write_str("[audit] no valid log on disk; starting fresh\n");
                    Self::from_records(Vec::new(), true)
                }
                disk::LoadOutcome::Corrupt => {
                    // CRC/length/format/structure failure — the bytes are
                    // untrustworthy AND possible evidence; preserve them.
                    Self::preserving_in_ram_log(
                        "on-disk log failed CRC/format check on load (suspect image preserved)",
                    )
                }
            },
            None => {
                hal::serial::write_str("[audit] no ATA disk; in-memory audit log only\n");
                Self::from_records(Vec::new(), false)
            }
        }
    }

    /// Build the empty, **non-persistent** in-RAM log used when tamper or
    /// corruption is detected on load (see [`AuditLog::boot`]). Because it is
    /// non-persistent, no later [`append`] will `save()` and clobber the suspect
    /// on-disk region. Emits the standard preservation warning, then records the
    /// detection `summary` as the session's first (in-RAM only) security event.
    fn preserving_in_ram_log(summary: &str) -> Self {
        hal::serial::write_str(
            "[audit] WARNING: on-disk log tamper/corruption detected; \
             preserving suspect image, running in-RAM only\n",
        );
        // `persistent: false` is the load-bearing choice here — every append on
        // this session stays in RAM and never writes back over the evidence.
        let mut session = Self::from_records(Vec::new(), false);
        session.append(
            Principal::Kernel,
            Action::SecurityEvent,
            "audit-log",
            summary,
        );
        session
    }

    /// Build a log from already-decoded `records`, recomputing the head hash and
    /// next-seq from them. Does not itself verify the chain (callers do).
    fn from_records(records: Vec<AuditRecord>, persistent: bool) -> Self {
        let head_hash = records.last().map_or(GENESIS_HASH, |r| r.entry_hash);
        let next_seq = records.len() as Seq;
        Self {
            records,
            head_hash,
            next_seq,
            persistent,
        }
    }

    /// Append one record. Stamps `seq` (monotonic) and `tick`
    /// ([`hal::pit::ticks`]), computes the chain hash
    /// `SHA256(head_hash ‖ encode(body))`, persists best-effort (write-through,
    /// like `fs::save`), and returns the assigned [`Seq`].
    ///
    /// **This is the only mutating method.** It cannot fail the caller's action: a
    /// disk error is logged and swallowed, so the in-RAM log stays authoritative
    /// and logging an event never breaks the event being logged.
    pub fn append(
        &mut self,
        principal: Principal,
        action: Action,
        target: &str,
        summary: &str,
    ) -> Seq {
        let seq = self.next_seq;
        let mut record = AuditRecord {
            seq,
            tick: hal::pit::ticks(),
            principal,
            action,
            target: BoundedStr::new(target),
            summary: BoundedStr::new(summary),
            reversal: Reversal::None,
            entry_hash: GENESIS_HASH,
        };

        // entry_hash = SHA256(prev_head ‖ encode(body)).
        let body = record.body_bytes();
        record.entry_hash = sha256::hash_two(&self.head_hash, &body);

        self.head_hash = record.entry_hash;
        self.next_seq += 1;
        self.records.push(record);

        self.save();
        seq
    }

    /// Re-walk the chain from genesis. `Ok(())` if every `entry_hash` re-links
    /// (`records[0]` links to [`GENESIS_HASH`] and each subsequent record links to
    /// its predecessor's hash); otherwise `Err(ChainError { at_seq })` naming the
    /// first record that fails.
    pub fn verify_chain(&self) -> Result<(), ChainError> {
        let mut prev = GENESIS_HASH;
        for record in &self.records {
            let body = record.body_bytes();
            let expected = sha256::hash_two(&prev, &body);
            if expected != record.entry_hash {
                return Err(ChainError { at_seq: record.seq });
            }
            prev = record.entry_hash;
        }
        Ok(())
    }

    /// Read-only iteration over records, oldest-first. Hands out `&AuditRecord`
    /// only — never `&mut` — so callers cannot edit history.
    pub fn iter(&self) -> impl Iterator<Item = &AuditRecord> {
        self.records.iter()
    }

    /// Read-only iteration over records, newest-first.
    pub fn iter_rev(&self) -> impl Iterator<Item = &AuditRecord> {
        self.records.iter().rev()
    }

    /// The number of records in the log.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// `true` when the log holds no records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// The current chain head hash (the last record's `entry_hash`, or all-zero
    /// when empty). A fast integrity anchor; honest note: still rewritable on disk.
    #[must_use]
    pub fn head_hash(&self) -> [u8; 32] {
        self.head_hash
    }

    /// Whether this log is backed by a persistence-capable ATA disk.
    #[must_use]
    pub fn is_persistent(&self) -> bool {
        self.persistent
    }

    /// Serialise the whole log and write it through to disk (best-effort, a no-op
    /// without a disk). A disk write error is logged and swallowed — the in-RAM
    /// log remains authoritative (mirrors `fs::save`).
    fn save(&self) {
        if !self.persistent {
            return;
        }
        if disk::save(&self.records, &self.head_hash).is_err() {
            hal::serial::write_str("[audit] WARNING: disk save failed (in-memory copy kept)\n");
        }
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

// ── kernel-global instance (spec §6.3 resolution) ──────────────────────────────

/// The single kernel-global audit log, behind the project's sanctioned
/// interior-mutability primitive ([`hal::mm::SpinMutex`]).
///
/// `SpinMutex::new` and `AuditLog::new` are both `const`, so this is
/// const-constructible without a lazy init. It starts empty + non-persistent;
/// [`init`] replaces it with [`AuditLog::boot`]'s loaded/verified contents at
/// boot. Mirrors how `hal::mm` holds the frame allocator/heap.
static AUDIT_LOG: SpinMutex<AuditLog> = SpinMutex::new(AuditLog::new());

/// Bring up the global audit log: construct it via [`AuditLog::boot`] (probe disk
/// → load + verify, or start fresh) and install it, then append the boot record.
///
/// Call once in `kmain`, after `fs::prove_persistence` (so the disk is known
/// good) and before the banner/idle loop. Emits the spec's `[audit] log ready`
/// and `[audit] chain verified` serial lines (acceptance §10.1, §11 QEMU proof).
pub fn init() {
    let booted = AuditLog::boot();
    {
        let mut log = AUDIT_LOG.lock();
        *log = booted;
    }

    // The first producer: a boot record (spec §9.1). Makes the log non-empty and
    // exercises append on every boot.
    let mut summary = String::from("sentinelos boot, version ");
    summary.push_str(env!("CARGO_PKG_VERSION"));
    append(Principal::Kernel, Action::Boot, "kmain", &summary);

    // One-line readiness + verification serial proof (xtask asserts these).
    let (count, verify) = with_log(|log| (log.len(), log.verify_chain()));
    hal::serial::write_str("[audit] log ready (");
    hal::serial::write_dec(count as u64);
    hal::serial::write_str(" records)\n");
    match verify {
        Ok(()) => hal::serial::write_str("[audit] chain verified ok\n"),
        Err(e) => {
            hal::serial::write_str("[audit] chain verify FAILED at seq ");
            hal::serial::write_dec(e.at_seq);
            hal::serial::write_str("\n");
        }
    }
}

/// Append a record to the kernel-global log. The thin, lock-acquiring entry point
/// every emit site (`shell`, `fs` wrappers, `wm`) calls. Returns the assigned
/// [`Seq`]. Never fails the caller (see [`AuditLog::append`]).
pub fn append(principal: Principal, action: Action, target: &str, summary: &str) -> Seq {
    AUDIT_LOG.lock().append(principal, action, target, summary)
}

/// Run `f` with shared access to the global log (e.g. the `audit` shell command's
/// read/verify path). Holds the lock for the closure's duration.
pub fn with_log<R>(f: impl FnOnce(&AuditLog) -> R) -> R {
    let guard = AUDIT_LOG.lock();
    f(&guard)
}

/// On-disk persistence for the audit log: serialise records to a byte image and
/// read/write it across the primary ATA disk via the safe [`hal::ata`] block API.
///
/// Mirrors `kernel::fs::disk` in shape and hardening (a `MAX_PAYLOAD` cap, bounded
/// `take_u32`/`take_slice`, `Option`-returning deserialisers, reuse of the same
/// CRC-32), and stays `#![forbid(unsafe_code)]` — all privileged port I/O lives in
/// the `hal::ata` TCB.
///
/// # Why a fixed high LBA offset (disk-safety, critical)
///
/// The audit log persists to the **same physical 16 MiB ATA image** as
/// `kernel::fs`, so it MUST occupy a non-overlapping region. `fs` lives at LBA 0
/// (its superblock) with a payload capped at `fs::disk::MAX_PAYLOAD` = 64 KiB =
/// 128 sectors, so `fs` never reaches beyond ~LBA 129. We place the audit log's
/// superblock at a fixed high offset, [`BASE_LBA`] = 16384 (the 8 MiB midpoint of
/// the 32768-sector image): ~8 MiB clear of the `fs` region below and ~8 MiB clear
/// of the disk end above. It cannot collide with `fs` for any payload either side
/// permits. The reader tolerates an unformatted region (bad/zero magic → treat as
/// empty), degrading gracefully exactly like `fs.rs`.
mod disk {
    use super::{Action, AuditRecord, BoundedStr, Principal, Reversal};
    use alloc::string::String;
    use alloc::vec;
    use alloc::vec::Vec;

    /// The 8-byte magic identifying a SentinelOS audit-log image (`"SNTLLOG1"`).
    const MAGIC: &[u8; 8] = b"SNTLLOG1";

    /// Current on-disk superblock **format version** (spec §12), written at offset
    /// `[48]` and validated on load. Reserved now so the format can evolve
    /// (rotation/compaction, a signed head, an extended superblock) in a
    /// forward-compatible way: a future reader can branch on this byte. The on-disk
    /// format is *unreleased*, so there is no migration — an image carrying any
    /// other version (including the all-zero of a pre-version image) is treated as
    /// [`LoadOutcome::Empty`] and re-seeded, the graceful path (it avoids raising a
    /// false tamper alarm for what is only a format bump). Offsets `[0..48)` are
    /// unchanged, so magic/len/crc/head_hash still decode identically.
    const FORMAT_VERSION: u8 = 1;

    /// Superblock byte offset of the [`FORMAT_VERSION`] field (in the previously
    /// reserved `[48..512)` region; `[49]` stays reserved for future flags).
    const VERSION_OFF: usize = 48;

    /// Fixed starting LBA of the audit-log superblock — the 8 MiB midpoint of the
    /// 16 MiB (32768-sector) image. Chosen to sit far above `kernel::fs`'s region
    /// (LBA 0..~129) and far below the disk end (32768), so the two on-disk
    /// structures can never overlap. See the module doc for the full rationale.
    const BASE_LBA: u32 = 16_384;

    /// Maximum payload we will read/write, bounding buffers allocated from a
    /// possibly-garbage superblock length. 256 KiB comfortably holds thousands of
    /// small records while keeping the log region (1 superblock + <=512 payload
    /// sectors) well within the disk and clear of the `fs` region.
    const MAX_PAYLOAD: usize = 256 * 1024;

    /// Maximum number of records the deserialiser will reconstruct from a
    /// CRC-passing-but-hostile payload, so a corrupt count cannot exhaust the heap.
    const MAX_RECORDS: usize = 65_536;

    /// Maximum encoded length of a single record, an extra guard against a corrupt
    /// length field (a record is fixed overhead + two <=256-byte bounded strings).
    const MAX_RECORD_LEN: usize = 1024;

    // ── encoding tags (forward-compatible: reserved tags are documented) ─────────

    /// `u8` tag for a [`Principal`]. Tags `4`/`5` are RESERVED for the goal-#1
    /// `Agent`/`Process` variants (which will carry a trailing `u32` id), so the
    /// on-disk format is forward-compatible.
    pub(super) fn principal_tag(p: Principal) -> u8 {
        match p {
            Principal::Kernel => 0,
            Principal::Shell => 1,
            Principal::FileSystem => 2,
            Principal::WindowManager => 3,
            // 4 => Agent, 5 => Process (reserved)
        }
    }

    /// Decode a [`Principal`] tag, or `None` for an unknown/reserved tag.
    fn decode_principal(tag: u8) -> Option<Principal> {
        match tag {
            0 => Some(Principal::Kernel),
            1 => Some(Principal::Shell),
            2 => Some(Principal::FileSystem),
            3 => Some(Principal::WindowManager),
            _ => None,
        }
    }

    /// `u8` tag for an [`Action`]. Tags `100+` are RESERVED for the goal-#1
    /// capability verbs (`CapabilityGrant`/`Deny`/`Revoke`).
    pub(super) fn action_tag(a: Action) -> u8 {
        match a {
            Action::Boot => 0,
            Action::Command => 1,
            Action::FsCreate => 2,
            Action::FsWrite => 3,
            Action::FsRemove => 4,
            Action::AppSpawn => 5,
            Action::AppClose => 6,
            Action::SecurityEvent => 7,
        }
    }

    /// Decode an [`Action`] tag, or `None` for an unknown/reserved tag.
    fn decode_action(tag: u8) -> Option<Action> {
        match tag {
            0 => Some(Action::Boot),
            1 => Some(Action::Command),
            2 => Some(Action::FsCreate),
            3 => Some(Action::FsWrite),
            4 => Some(Action::FsRemove),
            5 => Some(Action::AppSpawn),
            6 => Some(Action::AppClose),
            7 => Some(Action::SecurityEvent),
            _ => None,
        }
    }

    /// `u8` tag for a [`Reversal`] (always `0 = None` in the seed).
    pub(super) fn reversal_tag(r: Reversal) -> u8 {
        match r {
            Reversal::None => 0,
        }
    }

    /// Decode a [`Reversal`] tag, or `None` for an unknown/reserved tag.
    fn decode_reversal(tag: u8) -> Option<Reversal> {
        match tag {
            0 => Some(Reversal::None),
            _ => None,
        }
    }

    /// Encode a string field as `u32 LE len ‖ bytes` (same byte discipline as
    /// `fs.rs`). The `BoundedStr` cap guarantees `len <= MAX_STR_LEN`.
    pub(super) fn encode_str(s: &str, out: &mut Vec<u8>) {
        let bytes = s.as_bytes();
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(bytes);
    }

    /// Disk geometry discovered by [`probe`] — the addressable sector count, so we
    /// can bound writes against the real disk size.
    #[derive(Clone, Copy)]
    pub(super) struct Geometry {
        /// Total addressable 512-byte sectors on the disk.
        pub sectors: u32,
    }

    /// The result of a [`load`] attempt, distinguishing the three honest outcomes
    /// (spec §5.4): a valid image, an empty/unformatted region, or detected
    /// corruption.
    pub(super) enum LoadOutcome {
        /// A valid, CRC-passing image decoded into these records (chain still to
        /// be verified by the caller).
        Loaded(Vec<AuditRecord>),
        /// The region is blank/unformatted (no/zero magic): start a fresh log.
        Empty,
        /// The magic matched but the image failed CRC, length, or structural
        /// decoding: accidental corruption, report it.
        Corrupt,
    }

    /// Probe the primary ATA disk. Returns its geometry if a usable disk is
    /// attached, else `None`. Always `None` under `cfg(test)` so host unit tests
    /// never perform port I/O (mirrors `fs::disk::probe`).
    #[cfg(not(test))]
    pub(super) fn probe() -> Option<Geometry> {
        match hal::ata::identify() {
            Ok(info) => Some(Geometry {
                sectors: info.sectors,
            }),
            Err(_) => None,
        }
    }

    /// Test stub: no disk on the host, so the log stays purely in-memory.
    #[cfg(test)]
    pub(super) fn probe() -> Option<Geometry> {
        None
    }

    /// Test stub: never reached (host [`probe`] returns `None`, so `boot` never
    /// takes the load branch), but it must exist so the crate compiles under
    /// `cfg(test)`. Mirrors `fs::disk`'s real/stub split.
    #[cfg(test)]
    pub(super) fn load(_geo: Geometry) -> LoadOutcome {
        LoadOutcome::Empty
    }

    /// Test stub: a no-op success, so `save` compiles under `cfg(test)` without
    /// performing port I/O (the in-memory log is non-persistent in tests anyway).
    #[cfg(test)]
    pub(super) fn save(_records: &[AuditRecord], _head_hash: &[u8; 32]) -> Result<(), ()> {
        Ok(())
    }

    /// Load and deserialise the saved log from the audit region. Mirrors
    /// `fs::disk::load`'s hardening: bound the payload against [`MAX_PAYLOAD`] and
    /// the real disk geometry before allocating, validate CRC-32, then decode with
    /// bounded cursors. Tolerates an unformatted region (bad/zero magic →
    /// [`LoadOutcome::Empty`]) so a blank disk degrades gracefully.
    #[cfg(not(test))]
    pub(super) fn load(geo: Geometry) -> LoadOutcome {
        use hal::ata::{self, SECTOR_SIZE};

        // Need room for at least the superblock at BASE_LBA.
        if geo.sectors <= BASE_LBA {
            return LoadOutcome::Empty;
        }

        // Read the superblock (one sector at BASE_LBA).
        let mut sb = vec![0u8; SECTOR_SIZE];
        if ata::read_sectors(BASE_LBA, 1, &mut sb).is_err() {
            return LoadOutcome::Corrupt;
        }
        // An unformatted region (no magic / all-zero) is "empty", not "corrupt".
        if &sb[0..8] != MAGIC {
            return LoadOutcome::Empty;
        }

        // Format-version gate (spec §12). An image written by a *different* format
        // version (including the all-zero of a pre-version image) is not corrupt —
        // it is just a layout this build does not understand — so re-seed it
        // gracefully rather than raising a false tamper alarm.
        if sb[VERSION_OFF] != FORMAT_VERSION {
            return LoadOutcome::Empty;
        }

        let payload_len = read_u32(&sb[8..12]) as usize;
        let payload_crc = read_u32(&sb[12..16]);
        // The stored chain head (`head_hash`) is a cheap integrity anchor: after
        // decoding we re-check it against the records' actual head. Snapshot it now
        // while the superblock buffer is in scope.
        let mut stored_head = [0u8; 32];
        stored_head.copy_from_slice(&sb[16..48]);
        if payload_len == 0 {
            // No payload: the only consistent head is GENESIS. A non-genesis stored
            // head over an empty payload is a corrupt/forged superblock.
            return if stored_head == super::GENESIS_HASH {
                LoadOutcome::Empty
            } else {
                LoadOutcome::Corrupt
            };
        }
        if payload_len > MAX_PAYLOAD {
            return LoadOutcome::Corrupt;
        }

        // Bound sector addressing against the actual disk geometry.
        let sectors = payload_len.div_ceil(SECTOR_SIZE);
        // BASE_LBA + 1 (superblock) + payload sectors must fit on the disk.
        let end_lba = (BASE_LBA as u64) + 1 + sectors as u64;
        if end_lba > geo.sectors as u64 {
            return LoadOutcome::Corrupt;
        }

        let mut buf = vec![0u8; sectors * SECTOR_SIZE];
        let mut done = 0usize;
        while done < sectors {
            let chunk = (sectors - done).min(256);
            let off = done * SECTOR_SIZE;
            if ata::read_sectors(
                BASE_LBA + 1 + done as u32,
                chunk as u16,
                &mut buf[off..off + chunk * SECTOR_SIZE],
            )
            .is_err()
            {
                return LoadOutcome::Corrupt;
            }
            done += chunk;
        }

        let payload = &buf[..payload_len];
        if crc32(payload) != payload_crc {
            return LoadOutcome::Corrupt;
        }

        match deserialise_records(payload) {
            Some(records) => {
                // Cheap pre-check against the superblock's stored chain head: the
                // last decoded record's `entry_hash` (or GENESIS for an empty log)
                // must match the head written at save time. A mismatch means the
                // payload and its anchor disagree — treat it as corruption (which
                // the caller's `boot` then handles by preserving the suspect image,
                // not overwriting it). This makes the previously write-only
                // `head_hash` field meaningful without a full chain re-walk here
                // (the caller still does `verify_chain` on the loaded records).
                let actual_head = records.last().map_or(super::GENESIS_HASH, |r| r.entry_hash);
                if actual_head != stored_head {
                    return LoadOutcome::Corrupt;
                }
                LoadOutcome::Loaded(records)
            }
            None => LoadOutcome::Corrupt,
        }
    }

    /// Serialise `records` and write the image (superblock at [`BASE_LBA`] +
    /// payload after it) to the primary ATA disk. Returns `Err(())` on any disk
    /// error or if the image would exceed the disk (the caller logs + keeps the
    /// in-memory log). The `head_hash` is stored in the superblock as a fast
    /// integrity anchor (re-checked against the records by [`load`] on the next
    /// boot; honest note: still rewritable on disk by a privileged writer).
    #[cfg(not(test))]
    pub(super) fn save(records: &[AuditRecord], head_hash: &[u8; 32]) -> Result<(), ()> {
        use hal::ata::{self, SECTOR_SIZE};

        let geo = probe().ok_or(())?;

        let mut payload = Vec::new();
        serialise_records(records, &mut payload);
        if payload.len() > MAX_PAYLOAD {
            return Err(());
        }
        let crc = crc32(&payload);

        let payload_sectors = payload.len().div_ceil(SECTOR_SIZE).max(1);
        let total_sectors = 1 + payload_sectors; // superblock + payload

        // Refuse to write past the end of the disk.
        let end_lba = (BASE_LBA as u64) + total_sectors as u64;
        if end_lba > geo.sectors as u64 {
            return Err(());
        }

        let mut image = vec![0u8; total_sectors * SECTOR_SIZE];
        image[0..8].copy_from_slice(MAGIC);
        write_u32(&mut image[8..12], payload.len() as u32);
        write_u32(&mut image[12..16], crc);
        image[16..48].copy_from_slice(head_hash);
        // [48] = format version (spec §12); [49..512) stays reserved/zero.
        image[VERSION_OFF] = FORMAT_VERSION;
        image[SECTOR_SIZE..SECTOR_SIZE + payload.len()].copy_from_slice(&payload);

        let mut done = 0usize;
        while done < total_sectors {
            let chunk = (total_sectors - done).min(256);
            let off = done * SECTOR_SIZE;
            ata::write_sectors(
                BASE_LBA + done as u32,
                chunk as u16,
                &image[off..off + chunk * SECTOR_SIZE],
            )
            .map_err(|_| ())?;
            done += chunk;
        }
        Ok(())
    }

    // ── serialisation (pure; exercised by host unit tests) ───────────────────────

    /// Serialise a slice of records as `u32 LE count` followed by each record's
    /// `u32 LE encoded-len` framing + its bytes (body ‖ 32-byte entry_hash). The
    /// per-record length prefix lets the deserialiser bound each record.
    pub(super) fn serialise_records(records: &[AuditRecord], out: &mut Vec<u8>) {
        out.extend_from_slice(&(records.len() as u32).to_le_bytes());
        for record in records {
            let mut body = Vec::new();
            record.encode_body(&mut body);
            // record = body ‖ 32-byte entry_hash
            let total = body.len() + 32;
            out.extend_from_slice(&(total as u32).to_le_bytes());
            out.extend_from_slice(&body);
            out.extend_from_slice(&record.entry_hash);
        }
    }

    /// Deserialise a record payload. Returns `None` on any malformed/truncated
    /// input, an over-large count/length, an unknown tag, or trailing garbage —
    /// never panics, never reads out of bounds (same discipline as `fs.rs`).
    pub(super) fn deserialise_records(buf: &[u8]) -> Option<Vec<AuditRecord>> {
        let mut cursor = 0usize;
        let count = take_u32(buf, &mut cursor)? as usize;
        if count > MAX_RECORDS {
            return None;
        }
        let mut records = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            let rec_len = take_u32(buf, &mut cursor)? as usize;
            // A record is at minimum its 32-byte entry_hash plus a non-empty body;
            // anything outside `[32, MAX_RECORD_LEN]` is a corrupt length field.
            if !(32..=MAX_RECORD_LEN).contains(&rec_len) {
                return None;
            }
            let rec_bytes = take_slice(buf, &mut cursor, rec_len)?;
            let record = decode_record(rec_bytes)?;
            records.push(record);
        }
        // Reject trailing garbage after the declared record count.
        if cursor != buf.len() {
            return None;
        }
        Some(records)
    }

    /// Decode one record from its exact framed bytes (`body ‖ 32-byte hash`).
    fn decode_record(bytes: &[u8]) -> Option<AuditRecord> {
        let mut c = 0usize;
        let seq = take_u64(bytes, &mut c)?;
        let tick = take_u64(bytes, &mut c)?;
        let principal = decode_principal(*bytes.get(c)?)?;
        c += 1;
        let action = decode_action(*bytes.get(c)?)?;
        c += 1;
        let target = decode_str(bytes, &mut c)?;
        let summary = decode_str(bytes, &mut c)?;
        let reversal = decode_reversal(*bytes.get(c)?)?;
        c += 1;
        // The remaining bytes must be exactly the 32-byte entry_hash.
        let hash_bytes = take_slice(bytes, &mut c, 32)?;
        if c != bytes.len() {
            return None;
        }
        let mut entry_hash = [0u8; 32];
        entry_hash.copy_from_slice(hash_bytes);

        Some(AuditRecord {
            seq,
            tick,
            principal,
            action,
            target,
            summary,
            reversal,
            entry_hash,
        })
    }

    /// Decode a `u32 LE len ‖ bytes` string field into a [`BoundedStr`]. Rejects a
    /// length over the bounded cap or invalid UTF-8.
    fn decode_str(buf: &[u8], cursor: &mut usize) -> Option<BoundedStr> {
        let len = take_u32(buf, cursor)? as usize;
        if len > super::MAX_STR_LEN {
            return None;
        }
        let bytes = take_slice(buf, cursor, len)?;
        let s = core::str::from_utf8(bytes).ok()?;
        // The bytes are already within the cap, so `new` copies them verbatim.
        Some(BoundedStr(String::from(s)))
    }

    // ── bounded byte helpers (mirroring fs.rs) ───────────────────────────────────

    /// Read a little-endian `u32` from a 4-byte slice (caller guarantees length).
    fn read_u32(b: &[u8]) -> u32 {
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    }

    /// Write a little-endian `u32` into a 4-byte slice (caller guarantees length).
    fn write_u32(b: &mut [u8], v: u32) {
        b[..4].copy_from_slice(&v.to_le_bytes());
    }

    /// Take a little-endian `u32` at `*cursor`, advancing it; `None` if truncated.
    fn take_u32(buf: &[u8], cursor: &mut usize) -> Option<u32> {
        let bytes = take_slice(buf, cursor, 4)?;
        Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Take a little-endian `u64` at `*cursor`, advancing it; `None` if truncated.
    fn take_u64(buf: &[u8], cursor: &mut usize) -> Option<u64> {
        let bytes = take_slice(buf, cursor, 8)?;
        Some(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Borrow `len` bytes at `*cursor`, advancing it; `None` if out of bounds.
    fn take_slice<'a>(buf: &'a [u8], cursor: &mut usize, len: usize) -> Option<&'a [u8]> {
        let end = cursor.checked_add(len)?;
        let slice = buf.get(*cursor..end)?;
        *cursor = end;
        Some(slice)
    }

    /// A standard CRC-32 (IEEE 802.3, reflected, polynomial `0xEDB88320`) — the
    /// same algorithm as `fs::disk::crc32`, reused as the superblock integrity
    /// check. CRC detects accidental media corruption; the SHA-256 chain detects
    /// rewrites.
    pub(super) fn crc32(data: &[u8]) -> u32 {
        let mut crc: u32 = 0xFFFF_FFFF;
        for &byte in data {
            crc ^= byte as u32;
            for _ in 0..8 {
                let mask = (crc & 1).wrapping_neg();
                crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
            }
        }
        !crc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Append then verify always succeeds, and seq/tick/head advance correctly.
    #[test]
    fn append_then_verify_is_ok() {
        let mut log = AuditLog::new();
        assert!(log.is_empty());
        let s0 = log.append(Principal::Kernel, Action::Boot, "kmain", "boot v0");
        let s1 = log.append(Principal::Shell, Action::Command, "ls", "/home");
        let s2 = log.append(Principal::FileSystem, Action::FsWrite, "/a.txt", "5 bytes");
        assert_eq!((s0, s1, s2), (0, 1, 2));
        assert_eq!(log.len(), 3);
        assert_eq!(log.verify_chain(), Ok(()));
        // The head hash is the last record's entry hash.
        assert_eq!(log.head_hash(), log.iter().last().unwrap().entry_hash);
    }

    /// The genesis (first) record links to the all-zero predecessor hash.
    #[test]
    fn genesis_links_to_zero() {
        let mut log = AuditLog::new();
        log.append(Principal::Kernel, Action::Boot, "kmain", "boot");
        let first = log.iter().next().unwrap();
        let body = first.body_bytes();
        assert_eq!(first.entry_hash, sha256::hash_two(&GENESIS_HASH, &body));
    }

    /// Flipping a byte of any record's BODY makes `verify_chain` fail at that
    /// record's seq (the central tamper-evidence property, spec §10.3).
    #[test]
    fn tampering_a_body_breaks_the_chain_at_that_seq() {
        let mut log = AuditLog::new();
        log.append(Principal::Kernel, Action::Boot, "kmain", "boot");
        log.append(Principal::Shell, Action::Command, "mkdir", "/x");
        log.append(Principal::WindowManager, Action::AppSpawn, "Terminal", "");
        assert_eq!(log.verify_chain(), Ok(()));

        // Tamper with record seq=1's target in place (no public API does this; we
        // reach into the private field to simulate a disk-level rewrite).
        log.records[1].target = BoundedStr::new("rmdir");
        match log.verify_chain() {
            Err(ChainError { at_seq }) => assert_eq!(at_seq, 1),
            Ok(()) => panic!("tampered chain must not verify"),
        }
    }

    /// Tampering with a record's stored `entry_hash` also breaks the chain there.
    #[test]
    fn tampering_an_entry_hash_breaks_the_chain() {
        let mut log = AuditLog::new();
        log.append(Principal::Kernel, Action::Boot, "k", "a");
        log.append(Principal::Shell, Action::Command, "b", "c");
        log.records[0].entry_hash[0] ^= 0xFF;
        assert_eq!(log.verify_chain(), Err(ChainError { at_seq: 0 }));
    }

    /// Over-long target/summary are truncated (with a marker), never rejected, so
    /// logging an event can never fail the action it records.
    #[test]
    fn bounded_str_truncates_long_input() {
        let long = "x".repeat(10_000);
        let b = BoundedStr::new(&long);
        assert!(b.as_str().len() <= MAX_STR_LEN);
        assert!(b.as_str().ends_with(TRUNC_MARKER));
    }

    /// A short string is stored verbatim (no marker).
    #[test]
    fn bounded_str_short_is_verbatim() {
        let b = BoundedStr::new("/home/notes.txt");
        assert_eq!(b.as_str(), "/home/notes.txt");
    }

    // ── persistence (de)serialiser round-trip + hardening, mirroring fs.rs ───────

    /// Encoding a log then decoding it reproduces it exactly and the chain still
    /// verifies (spec §11 persistence round-trip).
    #[test]
    fn serialise_roundtrips_and_chain_holds() {
        let mut log = AuditLog::new();
        log.append(Principal::Kernel, Action::Boot, "kmain", "boot v1");
        log.append(Principal::Shell, Action::Command, "write", "/a.txt hello");
        log.append(Principal::FileSystem, Action::FsCreate, "/dir", "");
        log.append(Principal::WindowManager, Action::AppClose, "Net", "closed");

        let mut bytes = Vec::new();
        disk::serialise_records(&log.records, &mut bytes);
        let restored = disk::deserialise_records(&bytes).expect("decode");

        assert_eq!(
            restored, log.records,
            "round-trip is structurally identical"
        );
        let restored_log = AuditLog::from_records(restored, false);
        assert_eq!(restored_log.verify_chain(), Ok(()));
        assert_eq!(restored_log.head_hash(), log.head_hash());
    }

    /// An empty log round-trips to an empty log.
    #[test]
    fn serialise_roundtrips_empty_log() {
        let log = AuditLog::new();
        let mut bytes = Vec::new();
        disk::serialise_records(&log.records, &mut bytes);
        let restored = disk::deserialise_records(&bytes).expect("decode");
        assert!(restored.is_empty());
    }

    /// A truncated payload decodes to `None` (no panic).
    #[test]
    fn deserialise_rejects_truncated_payload() {
        let mut log = AuditLog::new();
        log.append(Principal::Kernel, Action::Boot, "kmain", "boot");
        let mut bytes = Vec::new();
        disk::serialise_records(&log.records, &mut bytes);
        bytes.truncate(bytes.len() - 3);
        assert!(disk::deserialise_records(&bytes).is_none());
    }

    /// An unknown principal tag decodes to `None` (rejects a corrupt image).
    #[test]
    fn deserialise_rejects_bad_principal_tag() {
        let mut log = AuditLog::new();
        log.append(Principal::Kernel, Action::Boot, "kmain", "boot");
        let mut bytes = Vec::new();
        disk::serialise_records(&log.records, &mut bytes);
        // The principal tag sits right after count(4) + reclen(4) + seq(8) +
        // tick(8) = byte offset 24; poison it with a reserved/unknown value.
        bytes[24] = 0xFE;
        assert!(disk::deserialise_records(&bytes).is_none());
    }

    /// A declared record count beyond `MAX_RECORDS` is rejected before allocating.
    #[test]
    fn deserialise_rejects_oversized_count() {
        let mut bytes = Vec::new();
        // count = u32::MAX (far over MAX_RECORDS), no record bodies follow.
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(disk::deserialise_records(&bytes).is_none());
    }

    /// A per-record length beyond `MAX_RECORD_LEN` is rejected.
    #[test]
    fn deserialise_rejects_oversized_record_len() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u32.to_le_bytes()); // count = 1
        bytes.extend_from_slice(&100_000u32.to_le_bytes()); // rec_len huge
        assert!(disk::deserialise_records(&bytes).is_none());
    }

    /// Trailing garbage after the declared records is rejected.
    #[test]
    fn deserialise_rejects_trailing_garbage() {
        let mut log = AuditLog::new();
        log.append(Principal::Kernel, Action::Boot, "kmain", "boot");
        let mut bytes = Vec::new();
        disk::serialise_records(&log.records, &mut bytes);
        bytes.push(0xAB); // one extra byte
        assert!(disk::deserialise_records(&bytes).is_none());
    }

    /// CRC-32 matches the known IEEE check value (same algorithm as fs.rs), so the
    /// superblock integrity check behaves identically.
    #[test]
    fn crc32_known_vector() {
        assert_eq!(disk::crc32(b"123456789"), 0xCBF4_3926);
    }

    /// A large, varied log encodes/decodes and stays under the payload cap (a
    /// sanity check that real logs never spike the heap on load).
    #[test]
    fn many_records_roundtrip_under_cap() {
        let mut log = AuditLog::new();
        for i in 0..500u64 {
            let mut t = String::from("/file");
            let mut s = String::from("entry ");
            // Cheap unique-ish content without core::fmt.
            t.push((b'a' + (i % 26) as u8) as char);
            s.push((b'0' + (i % 10) as u8) as char);
            log.append(Principal::FileSystem, Action::FsWrite, &t, &s);
        }
        assert_eq!(log.verify_chain(), Ok(()));
        let mut bytes = Vec::new();
        disk::serialise_records(&log.records, &mut bytes);
        let restored = disk::deserialise_records(&bytes).expect("decode 500");
        assert_eq!(restored.len(), 500);
        assert_eq!(
            AuditLog::from_records(restored, false).verify_chain(),
            Ok(())
        );
    }
}
