//! The kernel's SentinelFS instance: the `sfs-commit` task, the `Sfs` lock,
//! and the FS-1a boot proof (spec §6, §8, §11).
//!
//! # Who touches what
//!
//! - **The device** belongs to the `sfs-commit` task alone: the task opens the
//!   [`AtaDevice`] itself (`IDENTIFY` is I/O too) and keeps it on its own
//!   stack, so no other thread can reach it — structurally, not by
//!   convention.
//! - **[`Sfs`]**, the in-memory state (the mounted [`Volume`] with its cache
//!   and allocator, plus the request counters), sits behind one
//!   `hal::sync::SpinMutex`, taken through [`with_sfs`]: preemption is
//!   disabled for exactly the critical section (so a holder is never switched
//!   away mid-section, and `SpinMutex` not masking interrupts is harmless —
//!   nothing FS runs in IRQ context), and the section is always bounded
//!   in-memory work. **The lock is never held across device I/O**: the task
//!   seals a commit under it, releases it, writes, and takes it again only to
//!   copy the next block out or to publish the result.
//! - **Callers** never block on the device either: they post a request (a
//!   commit ticket), which unparks the task, and wait for it to serve the
//!   ticket. Today's only waiter is kmain's boot proof — an idle task, which
//!   may not park — so it yields meanwhile, handing its core straight to the
//!   task (FS-2's blocking callers will park on a waiter list instead).
//!
//! # Pacing
//!
//! The task serves requested commits first, and otherwise commits a dirty
//! transaction once [`COMMIT_INTERVAL`] ticks of `clock::mono_ticks()` have
//! passed since the last one. Between commits it is **parked** (spec §15
//! A25): with a dirty transaction until that pacing deadline
//! (`sched::park_until`), otherwise until something unparks it
//! (`sched::park`). Every [`with_sfs`] section that changes the task's
//! decision ([`Sfs::next_step`] before vs after, at one `now`) kicks it
//! after the lock is released ([`kick`]) — so a new wake reason needs no
//! kick of its own, provided `next_step` reflects it (a mutation of state
//! `next_step` does not read is not seen). [`request_commit`] also kicks
//! explicitly. The decision and the park are race-free
//! because an unpark that lands between them stores the task's wake permit,
//! so the park returns at once and the loop decides again. A parked task is
//! off its core's ready ring, so the BSP really idles. The deadline is checked
//! by the scheduler's tick; nothing *here* runs from `sched::on_tick` or any
//! other IRQ path (A7).
//!
//! # Where on the disk
//!
//! The window from sector [`SFS_BASE_LBA`] to the end of the disk (3840
//! blocks on the 16 MiB dev image, one group), past the old `kernel::fs`
//! image, which keeps working until FS-2 replaces it (spec §11).

use super::proof::{self, Control};
use super::scrub::{scrub, Report, ScrubWs};
use super::short_hex;
use super::volume::{
    self, write_commit, CommitError, CommitInfo, FormatError, FormatInfo, FormatParams, MountError,
    MountInfo, Volume, Workspace,
};
use crate::blk::ata::{AtaDevice, SFS_BASE_LBA};
use crate::blk::layout::Pointer;
use crate::blk::{BlkError, Block, BlockDevice, BlockNo};
use crate::clock;
use crate::sched::{SpawnError, TaskId, TaskIdCell};
use alloc::boxed::Box;
use core::sync::atomic::{AtomicBool, Ordering};
use hal::sync::SpinMutex;

/// Ticks of `clock::mono_ticks` between paced commits of a dirty
/// transaction (0.5 s at 100 Hz, §8).
pub const COMMIT_INTERVAL: u64 = 50;
/// How long the boot proof waits for the task, in mono ticks (generous: TCG
/// and a debug build hash 4 KiB blocks slowly).
const PROOF_TIMEOUT_TICKS: u64 = 3000;
/// The `sfs-commit` task's stack: 64 KiB, not the 16 KiB default. The task
/// runs every FS path that hashes or parses a block, and the kernel is built
/// in the dev profile, where frames keep a slot per temporary: the mount path
/// measured ~14 KiB deep (a 16 KiB stack overflowed into its guard page at
/// boot before the frames were trimmed). FS-1b's tree runs here too.
const TASK_STACK_PAGES: usize = 16;

/// Why the task could not bring the filesystem up.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StartError {
    /// No usable disk (or none large enough for the window).
    NoDevice(BlkError),
    /// The disk is `Unformatted` but formatting failed.
    Format(FormatError),
    /// Mount refused: `Corrupt` (never formatted over), `TooLarge`, or I/O.
    Mount(MountError),
}

impl StartError {
    /// Fixed label for `fmt`-free console output.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            StartError::NoDevice(e) => e.label(),
            StartError::Format(e) => e.label(),
            StartError::Mount(e) => e.label(),
        }
    }
}

/// Lifecycle of the kernel's filesystem.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Phase {
    /// The task has not been started.
    Stopped,
    /// The task is probing, mounting or formatting.
    Starting,
    /// Mounted; the task is serving.
    Mounted,
    /// The task could not bring the filesystem up and has exited.
    Failed(StartError),
}

/// The lock-protected in-memory state (the spec's `SpinMutex<Sfs>`).
pub struct Sfs {
    phase: Phase,
    volume: Option<Box<Volume>>,
    formatted: Option<FormatInfo>,
    mounted: Option<MountInfo>,
    requested: u64,
    served: u64,
    last: Option<Result<CommitInfo, CommitError>>,
    last_commit_tick: u64,
    /// FS-1b: one outstanding miss to read for a caller (ticketed).
    read_req: Option<(Pointer, u64)>,
    read_ticket: u64,
    read_served: u64,
    read_last: Option<Result<(), CommitError>>,
    /// FS-1b: scrub requests, the last report, and the task's scrub scratch.
    scrub_req: u64,
    scrub_served: u64,
    scrub_last: Option<Result<Report, BlkError>>,
    scrub_ws: Option<Box<ScrubWs>>,
    /// FS-1b: no interval commit while a caller's multi-operation group is in
    /// progress (requested commits are still served). A single flag: one
    /// group at a time (the boot proof). FS-2's facade, with concurrent
    /// callers, needs a count or an owner here.
    hold: bool,
    /// FS-1b: the boot's test-control sector, and the armed commit cut.
    control: Control,
    cut: Option<u32>,
}

/// What the commit task does next (see [`Sfs::next_step`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Next {
    /// Commit now.
    Commit,
    /// Park until this mono tick (the pacing deadline of a dirty transaction)
    /// or an unpark.
    ParkUntil(u64),
    /// Park until unparked: nothing to commit and nothing dirty (or the
    /// volume is read-only / not mounted).
    Park,
}

impl Sfs {
    const fn new() -> Sfs {
        Sfs {
            phase: Phase::Stopped,
            volume: None,
            formatted: None,
            mounted: None,
            requested: 0,
            served: 0,
            last: None,
            last_commit_tick: 0,
            read_req: None,
            read_ticket: 0,
            read_served: 0,
            read_last: None,
            scrub_req: 0,
            scrub_served: 0,
            scrub_last: None,
            scrub_ws: None,
            hold: false,
            control: Control::None,
            cut: None,
        }
    }

    /// Current lifecycle phase.
    #[must_use]
    pub const fn phase(&self) -> Phase {
        self.phase
    }

    /// What this boot mounted.
    #[must_use]
    pub const fn mounted(&self) -> Option<MountInfo> {
        self.mounted
    }

    /// What this boot formatted, if the disk was `Unformatted`.
    #[must_use]
    pub const fn formatted(&self) -> Option<FormatInfo> {
        self.formatted
    }

    /// The mounted volume (FS-1b callers run tree operations on it under
    /// the lock, through [`with_sfs`]).
    pub fn volume_mut(&mut self) -> Option<&mut Volume> {
        self.volume.as_deref_mut()
    }

    /// The boot's test-control request (normally [`Control::None`]).
    #[must_use]
    pub const fn control(&self) -> Control {
        self.control
    }

    /// Whether the task has work: a caller's read or scrub request, or a
    /// commit ([`commit_wanted`](Self::commit_wanted)). The task's loop asks
    /// this; [`run_commit`] serves whichever it is.
    fn commit_due(&self, now: u64) -> bool {
        self.read_req.is_some() || self.scrub_req > self.scrub_served || self.commit_wanted(now)
    }

    /// Whether a commit is due: requested, or a dirty transaction older than
    /// [`COMMIT_INTERVAL`] ticks at `now` while no caller holds commits.
    fn commit_wanted(&self, now: u64) -> bool {
        let Some(v) = self.volume.as_ref() else {
            return false;
        };
        if v.is_read_only() {
            return false;
        }
        self.requested > self.served
            || (!self.hold
                && v.is_dirty()
                && now >= self.last_commit_tick.saturating_add(COMMIT_INTERVAL))
    }

    /// Whether a mounted volume has uncommitted changes (host tests).
    #[cfg(test)]
    fn is_dirty(&self) -> bool {
        self.volume.as_ref().is_some_and(|v| v.is_dirty())
    }

    /// The commit task's decision at `now`: commit if [`Sfs::commit_due`];
    /// else, with a dirty writable volume and no [`hold_commits`] in force,
    /// park until its pacing deadline; else park until unparked. While held
    /// the pacing deadline does not apply, so the answer is `Park` — a
    /// deadline already past would return at once and the task would spin on
    /// the BSP for as long as the hold lasts. Releasing the hold changes the
    /// decision, which kicks the task ([`with_sfs`]).
    fn next_step(&self, now: u64) -> Next {
        if self.commit_due(now) {
            return Next::Commit;
        }
        match self.volume.as_ref() {
            Some(v) if !v.is_read_only() && v.is_dirty() && !self.hold => {
                Next::ParkUntil(self.last_commit_tick.saturating_add(COMMIT_INTERVAL))
            }
            _ => Next::Park,
        }
    }
}

/// The filesystem state. Only ever locked through [`with_sfs`].
static SFS: SpinMutex<Sfs> = SpinMutex::new(Sfs::new());
/// Set once the task has been spawned.
static STARTED: AtomicBool = AtomicBool::new(false);
/// The `sfs-commit` task's id, recorded by the task itself before it mounts.
/// Lock-free, so [`kick`] takes no lock.
static COMMIT_TASK: TaskIdCell = TaskIdCell::new();

/// Run `f` on the filesystem state with the lock held and preemption
/// disabled on this core. `f` must be bounded in-memory work: no device I/O,
/// no waiting, no allocation.
///
/// If `f` changed the commit task's decision — [`Sfs::next_step`] at one
/// `now`, before vs after: the volume became dirty, a request was posted, or
/// any wake reason FS-1b adds to `next_step` (read requests, scrubs, a
/// released hold) — the task is [`kick`]ed once the lock is released and
/// preemption is back on. A wake reason is only seen if `next_step` reads
/// it; that is the one rule a new one must follow.
pub fn with_sfs<R>(f: impl FnOnce(&mut Sfs) -> R) -> R {
    let now = clock::mono_ticks();
    crate::sched::preempt_disable();
    let (r, decision_changed) = {
        let mut guard = SFS.lock();
        run_noting_wake(&mut guard, now, f)
    };
    crate::sched::preempt_enable();
    if decision_changed {
        kick();
    }
    r
}

/// Run `f` on `s`; also report whether it changed the commit task's
/// decision at `now` (the pure part of [`with_sfs`]). A spurious `true`
/// (the task's own sections change it too) only costs the task one extra
/// loop: the kick stores its permit.
fn run_noting_wake<R>(s: &mut Sfs, now: u64, f: impl FnOnce(&mut Sfs) -> R) -> (R, bool) {
    let before = s.next_step(now);
    let r = f(s);
    (r, s.next_step(now) != before)
}

/// Start the `sfs-commit` task, pinned to the BSP (`spawn_on(0, …)`, with a
/// [`TASK_STACK_PAGES`]-page stack). It mounts the window (formatting it
/// first only if it is `Unformatted`) and then serves commits. Idempotent.
///
/// # Errors
///
/// The scheduler's [`SpawnError`].
pub fn start() -> Result<(), SpawnError> {
    if STARTED.swap(true, Ordering::AcqRel) {
        return Ok(());
    }
    with_sfs(|s| s.phase = Phase::Starting);
    match crate::sched::spawn_on_with_stack(0, "sfs-commit", commit_task, TASK_STACK_PAGES) {
        Ok(_) => Ok(()),
        Err(e) => {
            with_sfs(|s| s.phase = Phase::Stopped);
            STARTED.store(false, Ordering::Release);
            Err(e)
        }
    }
}

/// The `sfs-commit` task's id, once it has started (`None` before, and
/// whenever [`start`] was never called). Lock-free.
#[must_use]
pub fn commit_task_id() -> Option<TaskId> {
    COMMIT_TASK.get()
}

/// Wake the commit task so it re-decides (arms its pacing deadline, or
/// serves a request). [`with_sfs`] calls it whenever a section changed the
/// task's decision, and [`request_commit`] after posting a request (also
/// when the decision was already `Commit`). Harmless
/// when the task is awake: the unpark then only stores its permit.
///
/// Takes no lock — an atomic load and `sched::unpark` — so it is safe from
/// any context, including inside a [`with_sfs`] section and from IRQ
/// context.
pub fn kick() {
    if let Some(id) = commit_task_id() {
        let _outcome = crate::sched::unpark(id);
    }
}

/// Ask the task for a commit (even of an empty transaction: the generation
/// still advances and the slot alternates), and unpark it. Returns a ticket
/// for [`commit_outcome`], or `None` unless mounted read-write.
pub fn request_commit() -> Option<u64> {
    let ticket = with_sfs(|s| {
        let writable = s.volume.as_ref().is_some_and(|v| !v.is_read_only());
        if s.phase != Phase::Mounted || !writable {
            return None;
        }
        s.requested += 1;
        Some(s.requested)
    })?;
    kick();
    Some(ticket)
}

/// Once `ticket` has been served: the outcome of the latest commit (the one
/// that served it, unless another has completed since).
#[must_use]
pub fn commit_outcome(ticket: u64) -> Option<Result<CommitInfo, CommitError>> {
    with_sfs(|s| if s.served >= ticket { s.last } else { None })
}

/// Hold (`true`) or release interval commits around a group of operations
/// that must commit together (requested commits are still served). FS-1b's
/// boot ledger uses it; FS-2's facade calls will.
pub fn hold_commits(on: bool) {
    with_sfs(|s| s.hold = on);
}

/// Have the task read the committed block `p` names into the cache
/// (verified), for a caller whose operation reported `Miss(p)` in commit
/// `epoch` ([`Volume::epoch`], read under the same lock hold); waits,
/// yielding, up to `timeout` mono ticks. The caller then retries its
/// operation. A failed read or a block that no longer matches its hash
/// leaves the volume read-only — unless a commit has completed since the
/// miss, which makes it stale, not damage ([`Volume::resolve_tree_miss`];
/// the host race model found that case).
///
/// # Errors
///
/// The read's [`CommitError`]; [`CommitError::Busy`] if the task never
/// answered in time.
pub fn read_block(p: Pointer, epoch: u64, timeout: u64) -> Result<(), CommitError> {
    let posted = wait_for(timeout, || {
        with_sfs(|s| {
            if s.read_req.is_some() {
                return None;
            }
            s.read_ticket += 1;
            s.read_req = Some((p, epoch));
            Some(s.read_ticket)
        })
    });
    let ticket = posted.ok_or(CommitError::Busy)?;
    let outcome = wait_for(timeout, || {
        with_sfs(|s| (s.read_served >= ticket).then_some(s.read_last))
    });
    match outcome {
        Some(Some(r)) => r,
        _ => Err(CommitError::Busy),
    }
}

/// Ask the task to scrub the committed generation. Returns a ticket for
/// [`scrub_outcome`], or `None` unless mounted.
pub fn request_scrub() -> Option<u64> {
    with_sfs(|s| {
        s.volume.as_ref()?;
        s.scrub_req += 1;
        Some(s.scrub_req)
    })
}

/// Once `ticket` has been served: the latest scrub's report.
#[must_use]
pub fn scrub_outcome(ticket: u64) -> Option<Result<Report, BlkError>> {
    with_sfs(|s| {
        if s.scrub_served >= ticket {
            s.scrub_last
        } else {
            None
        }
    })
}

/// Identity for a fresh format: SHA-256-derived from the clocks. Not secret
/// (the uuid only has to differ between filesystems; the dirent key is
/// re-derived per §10 once keys exist).
fn format_params() -> FormatParams {
    let now = clock::mono_ticks();
    let mut seed = [0u8; 16];
    seed[..8].copy_from_slice(&now.to_le_bytes());
    seed[8..].copy_from_slice(&hal::pit::ticks().to_le_bytes());
    FormatParams::from_seed(&seed, now)
}

/// Mount `dev`; format it first only if it is `Unformatted` (A9: a disk that
/// carries the magic is never formatted automatically — `Corrupt` is
/// returned untouched). `params` is only called when formatting.
///
/// # Errors
///
/// [`StartError::Format`] / [`StartError::Mount`].
pub fn mount_or_format<D: BlockDevice>(
    dev: &mut D,
    ws: &mut Workspace,
    params: impl FnOnce() -> FormatParams,
) -> Result<(Box<Volume>, Option<FormatInfo>), StartError> {
    match Volume::mount(dev, ws) {
        Ok(v) => Ok((v, None)),
        Err(MountError::Unformatted) => {
            let info = volume::format(dev, ws, &params()).map_err(StartError::Format)?;
            let v = Volume::mount(dev, ws).map_err(StartError::Mount)?;
            Ok((v, Some(info)))
        }
        Err(e) => Err(StartError::Mount(e)),
    }
}

/// The `sfs-commit` task body. The only code that touches the device.
fn commit_task() {
    COMMIT_TASK.set(crate::sched::current_id());
    let mut dev = match AtaDevice::open(SFS_BASE_LBA) {
        Ok(d) => d,
        Err(e) => {
            with_sfs(|s| s.phase = Phase::Failed(StartError::NoDevice(e)));
            return;
        }
    };
    let mut ws = Workspace::new();
    let control = read_control(ws.block());
    let scrub_ws = Box::new(ScrubWs::new());
    match mount_or_format(&mut dev, &mut ws, format_params) {
        Ok((vol, formatted)) => with_sfs(|s| {
            s.control = control;
            s.cut = match control {
                Control::Cut { after } => Some(after),
                _ => None,
            };
            s.scrub_ws = Some(scrub_ws);
            s.mounted = Some(vol.info());
            s.formatted = formatted;
            s.volume = Some(vol);
            s.last_commit_tick = clock::mono_ticks();
            s.phase = Phase::Mounted;
        }),
        Err(e) => {
            with_sfs(|s| s.phase = Phase::Failed(e));
            return;
        }
    }
    loop {
        let now = clock::mono_ticks();
        // Decide under the lock, park with it released. An unpark between the
        // two stores this task's permit, so the park returns at once.
        match with_sfs(|s| s.next_step(now)) {
            Next::Commit => run_commit(&mut dev, &mut ws),
            Next::ParkUntil(deadline) => {
                let _woken = crate::sched::park_until(deadline);
            }
            Next::Park => crate::sched::park(),
        }
    }
}

/// Read the test-control sector ([`proof::CONTROL_LBA`]) through the
/// channel lock; anything unreadable or without the magic is no request.
/// Only kernels built with the `test-hooks` feature (the boot tests') read
/// it at all: a production kernel never halts because a disk carries it.
#[cfg(not(feature = "test-hooks"))]
fn read_control(_buf: &mut Block) -> Control {
    Control::None
}

/// See the production variant above: this is the boot tests' build.
#[cfg(feature = "test-hooks")]
fn read_control(buf: &mut Block) -> Control {
    let sector = &mut buf[..crate::blk::SECTOR_SIZE];
    match crate::blk::ata::read_sectors(proof::CONTROL_LBA, 1, sector) {
        Ok(()) => proof::parse_control(sector),
        Err(_) => Control::None,
    }
}

/// Serve whatever the task's loop found due ([`Sfs::commit_due`]): a
/// caller's read, then a scrub, then a commit if one is wanted.
fn run_commit(dev: &mut AtaDevice, ws: &mut Workspace) {
    serve_read(dev, ws);
    serve_scrub(dev);
    let now = clock::mono_ticks();
    if with_sfs(|s| s.commit_wanted(now)) {
        commit_once(dev, ws, now);
    }
}

/// A caller's miss: read with the lock released, insert (verified) under it.
fn serve_read(dev: &mut AtaDevice, ws: &mut Workspace) {
    let Some((p, epoch)) = with_sfs(|s| s.read_req) else {
        return;
    };
    let staging = ws.block();
    let read = dev
        .read_blocks(p.block, core::slice::from_mut(staging))
        .map(|()| &*staging);
    let res = with_sfs(|s| match s.volume.as_mut() {
        Some(v) => v.resolve_tree_miss(&p, read, epoch),
        None => Err(CommitError::Internal),
    });
    with_sfs(|s| {
        s.read_req = None;
        s.read_served = s.read_ticket;
        s.read_last = Some(res);
    });
}

/// A scrub of the committed generation, entirely with the lock released
/// (module docs of [`super::scrub`]: no commit can run underneath, the task
/// does both). Damage leaves the volume read-only.
fn serve_scrub(dev: &mut AtaDevice) {
    let job = with_sfs(|s| {
        if s.scrub_req <= s.scrub_served {
            return Ok(None);
        }
        // A request that cannot run is answered with an error, never with
        // the previous scrub's report.
        let (Some(v), Some(sws)) = (s.volume.as_ref(), s.scrub_ws.take()) else {
            return Err(());
        };
        let info = v.info();
        Ok(Some((*v.superblock(), info.sb_hash, info.slot, sws)))
    });
    let (sb, hash, slot, mut sws) = match job {
        Ok(Some(job)) => job,
        Ok(None) => return,
        Err(()) => {
            with_sfs(|s| {
                s.scrub_served = s.scrub_req;
                s.scrub_last = Some(Err(BlkError::BadBuffer));
            });
            return;
        }
    };
    let report = scrub(dev, &mut sws, &sb, &hash, slot);
    with_sfs(|s| {
        if report.is_err() || report.is_ok_and(|r| r.bad > 0) {
            if let Some(v) = s.volume.as_mut() {
                v.mark_read_only();
            }
        }
        s.scrub_ws = Some(sws);
        s.scrub_served = s.scrub_req;
        s.scrub_last = Some(report);
    });
}

/// The FS-1b torn-commit cut: a device that halts the machine after its
/// `after`-th block write (spec §11; armed by the test-control sector).
struct Cut<'a> {
    dev: &'a mut AtaDevice,
    after: u32,
    written: u32,
    gen: u64,
    dirty: usize,
}

impl BlockDevice for Cut<'_> {
    fn blocks(&self) -> u64 {
        self.dev.blocks()
    }

    fn read_blocks(&mut self, start: BlockNo, out: &mut [Block]) -> Result<(), BlkError> {
        self.dev.read_blocks(start, out)
    }

    fn write_blocks(&mut self, start: BlockNo, data: &[Block]) -> Result<(), BlkError> {
        self.dev.write_blocks(start, data)?;
        self.written = self.written.saturating_add(data.len() as u32);
        if self.written >= self.after {
            proof::print_cut(self.after, self.gen, self.dirty);
            hal::cpu::disable_interrupts();
            hal::cpu::halt_loop();
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), BlkError> {
        self.dev.flush()
    }
}

/// One commit, start to finish, with the lock released around all I/O.
fn commit_once(dev: &mut AtaDevice, ws: &mut Workspace, now: u64) {
    let ticket = with_sfs(|s| s.requested);
    // Phase 1 under the lock; a miss is read with the lock released and
    // handed back to the volume, which goes read-only if the read failed or
    // the block no longer matches its hash. Ends: `begin_commit` stops
    // reporting misses after `MAX_SEAL_RETRIES`.
    let plan = loop {
        let begun = with_sfs(|s| match s.volume.as_mut() {
            Some(v) => v.begin_commit(now),
            None => Err(CommitError::Internal),
        });
        let Err(CommitError::Miss(p)) = begun else {
            break begun;
        };
        let staging = ws.block();
        let read = dev
            .read_blocks(p.block, core::slice::from_mut(staging))
            .map(|()| &*staging);
        let resolved = with_sfs(|s| match s.volume.as_mut() {
            Some(v) => v.resolve_miss(&p, read),
            None => Err(CommitError::Internal),
        });
        if let Err(e) = resolved {
            break Err(e);
        }
    };
    // Phase 2 without the lock (each block is copied out under it), then
    // phase 3 under it.
    let result = plan.and_then(|plan| {
        let fetch = |stage, out: &mut Block| {
            with_sfs(|s| s.volume.as_ref().and_then(|v| v.fetch(stage, out)))
        };
        // The cut applies to the first commit that writes a dirty block, and
        // only inside the dirty set (cutting after the superblock would not
        // be a torn commit).
        let cut = with_sfs(|s| if plan.dirty > 0 { s.cut.take() } else { None });
        let io = match cut {
            Some(after) if after >= 1 && after as usize <= plan.dirty => {
                let mut c = Cut {
                    dev: &mut *dev,
                    after,
                    written: 0,
                    gen: plan.gen,
                    dirty: plan.dirty,
                };
                write_commit(&mut c, ws.block(), &plan, fetch)
            }
            Some(after) => {
                proof::print_cut_refused(after, plan.dirty);
                write_commit(dev, ws.block(), &plan, fetch)
            }
            None => write_commit(dev, ws.block(), &plan, fetch),
        };
        with_sfs(|s| match s.volume.as_mut() {
            Some(v) => v.finish_commit(io),
            None => Err(CommitError::Internal),
        })
    });
    with_sfs(|s| {
        s.served = s.served.max(ticket);
        s.last = Some(result);
        s.last_commit_tick = clock::mono_ticks();
    });
}

/// Wait (yielding) until `poll` yields a value or `timeout` mono ticks pass.
/// Its only callers are kmain's boot proofs (this file's and `sfs::proof`'s),
/// and kmain is the BSP's idle task, which may not park; a yield hands the BSP
/// straight to the commit task.
pub(super) fn wait_for<T>(timeout: u64, mut poll: impl FnMut() -> Option<T>) -> Option<T> {
    let deadline = clock::mono_ticks().saturating_add(timeout);
    loop {
        if let Some(v) = poll() {
            return Some(v);
        }
        if clock::mono_ticks() >= deadline {
            return None;
        }
        crate::sched::yield_now();
    }
}

fn write_hex8(h: &crate::blk::layout::Hash) {
    let hex = short_hex(h);
    if let Ok(s) = core::str::from_utf8(&hex) {
        hal::serial::write_str(s);
    }
}

/// FS-1a boot proof (spec §11). Starts the task, waits for the mount (and the
/// format, on a fresh image), prints the asserted line
///
/// ```text
/// [sfs] mount: gen=N slot=S sb=<8 hex> verified=yes groups=1 free=N/N reserve=64 ok
/// ```
///
/// (`free=` is free/total blocks by the committed bitmaps; `verified=yes`
/// means every block the mount read — both slots, the group index, every
/// bitmap — passed its hash before it was parsed), then asks for one empty
/// commit so the slot alternates on every boot, and prints
/// `[sfs] commit: gen=N+1 slot=1-S sb=<8 hex> blocks=B flushes=2 ok`.
/// Every line is `fmt`-free.
pub fn prove_mount() {
    use hal::serial::{write_dec, write_str};

    if let Err(e) = start() {
        write_str("[sfs] mount: spawn FAILED: ");
        write_str(e.label());
        write_str("\n");
        return;
    }
    let phase = wait_for(PROOF_TIMEOUT_TICKS, || {
        with_sfs(|s| (s.phase != Phase::Starting).then_some(s.phase))
    });
    let (formatted, mounted) = with_sfs(|s| (s.formatted, s.mounted));
    let info = match (phase, mounted) {
        (Some(Phase::Mounted), Some(info)) => info,
        (Some(Phase::Failed(StartError::NoDevice(e))), _) => {
            write_str("[sfs] mount: no-disk (");
            write_str(e.label());
            write_str(") skipped\n");
            return;
        }
        (Some(Phase::Failed(e)), _) => {
            write_str("[sfs] mount: ");
            write_str(e.label());
            if let StartError::Mount(MountError::Corrupt(d)) = e {
                write_str(" (");
                write_str(d.label());
                write_str("; never formatted over)");
            }
            write_str(" FAIL\n");
            return;
        }
        _ => {
            write_str("[sfs] mount: TIMEOUT FAIL\n");
            return;
        }
    };
    if let Some(f) = formatted {
        write_str("[sfs] format: window lba=");
        write_dec(u64::from(SFS_BASE_LBA));
        write_str(" blocks=");
        write_dec(f.total);
        write_str(" groups=");
        write_dec(u64::from(f.groups));
        write_str(" gen=1 sb=");
        write_hex8(&f.sb_hash);
        write_str(" (was unformatted)\n");
    }
    write_str("[sfs] mount: gen=");
    write_dec(info.gen);
    write_str(" slot=");
    write_dec(u64::from(info.slot));
    write_str(" sb=");
    write_hex8(&info.sb_hash);
    write_str(" verified=yes groups=");
    write_dec(u64::from(info.groups));
    write_str(" free=");
    write_dec(info.free);
    write_str("/");
    write_dec(info.total);
    write_str(" reserve=");
    write_dec(u64::from(info.reserve));
    write_str(" ok\n");

    // FS-1b: verify the tree this generation committed (and, on a recovery
    // boot, that the torn commit left exactly it), then queue the next
    // generation's ledger changes as one group of tree operations.
    hold_commits(true);
    let staged = proof::check_and_stage(info.gen, PROOF_TIMEOUT_TICKS);
    if !staged {
        hold_commits(false);
        return;
    }
    let Some(ticket) = request_commit() else {
        hold_commits(false);
        write_str("[sfs] commit: refused (not mounted read-write) FAIL\n");
        return;
    };
    let outcome = wait_for(PROOF_TIMEOUT_TICKS, || commit_outcome(ticket));
    hold_commits(false);
    write_str("[sfs] commit: ");
    match outcome {
        Some(Ok(c)) => {
            write_str("gen=");
            write_dec(c.gen);
            write_str(" slot=");
            write_dec(u64::from(c.slot));
            write_str(" sb=");
            write_hex8(&c.sb_hash);
            write_str(" blocks=");
            write_dec(c.blocks);
            write_str(" flushes=");
            write_dec(c.flushes);
            write_str(" ok\n");
            proof::prove_scrub(PROOF_TIMEOUT_TICKS);
        }
        Some(Err(e)) => {
            write_str(e.label());
            write_str(" FAIL\n");
        }
        None => write_str("TIMEOUT FAIL\n"),
    }
}

#[cfg(test)]
mod tests {
    use super::{run_noting_wake, Next, Sfs, COMMIT_INTERVAL};
    use crate::blk::allocator::AllocClass;
    use crate::blk::mem::MemDevice;
    use crate::sfs::volume::{format, FormatParams, Volume, Workspace};

    /// The commit task parks without a deadline while there is nothing to do,
    /// parks until the pacing deadline while dirty, and commits once a request
    /// is pending or the deadline has passed (spec §15 A25).
    #[test]
    #[cfg_attr(miri, ignore)]
    fn the_commit_task_parks_unless_a_commit_is_due() {
        let mut s = Sfs::new();
        assert_eq!(s.next_step(0), Next::Park, "nothing mounted");
        s.requested = 1;
        assert_eq!(s.next_step(0), Next::Park, "no volume to commit");
        s.requested = 0;

        let mut d = MemDevice::new(256);
        let mut ws = Workspace::new();
        format(&mut d, &mut ws, &FormatParams::from_seed(b"park", 1)).unwrap();
        let mut v = Volume::mount(&mut d, &mut ws).unwrap();
        s.last_commit_tick = 100;
        s.volume = Some(v);
        assert_eq!(s.next_step(100), Next::Park, "clean: park until unparked");
        s.requested = 1;
        assert_eq!(s.next_step(100), Next::Commit, "a request is due at once");
        s.served = 1;

        v = s.volume.take().unwrap();
        v.alloc(AllocClass::Normal, None).unwrap();
        assert!(v.is_dirty());
        s.volume = Some(v);
        let due = 100 + COMMIT_INTERVAL;
        assert_eq!(s.next_step(100), Next::ParkUntil(due));
        assert_eq!(s.next_step(due - 1), Next::ParkUntil(due));
        assert_eq!(s.next_step(due), Next::Commit);
    }

    /// A `with_sfs` section reports a change of the commit task's decision
    /// (so it can kick the task) exactly when one happens — whether or not
    /// the volume's dirtiness changed: a posted request on a clean volume
    /// (no dirtying) is a change, a first allocation is, a read or a second
    /// allocation is not.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn a_section_that_changes_the_decision_is_noticed() {
        let mut s = Sfs::new();
        assert_eq!(run_noting_wake(&mut s, 0, |_| ()), ((), false), "no volume");

        let mut d = MemDevice::new(256);
        let mut ws = Workspace::new();
        format(&mut d, &mut ws, &FormatParams::from_seed(b"kick", 1)).unwrap();
        s.volume = Some(Volume::mount(&mut d, &mut ws).unwrap());
        let now = 10;

        // A wake reason that is not dirtiness: a request, volume clean.
        let request = |s: &mut Sfs| {
            s.requested += 1;
            s.is_dirty()
        };
        assert_eq!(run_noting_wake(&mut s, now, request), (false, true));
        assert_eq!(s.next_step(now), Next::Commit);
        // Served: the decision goes back to Park (a change the task makes).
        assert_eq!(
            run_noting_wake(&mut s, now, |s| s.served = s.requested),
            ((), true)
        );

        let alloc = |s: &mut Sfs| {
            s.volume
                .as_mut()
                .map(|v| v.alloc(AllocClass::Normal, None).is_ok())
        };
        assert_eq!(
            run_noting_wake(&mut s, now, |s| s.is_dirty()),
            (false, false)
        );
        assert_eq!(run_noting_wake(&mut s, now, alloc), (Some(true), true));
        assert_eq!(
            s.next_step(now),
            Next::ParkUntil(s.last_commit_tick + COMMIT_INTERVAL)
        );
        assert_eq!(run_noting_wake(&mut s, now, alloc), (Some(true), false));
        assert_eq!(
            run_noting_wake(&mut s, now, |s| s.is_dirty()),
            (true, false)
        );
    }

    /// FS-1b's wake reasons reach the decision: while commits are held a
    /// dirty volume parks without a deadline even when the deadline has
    /// passed (no hot spin), releasing the hold changes the decision (so the
    /// section that releases it kicks the task), and a posted read or scrub
    /// request is a commit-task wake-up like a commit request.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn hold_parks_and_releasing_it_or_posting_a_read_or_scrub_kicks() {
        let mut s = Sfs::new();
        let mut d = MemDevice::new(256);
        let mut ws = Workspace::new();
        format(&mut d, &mut ws, &FormatParams::from_seed(b"hold", 1)).unwrap();
        let mut v = Volume::mount(&mut d, &mut ws).unwrap();
        v.alloc(AllocClass::Normal, None).unwrap();
        s.volume = Some(v);
        s.last_commit_tick = 0;
        let past = COMMIT_INTERVAL * 3;
        assert_eq!(
            s.next_step(past),
            Next::Commit,
            "unheld: the deadline passed"
        );

        assert_eq!(run_noting_wake(&mut s, past, |s| s.hold = true), ((), true));
        assert_eq!(
            s.next_step(past),
            Next::Park,
            "held + dirty + past deadline"
        );
        assert_eq!(s.next_step(0), Next::Park, "held + dirty, deadline ahead");
        // Releasing the hold changes the decision: the releasing section kicks.
        assert_eq!(
            run_noting_wake(&mut s, past, |s| s.hold = false),
            ((), true)
        );
        assert_eq!(s.next_step(past), Next::Commit);

        // While held, a posted read or scrub is still a wake-up.
        s.hold = true;
        let p = crate::blk::layout::Pointer::NULL;
        assert_eq!(
            run_noting_wake(&mut s, past, |s| s.read_req = Some((p, 0))),
            ((), true)
        );
        assert_eq!(s.next_step(past), Next::Commit);
        s.read_req = None;
        assert_eq!(
            run_noting_wake(&mut s, past, |s| s.scrub_req += 1),
            ((), true)
        );
        assert_eq!(s.next_step(past), Next::Commit);
    }
}
