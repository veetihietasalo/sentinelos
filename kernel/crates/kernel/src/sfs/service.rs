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
//! (`sched::park`). [`request_commit`] unparks it, and so does every
//! [`with_sfs`] section that turns the volume from clean to dirty — after the
//! lock is released, structurally, so no mutation can forget it ([`kick`]);
//! the decision and the park are race-free
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

use super::short_hex;
use super::volume::{
    self, write_commit, CommitError, CommitInfo, FormatError, FormatInfo, FormatParams, MountError,
    MountInfo, Volume, Workspace,
};
use crate::blk::ata::{AtaDevice, SFS_BASE_LBA};
use crate::blk::{BlkError, BlockDevice};
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

    /// Whether a commit is due: requested, or a dirty transaction older than
    /// [`COMMIT_INTERVAL`] ticks at `now`.
    fn commit_due(&self, now: u64) -> bool {
        let Some(v) = self.volume.as_ref() else {
            return false;
        };
        if v.is_read_only() {
            return false;
        }
        self.requested > self.served
            || (v.is_dirty() && now >= self.last_commit_tick.saturating_add(COMMIT_INTERVAL))
    }

    /// Whether a mounted volume has uncommitted changes.
    fn is_dirty(&self) -> bool {
        self.volume.as_ref().is_some_and(|v| v.is_dirty())
    }

    /// The commit task's decision at `now`: commit if [`Sfs::commit_due`];
    /// else, with a dirty writable volume, park until its pacing deadline;
    /// else park until unparked.
    fn next_step(&self, now: u64) -> Next {
        if self.commit_due(now) {
            return Next::Commit;
        }
        match self.volume.as_ref() {
            Some(v) if !v.is_read_only() && v.is_dirty() => {
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
/// If `f` turned the volume from clean to dirty, the commit task is
/// [`kick`]ed once the lock is released and preemption is back on, so it
/// arms its pacing deadline: a mutation cannot forget to tell it.
pub fn with_sfs<R>(f: impl FnOnce(&mut Sfs) -> R) -> R {
    crate::sched::preempt_disable();
    let (r, became_dirty) = {
        let mut guard = SFS.lock();
        run_noting_dirty(&mut guard, f)
    };
    crate::sched::preempt_enable();
    if became_dirty {
        kick();
    }
    r
}

/// Run `f` on `s`; also report whether it turned the volume from clean to
/// dirty (the pure part of [`with_sfs`]).
fn run_noting_dirty<R>(s: &mut Sfs, f: impl FnOnce(&mut Sfs) -> R) -> (R, bool) {
    let before = s.is_dirty();
    let r = f(s);
    (r, !before && s.is_dirty())
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
/// serves a request). [`with_sfs`] calls it whenever a section dirtied a
/// clean volume, and [`request_commit`] after posting a request. Harmless
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
    match mount_or_format(&mut dev, &mut ws, format_params) {
        Ok((vol, formatted)) => with_sfs(|s| {
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

/// One commit, start to finish, with the lock released around all I/O.
fn run_commit(dev: &mut AtaDevice, ws: &mut Workspace) {
    let now = clock::mono_ticks();
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
        let io = write_commit(dev, ws.block(), &plan, |stage, out| {
            with_sfs(|s| s.volume.as_ref().and_then(|v| v.fetch(stage, out)))
        });
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
/// Its only caller is kmain's boot proof, and kmain is the BSP's idle task,
/// which may not park; a yield hands the BSP straight to the commit task.
fn wait_for<T>(timeout: u64, mut poll: impl FnMut() -> Option<T>) -> Option<T> {
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

    let Some(ticket) = request_commit() else {
        write_str("[sfs] commit: refused (not mounted read-write) FAIL\n");
        return;
    };
    let outcome = wait_for(PROOF_TIMEOUT_TICKS, || commit_outcome(ticket));
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
    use super::{run_noting_dirty, Next, Sfs, COMMIT_INTERVAL};
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

    /// Every `with_sfs` section reports a clean → dirty transition (so it can
    /// kick the commit task) exactly when it happens: never with no volume,
    /// never for a read, never for a second change to an already dirty one.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn a_section_that_dirties_a_clean_volume_is_noticed() {
        let mut s = Sfs::new();
        assert_eq!(run_noting_dirty(&mut s, |_| ()), ((), false), "no volume");

        let mut d = MemDevice::new(256);
        let mut ws = Workspace::new();
        format(&mut d, &mut ws, &FormatParams::from_seed(b"kick", 1)).unwrap();
        s.volume = Some(Volume::mount(&mut d, &mut ws).unwrap());
        let alloc = |s: &mut Sfs| {
            s.volume
                .as_mut()
                .map(|v| v.alloc(AllocClass::Normal, None).is_ok())
        };
        assert_eq!(run_noting_dirty(&mut s, |s| s.is_dirty()), (false, false));
        assert_eq!(run_noting_dirty(&mut s, alloc), (Some(true), true));
        assert_eq!(run_noting_dirty(&mut s, alloc), (Some(true), false));
        assert_eq!(run_noting_dirty(&mut s, |s| s.is_dirty()), (true, false));
    }
}
