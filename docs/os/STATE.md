# SentinelOS — where things stand

One page for a fresh session (or a fresh container) to pick the kernel work back
up without re-deriving state from git. Update it at the end of any session that
changes direction; keep it short. Last updated **2026-10-04** (component PR-2 + SentinelFS FS-1a landed; PR-2b next).

## Landed (main)

- **Boot → desktop in QEMU.** Limine, GDT/IDT/TSS, PIC+PIT, paging + heap,
  PS/2 keyboard + mouse, Cyber Dusk lock screen → window manager with Terminal /
  Files / Net / System Panel, 15-command shell, in-memory FS persisted to IDE,
  e1000 + ARP/IPv4/ICMP (pings the gateway at boot).
- **Scheduler.** Cooperative + timer-preemptive kernel threads with per-task
  vector state; both proven at boot (`[sched] cooperative … ok`,
  `[sched] preemptive … gemm-exact=yes … ok`).
- **AI/ML compute.** int8 GEMM tiers scalar / AVX2 / AVX-512F / VNNI, self-tested
  per core; MLP + transformer-block boot proofs. AMX detected, not implemented.
- **CPU security.** NX / SMEP / SMAP / UMIP enforced.
- **SMP.** Phase 1: BSP LAPIC in virtual-wire mode (x2APIC MSRs on KVM /
  hardware, xAPIC MMIO under TCG). Phase 2 PR-1: every AP online via the Limine
  MP protocol — per-AP GDT/TSS/IST, shared IDT, own vector state + LAPIC, int8
  GEMM proven on each core; `make test` asserts `online=4/4 aps-ok=3`. Phase 2
  PR-2: **per-CPU scheduler** — per-core run queues (fixed rings) + task slab,
  pinned `spawn_on(cpu, …)`, reschedule IPIs (`send_ipi`/`eoi`, vector 0xF0)
  wake an AP out of `sti; hlt`; `[sched] pinned: … distinct=yes ok` asserted
  under TCG and KVM. Cross-core console lock landed with it. Phase 3a:
  **per-core LAPIC timer** — calibrated against the PIT on the BSP, 100 Hz on
  every core (vector 0xF1) driving `sched::on_tick`; the PIT is wall clock only;
  `[sched] ap-preemptive: cpu1 … tick-preempted=N ok` proves timer preemption
  on an AP with bit-exact GEMM state.
- **Core-independent monotonic clock (SMP 3b-i).** `kernel::clock::mono_ticks()`:
  max over per-core LAPIC-tick counts aligned on first tick, `fetch_max`, never
  backwards, ≤1 per tick (Kani). `sched::wait_on_other_core` + the preemption-proof
  tasks tick off it; hal-tcb invariant 4.15 retired as a hazard (`smp::wait_online`
  still opens interrupts: the AP it waits for is not ticking yet). Boot proof
  `[clock] mono: … pit-frozen=yes bsp-stalled-advance=yes rate-ok=yes ok` asserted.
  Zero `hal` delta.
- **Component model PR-1 (native).** `kernel::hash` (SHA-256, framed
  `ComponentId`), `kernel::host`: `ComponentRuntime` trait + `native::NativeRuntime`,
  envelope codec (60-byte header, ≤256 B payload), per-instance `InboxRing<Wire, 8>`,
  fixed 16-slot instance table. Boot proof `[comp] hello: id=9c1877d2 verified=yes
  wrong-id=refused runtime=native reply=ok ok` asserted by `make test`. Five new Kani
  harnesses (framing injective, codec round-trip, decode total, ring FIFO/no-loss,
  SHA padding). Zero `hal` delta; zero time-dependent semantics.
- **Component model PR-2 (bus + capabilities).** `kernel::cap`: a fixed 16 × 16 slab of
  per-instance tables behind an opaque `CapIndex` (generation ‖ table ‖ slot); exactly three
  producers — `grant` (manifest ∩ policy, Required/Optional planned against usable slots before
  any state changes), `delegate` (attenuated or equal via one decidable `is_attenuation_of`,
  checked before install), `mint_reply` (one-shot, ≤ 4 pending); cascading `revoke`/`release`;
  deny by default; allocation-free, rate-limited denial log. `kernel::bus`: one kernel-wide host
  under one leaf lock; components act only through a per-dispatch `bus::Ctx` (no API names a
  sender or a target; the kernel stamps `from`); a full inbox is `Busy`; silence is denial;
  run-to-completion dispatch with a per-instance `running` flag (no task per instance, §18.4).
  `make check-component-imports` keeps component code to `Ctx`/`BusError`/`Delegation`.
  Threat model: `docs/security/threat-model.md`. Kani: no forgery (bounded + three inductive
  steps), never amplifies, revoke removes every descendant. Boot proof `[cap] attested-from=yes
  deny-by-default=yes forge-attempt=refused denies-logged=13 ok`. Zero `hal` delta.
- **SentinelFS FS-1a (block layer + superblocks).** `kernel::blk`: DMA-shaped
  `BlockDevice`, `AtaDevice` as an LBA window (SentinelFS lives from LBA 2048 to the end
  of the dev image until FS-2 moves it to LBA 0; the toy `kernel::fs` keeps LBA 0), host
  `MemDevice` with the unflushed-subset / torn-sector crash model, verified reads into one
  64-block slab, per-group bitmaps + one-level index + metadata reserve. `kernel::sfs`:
  §7.1 superblocks (whole-block hash, `Corrupt` never formatted over), the `sfs-commit`
  task (64 KiB stack via `sched::spawn_on_with_stack`) as the only device user, commit =
  dirty → flush → inactive slot → flush. Every `hal::ata` call goes through
  `blk::ata`'s channel lock (`make check-ata-callers` in CI). `make test` now double-boots a
  fresh test disk and asserts the chain (`[sfs] mount: gen=2 slot=0 sb=<boot 1's commit>`)
  plus the toy FS's `persistence PROVEN` line. Scheduler: zombies are reaped only on the
  idle path (`sched::idle_reap`), never in `reschedule`. Zero `hal` code delta (hal-tcb §5e
  and §7 text corrected).
- **Verification.** Miri (hal + kernel ml/hash/host/cap/bus/blk/sfs) and Kani (hal + kernel,
  35 kernel harnesses, ~5 min) are **gating** CI; every workflow job carries a timeout,
  machine-checked. Source guards `check-no-vector`, `check-ata-callers` and
  `check-component-imports` run in Kernel CI. Boot timing harness (`make boot-timing`) is
  informational.
- **TCB registry.** `kernel/docs/hal-tcb.md` — every `unsafe` op, its argument,
  its evidence. Keep it in step with any `hal` change; reviewers read it first.

## Next (in sequencing order — consensus of 2026-09-18, spec §19)

**Direction (Veeti, 2026-09-18): the filesystem and the login/identity system are the
next big tracks — "aim for perfection".** Today's `kernel::fs` is a toy (one heap tree
serialised as a single CRC-32-guarded image over ATA PIO, rewritten whole; a crash mid-write
loses everything to the seeded fallback) and the Cyber Dusk lock screen checks nothing
(right arrow unlocks). **SentinelFS spec written and through review round 1**
(`docs/specs/2026-09-18-sentinelfs-design.md`, §15): copy-on-write, whole-block SHA-256
hashes on every pointer, two generation-numbered superblock slots (no journal), per-domain
content-addressed blobs, logged privileged snapshots/rollback, one 64-block cache slab, an
`sfs-commit` task that does all I/O (never PIO under the lock), deterministic allocation,
metadata reserve. **Zero new `hal` rows** (`FLUSH CACHE` already exists; FS-1b splits the
API). Staging: **FS-1a** (landed, see above) → **FS-1c** (storage-cap lattice type + `⊑` +
Kani never-amplifies, on top of component PR-2's `kernel::cap`; moved out of FS-1a
2026-10-03 because `kernel::cap` did not exist yet) → **FS-1b** (CoW tree + transactions +
torn-commit proof + flush split) → **FS-2** (files + facade; `read_file` becomes
into-buffer, `Corrupt`/`NoSpace` errors; fuzz lane; persistent orphan list for removes
beyond `PENDING_MAX`; real entropy for the format seed) → **FS-4** (blobs, snapshots, cap
enforcement) → **identity spec** → **FS-5** (superblock hash signed into the IntegrityLog).
Follow-ups owned in the spec as A25–A31. Before FS-2 adds callers that block on the commit
task: one **sched park/unpark** primitive (wake permit + optional mono deadline), designed
with component PR-2's blocking bus receive, replacing the task's yield-poll.
Login/identity spec next: it must solve Argon2id's ≥19 MiB vs the 4 MiB heap (a `hal::mm`
arena outside the heap), wrap both the tree key and the KeyAgent key from one unlock secret
(resolving component §18.1), and decide the rollback anchor. The superblock already reserves
the KDF params at [352,384) and a `keys` pointer at [392,440) to a kind-6 keyring block
(spec §7.1), so login needs no format bump.

0. **Component-model PR-2b** identity v2 + wide indices (decided 2026-10-03, component spec
   A12/A13; **merges before PR-3 is opened**): manifest declarations bound into `ComponentId`
   (v2 framing) with records naming **services**, not ids — policy becomes routes (honoured only
   to a provider whose id-bound manifest provides the service) + an allow-list; `CapIndex(u64) =
   generation:48 ‖ table:8 ‖ slot:8` (24-bit generations let any client retire a responder's
   table at bus speed, T-DOS-5); codec `WIRE_VERSION` 2; every id literal regenerated; boot line
   gains `manifest-tamper=refused`. Open for PR-2b: inline code vs `SHA-256(code)` by reference
   (then amend SentinelFS §7.3/§9: the stored component image is the v2 frame). Then **PR-3**
   delegates with an **ephemeral memory-only key** (`sealing=none secrets-persist=no`), fs key
   file refused 4/4; PR-3 must also decide the run-to-completion driver (which core drains
   which inbox) and grant re-binding after a provider restarts (`Ctx::rebind`).
1. **Memory-boundary gate** (docs, before PR-3 merges): wasm via `wasmi` under the §12
   conditions vs ring-3 ELF. Preconditions either way: a gating fuzz lane (none exists),
   `kernel/docs/external-tcb.md` + hal-tcb §1 amendment. Spike baseline in spec §19:
   `wasmi` 2.0 builds for the target, 10 crates, ~135 k lines, 303 `unsafe` sites in `wasmi`
   alone.
2. **IOAPIC** (SMP 3b-ii) — ACPI MADT walk as a pure `&[u8] -> Result` parser (Kani + fuzz),
   explicit device-IRQ routing, PIC masked. Blocks nothing above; after PR-3. Then: load
   balancing / stealing is a product decision, not a default.
3. **Component-model PR-4** state objects (signing-key id in records), **PR-5** Sentinel as
   components.
4. **AMX tier / inference workload 2** — `docs/specs/2026-07-16-inference-workload2-design.md`.
5. **Tiered memory** — `docs/specs/2026-07-14-tiered-memory-design.md` (design only).
6. **CPU security step 2** — `docs/specs/2026-07-14-cpu-security-features-design.md`.

## Decisions worth remembering

- **Native-first, wasm gated, ephemeral key** (2026-09-18, four-role review, spec §19).
  `wasmi` in ring 0 is TCB accounting, not reduction, until its `unsafe` is inventoried,
  fuzzed on the real 4 MiB / 16 KiB budgets and backstopped by page tables; ring-3 is the
  alternative, not rejected. Authority (caps, attestation) is provable now in safe Rust and
  is interpreter-independent, so it goes first. The reviewer's 3b-first objection was about
  the stallable clock, not the IOAPIC — so the clock is split out and lands before PR-2.
- **Think like Freenet, scoped** (2026-09-18): take the small core, attested callers,
  deny-by-default, secret-holding delegates, and content-addressed identity wholesale;
  take the commutative-monoid state discipline **only** for state that crosses devices or
  partitions. Kernel-arbitrated state (sched, mm, drivers, fs metadata) is not a monoid.

- **Trust Limine's AP path over a hand-rolled trampoline** (2026-09-18). Same
  trust we already place in its BSP path; saved six unverifiable TCB rows and
  made SMP testable on TCG. Fallback if we ever ship our own boot stage.
- **Live `CR4.OSXSAVE` gate, not a global flag**, for every vector save
  (`isr_common`, `context::switch`). `simd::enable` clears the bit if the save
  contract fails, so a set bit is the whole precondition, per core.
- **Locks taken from IRQ context are never held across an allocation**
  (scheduler queue/table are fixed-size); lock order is queue → table; only the
  BSP prints during bring-up even though the console is now cross-core locked.
- **Tasks are pinned; a core is told about work by IPI**, never by another core
  touching its `current`. No stealing until it is deliberately designed.
- **The PIT wall clock advances only via the BSP's IRQ0.** Waiting on another
  core with interrupts off froze it once (silent hang, found with `-d int`).
  Every cross-core wait opens the interrupt window.
- **Keep the preemption proof at 40 ticks** (PR #31 analysis): 200 ms of boot
  time is not worth halving a gating proof's margin.
- **Declarations name services, not component ids** (2026-10-03, component A12). Binding a
  target's id into a client's id rekeys every transitive dependent on each update and makes
  mutual declarations (KeyAgent ↔ Security Center) a hash cycle; the policy route records
  "reviewed against exactly B" instead.
- **Kernel-crate Kani harnesses must be discharged locally before merge**
  (`cargo kani -p kernel --harness NAME`); see `.github/workflows/verify.yml`.
- **Boot tests own their disk** (2026-10-03). `make test` / `test-kvm` / `boot-timing` use
  `target/sentinelos-test-disk.img`, recreated blank every run (`SENTINELOS_KEEP_TEST_DISK=1`
  opts out); `make run`'s dev image is never touched by a test; each CI job deletes both
  images before the cache save (a `!` cache path cannot exclude a file inside `kernel/target`).
  A cached image once made CI's result depend on whoever created the cache.
- **Reap only on the idle path** (2026-10-03). `reschedule` reaping at IF=0 took the heap
  lock and could deadlock a core against a task preempted inside the allocator; exits park
  in a per-core zombie ring and `sched::idle_reap` frees them with interrupts and
  preemption on. Never allocate or free with interrupts or preemption off while another
  task on the core may be suspended inside the allocator (hal-tcb §5e; kmain's IF=0 boot
  sequence qualifies only because it is never preempted).

## Working agreements

- Development happens on a branch; PRs are drafts until CI is green; `main`
  is always bootable.
- **Commit identity split (standing rule).** Commits Claude authors are
  committed as `Claude <noreply@anthropic.com>` (the repo's stop hook checks
  this) and **always** carry a `Co-Authored-By: Veeti Väinö Valtteri Hietasalo <33787357+veetihietasalo@users.noreply.github.com>`
  trailer so Veeti is credited as a contributor on every one, plus the Claude
  attribution trailers last.
- Boot proofs are hard assertions in `kernel/xtask` (`make test`), never prose.
- `println!("{}", n)` with integer args faults on this target — use
  `hal::serial::write_str` / `write_dec`.
- Agents: `kernel-architect` designs, `hal-specialist` owns unsafe,
  `kernel-reviewer` gates every `hal` change, `verification-engineer` owns
  Miri/Kani.
