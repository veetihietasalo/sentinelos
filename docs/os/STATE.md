# SentinelOS — where things stand

One page for a fresh session (or a fresh container) to pick the kernel work back
up without re-deriving state from git. Update it at the end of any session that
changes direction; keep it short. Last updated **2026-09-18** (component-model review round 1: consensus on what is next).

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
- **Verification.** Miri (hal + kernel ml/sched) and Kani (hal + kernel) are
  **gating** CI; every workflow job carries a timeout, machine-checked. Boot
  timing harness (`make boot-timing`) is informational.
- **TCB registry.** `kernel/docs/hal-tcb.md` — every `unsafe` op, its argument,
  its evidence. Keep it in step with any `hal` change; reviewers read it first.

## Next (in sequencing order — consensus of 2026-09-18, spec §19)

0. **Component-model PR-1, native-only.** `kernel::hash` (SHA-256, framed id), `kernel::host`
   with the `ComponentRuntime` trait and a `NativeRuntime`, an embedded native "hello"
   component: id verified, one export called through the envelope codec. No interpreter, no
   time-dependent semantics (budgets by count). Kani: id framing, codec round-trip, inbox
   ring never overwrites or loses. Boot line
   `[comp] hello: id=… verified=yes runtime=native reply=ok`. Amendment A4 (§16 rewrite for
   an authority-not-memory boundary) lands here.
1. **Core-independent monotonic clock** (SMP 3b-i). LAPIC-tick or TSC derived; retires
   hal-tcb invariant 4.15 (`pit::ticks()` stalls when the BSP is not servicing IRQ0). Small,
   no IOAPIC, no MADT walk. Must land before PR-2 because `expires` and reply timeouts must
   not tick off a counter another core can stall.
2. **Component-model PR-2** bus + capabilities (denials logged, `required`/`optional` caps),
   then **PR-3** delegates with an **ephemeral memory-only key**
   (`sealing=none secrets-persist=no`). fs key file refused 4/4.
3. **Memory-boundary gate** (docs, before PR-3 merges): wasm via `wasmi` under the §12
   conditions vs ring-3 ELF. Preconditions either way: a gating fuzz lane (none exists),
   `kernel/docs/external-tcb.md` + hal-tcb §1 amendment. Spike baseline in spec §19:
   `wasmi` 2.0 builds for the target, 10 crates, ~135 k lines, 303 `unsafe` sites in `wasmi`
   alone.
4. **IOAPIC** (SMP 3b-ii) — ACPI MADT walk as a pure `&[u8] -> Result` parser (Kani + fuzz),
   explicit device-IRQ routing, PIC masked. Blocks nothing above; after PR-3. Then: load
   balancing / stealing is a product decision, not a default.
5. **Component-model PR-4** state objects (signing-key id in records), **PR-5** Sentinel as
   components.
6. **AMX tier / inference workload 2** — `docs/specs/2026-07-16-inference-workload2-design.md`.
7. **Tiered memory** — `docs/specs/2026-07-14-tiered-memory-design.md` (design only).
8. **CPU security step 2** — `docs/specs/2026-07-14-cpu-security-features-design.md`.

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
- **Kernel-crate Kani harnesses must be discharged locally before merge**
  (`cargo kani -p kernel --harness NAME`); see `.github/workflows/verify.yml`.

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
