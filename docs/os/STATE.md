# SentinelOS — where things stand

One page for a fresh session (or a fresh container) to pick the kernel work back
up without re-deriving state from git. Update it at the end of any session that
changes direction; keep it short. Last updated **2026-09-18** (PR-2).

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
  under TCG and KVM. Cross-core console lock landed with it.
- **Verification.** Miri (hal + kernel ml/sched) and Kani (hal + kernel) are
  **gating** CI; every workflow job carries a timeout, machine-checked. Boot
  timing harness (`make boot-timing`) is informational.
- **TCB registry.** `kernel/docs/hal-tcb.md` — every `unsafe` op, its argument,
  its evidence. Keep it in step with any `hal` change; reviewers read it first.

## Next (in sequencing order from the strategy doc)

1. **IOAPIC + LAPIC timer** (SMP phase 3) — route device IRQs explicitly; give
   every AP a tick so its tasks are timer-preempted like the BSP's (today AP
   tasks switch only on IPI / `yield_now` / `exit`). The dual-path LAPIC
   register layer in `hal::apic` (`reg_read`/`reg_write`) is the base.
   Then: load balancing / stealing is a product decision, not a default.
3. **AMX tier / inference workload 2** — `docs/specs/2026-07-16-inference-workload2-design.md`.
4. **Tiered memory** — `docs/specs/2026-07-14-tiered-memory-design.md` (design only).
5. **CPU security step 2** — `docs/specs/2026-07-14-cpu-security-features-design.md`.

## Decisions worth remembering

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
- **Keep the preemption proof at 40 ticks** (PR #31 analysis): 200 ms of boot
  time is not worth halving a gating proof's margin.
- **Kernel-crate Kani harnesses must be discharged locally before merge**
  (`cargo kani -p kernel --harness NAME`); see `.github/workflows/verify.yml`.

## Working agreements

- Development happens on a branch; PRs are drafts until CI is green; `main`
  is always bootable.
- Boot proofs are hard assertions in `kernel/xtask` (`make test`), never prose.
- `println!("{}", n)` with integer args faults on this target — use
  `hal::serial::write_str` / `write_dec`.
- Agents: `kernel-architect` designs, `hal-specialist` owns unsafe,
  `kernel-reviewer` gates every `hal` change, `verification-engineer` owns
  Miri/Kani.
