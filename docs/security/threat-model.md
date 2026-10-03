# SentinelOS threat model

Status: **living document**, created 2026-10-03 with component-model PR-2 (amendment **A10** of
`docs/specs/2026-09-18-component-model-design.md`, which moved its §16 here; SentinelFS amendment
A24). Owner: security-engineer. Every security feature adds its entries here **before** its code
lands; every entry names the mechanism that defeats the threat and the evidence that the mechanism
works (a boot proof asserted by `make test`, a Kani harness, or a host test). An entry without
evidence is a claim, and is marked as one.

Scope of this revision: the component authority boundary (host, capabilities, bus). The storage
threat model lives in `docs/specs/2026-09-18-sentinelfs-design.md` §12 until SentinelFS lands code,
then moves here the same way.

## 1. Assumptions

- **Kerckhoffs.** The adversary knows every byte of the kernel and of every component, including
  this document, the capability-index encoding and the policy table. The only secrets are the
  delegates' keys (component PR-3). Nothing below depends on an index, a tag or a layout being hard
  to guess: a guessed index is refused for the same reason a stolen one is.
- **Hardware and boot chain are trusted.** The CPU, the firmware and Limine are in the root of
  trust (hal-tcb §1). Physical attacks, DMA from malicious devices, fault injection and
  micro-architectural side channels are out of scope for this revision.
- **First-party code is reviewed.** Everything compiled into the image, native components
  included, is reviewed as kernel code.

## 2. Trust boundaries

**Trusted (the root of trust):** `hal` (the only `unsafe`, registered row by row in
`kernel/docs/hal-tcb.md`); the safe kernel (`#![forbid(unsafe_code)]`), `kernel::host`,
`kernel::cap` and `kernel::bus` included; the component runtime (native: the kernel itself;
external: the gated external TCB of component spec §12). Delegates are components under the same
rules, but the KeyAgent and PolicyAgent are first-party and reviewed as TCB; they get registry rows
when `external-tcb.md` lands (component A5, A9). A bug in any of these is a bug in the root of
trust, handled by the TCB discipline, not by this model.

**Two boundaries, landed one at a time** (component spec §12, review consensus 2026-09-18).

- *Authority boundary* (PR-1 onward, every runtime): a component is confined by what it can
  **name** (a `CapIndex`, valid only in its own table) and **reach** (the bus). The kernel stamps
  `from`; deny by default; silence is denial. PR-1 proved identity (the wrong id is refused before
  any runtime sees the bytes) and kernel-stamped `from` on kernel calls; **PR-2 proves the rest of
  this boundary** (§5).
- *Memory boundary* (the gate before PR-3): whether a component can touch memory it was not
  handed. **Native components have none.** A native component runs in ring 0 in the kernel address
  space, so the authority boundary stops a *confused* component, not a *malicious* one. Therefore
  only **first-party** components (compiled into the image, reviewed as kernel code) run on the
  native runtime, and **no non-first-party component runs anywhere** until the gate lands a memory
  boundary (wasm under the §12 conditions, or ring-3).

## 3. Adversaries

| # | Adversary | In scope now? | Why |
|---|---|---|---|
| A1 | **Confused component** — first-party, buggy: presents the wrong index, a stale one, a payload too long for its cap, answers a request twice | **Yes** | The authority boundary exists for exactly this; every probe in §5 is this adversary |
| A2 | **Malicious component** | Not admitted | Native code is ring 0 and could bypass any software check. No such component runs before the memory gate. The authority mechanisms are nonetheless written as if A2 were present: everything a component hands the kernel (indices, tags, payloads, timing) is adversarial input today |
| A3 | **Malicious instantiator** — whoever supplies a manifest | Not reachable | Manifests are compiled into the image; there is no loader and no syscall. Gap recorded as T-MAN-1 (decided: component A12, PR-2b) |
| A4 | **Network attacker** | Partly | `kernel::net` exists (ARP/IPv4/ICMP); not modelled in this revision |
| A5 | **Disk / offline attacker** | Pointer | SentinelFS spec §12 |

## 4. What a component can and cannot do

**A component can:** consume its own budgets (by count now; fuel and memory once a metering
runtime exists); send to targets it holds capabilities for; delegate what it holds, attenuated or
equal, to instances it can already reach; revoke what it delegated; refuse to answer; lie in its
own payloads; on the native runtime, do anything kernel code can — which is exactly why that
runtime is first-party only.

**A component cannot, on any runtime (authority — enforced since PR-2):** forge `from`; reach a
target without a capability; use an index from another table, a revoked one or an expired one;
amplify a capability by delegating it; keep a delegated copy alive after its ancestor is revoked;
answer a request twice, late, or on someone else's behalf; make the kernel fabricate a reply; hold
a capability the policy did not grant; start without a capability its manifest marks required;
escape its identity (the host hashed what it runs).

**A component cannot, after the gate (memory):** read another instance's memory or a delegate's
secret; touch hardware; overrun its linear memory or its stack.

**What "cannot exhaust the machine" honestly means today.** Inboxes are bounded (`Busy`, never
growth), instance and capability tables are fixed slabs, payload arenas are sized at build time
inside the kernel-wide host (PR-2: `kernel::host`, `kernel::cap` and `kernel::bus` allocate
nothing, ever). But the kernel runs `panic = "abort"` with an infallible allocator over a 4 MiB
heap and 16 KiB guard-paged thread stacks, so an allocation failure or a stack overrun **halts the
machine** rather than corrupting it. A wasm runtime must therefore cap linear memory *before* it
allocates and prove its stack high-water mark stays under the guard page (component §12
conditions). Until then the claim is: *bounded by construction where we allocate; halt, not
corrupt, where we cannot.*

## 5. Threat register — component authority boundary (PR-2)

Evidence key: **boot** = a field of the `make test`-asserted line
`[cap] attested-from=yes deny-by-default=yes forge-attempt=refused denies-logged=N ok`
(`kernel::bus::proof::prove_caps`); **Kani** = a harness in `kernel::cap` discharged before merge
(the table harnesses are inductive — from any valid table state, one call of each mutator — so
they hold after every sequence of operations; spec §8);
**test** = a host unit test (also run under Miri in `verify.yml`).

| ID | Threat | Mechanism that defeats it | Evidence | Residual / status |
|---|---|---|---|---|
| **T-ATT-1** | A component claims to be another (forges `from` on an event, request, reply or delegation notice) | The host builds every envelope. Component code reaches the bus only through a `bus::Ctx` the host mints for the instance it is running; no bus API takes a sender, and `Ctx` cannot be constructed outside `kernel::bus`. `from = {instance, component}` is copied from the running instance's record (A2) | boot `attested-from` (event, request, reply and delegation notice each checked against the instance table); test `bus::tests::from_is_stamped_by_the_host_*` | Native code is ring 0 and could call crate-internal APIs; the source guard of T-NAT-1 keeps component modules from naming them |
| **T-CAP-1** | Ambient authority: send to any instance without a capability | Deny by default: `send`/`request` look the index up in the *sender's own* table; no API names a target; the policy table is an allow-list (no rule → nothing) | boot `deny-by-default` (carol: manifest asked, policy refused, every send/request/reply refused, nothing delivered) | — |
| **T-CAP-2** | Forge a capability index: never issued, minted for another table, revoked/used/reclaimed, expired | `CapIndex = generation:24 ‖ table:4 ‖ slot:4`. The table field must equal the holder's table (*foreign*); the slot's generation is bumped on every free and the slot retired at 2²⁴−1 (*stale* can never alias a newer capability, ABA-free); generation 0 is never issued; expiry is checked against `clock::mono_ticks()` on every use | boot `forge-attempt=refused` (all four classes, each with a positive control first); Kani `cap::table::proofs::no_capability_without_a_producer` (bounded sequence, ghost) and the inductive steps `producers_install_exactly_what_they_checked`, `revoke_removes_every_descendant`, `reclamation_frees_the_chosen_and_their_descendants` (only a producer installs, into an empty slot at its current generation; survivors never change; a freed slot's generation moves on or the slot retires, so an index to a freed capability never resolves again); tests | **Generation exhaustion — T-DOS-5.** Retiring is what keeps a stale index from ever aliasing, but every free spends a generation of one slot, so a table's lifetime is ≈ 2²⁴ × usable slots ≈ 235 M frees whatever slot is chosen, and retirement survives `clear_table`/`terminate`: the next instance in that host slot inherits the retired slots (instantiation counts them: a required grant that no longer fits refuses the start, an optional one is logged `table-full` — tests `bus::tests::grants_that_do_not_fit_*`, `an_optional_grant_without_room_*`). Decided (component A13): 48-bit generations in PR-2b |
| **T-CAP-3** | Amplify by delegation (more ops, a looser attenuation, a later expiry, another target) | `delegate` requires `Delegate` on the parent and installs the child only if `child.is_attenuation_of(parent)`: same target, `ops' ⊆ ops`, `attenuation' ⊑ attenuation`, `expires' ≤ expires`. One total, decidable predicate; reply capabilities never carry `Delegate` | Kani `delegate_never_amplifies` (semantic: every access the child permits at any tick, the parent permits) and `attenuation_order_is_sound_and_transitive` (⊑ sound and transitive; a well-formed reply right is `{Reply}` only — and the tables hold only well-formed capabilities); boot probes (longer payload limit, extra op) | — |
| **T-CAP-4** | Keep authority after revocation through a derived copy | Every capability records its parent `(table, slot, generation)`. `revoke` frees all descendants, `release` the capability and its descendants; every removal (also expiry, `terminate`) ends with an orphan sweep to the end of every chain, bounded by the slab size. Invariant: no live capability has a dead parent | Kani `revoke_removes_every_descendant` and `reclamation_frees_the_chosen_and_their_descendants`, from any valid table state: a capability is freed iff it was chosen or its parent was freed (with the delegation records a forest — they only gain leaves — that is exactly "every descendant, nothing else"); boot cascade probe (a grandchild in a third table is refused after the root's holder revokes); test `cap::table::tests::release_frees_a_full_slab_chain_in_worst_scan_order` (a 256-deep chain at the production size, in the scan order that needs every propagation round — the Kani bound alone, 2 × 2, cannot tell a round bound of `T·S` from `T·S/2`) | **No selective revocation:** `Ctx::delegate` returns `()`, so a delegator can revoke everything it derived from a capability (`revoke(cap)`) but not one delegation alone (spec §8, PR-2 limits) |
| **T-CAP-5** | Be granted more than policy allows | `grant` installs `request ∧ rule` (the meet: ops ∩, attenuation by ⊑, earliest expiry) and nothing when no rule matches. Refused optional requests are logged | Kani: `producers_install_exactly_what_they_checked` (a granted capability is exactly `request ∧ bound`) and `attenuation_order_is_sound_and_transitive` (the meet lies below both); boot (carol) | Policy is a static first-party table until the PolicyAgent (PR-5) |
| **T-CAP-6** | Run degraded after a required capability was refused (A8) | Manifests mark each request `Required` or `Optional`; all requests are resolved **before** any state changes; a missing required one refuses instantiation (`MissingRequiredCap`), logged | boot (carol with the request marked required is refused, instance count unchanged); tests | Requires the manifest to be honest: T-MAN-1 |
| **T-REP-1** | Forge or replay a reply; answer twice; answer after the requester gave up; make the host fabricate one | Each request mints a **one-shot reply capability** in the responder's table: target `(requester, tag)`, ops `{Reply}`, expiry `now + timeout` (requester's choice, clamped to 1..=1000 ticks). It is freed on successful use. An expired one is refused, and its slot is reclaimed (with every other expired capability in that table) exactly when the responder's table reaches either capacity limit — no free slot, or 4 reply rights pending — on the next request or authorised delegation to it, and when a late answer presents it; `terminate` of either party frees it too. Presenting an expired capability that is *not* a reply right to `reply` is refused and leaves it alone. The host never synthesises a `Reply` envelope: **silence is denial** | boot (second answer refused; late answer refused; requester's inbox empty); tests, incl. `bus::tests::expired_reply_rights_never_lock_a_silent_responder_out` and `an_expired_capability_offered_as_a_reply_right_is_refused_and_kept` | — |
| **T-DOS-1** | Flood an inbox | Fixed `InboxRing<Wire, 8>`: full → `Busy`, nothing dropped, nothing grows. Authority is checked **before** fullness, so an unauthorised sender learns nothing about the target | Kani `inbox_ring_is_fifo_and_never_loses_or_overwrites_bounded` (PR-1); test `bus::tests::unauthorised_sender_never_sees_busy_and_nothing_is_dropped` | — |
| **T-DOS-2** | Fill another instance's capability table (requests mint reply capabilities; delegations install children) | At most 4 pending reply capabilities per table; reply timeouts clamped to 1..=1000 ticks; expired capabilities are reclaimed when either capacity limit is reached (a request finding no free slot or 4 rights pending; an **authorised** delegation finding the table full, which is then retried once) and on a late answer — a refused call reclaims nothing and changes nothing; a delegation checks authority (`CapSpace::check_delegate`) and the recipient's inbox **before** installing, so a `Busy` delegation spends none of the recipient's generations; a delegation that would be dead on arrival (`ttl = 0`) is refused; delegating to an instance requires a `Send` capability to it; a full table answers `Busy` | tests (`bus::tests::expired_reply_rights_*`, `only_an_authorised_delegation_reclaims_*`, `a_delegation_into_a_full_inbox_spends_no_generation`, `a_delegation_dead_on_arrival_*`, `pending_replies_are_capped_*`) | One requester can hold all 4 pending-reply slots of a responder for up to 1000 ticks, again and again (no per-requester fairness). A holder of a `Send` capability can fill the recipient's table (16) by delegation, after which the recipient refuses every request (`Busy`) until it `release`s |
| **T-DOS-3** | Flood or erase the audit trail of denials | Per-holder token bucket (burst 8, one token per 50 ticks); suppressed denials are counted per holder and carried into that holder's next record; the 32-record ring counts every overwrite; nothing is printed per denial, so the console is not a component-controlled channel | boot (`denies-logged=N`, a burst from carol is partly suppressed, `logged + suppressed == total`); Kani `deny_log_counts_every_denial`; tests | In-memory, per boot: the IntegrityLog (PR-4) makes it durable and signed. One holder at the default rates can push every other record out of the 32-entry ring in about 12 s (8 at once, then one per 0.5 s); overwrites are counted, their contents are lost. Follow-ups: `reset_bucket` drops a trailing `suppressed_since` (refusals suppressed under a slot's previous instance never reach a record, though they stay in the totals); `NoSuchSender` refusals share the kernel bucket with instantiation refusals |
| **T-DOS-4** | Exhaust kernel memory through the bus | `kernel::host`/`cap`/`bus` never allocate: every instance's arena, every table and the log live in the kernel-wide static, sized at build time | review; `bus` has no `alloc` import | — |
| **T-DOS-5** | Retire another instance's capability table by churning its generations: every free spends one, a slot retires at 2²⁴−1, retirement survives `terminate` | **Open until PR-2b** (component A13): `CapIndex(u64) = generation:48 ‖ table:8 ‖ slot:8` makes the budget unreachable within a boot at the bus's maximum free rate; retirement stays (never wrap); instantiation plans grants against usable slots only | — (PR-2b: §8 arithmetic; cap harnesses on the wide index) | Today a client of an answering responder, or a delegator with `Send` to the victim (delegations into its table, then revoked), spends ≈ 235 M frees at bus speed. The cheapest path is closed in PR-2: a delegation into a full inbox used to install, then release — it is now answered `Busy` before anything is installed (T-DOS-2). Not reachable in PR-2's image (no long-lived responder); PR-3's KeyAgent is the first |
| **T-CON-1** | Deadlock or a stalled core through bus locks | One lock, `bus::HOST`: never taken from IRQ context, yet held only with interrupts masked (so its holder is never preempted and no same-core waiter can spin — hal-tcb §5e's rule, on its stricter side), never across a context switch, never around an allocation or a console write, and nothing else is acquired while it is held (a **leaf** lock). Component code always runs with no host lock held. Nothing on the bus spawns, parks or reaps a task | review (module docs of `kernel::bus`) | A native component that re-enters the bus from inside `bus::with_host` deadlocks its core (first-party bug class; the source guard of T-NAT-1 keeps component modules from naming `with_host`). Follow-up: a `HOST_OWNER` re-entrancy guard that turns that deadlock into a refusal |
| **T-CON-2** | Check-then-use race (capability revoked between check and enqueue) | Check, target resolution, reply-capability mint and enqueue happen in one critical section | review | — |
| **T-CON-3** | Make revocation slow, to hold the host lock (interrupts masked) for long | Revocation is bounded by the slab: the orphan sweep reads the slab once, propagates over a flag map — at most `slots` rounds of `slots` flags, stopping at the first round that changes nothing — and writes the slab once (16 × 16 slots: ≤ 65 536 flag steps, in the worst case of a 256-deep chain) | review; the bounds are loop constants; test `cap::table::tests::release_frees_a_full_slab_chain_in_worst_scan_order` | Bounded, not small, and not free: **every** removal pays at least three passes over the 256 slots under the lock with interrupts masked. A depth cap, incremental revocation or a fast path if it is ever measured on a hot path (not now: the verified code stays as verified) |
| **T-CON-4** | Run one instance's code on two cores at once (two `dispatch`es, or a `call` and a `dispatch`), so its handler races with itself | `dispatch` and `call` set the instance's `running` flag under the host lock before running its code and clear it after; while it is set both refuse (`CallError::Busy`) and take nothing | test `bus::tests::one_instance_never_runs_twice_at_once` | Which core drives which inbox, when, and fairness under the one IF = 0 lock is open for PR-3 (component spec §18.4) |
| **T-TIME-1** | Stall a clock to keep an expiring capability alive | Expiry and reply timeouts tick off `clock::mono_ticks()`: advanced by any core, never backwards, at most one per tick (Kani, PR-1b); one stalled core cannot stop it. The bus reads it **inside** the host lock: a tick read before waiting for the lock would be stale by the wait, and a stale tick fails open for expiry | Kani `mono_never_regresses_and_steps_by_at_most_one`; boot `[clock] mono … bsp-stalled-advance=yes` | If **every** core stops ticking, expiry is delayed (fails open for expiry only). Expiry bounds convenience grants; revocation is immediate and clock-independent |
| **T-ID-1** | A stale instance identity reused | `InstanceId`s are never reused (64-bit counter); at `terminate` every capability in the instance's table and every capability anywhere that targets it is freed (descendants included); a `Ctx` for a dead instance is refused | tests `bus::tests::terminate_*` | — |
| **T-INFO-1** | Learn other components' table layout from error codes | Components see only `Denied` or `Busy`; the precise reason goes to the audit log only | review | A delivered envelope carries the sender's `CapIndex` (its `cap` field), which reveals the sender's host slot and that slot's generation — a churn counter. Harmless to authority (an index is valid only in its own table), a small information channel |
| **T-MAN-1** | An instantiator strips a `Required` mark, or drops, adds or reorders a manifest's requests (`Ctx::granted(i)` is by manifest order, so a swap makes a component use one grant for another's purpose while every grant stays within policy) | **Decided (component A12), lands in PR-2b**: the id covers the declarations (v2 framing, requests in manifest order), so `verify` refuses an edited manifest as `IdMismatch` before anything runs; records name services, routed by the policy, so binding does not cascade. Until then not reachable: manifests are compiled into the image and only the kernel instantiates | — (PR-2b: tampered-declaration probe refused `id-mismatch`; Kani framing injectivity with records) | **PR-2b merges before PR-3 is opened**; never later than FS-4, the first persisted id, or the first manifest from outside the image |
| **T-NAT-1** | A native component bypasses the bus (ring 0, same crate): calls the host's crate-internal functions, the kernel's control channel `bus::call` (stamped `from = KERNEL`, no capability needed), or anything else in the kernel | **Accepted** for first-party code only (§2). A *confused* component is still kept honest at build time: it is handed only a `&Ctx`, which cannot be built outside `kernel::bus`; everything else on the bus (`HOST`, `with_host`, `locked`, `call`, `call_envelope`, `dispatch`, `instantiate`, `terminate`) is `pub(crate)`; and since component modules live in the same crate, a source guard fails CI if one names anything of `crate::bus` beyond `Ctx`, `BusError` and `Delegation`, or `Host`/`HOST`, or `crate::cap::table`. Under a memory boundary the component reaches only the `Ctx` operations (host imports), never `bus::call` | `cargo xtask check-component-imports` (kernel.yml step; component modules: `host/probe.rs`, `host/native.rs`, any future `components/`) and its unit tests in `kernel/xtask` | A source scan, not a proof: it stops a confused component, not a malicious one (A2, not admitted). Gate before PR-3 |
| **T-SEC-1** | Payload residue in reused arenas (signatures, plaintext replies) | **Open** (component A9) | — | PR-3 zeroizes arenas on revoke and exit |

## 6. Open items

1. **T-MAN-1** — decided (component A12): manifest declarations bound into the id by the v2
   framing, records naming services; lands in PR-2b, before PR-3 is opened.
2. **T-SEC-1** — arena zeroization (PR-3, A9).
3. **Memory boundary** — the gate before PR-3 (component §12); until then T-NAT-1 stands.
4. **Durable audit** — the deny log is in memory and per boot; PR-4's IntegrityLog signs and
   persists it.
5. **Policy authority** — the static boot policy becomes the PolicyAgent delegate (PR-5).
6. **Generation exhaustion** (T-DOS-5) — decided (component A13): `CapIndex(u64)`, 48-bit
   generations, codec `WIRE_VERSION` 2; lands in PR-2b, before PR-3 is opened.
7. **The run-to-completion driver** (T-CON-4 residual, component §18.4) — which core drains which
   inbox, when, and fairness under the one host lock (PR-3).

## 7. Change log

- 2026-10-03 — Created from component spec §16 (A10). PR-2 entries T-ATT-1 … T-SEC-1, including T-CON-3 (revocation cost) and the control-channel note in T-NAT-1; Kani evidence names as merged.
- 2026-10-03 — PR-2 review round 1 (kernel-reviewer): T-REP-1/T-DOS-2 state exactly when expired rights are reclaimed (the silent-responder lockout fixed); T-CAP-2 records generation exhaustion; T-CAP-4/T-CON-3 cite the production-size chain test; T-NAT-1 cites the component source guard; new T-CON-4 (per-instance reentrancy); residuals added to T-DOS-2, T-DOS-3, T-INFO-1, T-CON-1; T-TIME-1 notes the in-lock clock read.
- 2026-10-03 — kernel-architect decisions: T-MAN-1 restated (a reorder is the dangerous rewrite) and decided as component A12 (PR-2b); new T-DOS-5 (generation exhaustion), decided as A13 (PR-2b), the T-CAP-2 residual aligned; a `Busy` delegation no longer spends a generation (T-DOS-2).
