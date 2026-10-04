# Component Model — attested messaging, delegates, and content-addressed components

Status: **PR-1 + PR-1b implemented (2026-09-18); PR-2 implemented (2026-10-03)** —
`kernel::hash`, `kernel::host` (native runtime, envelope codec, inbox ring, manifests with
required/optional capabilities), `kernel::clock` (core-independent monotonic clock),
`kernel::cap` (per-instance capability tables, the `⊑` lattice, the rate-limited denial log) and
`kernel::bus` (the kernel-wide host; attested send/request/reply/delegate/revoke); boot lines
asserted; review round 1 complete, sequencing and the three open decisions settled in §19; A8
and A10 applied with PR-2 (the threat model now lives in `docs/security/threat-model.md`), A5,
A6, A7's remainder and A9 land with the PRs named there · Tracks A (kernel core) + D (security
subsystem) · Author: kernel-architect; PR-2 implementation: security-engineer — PR-2 review
round 1 (kernel-reviewer, 2026-10-03): blocked on three issues, all fixed (§19, *PR-2 review
round 1*); **pending kernel-reviewer re-review**. **PR-2b implemented (2026-10-04)** — A12
identity v2 (declarations in the id, records name services, policy = routes + allow-list) and
A13 wide indices (`CapIndex(u64)`, codec `WIRE_VERSION` 2); boot line gains
`manifest-tamper=refused` (§14, §19 *PR-2b implementation*); merges before PR-3 is opened
Depends on: SMP phases 1–3a (shipped: per-CPU scheduler, IPIs, per-core tick), `kernel::fs`
(persistence), `kernel::sched` (`spawn_on`, pinned tasks), `sentinel-core` (the portable
security crate + `SecurityProvider`), the Security Center design
(`docs/specs/2026-06-03-sentinel-security-center-design.md`, §5/§13), and the closed audit-log
proposal (PR #1, 2026-06-04), whose append-only hash-chained record is revived here as a
**state object**.
Escalation: **architectural.** This spec replaces two roadmap steps — VISION build-order 4
(*userland + syscalls*) and 6 (*port the Sentinel subsystem*) — with one design. The kernel-side
mechanism is safe Rust (zero new `hal` rows); the one contentious item is a third-party
WebAssembly interpreter near the trust boundary (§12), which needs **kernel-reviewer +
verification-engineer** sign-off as an *external TCB component* before it lands.

## 1. Summary

SentinelOS userland is not processes and POSIX. It is **components**: sandboxed units of code
identified by the hash of what they are, that own nothing they were not handed, that talk to
each other and to the kernel only through **messages the kernel stamps with the sender's
identity**, and whose shared state is an **object that validates itself**. Secrets live in
**delegates** — components that answer requests ("sign this", "decrypt this") but never release
the key. The kernel is small, is the sole attester, and exposes hardware only as **native
services** reached by capability. The security subsystem is not a privileged daemon bolted onto
this; it *is* a set of components under the same rules, and `sentinel-core` runs unchanged in the
desktop Security Center and in the OS because both host it the same way.

The model is Freenet's (core + contracts + delegates + UIs; summaries/deltas; platform-attested
callers; "no reply means no") applied to a single machine with a coordinator. Where Freenet's
constraints exist to survive having *no* coordinator — the commutative-monoid discipline on all
shared state — we adopt them **only** for state that genuinely crosses devices or partitions
(§10). Everything else keeps the kernel as arbiter.

## 2. What we take from Freenet, and what we do not

| Freenet | SentinelOS | Take? |
|---|---|---|
| Small core (<5 MB) hosting sandboxed wasm components | Framekernel: `hal` TCB + safe kernel hosting components; native services for hardware and compute | **Yes** — already our shape |
| Contracts: replicated state whose code defines validity; `summarize_state` / `get_state_delta` / `update_state`; state forms a commutative monoid | **State objects**: `validate` / `update` always; `summarize` / `delta` / `merge` **only** for the *mergeable* class (integrity log, identity directory, sync-able preferences) | **Scoped** |
| Delegates: hold secrets, act on the user's behalf, message-only interface, "applications use secrets without receiving them" | **Delegates**: identical role; kernel-hosted; secrets store encrypted at rest | **Yes** |
| UIs: web apps over WebSocket to the local core | **UI components**: wasm components drawing into a compositor surface capability (Cyber Dusk widgets are a native service) | **Yes**, different transport |
| Caller identity attested by the platform; absence of a response is denial | Kernel stamps every message's sender; deny by default; no implicit grants | **Yes** — the highest-leverage rule |
| Key-based addressing: address = hash(code, parameters) | **Content-addressed component identity**; the kernel verifies the hash before instantiation | **Yes** |
| Small-world routing, peer discovery, network replication | Out of scope for the OS. A future "sync" component may *use* Freenet; the kernel does not embed it | **No** |
| Commutative monoid on **all** contract state | Only on mergeable state objects. Scheduler, memory, drivers, filesystem metadata are kernel-arbitrated, single-writer, and stay that way | **No** (cargo cult otherwise) |

## 3. Vocabulary

- **Component** — a sandboxed unit of code plus its instantiation parameters, identified by a
  [`ComponentId`](#6-identity) = hash(code ‖ params ‖ declarations) — the declarations being the
  capabilities it requests and the services it provides (v2, A12; shipped in PR-2b).
  Three kinds: **state object**, **delegate**, **UI**.
- **Service** — a capability the safe kernel exports natively (compute/GEMM, compositor surface,
  storage, network socket, clock, randomness, integrity vectors). Services are the *only* path
  to hardware.
- **Capability** — an unforgeable, kernel-held reference `(target, allowed ops, attenuation,
  expiry)` that a component can *use* but never *fabricate*. Held in a per-component table
  inside the kernel; a component sees only opaque indices.
- **Attested message** — an envelope the kernel delivers with `from: ComponentId` filled in by
  the kernel, never by the sender.
- **Delegate** — a component with a **secrets store** and a message policy; performs
  operations *with* a secret on request without ever returning it.
- **State object** — a component whose exports are pure, deterministic functions over a byte
  state: `validate`, `update`, and (mergeable class) `summarize`, `delta`, `merge`.
- **Host** — the safe-kernel module that instantiates components, runs them on the component
  runtime (§12), owns the capability tables, and routes messages.

## 4. Principles (each is testable; each maps to a boot proof in §14)

1. **The kernel attests identity.** Every delivered message carries the sender's
   `ComponentId`, stamped by the host from the *running instance*, not from message content.
   A component cannot claim to be another. (Proof: PR-2.)
2. **No ambient authority.** A component can only act through capabilities it was granted at
   instantiation (manifest) or handed at runtime (delegation, attenuated). Default is deny;
   an unanswered request is a denial; there are no implicit grants and no time-based upgrades.
   (Proof: PR-2.)
3. **Secrets never cross a boundary.** Keys and tokens live in delegates; requests get
   signatures, plaintexts, or decisions back — never the material. The secrets store is
   readable only by the owning delegate instance. (Proof: PR-3.)
4. **Components are what they hash to.** `ComponentId = H(code ‖ params ‖ declarations)` (v2,
   A12; shipped in PR-2b). The host verifies the hash of the bytes it is about to run, and of
   what they declare, against the id it was asked for. Two instances with the same id run the
   same code with the same parameters and the same capability requests and provided services;
   state is per instance. (Proof: PR-1; declarations: PR-2b, `manifest-tamper=refused`.)
5. **State objects validate themselves.** No one, including the kernel, mutates a state
   object's bytes except through its own `update`, which rejects invalid transitions.
   Mergeable objects additionally satisfy `merge(a, b) == merge(b, a)`,
   `merge(a, merge(b, c)) == merge(merge(a, b), c)`, `merge(a, a) == a` — proven on host for
   bounded inputs. (Proof: PR-4.)
6. **Message passing only.** No shared mutable memory between components. Large read-only
   payloads may later travel as a shared-buffer capability; mutable sharing is never a
   primitive.
7. **Bounded resources.** Every component runs under a fuel budget (instructions), a memory
   limit, and a fixed-size inbox. A full inbox refuses with `Busy`; nothing in the host
   allocates on behalf of an untrusted sender under a lock (the rule `kernel::sched` already
   lives by).
8. **Pure where verifiable.** State-object functions are deterministic and I/O-free, so they
   run identically on the host toolchain and in the kernel: unit tests, Miri, and Kani apply
   to the real code.
9. **Hardware only through services.** Components never see ports, MMIO, or interrupts.
   Compute stays native (the AVX-512/AMX tiers), exposed as a service; wasm SIMD is 128-bit
   and is not how we do inference.

## 5. Architecture

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  components (sandboxed, content-addressed)                                     │
│   ┌─────────────────┐  ┌──────────────────┐  ┌────────────────────────────┐   │
│   │ state objects   │  │ delegates        │  │ UI components              │   │
│   │ IntegrityLog    │  │ KeyAgent         │  │ Security Center            │   │
│   │ IdentityDir     │  │ PolicyAgent      │  │ Terminal / Files / …       │   │
│   └────────┬────────┘  └────────┬─────────┘  └──────────────┬─────────────┘   │
│            │  attested messages │                            │                 │
├────────────┴───────────────────┴────────────────────────────┴─────────────────┤
│  safe kernel (#![forbid(unsafe_code)])                                         │
│   kernel::host      instantiate · verify id · runtime trait · fuel/memory caps │
│   kernel::cap       per-component capability tables · grant/attenuate/revoke   │
│   kernel::bus       fixed inbox rings · kernel stamps `from` · request/reply   │
│   kernel::secrets   per-delegate encrypted store                               │
│   kernel::state     drives state-object exports; persistence via kernel::fs    │
│   services          compute (ml) · compositor (wm/ui) · storage (fs) ·         │
│                     net · clock (pit/lapic) · integrity vectors (sentinel)     │
│   sched · smp · mm · fs · net · interrupts   (unchanged, kernel-arbitrated)    │
├───────────────────────────────────────────────────────────────────────────────┤
│  hal (the TCB)   ports · MMIO · paging · ISRs · LAPIC · context switch          │
│  external TCB    the component runtime (§12) — pinned, inventoried, gated       │
└───────────────────────────────────────────────────────────────────────────────┘
```

Nothing above the line touches hardware. Nothing below the line trusts a component. The
host is the only code that turns component bytes into a running instance, and the bus is the
only code that moves a message — both safe Rust, both small enough to reason about.

## 6. Identity

```rust
pub struct ComponentId([u8; 32]);          // SHA-256(v2 frame: code, params, requests, provides)
pub struct InstanceId(u64);                // per boot, per instantiation
```

- **SHA-256**, pure safe Rust, `no_std`, in the safe kernel (`kernel::hash`): the closed PR #1
  already argued for it (no `unsafe`, no `serde`, test vectors + a Kani harness on the
  compression-function padding arithmetic). BLAKE3 is faster but adds a dependency; revisit
  when component sizes make hashing measurable.
- **Framed, not concatenated** (A1). `TAG = b"sentinelos:component:v1"`; each field is
  length-prefixed. Unframed `H(code ‖ params)` lets `(A, BC)` and `(AB, C)` share an id, so the id
  would not bind the code/params split. Kani target: the framing is injective on bounded inputs.
- **Declarations join the id (A12; decided 2026-10-03, shipped in PR-2b 2026-10-04 — after PR-2,
  before PR-3 is opened).** v1 covered code and params only, so one id could arrive with different capability
  requests (threat model T-MAN-1). v2 is
  `SHA-256("sentinelos:component:v2" ‖ le64(|code|) ‖ code ‖ le64(|params|) ‖ params ‖ le64(n) ‖ req₁ ‖ … ‖ reqₙ ‖ le64(m) ‖ prov₁ ‖ … ‖ provₘ)`.
  Requests keep **manifest order** (`Ctx::granted(i)` indexes by it, so order is meaning):
  `req = service[32] ‖ le32(ops) ‖ u8(need: 0 = Required, 1 = Optional) ‖ u8(attenuation kind) ‖ le16(len) ‖ attenuation[len]`;
  kind 0 is `Message` (`len = 2`, `le16(max_len)`); FS-1c's storage attenuation is kind 1 with its
  own canonical encoding — additive. `prov = service[32]`, the services the component answers,
  strictly ascending (a set has one encoding). Still one `frame_into` for the hasher and the Kani
  sink; the injectivity harness gains both lists. *As shipped:* `kernel::host::frame_into`,
  `TAG = b"sentinelos:component:v2"`; a non-canonical `provides` (unsorted or duplicated) is
  refused before hashing (`InstantiateError::NonCanonicalProvides`); `code` is **inlined** (§18
  item 8, decided; the by-reference variant is a v3 option, §19 A14); `ServiceName` is
  `kernel::cap::ServiceName`, canonical by construction (every constructor checks the bytes).
  `frame_into` is exactly three writers into one sink — `frame_head` (tag, code, params),
  `frame_requests`, `frame_provides` — and the injectivity proof is three harnesses composed by
  the prefix-free-code argument (§19 *PR-2b implementation*).
- **Records name services, never a `ComponentId`.** A target id would make every id a function of
  the ids it declares: one update rekeys every transitive dependent and voids every policy rule,
  allow-list and consent that names them; mutual declarations become a hash cycle, and so does
  §9's own pair — the KeyAgent's allow-list names the Security Center's id while the Security
  Center declares the KeyAgent; and a kernel service (storage, compute) has no id to name. The
  policy routes each service to a provider id (§8) and honours a route only to a component whose
  own id-bound `prov` list names that service, so a provider is chosen by two parties, neither of
  them the instantiator. "A was reviewed against exactly B" is recorded in the route, where it is
  enforced; updating B changes one route, not A's id.
- **The stored form (FS-4).** A component image in the `Public` blob domain is exactly the v2
  framed input, so its plain SHA-256 is the id ("the id is the storage key"); the loader takes
  code, params and declarations from that verified image through a total, canonical decoder
  (Kani: `decode ∘ encode = id`; non-canonical bytes refused) — never from anywhere else.
- The host **verifies** `H(framed(code, params, declarations)) == requested id` before instantiation; a mismatch is
  a refusal, logged to the IntegrityLog. This is what makes "the kernel knows what it runs"
  literal, and it composes with the vision's "verifiable by design".
- Identity is *what*, instance is *which*. Capabilities and messages address **instances**. A
  manifest's requests named component **ids** until PR-2b and name **services** since; the policy
  routes each service to a provider id, and the host binds that id to an instance (§8).

## 7. Messages and attestation

```rust
pub struct Envelope {
    pub from: Sender,              // written by the kernel, never by the sender
    pub to: InstanceId,            // resolved from the capability used to send
    pub cap: CapIndex,             // the sender's capability that authorised this send
    pub kind: Kind,                // Request { reply_tag } | Reply { reply_tag } | Event
    pub payload: Bytes,            // ≤ MAX_PAYLOAD; larger via a shared-buffer cap (later)
}
pub struct Sender { pub instance: InstanceId, pub component: ComponentId }
```

- **Attestation names both ids** (A2). Capabilities and inboxes address *instances*; delegate
  allow-lists and policy ("only sign for the Security Center") name *components*. The kernel
  stamps both from the running instance's record; the sender writes neither.

- **Send** = `bus::send(cap, payload)`. The host looks up `cap` in the *sender's* table,
  checks `op::Send` is allowed for that target, fills `from` from the running instance, and
  enqueues into the target's inbox ring. The sender never names a target directly.
- **Inbox** = fixed ring per instance (`MAX_INBOX` envelopes, payloads in a fixed arena). Full
  → `Err(Busy)` to the sender; nothing is dropped silently and nothing grows.
- **Request/reply** carries a `reply_tag`; the reply travels back over a one-shot reply
  capability the host mints for that request and revokes on use or timeout. Timeouts are the
  requester's concern; the host never fabricates a reply. **Silence is denial.** *(As shipped
  in PR-2: freed on use, or when the responder releases it, declining to answer. Once expired it
  is refused, and its slot is reclaimed together with every other expired capability in the
  responder's table when the next request to the responder finds either capacity limit
  reached — no free slot, or 4 reply rights pending — or when an authorised delegation to the
  responder finds its table **full**; on its own when the responder releases it or a late answer
  presents it; threat model T-REP-1, T-DOS-2.)*
- **Delivery** is by the scheduler: a component instance is a pinned task (`spawn_on`); an
  inbox push wakes it exactly like the reschedule IPI wakes a core today. Cross-core delivery
  reuses that path unchanged. *(Superseded at PR-2 by run-to-completion dispatch; measurement
  and decision in §18.4.)*
- Cross-core safety follows `kernel::sched`'s rule: bus locks are taken with interrupts
  masked, never across a switch, never around an allocation — the payload arena is
  pre-sized at instantiation.

**As shipped in PR-2** (`kernel::bus`, 2026-10-03):

- **Component code acts only as itself.** It runs in exactly two places, `bus::dispatch` (one
  envelope from the inbox → the instance's message handler) and `bus::call` (a kernel call into
  an export), each with no host lock held and handed a `bus::Ctx` minted for *that* instance.
  `Ctx` cannot be built outside `kernel::bus` and no operation on it takes a sender or a target:
  `bus::send(cap, payload)` above is `Ctx::send(cap, payload)`, and likewise `request`, `reply`,
  `delegate`, `revoke`, `release`. The host stamps `from` from the running instance's record.
  On the native runtime this stops a *confused* component, not a malicious one (§16 → threat
  model T-NAT-1).
- **Reply tags.** Both ends see kernel-chosen tags. The responder's `Request { reply_tag }` *is*
  the `CapIndex` of the one-shot reply capability minted in **its** table (target
  `(requester, tag)`, ops `{Reply}`, expiring at the requester's timeout, clamped to
  `1..=1000` ticks, at most 4 pending per table); it answers with `Ctx::reply(CapIndex(reply_tag),
  …)`, which spends the capability. The requester's `Reply { reply_tag }` is the tag
  `Ctx::request` returned. *Since PR-2b (R10) the two are distinct types:* the responder is handed
  `Request { reply: CapIndex }` and answers `Ctx::reply(reply, …)`; the requester gets a
  `ReplyTag(u64)` from `Ctx::request` and sees it again as `Reply { tag }` — not an index, so it
  cannot be presented as one by mistake. Both travel in the wire's `u64` `reply_tag` field; a
  kernel call's `Request` carries `CapIndex::KERNEL` (the export answers by returning). A late or second answer is refused; nothing is fabricated. Expired
  rights are reclaimed as in the *Request/reply* bullet above, so requests a responder leaves
  unanswered can never lock it out.
- **Delegation notices.** A delegated capability is announced to its recipient by a
  kernel-written `Kind::Grant { granted }` envelope (wire kind 3; `from` = the delegator, `cap`
  = the delegator's `via` capability). The recipient learns its new index from the kernel,
  never from the delegator's payload, so a delegator cannot point it at one of its *own*
  capabilities (no confused deputy).
- **The kernel's control channel.** Kernel calls (`bus::call`, PR-1's `greet` path) need no
  capability and never enter the instance's inbox: still built and stamped by the kernel and
  round-tripped through the envelope codec, but component traffic can neither delay nor
  displace them. The inbox carries component traffic only.
- **Authority before capacity.** An unauthorised sender gets `Denied`, never `Busy`, so it
  learns nothing about the target's inbox; components see only `Denied`/`Busy`, the precise
  reason goes to the denial log (§8).
- **One leaf lock, no allocation.** The kernel-wide host (`bus::HOST`) holds every instance's
  inbox arena, every capability table and the denial log in one fixed value sized at build
  time — the bus allocates nothing, ever. Its lock is taken with interrupts masked, held for
  bounded table/ring work only, never across a switch, never around an allocation or a
  console write, and **nothing else is acquired while it is held** (a leaf: never nested with
  `sched`'s queue → table locks, the console lock or the heap lock). Check, target resolution,
  reply-capability mint and enqueue are one critical section, and the mono clock is read inside
  it (a tick read before waiting for the lock is stale by the wait, and fails open for expiry).
  Against hal-tcb §5e's rule
  (IRQ-reachable locks only with `IF = 0`; others may be held with `IF = 1` if no same-core
  waiter spins): `HOST` is **never taken from IRQ context**, and is held with `IF = 0` anyway,
  by choice — its holder is never preempted, so no same-core waiter can exist.
- **One instance, one core at a time.** `dispatch` and `call` set the instance's `running`
  flag under the host lock before running its code and clear it after; while it is set both
  refuse (`CallError::Busy`) and take nothing, so a handler never runs concurrently with itself
  (threat T-CON-4). Who drives dispatch is open for PR-3 (§18.4).
- **Only `Ctx` reaches component code.** Everything else on the bus is `pub(crate)`, and since
  native components live in the kernel crate, `cargo xtask check-component-imports` (a CI step)
  fails if a component module names anything of `crate::bus` beyond `Ctx`, `BusError` and
  `Delegation`, or the host, or `crate::cap::table` (threat T-NAT-1).
- **No blocking primitive.** Dispatch is run-to-completion (§18.4), so the bus needs no
  park/unpark; none is added to `sched`. When a component must block, the primitive is designed
  once (park/unpark with a wake permit and an optional mono-clock deadline) and shared with
  SentinelFS's commit task.

## 8. Capabilities

```rust
pub struct Capability {
    target: Target,                // Instance(InstanceId) | Service(ServiceId)
    ops: OpSet,                    // bitset: Send, Subscribe, Read, Write, Delegate, …
    attenuation: Attenuation,      // e.g. a storage path prefix, a byte quota, a vector set
    expires: Option<Tick>,
}
static CAP_TABLES: [SpinMutex<CapTable>; MAX_INSTANCES];   // fixed slab, kernel-only
```

- **Grant** at instantiation from the component's **manifest** (what it asks for) intersected
  with the **policy** for who is instantiating it — the user, via the PolicyAgent delegate
  (§9). Unrequested → not granted; requested but refused → instantiation still proceeds
  without it (a component must cope with denial, principle 2).
- **Delegate** (verb): a holder may pass a capability to another instance only *attenuated or
  equal*, never amplified. The host enforces `ops' ⊆ ops` and `attenuation' ⊑ attenuation`.
- **Revoke**: a grantor may revoke what it delegated; expiry is a tick. Revocation cascades
  through the delegation tree the host records.
- Components see `CapIndex`, an opaque `u64` (a `u32` until PR-2b, A13) valid only in their own
  table. Forgery is structurally impossible: the table lives in the kernel and indices are
  checked on use.
- Kani targets: "no capability exists in a table that was not produced by `grant` or by an
  attenuating `delegate`" over a bounded sequence of operations — the analogue of the
  scheduler's Invariant #4 proof.

**As shipped in PR-2** (`kernel::cap`, 2026-10-03):

- **Shape.** `Target = Instance(InstanceId) | Reply { to, tag }` (the per-request reply right;
  never granted, never delegable). `OpSet` bits: `Send`, `Request`, `Reply`, `Delegate`;
  well-formedness ties ops to the target (`Instance` ⊇ `{Send, Request, Delegate}`, `Reply` =
  `{Reply}`) and the attenuation's kind to the target. `Attenuation::Message { max_len }`, a
  total order (`max_len ≤ MAX_PAYLOAD`). `expires: Option<Tick>` on `clock::mono_ticks()`,
  exclusive. `Service(ServiceId)` is not built yet: no service exists to designate.
- **One predicate.** `Capability::is_attenuation_of` (`⊑`): same target, `ops' ⊆ ops`,
  `attenuation' ⊑ attenuation`, `expires' ≤ expires` — total, decidable, and the only thing
  `delegate` consults. What a capability *permits* is `Capability::permits(access, now)`; Kani
  proves `⊑` sound against it (whatever a child permits at any tick, its parent permits) and
  transitive.
- **Grant** = `request ∧ policy`: the meet (ops ∩, attenuation by `⊑`, earliest expiry). The
  policy is a static allow-list of `(holder id, target id, ops, attenuation, ttl)`, **deny by
  default**, until the PolicyAgent (§9, PR-5). A manifest names component ids; the host binds
  each to the **oldest live instance** of that component. Every request is resolved before
  anything changes — against the policy and the room left in the new instance's table (retired
  slots excluded): a `Required` one that cannot be granted refuses the instantiation
  (`MissingRequiredCap`), an `Optional` one is skipped; both are logged (A8; no room is logged
  as `table-full`). The requests were not part of the id in PR-2 (threat model T-MAN-1). **Decided
  (A12), shipped in PR-2b (2026-10-04):** they are bound into it (§6, v2) and name **services** —
  `ServiceName`, a 32-byte canonical label (ASCII `[a-z0-9._/-]`, NUL-padded, the version in the
  name: `sentinel.keyagent/1`). The policy becomes two tables: **routes** `(service, provider
  id)`, one provider per service, honoured only if the provider's own manifest provides that
  service; and the **allow-list** `(holder id, service, ops, attenuation, ttl)`. A request
  resolves service → route → provider id → oldest live instance, then meets the allow-list's
  bound exactly as now; no route, no live provider, or a provider that does not provide the
  service refuses, logged. `Target::Instance`, the tables, `⊑` and every cap harness are
  unchanged; `Target::Service` stays reserved for kernel services, which a route names when the
  first exists (FS-4). *As shipped:* `cap::Policy { routes: &[Route { service, provider }], rules:
  &[PolicyRule { holder, service, ops, attenuation, ttl }] }`; `Host::plan_grant` resolves, in
  order, route (exactly one — a service routed twice routes nowhere, fail closed; the boot policy
  is checked at build time) → `NoRoute`; oldest live instance of the provider id → `NoProvider`;
  that instance's verified manifest provides the service → `NotProvided`; the holder's rule →
  `PolicyRefused` (new `DenyReason`s `no-route`, `no-provider`, `not-provided`). A refused
  `Required` request is logged as `missing-required`, as in PR-2. Each provider instance records
  the `provides` of the manifest it was verified from, so the check reads the id-bound list.
- **Delegate** requires `Delegate` on the parent and a `via` capability carrying `Send`: you can
  hand authority only to an instance you can already reach. The child keeps the parent's
  target and records its parent `(table, slot, generation)`.
- **Revoke / release.** `revoke(cap)` frees everything derived from `cap`, at any depth, in
  any table, and keeps `cap`; `release(cap)` frees `cap` too (for a reply capability: decline
  to answer). Every removal finishes with an orphan sweep — read the slab once, let "parent
  gone" flow down a flag map for at most `slots` rounds, write the slab once — so no live
  capability ever has a dead parent. Expiry needs no cascade (a child never outlives its
  parent) but gets the sweep anyway. `terminate` frees an instance's table and everything
  anywhere that names it.
- **Indices.** `CapIndex = generation:24 ‖ table:4 ‖ slot:4`. A foreign table field is refused
  (*foreign*); every free bumps the slot's generation, and a slot that would wrap is retired, so
  a revoked/used/reclaimed index is *stale* forever and never aliases a newer capability;
  generation 0 is never issued (`CapIndex::KERNEL` is valid nowhere). Tables: 16 instances × 16
  capabilities, a fixed slab inside the kernel-wide host.
  **Widened in PR-2b (A13; shipped 2026-10-04):** `CapIndex(u64) = generation:48 ‖ table:8 ‖ slot:8`
  (`GEN_MAX = 2⁴⁸ − 1`, `CapRef.gen`/`Slot.gen` `u64`, `FITS_THE_INDEX` up to 256 × 256; the
  production slab stays 16 × 16). Every free spends
  one generation of one slot, whichever slot `install` picks, so a table's lifetime budget is the sum
  over its usable slots — at 24 bits ≈ 235 M frees, which a client of an answering responder, or a
  delegator with `Send` to the victim, spends at bus speed (threat model T-DOS-5). At 48 bits a slot
  outlasts 325 days of continuous churn at 10⁷ frees/s, several times what one leaf lock sweeping
  ≥ 3 × 256 slots per free can deliver. Retirement stays as the never-wrap backstop; 8-bit table and
  slot fields let the slab grow (T-CON-3 bounds it, not the index) without another ABI change. The
  codec's `reply_tag` and `cap` become u64 (`WIRE_VERSION` 2, 68-byte header).
- **Denials are logged, rate-limited** (A8): `cap::deny::DenyLog`, fixed size, no allocation.
  Each record: tick, the kernel-stamped holder (instance + component), the index presented,
  the action, the reason. A token bucket per holder (burst 8, one per 50 ticks) — refusals at
  instantiation use the kernel's bucket — suppresses, never loses: suppressed refusals are
  counted and carried into the holder's next record, ring overwrites are counted, and
  `logged + suppressed == total`. Nothing is printed per denial.
- **Kani** (each discharged locally, the table harnesses on a 2 × 2 slab; times in §14's PR-2
  row). The target above is `cap::table::proofs::no_capability_without_a_producer`: a bounded,
  fully symbolic sequence from the empty slab, with a ghost of what each producer returned — two
  steps fit the budget (three take 139 s). Three **inductive** harnesses lift the bound: each
  starts from *any* table state satisfying the invariant (well formed; granted and reply
  capabilities parentless; a delegated one ⊑ a live parent that may delegate — no orphans) and
  applies one call of a mutator with symbolic arguments; between them they cover every mutator,
  so what they prove holds after every sequence, of any length.
  `producers_install_exactly_what_they_checked`: `grant`/`delegate`/`mint_reply` change exactly
  the slot they return, previously empty, to exactly the meet, the requested child or the reply
  right, and only ever add leaves to the delegation forest. `revoke_removes_every_descendant`
  (`revoke`, `release`) and `reclamation_frees_the_chosen_and_their_descendants` (expiry,
  `clear_table`, `free_where`): a capability is freed iff it was chosen or its parent was freed
  — every descendant, nothing else — survivors are unchanged, and a freed slot's generation
  moves on. These store `Token`, a 5-byte value whose ⊑ is an arbitrary symbolic relation (the
  tables are generic over `cap::Authority`), so they hold for every relation, `Capability`'s
  included. On `Capability` itself: `delegate_never_amplifies` (semantic: whatever the child
  permits at any tick, the parent permits) and
  `cap::proofs::attenuation_order_is_sound_and_transitive` (⊑ sound and transitive; the meet
  below both; a well-formed reply right is `{Reply}` only). Plus
  `cap::deny::proofs::deny_log_counts_every_denial`; the codec round-trip harness now covers
  `Grant`. Three code shapes exist for the verifier (constant-range scans; a slot at a run-time
  position copied, never borrowed; the read-once/write-once sweep; recorded in `cap::table`).
  They are **not free**: every removal now makes at least three passes over all 256 slots (scan,
  one propagation round, free), plus a round per chain link — up to (T·S)² = 65 536 flag steps —
  under the global host lock with interrupts masked; no fast path is added, so the verified code
  stays as verified (threat T-CON-3). On a 2 × 3 slab they took the revocation harness from over
  ten minutes (stopped) to 75 s, and the old sweep alone cost 2.4× on the 2 × 2 slab (72 s → 30
  s). 2 × 3 still overran for the removal steps (reclamation: 198 s), hence 2 × 2 for all of
  them — one size, so the induction composes. A 2 × 2 slab cannot tell the sweep's round bound
  `T·S` from `T·S/2`, so a host test drives a 256-deep chain at the production size in the scan
  order that needs every round (`release_frees_a_full_slab_chain_in_worst_scan_order`).

- **Limits of PR-2** (declared at review round 1). *No selective revocation of one
  delegation:* `Ctx::delegate` returns `()`, so a delegator can revoke everything it derived
  from a capability (`revoke(cap)`) but not one delegation alone; a per-delegation handle is an
  API question for PR-3. *Manifest grants are not re-issued when a target restarts:*
  `terminate` frees every capability naming the old instance, and a holder gets nothing for the
  target's next instance until the holder itself is re-instantiated (§18, item 7).
  *Generation exhaustion:* a table absorbed about 235 M frees per boot before its slots retired
  for good, and retirement outlives the instance (threat T-DOS-5; **closed in PR-2b**, A13: 48-bit
  generations — a slot outlasts 325 days of continuous churn at 10⁷ frees/s). A delegation no longer spends one when it answers `Busy`: authority
  and the recipient's inbox are checked before anything is installed
  (`CapSpace::check_delegate`).

**Extension point — storage capabilities (SentinelFS FS-1c).** Storage slots in as a purely
additive change, written against the same predicate: (1) `Target::Storage(..)` with its
`allowed_ops` arm, using new `Op` bits (reserved: bits 8–12 for `Read`, `Write`, `Snapshot`,
`Rollback`, `Format`; existing bits never move); (2) `Attenuation::Storage(..)` carrying the
SentinelFS §9 lattice (tree `Live | SnapshotRo(name)`, path prefix by components, blobs
`None | Domain(d) | RefSet`, quota) with its arms of `is_attenuation_of`, `admits` and `fits`
(cross-kind is `false`, so no new variant can weaken an existing one); (3)
`Access::Storage { op, path, bytes }`. `Attenuation::meet` (used by `grant`) is defined from
`⊑` alone — incomparable values simply do not grant — so it needs no new code; `delegate`,
`revoke`, the tables and every Kani harness are written against `⊑`/`admits`/`permits` and do
not change; FS-1c extends the harnesses' symbolic generators (`cap::proofs::any_target`,
`any_attenuation`, `any_access`) with the new variants and re-runs them, which turns the existing
"never amplifies" proofs into its own.

## 9. Delegates

A delegate is a component with two extras: a **secrets store** and a **message policy**.

- `secrets::put(key, bytes)` / `secrets::get(key) -> bytes` are services granted **only** to
  the owning delegate's instance capability; the host refuses any other caller. At rest the
  store is encrypted by `kernel::fs` with a device key; **key sealing without a TPM is an open
  question (§18)** — until then the device key is kernel-memory only and secrets do not
  survive a cold boot on a machine we cannot seal to.
- **Policy**: the delegate inspects `from` on every message and decides. The platform gives it
  a trustworthy `from`; the delegate supplies the allowlist. "Only sign for the Security
  Center's id", "only answer the compositor", "only when the user confirmed in the last
  minute".
- **The three first delegates.**
  - **KeyAgent** — holds the device identity keypair; `sign(bytes) -> Signature`,
    `verify(bytes, sig) -> bool`. Never returns a private key. Every IntegrityLog record is
    signed here.
  - **PolicyAgent** — the user's consent authority: answers "may component *X* have
    capability *Y*?" It is where "clean is a valid result — never invent threats" and
    deny-by-default become code the user owns.
  - **IdentityAgent** — pairs devices; issues attenuated capabilities for sync.

## 10. State objects

```rust
// exported by every state object (pure, deterministic, no I/O)
fn validate(state: &[u8], params: &[u8]) -> bool;
fn update(state: &[u8], delta: &[u8], params: &[u8]) -> Result<Vec<u8>, Reject>;
// exported additionally by the *mergeable* class
fn summarize(state: &[u8]) -> Vec<u8>;
fn delta(state: &[u8], other_summary: &[u8]) -> Vec<u8>;
fn merge(a: &[u8], b: &[u8]) -> Vec<u8>;            // commutative, associative, idempotent
```

- **Local class** (single writer, kernel-arbitrated): validity is the contract, no merge.
  Candidates: a component's own preferences, a UI's layout state.
- **Mergeable class** (partition-tolerant): the monoid laws hold and are **proven on host**
  (property tests + bounded Kani) before the object is trusted. Candidates, and the only ones
  for now:
  - **IntegrityLog** — a set of signed, content-addressed finding records
    (`Finding { id, vector, severity, first_seen, last_seen, sig }`); `merge` = union with
    `last_seen = max`; `validate` = every record verifies against the KeyAgent's public key
    and every `id` equals `H(vector ‖ identity)`. This is PR #1's audit log, done properly: the
    same object reconciles two devices' views, survives an offline period, and proves tampering
    by a failed `validate`. `sentinel-core`'s finding key already is content-addressed
    (Security Center spec §6).
  - **IdentityDir** — the user's paired devices and their public keys; union-merge.
- **Explicitly not state objects**: scheduler queues, page tables, driver state, filesystem
  metadata. They have a coordinator — the kernel — and a monoid would buy nothing but cost.
- Persistence: the kernel stores state bytes through `kernel::fs`; only the object's own
  `update` ever changes them; `validate` runs on load and a failure quarantines the object and
  logs to IntegrityLog.

## 11. The Sentinel security subsystem as components

This is the design's payoff and the reason the two roadmap steps merge.

| Security Center (Tauri) | SentinelOS | Same code? |
|---|---|---|
| `sentinel-core` (vectors, findings, snapshots, diff) | `sentinel-core` compiled as a **component** | **Yes** — unchanged crate |
| `SecurityProvider` impl per host OS (`macos`, `linux`) | **`sentinelos` provider = a native service** exposing the OS's own integrity vectors: loaded components and their ids, the capability grant/deny log, persistence (autostart manifests), network beacons (from `kernel::net`), delegate access attempts | New, kernel-side, safe Rust |
| findings kept in the app | findings appended to the **IntegrityLog** state object, signed by **KeyAgent** | New object |
| Tauri UI | **Security Center UI component** rendering through the compositor service | Ported UI, same tokens |
| "read-only by default; clean is a valid result" | **PolicyAgent** encodes it; no component can escalate its own grants | Rule becomes mechanism |

The OS's integrity vectors are richer than a host provider's because the OS *is* the platform:
"which code is running" is a list of verified hashes, not a heuristic; "what was granted" is
the capability log, not a TCC database read; "what persists" is the manifest set. Continuous
monitoring stops being detection and becomes bookkeeping.

## 12. Execution format: the decision

**Decision (revised 2026-09-18, §19): components are native first.** PR-1 lands the
`ComponentRuntime` trait with a **native** implementation and proves identity, attestation,
deny-by-default and silence-is-denial with no interpreter in the kernel. Under native-first the
boundary is **authority, not memory**: a native component is a pinned ring-0 task confined by what
it can *name* (`CapIndex`) and *reach* (the bus). That stops a confused component, not a malicious
one; §16 must say so, and no non-first-party component runs until a memory boundary exists.
Whether that boundary is **wasm (`wasmi` under the conditions below)** or **ring-3 ELF** is a
dated gate: its own spec, decided **before PR-3 merges**. Neither is rejected. The trait gets its
second implementation at that gate, before it freezes.

| | wasm components (interpreter in the safe kernel) | native ELF processes (ring 3, paging isolation) |
|---|---|---|
| Isolation | By construction: linear memory, no pointers out, fuel + memory caps | By hardware: page tables, privilege levels; needs a syscall trampoline + user/kernel copy discipline (new `hal` rows) |
| Portability | The **same** component runs in the Tauri Security Center (host wasm) and in the OS — "write once" made literal | OS-specific ABI; every app is a port |
| Identity | `H(code ‖ params)` over a small, platform-independent blob | Hash of an ELF; toolchain-dependent bytes |
| Verification | State-object functions run under Miri/Kani on the host as-is | Harder; user-mode code is opaque to the kernel's verification |
| Performance | Interpreter: fine for policy, UI logic, logs; wrong for inference (128-bit SIMD only) | Native |
| TCB cost | A third-party interpreter **with internal `unsafe`** near the boundary | Ring-3 entry/exit, `swapgs`, user-pointer validation — sharp `hal` work |
| Fits the wedge (private AI compute) | Yes, with compute as a native service the component *asks* for | Also yes, later, via a compat layer |

**Wasm candidate: `wasmi`** (2.0.0, 2026-09-01): a pure-Rust interpreter with first-class
`no_std` support, built-in **fuel metering**, and the proposals we want (bulk memory,
multi-value, SIMD, reference types). Spike, same day: `default-features = false,
features = ["validate"]` builds for `x86_64-unknown-none`; 10 packages in the tree; ~135 k
lines of third-party code, none `#![forbid(unsafe_code)]`; `unsafe` sites by grep in §19.
**Conditions to pass the gate** (kernel-reviewer, security-engineer, verification-engineer):
exact pinned **and vendored** version with an audit trail (not a 17-day-old major); the
`unsafe` inventory registered as an external-TCB row in a new `kernel/docs/external-tcb.md`
(hal-tcb §1 amended to admit that class; `crates/host`'s own code `#![forbid(unsafe_code)]`);
a `ResourceLimiter` that caps linear memory *before* allocation; fallible allocation or a
pre-reserved arena (today's allocator aborts on OOM); a measured stack high-water mark under
the guard page for parse + instantiate + run; a page-table backstop under linear memory; a
loader fuzz target with a persisted corpus in a **gating** CI lane (none exists today); the
upstream suite run in **our `no_std` config**, not the host one. Two further facts:

1. It is **not** `#![forbid(unsafe_code)]`. Its `unsafe` surface (executor, memory access)
   is inventoried (§19 baseline; `cargo geiger` at the gate), the version pinned and vendored,
   and the crate registered in `kernel/docs/external-tcb.md` (A5) as an **external TCB
   component** with the limits we rely on (fuel bound, memory bound, no host imports beyond the
   bus/service shims) and its own lane: the loader fuzz target, the upstream suite in our
   `no_std` config, and the one in-kernel boot vector (not a differential test, A7). It lives
   in a **new crate** `crates/host` whose own code is `#![forbid(unsafe_code)]` — `kernel` and
   `ui` stay `#![forbid(unsafe_code)]` and `hal` stays the only place *we* write `unsafe`.
2. It is **swappable**: `trait ComponentRuntime { fn instantiate(..); fn call(..); fn fuel(..) }`
   is the only thing `kernel::host` sees. A safe-Rust interpreter of our own is a real,
   bounded project (core wasm is small; fuel is trivial to add) and becomes the plan the day
   `wasmi`'s unsafe inventory or size stops being acceptable.

**Component ABI**: raw core-wasm exports with a fixed envelope codec (length-prefixed bytes),
**not** the wasm Component Model / WIT. WIT tooling is heavy, moving, and not `no_std`; the
envelope codec is a few hundred lines we can prove. Revisit when the ecosystem settles.

## 13. Kernel changes (all safe Rust)

| Module | Role | Notes |
|---|---|---|
| `kernel::hash` | SHA-256 | pure; test vectors + Kani on padding arithmetic |
| `kernel::host` | instantiate / verify id / run on `ComponentRuntime`; per-instance fuel + memory caps; manifests with required/optional caps | PR-2: kernel-wide (`bus::HOST`); run-to-completion dispatch, not instance = task (§18.4) |
| `kernel::cap` | fixed slab of per-instance tables; `grant` / `delegate` / `revoke` / `check`; denial log | shipped PR-2; Kani: no forgery, never amplifies, revoke removes every descendant |
| `kernel::bus` | inbox rings + payload arenas; `send` stamps `from`; reply caps | shipped PR-2; allocates nothing; one leaf lock |
| `kernel::secrets` | per-delegate store; encrypted via `fs` | key sealing: §18 |
| `kernel::state` | drives state-object exports; load-time `validate`; persistence | monoid proofs on host |
| `kernel::services::*` | compute (`ml`), compositor (`wm`/`ui`), storage (`fs`), net, clock, integrity vectors | thin capability-checked shims over existing modules |
| `crates/host` | the component runtime crate (ours + `wasmi`) | external TCB; gated |

PR-1 as shipped: `kernel::hash` and `kernel::host::{codec, inbox, native}` inside the `kernel`
crate (`#![forbid(unsafe_code)]`); `Host<R: ComponentRuntime>` is built by the boot proof and
becomes a kernel-wide instance in PR-2 when the bus needs it. `crates/host` appears at the gate,
when there is a dependency to isolate.

PR-2 as shipped: `kernel::cap::{table, deny}` and `kernel::bus` (with `bus::proof`), plus
`kernel::host::probe` (the three first-party probe components of the boot proof). The host is
kernel-wide (`bus::HOST`, a `static` of ~60 KiB: every arena and table is inside it, nothing is
allocated). `ComponentRuntime` gained `release` and `entry`, and runs component code through
associated functions over a `Copy` entry (`call`, `deliver`) so the host can invoke it with no
lock held; native components gained a message handler and receive a `bus::Ctx`. The PR-1 hello
proof runs on the kernel-wide host and terminates its instance afterwards. `hal` delta: none.

**`hal` delta: none** for PR-1 through PR-5. Ring-3 support (GDT user segments, TSS `rsp0`,
`syscall`/`sysret` or `int` gate, user-pointer validation) is *only* needed if native
processes come later, and stays a separate spec.

## 14. Boot proofs and PR staging

Each PR is independently bootable and adds one hard assertion to `cargo xtask test`.

| PR | Lands | Boot-proof line (asserted) |
|---|---|---|
| **PR-1** hash + host (native) — **shipped 2026-09-18** | `kernel::hash` (SHA-256, framed id §6), `kernel::host` with `ComponentRuntime` + `native::NativeRuntime`, the embedded native `hello` component: a one-bit-wrong id refused before the runtime sees the bytes, the honest id verified, `greet` called through the inbox ring and the envelope codec with the kernel stamping `from` on request and reply. **Zero time-dependent semantics.** Kani (4 new harnesses): id framing injective, codec round-trip, decode total, inbox ring FIFO / never loses / never overwrites; plus SHA-256 padding. | `[comp] hello: id=<first 8 hex> verified=yes wrong-id=refused runtime=native reply=ok ok` |
| **PR-1b** clock (SMP 3b-i) — **shipped 2026-09-18** | `kernel::clock`: a core-independent monotonic clock — the max over per-core tick counts aligned on each core's first tick, advanced by *any* core's LAPIC tick via `fetch_max`, never backwards, at most one per tick (Kani). `sched::wait_on_other_core` and the preemption-proof tasks tick off it; hal-tcb invariant 4.15 retired as a hazard. LAPIC-derived, not TSC: zero `hal` delta. No IOAPIC, no MADT walk. Landed before PR-2 because `expires` and reply timeouts must not tick off a counter another core can stall. | `[clock] mono: source=lapic cores=4 ticking=4 lag-max=N pit-frozen=yes bsp-stalled-advance=yes rate=N/N rate-ok=yes ok` |
| **PR-2** bus + capabilities — **shipped 2026-10-03** | `kernel::cap`: a fixed 16 × 16 slab of per-instance tables; `grant` = manifest ∧ policy, `delegate` attenuated-or-equal by the one predicate `⊑`, `revoke`/`release` cascading through the recorded delegation tree, `check`; generation-tagged `CapIndex`; the allocation-free, rate-limited deny log. `kernel::bus`: the kernel-wide host — `bus::Ctx` send / request / reply / delegate / revoke, `from` stamped from the running instance's record, full inbox → `Busy`, a one-shot reply capability per request (revoked on use or timeout; the host never fabricates a reply). Three first-party native probes: alice holds a `Send` capability to bob; carol holds none (her manifest asks, the policy refuses; marked required, she refuses to start). `expires` and reply timeouts on the mono clock; **denials logged, rate-limited**; §18.4 decided (run-to-completion dispatch). Kani (7 new harnesses, each measured locally on a shared 4-core machine, re-measured after review round 1): no capability without a producer — bounded, 51 s — and its inductive steps (producers 19 s, revoke/release 31 s, reclamation 48 s); delegate never amplifies 7 s; `⊑` sound and transitive 4 s; deny log counts every denial 15 s. The PR-1 codec round-trip harness, extended to `Grant`, takes 82 s locally, 49.7 s in CI (86 s locally without the new kind: not a PR-2 regression, left at PR-1's bound; §19 R16). Review round 1 added the component source guard (`check-component-imports`) and the production-size revocation chain test. | `[cap] attested-from=yes deny-by-default=yes forge-attempt=refused denies-logged=N ok` (N = 13 on the reference boot) |
| **PR-2b** identity v2 + wide indices — **shipped 2026-10-04** | §6 v2 framing — declarations bound, records name services, `provides` (A12; `code` inline, §18.8); policy = routes + allow-list (§8), refusals `no-route` / `no-provider` / `not-provided` / `policy-refused`; `CapIndex(u64) = generation:48 ‖ table:8 ‖ slot:8`, codec `WIRE_VERSION` 2 with a 68-byte header (A13); distinct `ReplyTag` / reply `CapIndex` at the `Ctx` API (R10); every id literal regenerated (hello `f8ca98cb…`, alice `a03a9c97…`, bob `d921f1d5…`, carol `9fca63b0…`, carol-strict `4425fca7…` — its own id); the literal test walks every manifest in the image. Tamper probe: alice's id with a `Required` stripped, two requests swapped, an op added, a request dropped, a service added to `provides` — each `id-mismatch`, no instance, no grant planned. Kani, each measured locally on a 4-core machine shared with two other agents' Kani jobs (load ≈ 3): frame injectivity as three composed harnesses (§19 *PR-2b implementation*) — head injective and prefix-free 31 s, requests self-delimiting 49 s, provides 33 s; on the wide index (the four table harnesses and the codec round trip now name `minisat`; the default, cadical, in brackets) no capability without a producer 61 s [83], producers 29 s [34], revoke/release 37 s [69], reclamation 55 s [105], delegate never amplifies 10 s, `⊑` sound and transitive 1 s, deny log 19 s, codec round trip 35 s at payload bound 4 [113; 113 at bound 3, so the bound stays 4], decode total 3 s. Same-machine, same-hour baseline of the PR-2 code (cadical): no-producer 65 s, revoke 40 s, reclamation 62 s — the load, not only the width, puts the no-producer harness at the 60 s line. **Merges before PR-3 is opened.** | `[cap] attested-from=yes deny-by-default=yes forge-attempt=refused manifest-tamper=refused denies-logged=N ok` (N = 13 on the reference boot) |
| **PR-3** delegates + secrets | `kernel::secrets`, **KeyAgent** with an **ephemeral, memory-only key** (§18.1); zeroization of payload arenas on revoke/exit; a component requests a signature and verifies it; a probe tries to read the secret. | `[delegate] keyagent: signed=ok verified=yes secret-readable=no sealing=none secrets-persist=no ok` |
| **Gate** memory boundary | Docs: the wasm-vs-ring-3 decision spec with the §12 conditions checked off; `external-tcb.md`; the fuzz lane gating. Must merge **before PR-3**. | n/a |
| **PR-4** state objects | `kernel::state`, **IntegrityLog**; records carry a signing-key id resolved through IdentityDir (A6), so a new boot's key does not quarantine the previous boot's log; two divergent logs merged both ways; a tampered record rejected | `[state] integrity-log: merge-commutes=yes idempotent=yes tamper-rejected=yes ok` |
| **PR-5** Sentinel as components | `sentinel-core` as a component + the `sentinelos` provider service + **PolicyAgent**; the Security Center UI component | `[sentinel] sweep: vectors=N findings=N logged=yes signed=yes ok` |
| **SMP 3b-ii** IOAPIC | ACPI MADT walk (pure `&[u8] -> Result` parser in the safe kernel, Kani + fuzz), IOAPIC routing, PIC masked. Blocks nothing above; **after PR-3**. | existing `[smp]`/`[timer]` lines + `[ioapic] …` |

Every PR: host tests for the pure parts, Kani where the design names it (§8, §10, §6), the
`hal-tcb.md` external-TCB row updated with the pinned runtime version and inventory.

## 15. Verification plan

- **Pure code first.** Hash, capability algebra (`ops' ⊆ ops`, attenuation lattice), envelope
  codec, and every state object's `validate`/`merge` are `no_std` pure functions: unit tests,
  property tests on host, Miri, and bounded Kani — the same lane `kernel::sched` and
  `kernel::ml` already use.
- **Runtime as external TCB**: pinned version, `unsafe` inventory in `hal-tcb.md`, upstream
  test suite in CI, a fuzz target on the module loader, fuel/memory-cap tests that *fail* a
  runaway component in a bounded time (asserted in the boot test).
- **Differential**: the same component bytes executed on the host runtime and in the kernel
  produce identical state for identical inputs (principle 8 made a test).
- **Threat-model probes as boot proofs**: every "cannot" in §16 is a probe component in the
  boot test that tries it and is refused.

## 16. Threat model (what a component can and cannot do)

**Moved to [`docs/security/threat-model.md`](../security/threat-model.md)** (amendment A10,
PR-2, 2026-10-03), where it is a living document with a threat register: every entry names
the mechanism that defeats the threat and the evidence (boot proof, Kani harness or host test)
that it works. What used to be here — the Kerckhoffs assumption, the two boundaries
(*authority* from PR-1 on, every runtime; *memory* at the gate before PR-3, none on the native
runtime, hence first-party only), what a component can and cannot do, what "cannot exhaust the
machine" honestly means under `panic = "abort"`, and what is trusted — is there verbatim in
substance (§1–§4), extended with the PR-2 register (§5: T-ATT-1 … T-SEC-1) and the open items
(§6), among them **T-MAN-1** (manifest capability declarations are not yet bound into the
content address — decided as A12, lands in PR-2b) and **T-NAT-1** (a native component is ring 0).

## 17. What this changes in the roadmap

- VISION build-order **4 (userland + syscalls)** and **6 (port the Sentinel subsystem)** become
  this design; README roadmap **7** ("syscalls, processes") and **8** ("port `sentinel-core`")
  become PR-1…PR-5 above. Compositor/GUI (**5**) is unchanged and becomes the compositor
  *service*.
- The strategy doc's wedge ("models and data stay isolated from the host itself") gains its
  mechanism: a model and its data are components; inference is a native service they hold a
  capability to; nothing else can reach either.
- Native processes and the compatibility layer stay on the long road, now clearly *behind* a
  capability boundary rather than *as* the OS.

## 18. Open questions

1. **Key sealing without a TPM.** **Resolved 2026-09-18 (§19): ephemeral, memory-only key for
   PR-3**, asserted as `sealing=none secrets-persist=no` plus a second-boot probe
   (`cold-boot-recovered=no`). A key file on the fs is refused by all four roles: a key stored
   beside its ciphertext is not sealing, and the log's signature would mean "whoever could read
   the disk could sign". A passphrase waits for a memory-hard KDF (Argon2id) and a trusted input
   path; a TPM 2.0 driver reopens the question. Until then the signature means "this record came
   from this boot's KeyAgent": within-boot chain integrity only.
2. **Hash.** SHA-256 (in-tree, PR #1 precedent) vs BLAKE3 (dependency, faster). Start SHA-256.
3. **UI component rendering.** Draw commands into a compositor surface capability (small,
   fits Cyber Dusk's widget set as a service) vs. pixel buffers (flexible, expensive). Start
   with draw commands.
4. **Instance = task.** One pinned task per component instance is simple and reuses
   `spawn_on`; a run-to-completion actor model over fewer tasks may scale better. Measure at
   PR-2. **Decided at PR-2 (2026-10-03): run-to-completion dispatch** — the simplest model that
   meets the proof. *Measured* on the PR-2 boot (`[cap] measure:` line, informational; TCG,
   `-smp 4`, the unoptimised `make test` kernel, 100 Hz ticks, four boots; no KVM in the
   measuring environment): one complete delivery in the dispatch model — an attested
   `Ctx::send` plus one `bus::dispatch` that runs the handler — 1 300–2 371 per 5 ticks
   (≈ 21–38 µs); one context-switch round trip — the least instance = task adds to *every*
   delivery (switch to the instance's task and back, each switch with the eager per-task
   `xsave`/`xrstor`) — 1 209–1 836 per 5 ticks (≈ 27–41 µs), so instance = task would cost
   ≈ 1.9–2.3× per delivery (per boot: 1 + deliveries ÷ round trips). TCG timings are noisy
   and say little about hardware; the decision rests as much on what is counted. *Counted*: instance = task needs, per instance, a 16 KiB guard-paged stack, a
   4 160-byte `XsaveArea` on the heap and one of the scheduler's `MAX_TASKS = 64` slots (16
   instances = a quarter of every task the kernel can run); dispatch needs none — each
   instance's arena is part of the static host. *Missing*: instance = task also needs a
   block-on-inbox primitive (tasks can only yield or spin today) and a way to stop a task from
   outside for `terminate` (tasks only exit themselves); neither exists. Revisit when a
   component must block on something (the KeyAgent's user-confirmation path, PR-3) or when an
   instance needs its own stack for isolation (ring-3 at the memory gate). The `bus::Ctx`
   design does not change either way: a per-instance task would mint its `Ctx` the same way.
   **Open for PR-3: the driver.** Run-to-completion needs someone to run it: which core drains
   which inbox, when, and with what fairness under the one host lock held at `IF = 0` — today
   only the boot proof calls `dispatch`. **Closed at review round 1: per-instance reentrancy.**
   Two cores could run one instance's handler at once (`dispatch` + `dispatch`, or `call` +
   `dispatch`); `dispatch` and `call` now set the instance's `running` flag under the host lock
   before running its code and clear it after, and refuse while it is set (`CallError::Busy`),
   so handlers need not be reentrant (threat T-CON-4).
5. **Literal Freenet compatibility.** Could a Freenet contract or delegate run unmodified
   (`freenet-stdlib` ABI)? Tempting and out of scope; the ABI here is ours. Keep the door open
   by not inventing an incompatible *state* interface where theirs already fits (§10 mirrors
   their three functions on purpose).
6. **Runtime replacement trigger.** Define the `unsafe`-inventory and size thresholds at which
   the safe-Rust interpreter project starts, so the decision is made by a number, not a mood.
   Baseline measured 2026-09-18 in §19; the thresholds are written in the memory-boundary gate
   spec **before** `wasmi` lands, not after.
7. **Grants never re-bind** (PR-3). They are bound once, at the holder's instantiation, and
   `terminate` frees them, so a KeyAgent restart leaves every client without its capability.
   PR-3 needs something like `Ctx::rebind(i)`, re-running `plan_grant` for request `i`; routes
   (A12, shipped in PR-2b) make that well-defined: request `i` names a service, the route names
   the provider id, and `plan_grant` picks that id's oldest live instance — a restarted provider
   with the same id is found again, a different id is not (recorded only; PR-3).
8. **Inline `code` or `SHA-256(code)` by reference** in the v2 frame — to decide in PR-2b. The
   architect leans by reference, so large code dedups across params/declaration variants. A v3
   is free before FS-4 and a migration after. **Decided in PR-2b (2026-10-04): inline**, as v1
   did. It keeps FS-4's rule "the stored image *is* the v2 frame, its plain SHA-256 is the id"
   one object with one decoder, and nothing persists an id yet, so the choice costs nothing to
   revisit. The by-reference variant is recorded as a **v3 option to settle before FS-4** (§19
   A14).
9. **Service names for non-first-party components** (longer than 32 bytes, vendor collisions):
   decide at the memory gate.

## 19. Review round 1 (2026-09-18): consensus and amendments

Four roles read the spec independently and answered three questions: what is the next kernel PR,
the §12 execution-format fork, and §18.1 key sealing. Verdicts and the consensus:

| Question | kernel-architect | kernel-reviewer | security-engineer | verification-engineer | **Consensus** |
|---|---|---|---|---|---|
| Next PR | PR-1 native-first; a small core-independent clock before PR-2; IOAPIC after PR-3 | SMP 3b first: will not gate authority on a clock with a known stall path (hal-tcb 4.15) — unless PR-1/PR-2 carry no time semantics | PR-1 native; 3b becomes a security prerequisite the moment `expires` ticks off `pit::ticks()` | PR-1 native; fuzz lane built as its scaffolding | **PR-1 native-only with zero time semantics → PR-1b core-independent clock → PR-2.** IOAPIC (3b-ii) after PR-3. |
| §12 fork | wasm behind the trait, later; ring-3 rejected this cycle (largest TCB expansion in the project) | `wasmi` **blocked** in PR-1; "hal delta: none" is accounting, not reduction; conditions in §12 | ring-3 is the only boundary this seat trusts; `wasmi` in ring 0 inverts the framekernel thesis; wants a dated ring-3 spec | native-only; `wasmi` never before a gating fuzz lane; what we can prove is our side of the trait | **Native-only now.** Memory boundary (wasm under §12 conditions vs ring-3) is a dated gate, decided before PR-3. |
| §18.1 sealing | ephemeral; loud line | ephemeral; refuses image-shipped or constant-derived keys, weak KDFs, key files | ephemeral; key file never; passphrase honest but empty today | ephemeral; assert `persists=no` and a second-boot probe | **Ephemeral in-memory key for PR-3.** fs key file refused 4/4. |

**Spike (same day).** `wasmi = "2.0.0"`, `default-features = false, features = ["validate"]`,
`cargo build --release --target x86_64-unknown-none`: builds in 17 s; 10 packages in the tree
(`wasmi`, `wasmi_core`, `wasmi_ir`, `wasmi_collections`, `wasmparser 0.228`, `spin 0.9.9`,
`libm 0.2.16`, `bitflags 2.13`). `unsafe` sites by grep over `.rs`: `wasmi` 303 (executor
handlers 157, `code_map` 49, `instance` 58), `spin` 136, `libm` 57, `wasmi_collections` 27,
`wasmi_core` 12, `wasmi_ir` 3, `wasmparser` 1, `bitflags` 3. About 135 k lines of third-party code;
no crate in the tree is `#![forbid(unsafe_code)]`. `kernel/Cargo.lock` today has 6 packages with one
third-party crate (`limine`). This is the baseline the §18.6 trigger is measured against.

**Amendments.** A1–A3 are applied in this revision; the rest land with the PR named.

| # | Where | Finding | Status |
|---|---|---|---|
| A1 | §6 | `H(code ‖ params)` unframed: `(A, BC)` and `(AB, C)` collide, so the id does not bind the split. Domain tag + length prefixes. | applied |
| A2 | §7 vs §4/§9 | Envelope carried only `InstanceId`; attestation and delegate allow-lists need `ComponentId`. Kernel stamps both. | applied |
| A3 | §12/§14 | `wasmi` out of PR-1; PR-1 native-only; PR-1b clock inserted; memory-boundary gate before PR-3; IOAPIC after PR-3. | applied |
| A4 | §13/§16 | "hal delta: none" is TCB accounting, not reduction. §16 "cannot exhaust the machine" is false under `panic = "abort"`, an infallible allocator, a 4 MiB heap and 16 KiB stacks. Rewrite §16 for native-first: confines confused components, not malicious ones; non-first-party components barred until the gate; state the Kerckhoffs assumption. | applied (PR-1) |
| A5 | hal-tcb §1 | External dependencies need their own class: `kernel/docs/external-tcb.md`, admitted by an amendment to hal-tcb §1. `crates/host` own code `#![forbid(unsafe_code)]`; only the dependency is exempt. | gate |
| A6 | §10 vs §18.1 | An ephemeral key means IntegrityLog `validate` against "the KeyAgent's public key" quarantines the previous boot's log on reload. Records carry a signing-key id resolved through IdentityDir, or PR-4's log is explicitly in-memory. | PR-4 |
| A7 | §15 | No fuzz lane exists (hal-tcb §3: **pending**); nothing that depends on fuzz merges before the lane gates. "Differential host vs kernel" is one hand-picked vector, not a property; say so or drop it. The upstream `wasmi` suite is `std`-only. Missing: a Kani ring harness (full → `Err(Busy)`, never overwrite, never lose) and a host-side threaded model of the bus rings for data races (Miri only sees host threads). | ring harness applied (PR-1); fuzz + race model at the gate |
| A8 | §8/§11 | Denials are asserted but never logged; §11 sells the capability log as an integrity vector. Log denies, rate-limited. Manifests need `required` vs `optional` caps: refuse to start rather than run degraded. | **applied (PR-2)**: `cap::deny::DenyLog` — every refusal logged with the kernel-stamped holder, index, action and reason; per-holder token bucket, suppressed counted and carried, never lost; `CapNeed::{Required, Optional}`, a missing required capability refuses the start (`MissingRequiredCap`) |
| A9 | §7/§9 | Zeroization: payload arenas are reused, so signatures and plaintext replies linger; zero on revoke and exit. Delegates are either TCB with registry rows or not trusted — §16 currently assumes both. | PR-3 |
| A10 | §16 | Eight lines in a design doc is not a threat model; `docs/security/` does not exist. Split §16 out when PR-2 lands. | **applied (PR-2)**: `docs/security/threat-model.md` (§16 moved, extended with the PR-2 threat register); §16 is a pointer |
| A11 | §12 | `wasmi` 2.0.0 was 17 days old at review. No brand-new major into the TCB; pin and vendor a version with an audit trail when the gate opens. | recorded |
| A12 | §6/§8; threat model T-MAN-1 | Manifest capability declarations are not in the id: one id arrives with different requests (carol-strict shares carol's id), so an instantiator can strip a `Required`, drop or add requests within the policy's bound, or swap two — `Ctx::granted(i)` is by order, so a swap re-purposes grants. Reviewer: bind now, each record naming the target's id. Architect: bind, but records name **services** — target ids rekey every transitive dependent, make mutual declarations and §9's KeyAgent ↔ Security Center allow-list a hash cycle, and cannot name a kernel service. | **shipped in PR-2b (2026-10-04)** (decided 2026-10-03; before PR-3 is opened): v2 framing — requests in manifest order, then provided services (§6), `code` inlined (§18.8); policy = routes (honoured only to a provider whose id-bound manifest provides the service) + allow-list (§8); every id literal regenerated, carol-strict its own id (`4425fca7…`); the tamper probe — alice's id with a `Required` stripped, two requests swapped, an op added, a request dropped, a service added to `provides` — refused `id-mismatch` before anything runs (`manifest-tamper=refused`); Kani: frame injectivity over code, params, requests and provides as three composed harnesses (`framing_is_injective_bounded`, `request_framing_is_self_delimiting_bounded`, `provides_framing_is_injective_bounded`; §19 *PR-2b implementation*) |
| A13 | §7/§8; threat model T-CAP-2, T-DOS-5 | `generation:24` makes a table's lifetime ≈ 2²⁴ × usable slots (≈ 235 M frees) whatever slot is chosen; a client of an answering responder, or a delegator with `Send` to the victim (a delegation into a full inbox installs, then releases), spends it at bus speed — minutes on hardware — leaving the instance `Busy` to every requester and delegator for the rest of the boot. Resetting on owner change does not help a live responder; lowest-generation-first does not change the budget. | **shipped in PR-2b (2026-10-04)** (decided 2026-10-03; before PR-3, the first long-lived responder, and before the gate fixes the component ABI): `CapIndex(u64) = generation:48 ‖ table:8 ‖ slot:8`; codec `reply_tag`/`cap` u64, 68-byte header, `WIRE_VERSION` 2 (v1 refused); requester tag `ReplyTag(u64)` (R10); probe `act` encodings widened; every cap harness and the codec round-trip and decode-total harnesses re-run on the wide index (times in §14) |
| A14 | §6/§18.8; SentinelFS §7.3 | `code` inline vs `SHA-256(code)` by reference in the id frame. PR-2b inlines (one object, one canonical decoder for FS-4's "the stored image is the frame"). By reference would let one large code blob serve many params/declaration variants (dedup) and let the loader verify code and declarations separately — at the cost of a second object and a two-step verify | **recorded: v3 option, settle before FS-4** (the first persisted id; after it, changing the frame is a migration). If chosen: `TAG` `…:v3`, `code` replaced by `sha256(code)[32]`, the image stores code as its own `Public` blob keyed by that hash |

**Minds change on.** Architect and verification: a `wasmi` executor whose `unsafe` is confined and
fuzz/Miri-clean on the real budgets collapses PR-1 and the gate into one. Reviewer: PR-1/PR-2 with
provably zero time semantics puts the component work ahead of 3b (this is now the plan). Security: a
page-table backstop under linear memory is the minimum for `wasmi` to count as a boundary; IdentityDir
sync to a paired device forces a persistent device key and therefore sealing, immediately.

### PR-2 review round 1 (2026-10-03, kernel-reviewer)

Verdict: **blocked on three issues, the authority boundary itself held** (no forged `from`, no
foreign / stale / revoked / expired index use, no amplification, no double or late reply, no
fabricated reply). Dispositions:

| # | Finding | Status |
|---|---|---|
| R1 | Silent-responder lockout: expired reply rights were reclaimed only when the responder's table had no free slot, yet still counted against the 4-pending cap — four unanswered requests locked a responder out | **fixed**: reclaimed when either limit is reached; test `expired_reply_rights_never_lock_a_silent_responder_out`; §7, T-REP-1, T-DOS-2 say exactly when |
| R2 | The `cap-pong` wait waited for the task to be *reaped*, which SentinelFS moves to the BSP idle loop: 10 000 wasted yields after the merge | **fixed**: waits for `cap-pong` to leave its loop (`PONG_EXITED`); a failed spawn returns at once; `prove_caps` stays ahead of `sfs::prove_mount` (dilution; spawning allocates at `IF = 0`) |
| R3 | The orphan sweep's round bound is unconstrained at the Kani size: `T·S/2` rounds pass 2 × 2 and every test, and leave live orphans at 16 × 16 | **fixed**: production-size worst-scan-order chain test (fails on that mutation) |
| R4 | Generation exhaustion: a table absorbs ~235 M frees per boot; retirement outlives the instance; the "unreachable" required-grant path became reachable, unlogged, and an optional one was logged `malformed` | **decided: A13** (48-bit generations, PR-2b; threat T-DOS-5). Now: instantiation plans grants against the table's usable slots before changing anything, logs a refused start, and logs `table-full` truthfully; a delegation into a full inbox is answered `Busy` before anything is installed, so it spends no generation (`CapSpace::check_delegate`; test `a_delegation_into_a_full_inbox_spends_no_generation`) |
| R5 | T-NAT-1 overclaimed: nothing stopped a native component naming `bus::{call, dispatch, with_host, HOST}` or the host's tables | **fixed**: those are `pub(crate)`; `cargo xtask check-component-imports` (unit-tested, a kernel.yml step) fails if a component module names more than `bus::{Ctx, BusError, Delegation}`, or the host, or `cap::table`; T-NAT-1 reworded. Residuals recorded in T-DOS-2, T-DOS-3, T-INFO-1 |
| R6 | §18.4: the run-to-completion driver unspecified; two cores could run one instance's handler at once | driver **open for PR-3**; reentrancy **fixed** (`running` flag, T-CON-4) |
| R7 | §8 claimed the verifier shapes cost nothing at run time | **corrected** (three passes over 256 slots per removal, under the lock, IF = 0) |
| R8 | Undeclared limits: no selective revocation of one delegation; grants not re-issued on target restart | **declared** (§8 *Limits of PR-2*) |
| R9 | Clock read before the lock (fails open for expiry); `delegate` reclaimed the recipient's table even when refused; `reply` released any expired capability; `ttl = 0` installed a dead child and notified; dead `CallError::InboxFull`; `Host::instantiate` hashed under the caller's lock; the cap proof missing from the `TEST PASSED` summary | **fixed** (tests for the `reply`, `delegate` and `ttl` cases; `Host::instantiate` is test-only) |
| R10 | Distinct reply-tag types at the `Ctx` API (a responder's reply right and a requester's tag are both `u32` / `CapIndex` today) | **done in PR-2b**: `Kind::Request { reply: CapIndex }`, `Kind::Reply { tag: ReplyTag }`, `Ctx::request -> ReplyTag`, `Ctx::reply(CapIndex, …)`; `Target::Reply { to, tag: ReplyTag }` |
| R11 | The probes' `act` export and their policy allow-list ship in every boot | follow-up: gate them to the proof **before PR-3** |
| R12 | `DenyLog::reset_bucket` drops a trailing `suppressed_since`; `NoSuchSender` shares the kernel bucket with instantiation refusals | follow-up (T-DOS-3) |
| R13 | `ComponentRuntime::{call, deliver}` are associated functions over a `Copy` entry: a stateful runtime (wasm) cannot keep its state behind them while `HOST` is the only lock | note for the memory gate |
| R14 | A `HOST_OWNER` re-entrancy guard, turning a bus re-entry from a handler that holds `HOST` into a refusal instead of a deadlock | follow-up (T-CON-1) |
| R15 | The boot proof's `rate_limited` field relies on carol's bucket not refilling during the burst (a timing margin, ample on TCG today) | follow-up |
| R16 | `envelope_codec_round_trips_bounded` takes 81.6 s locally (49.7 s in CI), with or without `Grant` | accepted with this note; verification-engineer may cut its payload bound from 4 to 3. **PR-2b:** the v2 header took it to 113 s under cadical, and cutting the bound to 3 did not help (113 s); under `minisat` it takes ~35 s at bound 4, so the bound stays 4 and the harness names `minisat` |
| R17 | T-MAN-1: bind manifest capability declarations into `ComponentId` | **decided: A12** (v2 framing, records name services); **shipped in PR-2b** |
| R18 | Re-review note: the component source guard checks all of `host/native.rs`, which also holds the runtime | follow-up: if PR-3's runtime ever needs `Host` in `host/native.rs`, move the `hello` component into `components/` rather than loosening the guard |

### PR-2b implementation (2026-10-04, security-engineer)

A12 and A13 as decided; the choices the decisions left open, and where the code goes past the
letter of §6/§8:

- **§18.8: `code` inline** (A14 records by-reference as the v3 option before FS-4).
- **`ServiceName` lives in `kernel::cap`** (beside `CapRequest`/`Policy`), which the component
  source guard already allows; the guard's allow-list is unchanged. Constructors: `new(&str)`,
  `from_bytes(&[u8; 32])` (accepts exactly the canonical encoding) and the compile-time
  `service_literal`.
- **Canonical `provides`** is checked in `Manifest::verify` *before* hashing, with its own error
  (`NonCanonicalProvides`), so a non-canonical list is never "the wrong id" but "not a manifest".
- **One provider per service** is enforced twice: `Policy::route` returns nothing for a service
  routed twice (fail closed, logged `no-route`), and the boot policy asserts
  `routes_are_unique()` at build time.
- **Grant order** follows §8: route → live provider → the provider's id-bound `provides` →
  allow-list. A `Required` request refused for any of these is logged `missing-required` (as in
  PR-2); the precise reason is logged for `Optional` ones. Tests cover each reason.
- **R10 done** (distinct `ReplyTag` / `CapIndex` at the `Ctx` API). A kernel call's `Request` now
  carries `CapIndex::KERNEL` instead of the kernel's tag (the export answers by returning; the tag
  rides on the `Reply`).
- **The tamper probe uses alice's manifest** (an honest, running component) under her own id,
  with five edits: the four §14 names plus a service added to `provides` (a squat on carol's
  name, T-ROUTE-1). "Before anything runs" is checked as: no instance appears and the denial log
  does not move (no grant was planned). An `id-mismatch` is not written to the denial log —
  nothing was granted or denied — and waits for the IntegrityLog (PR-4).
- **The framing proof is three harnesses, not one** (a deviation from the letter of §14/A12, not
  from what is proven). `framing_is_injective_bounded` over the whole frame — up to 209 bytes, 128
  of them symbolic service names — did not fit the 60 s budget in any shape tried: two symbolic
  frames compared byte for byte, and a round trip of the frame with symbolic code/params lengths,
  each ran CBMC out of memory (15 GiB); a round trip with every length dispatched to a constant took
  ~4.5 s of symbolic execution per branch over 144 branches; the declarations alone as one round
  trip took 437 s. So `frame_into` is written as three writers into one sink (`frame_head`,
  `frame_requests`, `frame_provides`) and each is proven on its own: the head injective and
  prefix-free (`framing_is_injective_bounded`, code and params ≤ 3 bytes, the PR-1 harness's
  bounds), the request list injective and self-delimiting — recovered field by field, in order,
  from the list followed by arbitrary bytes, reading exactly its own length
  (`request_framing_is_self_delimiting_bounded`, ≤ 2 requests), the provides list injective
  (`provides_framing_is_injective_bounded`, ≤ 2). The standard prefix-free-code argument, written
  out in `host::proofs`' module docs, composes them into injectivity of the whole frame; the
  composition step is a three-line argument on paper, not a Kani run.
- **Solver choice on the wide index.** 48-bit generations in a `u64` index grew the table
  harnesses' formulas ~30 % and roughly doubled cadical's time (reclamation 105 s, revoke 69 s,
  no-producer 83 s, codec round trip 113 s — over the 60 s budget). The four table harnesses and
  the codec round trip now carry `#[kani::solver(minisat)]`, which discharges the same formulas in
  29–61 s (times in §14). Nothing about what is proven changed: same harnesses, same bounds, the
  2 × 2 slab, generations over the full `1..=GEN_MAX`. The no-producer harness sits at the 60 s line
  on a loaded machine (61 s; the PR-2 code took 65 s under cadical in the same hour).
- **Probes:** `hello` now provides `sentinel.hello/1` (unrouted); bob and carol provide
  `sentinel.probe.bob/1` / `sentinel.probe.carol/1`, routed to their ids. The `act` protocol
  carries `u64` indices and tags (`[code][u64]` answers, `ANSWER_LEN = 9`).

## 20. References

- Freenet developer manual — tutorial, components overview, contracts, delegates:
  <https://freenet.org/build/manual/tutorial/>, <https://freenet.org/build/manual/components/overview/>,
  <https://freenet.org/build/manual/components/contracts/>, <https://freenet.org/build/manual/components/delegates/>.
- `wasmi` 2.0.0 — <https://docs.rs/crate/wasmi/latest> (`no_std`, interpreter, fuel metering).
- Security Center design (`docs/specs/2026-06-03-sentinel-security-center-design.md`), §5, §6, §13.
- Closed PR #1 (2026-06-04): audit-log / agent-native architecture — the IntegrityLog's origin.
- Capability systems: seL4 (capability-based kernel API), Tock (grants + capsules on a small
  Rust kernel) — the two designs this most resembles once "component" is read as "capsule".
