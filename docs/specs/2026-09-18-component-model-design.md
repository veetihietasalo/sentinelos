# Component Model — attested messaging, delegates, and content-addressed components

Status: **proposed · review round 1 complete (2026-09-18)** — sequencing and the three open
decisions settled in §19; amendments A4–A10 land with the PRs named there · Tracks A (kernel core)
+ D (security subsystem) · Author: kernel-architect
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
  [`ComponentId`](#6-identity) = hash(code ‖ params). Three kinds: **state object**,
  **delegate**, **UI**.
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
4. **Components are what they hash to.** `ComponentId = H(code ‖ params)`. The host verifies
   the hash of the bytes it is about to run against the id it was asked for. Two instances
   with the same id run the same code with the same parameters; state is per instance.
   (Proof: PR-1.)
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
pub struct ComponentId([u8; 32]);          // SHA-256(TAG ‖ le64(|code|) ‖ code ‖ le64(|params|) ‖ params)
pub struct InstanceId(u64);                // per boot, per instantiation
```

- **SHA-256**, pure safe Rust, `no_std`, in the safe kernel (`kernel::hash`): the closed PR #1
  already argued for it (no `unsafe`, no `serde`, test vectors + a Kani harness on the
  compression-function padding arithmetic). BLAKE3 is faster but adds a dependency; revisit
  when component sizes make hashing measurable.
- **Framed, not concatenated** (A1). `TAG = b"sentinelos:component:v1"`; each field is
  length-prefixed. Unframed `H(code ‖ params)` lets `(A, BC)` and `(AB, C)` share an id, so the id
  would not bind the code/params split. Kani target: the framing is injective on bounded inputs.
- The host **verifies** `H(framed(code, params)) == requested id` before instantiation; a mismatch is
  a refusal, logged to the IntegrityLog. This is what makes "the kernel knows what it runs"
  literal, and it composes with the vision's "verifiable by design".
- Identity is *what*, instance is *which*. Capabilities and messages address **instances**; a
  manifest names **ids** (what may be instantiated) and the host binds them.

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
  requester's concern; the host never fabricates a reply. **Silence is denial.**
- **Delivery** is by the scheduler: a component instance is a pinned task (`spawn_on`); an
  inbox push wakes it exactly like the reschedule IPI wakes a core today. Cross-core delivery
  reuses that path unchanged.
- Cross-core safety follows `kernel::sched`'s rule: bus locks are taken with interrupts
  masked, never across a switch, never around an allocation — the payload arena is
  pre-sized at instantiation.

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
- Components see `CapIndex`, an opaque `u32` valid only in their own table. Forgery is
  structurally impossible: the table lives in the kernel and indices are checked on use.
- Kani targets: "no capability exists in a table that was not produced by `grant` or by an
  attenuating `delegate`" over a bounded sequence of operations — the analogue of the
  scheduler's Invariant #4 proof.

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
| `kernel::host` | instantiate / verify id / run on `ComponentRuntime`; per-instance fuel + memory caps; one pinned task per instance | uses `sched::spawn_on`; instance = task |
| `kernel::cap` | fixed slab of per-instance tables; `grant` / `delegate` / `revoke` / `check` | Kani: no forgery |
| `kernel::bus` | inbox rings + payload arenas; `send` stamps `from`; reply caps | fixed-size; no alloc under lock |
| `kernel::secrets` | per-delegate store; encrypted via `fs` | key sealing: §18 |
| `kernel::state` | drives state-object exports; load-time `validate`; persistence | monoid proofs on host |
| `kernel::services::*` | compute (`ml`), compositor (`wm`/`ui`), storage (`fs`), net, clock, integrity vectors | thin capability-checked shims over existing modules |
| `crates/host` | the component runtime crate (ours + `wasmi`) | external TCB; gated |

**`hal` delta: none** for PR-1 through PR-5. Ring-3 support (GDT user segments, TSS `rsp0`,
`syscall`/`sysret` or `int` gate, user-pointer validation) is *only* needed if native
processes come later, and stays a separate spec.

## 14. Boot proofs and PR staging

Each PR is independently bootable and adds one hard assertion to `cargo xtask test`.

| PR | Lands | Boot-proof line (asserted) |
|---|---|---|
| **PR-1** hash + host (native) | `kernel::hash` (SHA-256, framed id §6), `kernel::host` with `ComponentRuntime` + `NativeRuntime`, an embedded native "hello" component: id verified, one export called through the envelope codec. **Zero time-dependent semantics** (budgets by count, no expiry). Kani: id framing, codec round-trip, inbox ring never overwrites or loses. | `[comp] hello: id=<first 8 hex> verified=yes runtime=native reply=ok` |
| **PR-1b** clock (SMP 3b-i) | A core-independent monotonic clock (LAPIC-tick or TSC derived) so `pit::ticks()` is no longer the only clock; hal-tcb invariant 4.15 retired. No IOAPIC, no MADT walk. **Lands before PR-2** because `expires` and reply timeouts must not tick off a counter another core can stall. | `[clock] mono: source=<lapic\|tsc> cores=N skew-max=N ok` |
| **PR-2** bus + capabilities | `kernel::bus`, `kernel::cap`; two components; one holds a Send cap to the other, a third holds none. `expires` on the mono clock. **Denials logged, rate-limited.** Manifests declare `required` vs `optional` caps: a component missing a required cap refuses to start. | `[cap] attested-from=yes deny-by-default=yes forge-attempt=refused denies-logged=N ok` |
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

## 16. Threat model (what a malicious component can and cannot do)

Can: consume its own fuel and memory budget; send to targets it holds capabilities for;
refuse to answer; lie in its own payloads.
Cannot: forge `from`; reach a target without a capability; amplify a capability; read another
instance's memory or a delegate's secret; touch hardware; exhaust the machine (fuel, memory,
inbox all bounded); escape its identity (the host hashed what it runs).
Trusted: `hal`, the safe kernel, the component runtime (external TCB), the KeyAgent's
policy. A bug there is a bug in the root of trust and is handled by the existing TCB
discipline, not by this model.

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
   PR-2.
5. **Literal Freenet compatibility.** Could a Freenet contract or delegate run unmodified
   (`freenet-stdlib` ABI)? Tempting and out of scope; the ABI here is ours. Keep the door open
   by not inventing an incompatible *state* interface where theirs already fits (§10 mirrors
   their three functions on purpose).
6. **Runtime replacement trigger.** Define the `unsafe`-inventory and size thresholds at which
   the safe-Rust interpreter project starts, so the decision is made by a number, not a mood.
   Baseline measured 2026-09-18 in §19; the thresholds are written in the memory-boundary gate
   spec **before** `wasmi` lands, not after.

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
| A4 | §13/§16 | "hal delta: none" is TCB accounting, not reduction. §16 "cannot exhaust the machine" is false under `panic = "abort"`, an infallible allocator, a 4 MiB heap and 16 KiB stacks. Rewrite §16 for native-first: confines confused components, not malicious ones; non-first-party components barred until the gate; state the Kerckhoffs assumption. | PR-1 |
| A5 | hal-tcb §1 | External dependencies need their own class: `kernel/docs/external-tcb.md`, admitted by an amendment to hal-tcb §1. `crates/host` own code `#![forbid(unsafe_code)]`; only the dependency is exempt. | gate |
| A6 | §10 vs §18.1 | An ephemeral key means IntegrityLog `validate` against "the KeyAgent's public key" quarantines the previous boot's log on reload. Records carry a signing-key id resolved through IdentityDir, or PR-4's log is explicitly in-memory. | PR-4 |
| A7 | §15 | No fuzz lane exists (hal-tcb §3: **pending**); nothing that depends on fuzz merges before the lane gates. "Differential host vs kernel" is one hand-picked vector, not a property; say so or drop it. The upstream `wasmi` suite is `std`-only. Missing: a Kani ring harness (full → `Err(Busy)`, never overwrite, never lose) and a host-side threaded model of the bus rings for data races (Miri only sees host threads). | PR-1 (ring harness), gate (fuzz, race model) |
| A8 | §8/§11 | Denials are asserted but never logged; §11 sells the capability log as an integrity vector. Log denies, rate-limited. Manifests need `required` vs `optional` caps: refuse to start rather than run degraded. | PR-2 |
| A9 | §7/§9 | Zeroization: payload arenas are reused, so signatures and plaintext replies linger; zero on revoke and exit. Delegates are either TCB with registry rows or not trusted — §16 currently assumes both. | PR-3 |
| A10 | §16 | Eight lines in a design doc is not a threat model; `docs/security/` does not exist. Split §16 out when PR-2 lands. | PR-2 |
| A11 | §12 | `wasmi` 2.0.0 was 17 days old at review. No brand-new major into the TCB; pin and vendor a version with an audit trail when the gate opens. | recorded |

**Minds change on.** Architect and verification: a `wasmi` executor whose `unsafe` is confined and
fuzz/Miri-clean on the real budgets collapses PR-1 and the gate into one. Reviewer: PR-1/PR-2 with
provably zero time semantics puts the component work ahead of 3b (this is now the plan). Security: a
page-table backstop under linear memory is the minimum for `wasmi` to count as a boundary; IdentityDir
sync to a paired device forces a persistent device key and therefore sealing, immediately.

## 20. References

- Freenet developer manual — tutorial, components overview, contracts, delegates:
  <https://freenet.org/build/manual/tutorial/>, <https://freenet.org/build/manual/components/overview/>,
  <https://freenet.org/build/manual/components/contracts/>, <https://freenet.org/build/manual/components/delegates/>.
- `wasmi` 2.0.0 — <https://docs.rs/crate/wasmi/latest> (`no_std`, interpreter, fuel metering).
- Security Center design (`docs/specs/2026-06-03-sentinel-security-center-design.md`), §5, §6, §13.
- Closed PR #1 (2026-06-04): audit-log / agent-native architecture — the IntegrityLog's origin.
- Capability systems: seL4 (capability-based kernel API), Tock (grants + capsules on a small
  Rust kernel) — the two designs this most resembles once "component" is read as "capsule".
