# Component Model — attested messaging, delegates, and content-addressed components

Status: **proposed** · Tracks A (kernel core) + D (security subsystem) · Author: kernel-architect
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
pub struct ComponentId([u8; 32]);          // SHA-256(code_bytes ‖ params_bytes)
pub struct InstanceId(u64);                // per boot, per instantiation
```

- **SHA-256**, pure safe Rust, `no_std`, in the safe kernel (`kernel::hash`): the closed PR #1
  already argued for it (no `unsafe`, no `serde`, test vectors + a Kani harness on the
  compression-function padding arithmetic). BLAKE3 is faster but adds a dependency; revisit
  when component sizes make hashing measurable.
- The host **verifies** `H(code ‖ params) == requested id` before instantiation; a mismatch is
  a refusal, logged to the IntegrityLog. This is what makes "the kernel knows what it runs"
  literal, and it composes with the vision's "verifiable by design".
- Identity is *what*, instance is *which*. Capabilities and messages address **instances**; a
  manifest names **ids** (what may be instantiated) and the host binds them.

## 7. Messages and attestation

```rust
pub struct Envelope {
    pub from: InstanceId,          // written by the kernel, never by the sender
    pub to: InstanceId,            // resolved from the capability used to send
    pub cap: CapIndex,             // the sender's capability that authorised this send
    pub kind: Kind,                // Request { reply_tag } | Reply { reply_tag } | Event
    pub payload: Bytes,            // ≤ MAX_PAYLOAD; larger via a shared-buffer cap (later)
}
```

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

**Decision: components are WebAssembly, run in-kernel by a `no_std` interpreter behind a
`ComponentRuntime` trait; hardware and compute stay native services. Native (ring-3 ELF)
processes are deferred, not rejected.**

| | wasm components (interpreter in the safe kernel) | native ELF processes (ring 3, paging isolation) |
|---|---|---|
| Isolation | By construction: linear memory, no pointers out, fuel + memory caps | By hardware: page tables, privilege levels; needs a syscall trampoline + user/kernel copy discipline (new `hal` rows) |
| Portability | The **same** component runs in the Tauri Security Center (host wasm) and in the OS — "write once" made literal | OS-specific ABI; every app is a port |
| Identity | `H(code ‖ params)` over a small, platform-independent blob | Hash of an ELF; toolchain-dependent bytes |
| Verification | State-object functions run under Miri/Kani on the host as-is | Harder; user-mode code is opaque to the kernel's verification |
| Performance | Interpreter: fine for policy, UI logic, logs; wrong for inference (128-bit SIMD only) | Native |
| TCB cost | A third-party interpreter **with internal `unsafe`** near the boundary | Ring-3 entry/exit, `swapgs`, user-pointer validation — sharp `hal` work |
| Fits the wedge (private AI compute) | Yes, with compute as a native service the component *asks* for | Also yes, later, via a compat layer |

**Runtime candidate: `wasmi`** (2.0.0, 2026-09-01): a pure-Rust interpreter with first-class
`no_std` support, built-in **fuel metering**, and the proposals we want (bulk memory,
multi-value, SIMD, reference types). Two facts decide how it is treated:

1. It is **not** `#![forbid(unsafe_code)]`. Its `unsafe` surface (executor, memory access)
   must be inventoried (e.g. `cargo geiger`), the version pinned, and the crate registered in
   `kernel/docs/hal-tcb.md` as an **external TCB component** with the limits we rely on (fuel
   bound, memory bound, no host imports beyond the bus/service shims) and its own verification
   lane: differential tests of the same component under the host and the kernel, a fuzz target
   on the module loader, and the upstream test suite in CI. It lives in a **new crate**
   `crates/host` (safe Rust of ours + the dependency) — `kernel` and `ui` stay
   `#![forbid(unsafe_code)]` and `hal` stays the only place *we* write `unsafe`.
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
| **PR-1** hash + host + runtime | `kernel::hash`, `crates/host` (runtime trait + `wasmi`), `kernel::host` instantiating an embedded "hello" component, verifying its id, calling an export | `[comp] hello: id=<first 8 hex> verified=yes reply=ok fuel-used=N` |
| **PR-2** bus + capabilities | `kernel::bus`, `kernel::cap`; two components; one holds a Send cap to the other, a third holds none | `[cap] attested-from=yes deny-by-default=yes forge-attempt=refused ok` |
| **PR-3** delegates + secrets | `kernel::secrets`, **KeyAgent**; a component requests a signature and verifies it; a probe tries to read the secret | `[delegate] keyagent: signed=ok verified=yes secret-readable=no ok` |
| **PR-4** state objects | `kernel::state`, **IntegrityLog**; two divergent logs merged both ways; a tampered record rejected | `[state] integrity-log: merge-commutes=yes idempotent=yes tamper-rejected=yes ok` |
| **PR-5** Sentinel as components | `sentinel-core` as a component + the `sentinelos` provider service + **PolicyAgent**; the Security Center UI component | `[sentinel] sweep: vectors=N findings=N logged=yes signed=yes ok` |

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

1. **Key sealing without a TPM.** The device key that encrypts secrets at rest: TPM 2.0 where
   present (a driver, later), else a user passphrase at boot, else memory-only with a loud
   "secrets do not persist" line. Decide before PR-3.
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

## 19. References

- Freenet developer manual — tutorial, components overview, contracts, delegates:
  <https://freenet.org/build/manual/tutorial/>, <https://freenet.org/build/manual/components/overview/>,
  <https://freenet.org/build/manual/components/contracts/>, <https://freenet.org/build/manual/components/delegates/>.
- `wasmi` 2.0.0 — <https://docs.rs/crate/wasmi/latest> (`no_std`, interpreter, fuel metering).
- Security Center design (`docs/specs/2026-06-03-sentinel-security-center-design.md`), §5, §6, §13.
- Closed PR #1 (2026-06-04): audit-log / agent-native architecture — the IntegrityLog's origin.
- Capability systems: seL4 (capability-based kernel API), Tock (grants + capsules on a small
  Rust kernel) — the two designs this most resembles once "component" is read as "capsule".
