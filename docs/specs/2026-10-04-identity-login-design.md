# Identity and login: one unlock secret, a keyring, a trusted input path

Status: **proposed · review round 1 complete (2026-10-04)** — four seats APPROVE WITH
CONDITIONS; Veeti's product decisions P1–P6, blocking items B1–B8 and amendments C1–C12,
D1–D16 recorded in §19, applied inline in this revision or owned by the PR named there ·
Track A (kernel core) + D (security subsystem) · Author: kernel-architect
Depends on: `hal::mm` (frame allocator, HHDM, the fixed 4 MiB heap; hal-tcb §5), `hal::keyboard`
(PS/2 IRQ1 ring; hal-tcb §2g), `kernel::input` (scancode decoder, `LockState`), `kernel::hash`
(SHA-256), `kernel::sched` (`spawn_on`, preemptive APs; park/unpark from SentinelFS A25 when it
lands), SentinelFS (`docs/specs/2026-09-18-sentinelfs-design.md`: §7.1 `kdf_params` at [352,384)
and the `keys: Pointer` at [392,440), §9 attestation, §10 key hierarchy, §12 threat model, §15
A22), the component model (`docs/specs/2026-09-18-component-model-design.md`: §9 delegates, §18.1
sealing, A9 zeroization, A12 service names, PR-3), the threat model
(`docs/security/threat-model.md`), and the Cyber Dusk design language
(`docs/specs/2026-06-03-ui-design-language.md`).
Escalation: **architectural + TCB.** Three new `hal` rows (§9.3: one `hal::mm` arena primitive,
one secure-zero primitive, one `RDRAND` wrapper), a new zero-dependency safe crate
`kernel/crates/crypto` holding in-tree cryptography (§8.3), and the first secret the kernel ever
persists. **No SentinelFS format bump**: the superblock fields and block kind 6 were reserved by
FS-1a for exactly this (§10.2). ID-0 merges on kernel-reviewer sign-off for R1/Z1 and the crate
boundary; security-engineer sign-off on the in-tree primitives gates ID-1, not ID-0, so PR-3 and
FS-2 do not wait on it (C1). In-tree crypto is decided (Veeti, P2). Direction from
Veeti (2026-09-18): filesystem and login are the next big tracks, "aim for perfection". This
spec says what perfection means for a login on this machine, and where it stops.

## 1. Summary

Today the Cyber Dusk lock screen checks nothing: the right arrow unlocks. This spec replaces it
with a **passphrase** that unwraps a random 256-bit **master key** from a CoW **keyring block**
(SentinelFS block kind 6). The master key in turn unwraps the SentinelFS **tree key** and the
KeyAgent's **device signing seed**, so one secret, typed once, opens the data at rest *and*
gives the IntegrityLog a signing key that survives a reboot. That resolves component §18.1
(`sealing=none` becomes `sealing=passphrase`) and unblocks SentinelFS FS-5.

The passphrase is stretched by **Argon2id** at parameters calibrated per machine to a **2 s**
unlock (Veeti, P1): 64 MiB, t ≥ 3, p = 4 on the QEMU dev machine; up to 1 GiB on hardware. That memory cannot come from the 4 MiB
heap, so it comes from a **frame arena** in `hal::mm`: physical frames reached through the
HHDM, reserved all-or-nothing (and failing cleanly, never by an OOM halt), wiped and returned
after every attempt. The kernel owns the PS/2 path while locked: keystrokes go to the
passphrase field and nowhere else, never to a log, never to a component. Ctrl+Alt+Del is the
secure-attention key. Failed attempts are counted **on disk before the verdict is shown**, so
pulling the plug on a wrong guess does not reset the delay.

What this spec does not claim: protection against an evil maid who replaces the kernel (there
is no measured boot), against a full-disk rollback (there is no TPM driver, so v1 ships
`anchor: None`), against code already running in the unlocked session (ring 0, first-party
only until the memory-boundary gate), or — until SentinelFS FS-E lands — confidentiality of
file data on disk: the setup screen, the Security Center and the boot line
(`data-at-rest=plaintext`) say so (D14).

## 2. Goals and non-goals

Goals (v1, ID-0 … ID-5):

1. **One secret opens everything it should.** A passphrase unwraps the master key, which
   unwraps the tree key and the KeyAgent seed. No key is ever on disk in the clear or wrapped by
   anything derivable without the secret (component §18.1: a key file was refused 4/4).
2. **Offline guessing costs memory.** Argon2id at calibrated parameters, never below a stated
   floor; the parameters are authenticated by the wrap itself, so they cannot be downgraded.
3. **Online guessing is throttled across reboots.** The failure counter persists before the
   verdict; the backoff schedule is a pure function of it.
4. **No OOM halt on the login path.** Every allocation from keystroke to installed keys is
   either fixed-size or fallible; asserted by `heap-delta=0 heap-allocs=0` (B7).
5. **A trusted input path.** While locked, only the kernel reads the keyboard; the
   passphrase never reaches a log, a component or the desktop's typeahead.
6. **Passphrase changes without re-encryption.** Add, remove and replace a slot by rewrapping
   one 32-byte master key; never a state with no usable slot (Kani).
7. **A recovery key** that unlocks without Argon2id, so a machine with too little memory, or
   a forgotten passphrase, is not a brick.
8. **Persistent device identity** for the KeyAgent, same key id on every boot after unlock.
9. **Calibrated, honest latency**: ~2 s on hardware/KVM (P1), stated (not hidden) under TCG.

Non-goals (v1): measured or secure boot (§7.4); TPM, PIN-only unlock, FIDO2 (slot kinds
reserved, §10.3); multi-user login (format ready, §14); remote or network unlock; rollback
*protection* (§13: detection within the disk only); SentinelFS data encryption itself (its own
PR, **FS-E**, after FS-4; this spec supplies its keys and the AEAD construction, §10.6);
suspend/lid close (no ACPI events yet); hiding the passphrase from a key logger in hardware.

## 3. What we have, honestly

- **The lock screen** is a state in the BSP idle loop (`idle_loop` in `kernel/crates/kernel/src/lib.rs`):
  `LockState::Locked → Unlocking → Desktop`; `KeyEvent::RightArrowPressed` or `EnterPressed`
  starts the unlock animation. There is no secret, no check, no relock, and no way back to the
  lock screen once on the desktop.
- **The keyboard path is already kernel-owned.** `hal::keyboard::on_irq` drains port `0x60`
  into a lock-free SPSC ring; the idle loop is the ring's only consumer
  (`hal::keyboard::poll_scancode`) and decodes SET 1 with `kernel::input::ScancodeDecoder`
  (US-QWERTY, Shift; no Caps Lock, Ctrl, Alt or Delete). Nothing else reads it. That is the
  trusted path's foundation; it has to stay that way by rule, not by accident (§11.1).
- **Memory.** Limine HHDM-maps all physical RAM read-write. `hal::mm` has a LIFO frame
  allocator (`alloc_frame`/`dealloc_frame`, 4 KiB frames), a fixed 4 MiB heap mapped eagerly at
  `0xFFFF_F000_…` behind an infallible `#[global_allocator]` (`panic = "abort"`; an allocation
  failure halts), guard-paged stacks, and **no unmap**. `make run`/`make test` give QEMU
  `-m 256M` (QEMU's own default is 128 MiB). Usable RAM under `-m 256M` is about 245 MiB.
- **Randomness: none.** `hal::cpuid` reports `rdrand`/`rdseed` but nothing executes them. The
  SentinelFS format seed (`fs_uuid`, `dirent_key`) comes from tick counters (SentinelFS A26).
  PR-3's ephemeral key needs a real source too.
- **Crypto: SHA-256 only** (`kernel::hash`, in-tree, safe, Kani on padding). No HMAC, no AEAD,
  no KDF, no constant-time compare.
- **Zeroization: impossible in safe code, as a guarantee.** The kernel crate is
  `#![forbid(unsafe_code)]`; plain stores to dead memory may be elided; `write_volatile` is
  `unsafe`. Component A9 (arena zeroization) and SentinelFS §10 (cache zeroize on lock) both
  assume a primitive that does not exist.
- **SentinelFS** (FS-1a): superblock `kdf_params` [352,384) and `keys` [392,440) are validated
  as **zero**; a non-zero byte is refused, so a kernel that cannot unwrap never mounts an
  encrypted tree as plaintext. Block kind 6 is reserved and refused.
- **KeyAgent** does not exist yet; PR-3 will land it with an ephemeral memory-only key
  (`sealing=none secrets-persist=no`).
- The build is `dev` (unoptimised) for `make test`. Unoptimised Argon2id under TCG would take
  minutes; §8.2 and §8.3 deal with that.

## 4. Vocabulary

| Term | Meaning |
|---|---|
| **Secret** | What the user supplies: a passphrase (v1), a recovery key (v1), later a FIDO2 `hmac-secret` or a TPM-released value. |
| **Slot** | One way in: a secret kind, its KDF parameters and salt, and an AEAD wrap of the master key under the KEK that secret derives. |
| **KEK** | Key-encryption key, `Argon2id(passphrase)` or `HKDF(recovery key)`. SentinelFS §10 calls it `unlock_key`. Lives only for the duration of one unwrap. |
| **Master key** | 256 random bits, one per keyring (per user once multi-user exists). Wrapped once per slot; wraps the subkeys. Never written unwrapped; never leaves `kernel::keyring`. |
| **Subkey** | A random 256-bit key wrapped by the master key: the **tree key** (SentinelFS), the **device seed** (KeyAgent), later per-user keys. |
| **Keyring block** | SentinelFS metadata block kind 6, named by the superblock's `keys` Pointer: header, slots, wrapped subkeys, failure counter. CoW like every metadata block. |
| **Arena** | `hal::mm::FrameArena`: physical frames owned for one Argon2id run, reached through the HHDM, wiped and returned on drop. |
| **Locked / Unlocked / Sealed** | *Locked*: the lock screen is up; keys may still be resident (screen lock). *Sealed*: every key is wiped; unlocking needs the secret again (§11.4). |
| **SAK** | Secure-attention key: Ctrl+Alt+Del, always handled by the kernel, always shows the genuine lock screen. |

## 5. Principles (each maps to a boot proof in §16)

1. **No secret, no key.** Every key that protects persistent state is derived from or wrapped
   under the user's secret; nothing in the image or on the disk alone unwraps anything. Proof:
   boot 2 refuses a wrong passphrase and the KeyAgent answers `locked` before unlock
   (`verdict=denied`, `before-unlock=locked`).
2. **Parameters are authenticated by the secret.** Each slot's KDF parameters, salt, kind and
   user are associated data of its wrap; editing them makes the unwrap fail, never weaker.
   Proof: host test (tampered `m_kib` → `Unauthentic`); Kani: parameter decode is total.
3. **The login path cannot halt on memory.** Arena frames are reserved all-or-nothing from the
   frame allocator and fail with an error the lock screen can show; everything else is
   fixed-size and pre-allocated. Proof: `heap-delta=0 heap-allocs=0` on every unlock line
   (window: Enter → keys installed, before the WM is created); `frames-returned=yes`.
4. **What the kernel derives, it wipes — in memory it names.** KEK, master, subkeys, the
   passphrase buffer, the KDF hand-off slot, every secret-bearing crypto state (Argon2 H0,
   BLAKE2b, HMAC pads, HKDF PRK, ChaCha and Poly1305 state, scratch blocks) and the arena are
   caller-owned and wiped with a primitive the compiler cannot elide (B4). **Scope, honestly:**
   copies the compiler makes in registers and stack spills are not ours to name; the
   `login-kdf` task scrubs its stack after each job, which is best effort. Proof: `wiped=yes`
   and `slot-wiped=yes` (read back with volatile reads under `login-test`). Read-back cannot
   prove non-elision; that evidence is construction (volatile stores) plus Miri (B7).
5. **The verdict follows the count.** A failed attempt is durable before it is shown. Proof:
   `persisted-before-verdict=yes`; Kani on the login state machine.
6. **Keystrokes while locked go to the field and nowhere else.** Proof: xtask types the test
   passphrase over QMP and asserts it never appears in the serial log; keys typed during the KDF
   never reach the terminal (`typeahead-dropped=yes`).
7. **Never lose the master key.** No slot operation can leave the keyring without a slot that
   unwraps the current master key. Proof: Kani over bounded slot-operation sequences;
   `last-slot-remove=refused`.
8. **Fail closed, report honestly.** A keyed volume is never mounted as plaintext; a corrupt
   keyring is `Corrupt`, not "wrong passphrase"; a machine too small to unlock says so.
   Proof: the existing v2 zero-field refusal stays for kernels without login; host corpus.

## 6. Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│  components: KeyAgent (delegate) · IntegrityLog · Security Center · Terminal …  │
│      ▲ KeyAgent asks the kernel to sign; the seed never crosses the bus (§12.3)  │
├──────┴──────────────────────────────────────────────────────────────────────────┤
│  kernel (#![forbid(unsafe_code)])                                                │
│   kernel::login    lock-screen state machine · SecretBuf · backoff · SAK · idle  │
│   kernel::keyring  kind-6 codec · slots · wrap/unwrap · subkeys · typestate      │
│   kernel::kdf      the login-kdf task · arena adapter · progress                 │
│   kernel::rng      HMAC-DRBG seeded from hal::rng · health tests                 │
│   kernel::input    decoder (+ Caps Lock, Ctrl, Alt, Delete) · the one router     │
│   kernel::sfs      accepts kdf_params / keys; locked mount (FS-E later)          │
│   kernel::secrets  (component PR-3) holds the seed and signs: provision / seal   │
├─────────────────────────────────────────────────────────────────────────────────┤
│  crates/crypto (#![no_std], #![forbid(unsafe_code)], zero dependencies)          │
│   sha256 (moved from kernel::hash) · hmac · hkdf · hmac_drbg · blake2b ·         │
│   argon2id (generic over Argon2Memory) · chacha20 · poly1305 · xchacha20poly1305 │
│   · ct (constant-time eq) · ed25519 + sha512 (ID-1b) · trait Wipe                │
├─────────────────────────────────────────────────────────────────────────────────┤
│  hal (TCB)   mm::FrameArena (M16) · mem::secure_zero (Z1) · rng::rdrand64 (R1)   │
│              keyboard (K1–K5, unchanged) · framebuffer · frame allocator         │
└─────────────────────────────────────────────────────────────────────────────────┘
```

**Framekernel classification.**

| Module | Class | Owner | Why it lives there |
|---|---|---|---|
| `hal::mm::arena` (`FrameArena`) | HAL/TCB, `unsafe` | hal-specialist | Forming a reference to a physical frame through the HHDM is a raw-pointer operation; nothing above `hal` can do it. Exactly one new op (M16). |
| `hal::mem::secure_zero` | HAL/TCB, `unsafe` | hal-specialist | `write_volatile` is `unsafe`; a guaranteed wipe cannot be written in a `forbid(unsafe_code)` crate. One op (Z1). |
| `hal::rng::rdrand64` | HAL/TCB, `unsafe` | hal-specialist | An instruction wrapper (`rdrand` + carry check), cpuid-gated. One op (R1). |
| `crates/crypto` | safe crate | kernel-engineer (security-engineer reviews) | Pure functions over byte slices; host-testable, Miri-able, Kani-able; no `hal`, no `alloc` needed. A crate, not a kernel module, so it can have `opt-level = 3` **and `overflow-checks = true`** in the dev profile and be tested on the host without the kernel. Crate lints (B8): `#![deny(clippy::arithmetic_side_effects, clippy::indexing_slicing, clippy::unwrap_used, clippy::panic)]`, also on `kernel::keyring`'s and the recovery key's decoders. |
| `kernel::keyring`, `kernel::kdf`, `kernel::login`, `kernel::rng` | safe kernel | kernel-engineer | Policy, codecs, state machines. Everything decidable is here. |
| Lock-screen drawing (`ui`) | safe crate | ui-engineer | Pixels only; receives a view model (`LockView`), never a secret. |

**Dependency graph** (new edges only; no cycles): `kernel → crypto`, `kernel → hal` (existing).
`crypto` depends on nothing (not `hal`, not `alloc`): host tests and Kani see it whole.
`ui` does not gain `crypto` or `keyring`; it receives `LockView { shimmer_step: u8, caps:
bool, message: LockMessage, progress: Option<u8> }` (no length, §11.3). `kernel::hash` keeps its
public API (`Sha256`, `sha256`, `ComponentId` framing) and re-exports `crypto::sha256` (ID-0,
after PR-2b merges, so the move does not collide with PR-2b's v2 framing work in `hash.rs`).
`kernel::hash` stays the **only** import path for SHA-256 in kernel code: a review rule plus a
source guard (`check-crypto-imports`: no kernel module names `crypto::sha256`); the SHA-padding
Kani harness moves to `cargo kani -p crypto` (C11). `opt-level = 3` on `crypto` shifts the
`boot-timing` baselines; ID-0 records new ones.
`xtask` (own workspace) gains a QMP client; a new host-only workspace `kernel/crypto-oracle/`
(committed lock, own CI job) holds differential tests against RustCrypto and a second,
independent oracle (libsodium or the reference C) as **test oracles**, never linked into the
kernel (`kernel/Cargo.lock` stays at 6 packages plus `crypto`).

**Wiping across the crate boundary (B4).** `crates/crypto` cannot call `hal`. Every
secret-bearing state is therefore a **caller-owned** type implementing `crypto::Wipe`
(`fn wipe_slices(&mut self, f: &mut dyn FnMut(&mut [u8]))` exposing its secret bytes): Argon2's
H0 (KEK-equivalent), BLAKE2b state, HMAC inner/outer pads, the HKDF PRK, ChaCha20 state, Poly1305
`r`/`s`/accumulator, and Argon2's scratch blocks, which the caller passes in rather than the
crate allocating them on its stack. The kernel wraps each in a `Wiped<T>` whose `Drop` runs Z1
over every slice. Key bytes live in **one static key store** inside `kernel::keyring` (master,
subkeys, KEK) with a typestate **token**, not key arrays, in `Keyring<Unlocked>`; `SecretBuf`
lives in exactly one place (the static login state). A host test enumerates the secret types
and fails if one does not implement `Wipe`. After each job `login-kdf` calls a stack scrub
(a large zeroed local through Z1, `black_box`ed) before parking.

**Execution (C6).** Argon2id runs on a dedicated `login-kdf` task, spawned **once at boot** (its
stack and `XsaveArea` are allocated then, not at unlock), pinned to CPU 1 when an AP is online,
else the BSP. **ID-2 lands after sched park/unpark** (SentinelFS A25, in flight) and the task
parks from the first day; fallback if A25 slips: spawn it after the AP proofs and yield-poll.
The BSP idle task draws the UI and **can never park** (A25 must refuse or debug-assert that), so
every login wait is a **polled state**: `Persisting { ticket }` and `Resetting { ticket }` poll a
non-blocking `sfs::request_commit() -> Ticket` / `sfs::poll(ticket)` once per frame, and
`Deriving` polls the KDF slot. The hand-off is a fixed `SpinMutex<KdfSlot>`: publish the job,
then unpark; the task re-checks the slot after every park. Rules: the idle loop only
`try_lock`s it; critical sections only copy (never allocate, never touch the arena, never
inside `with_sfs`); its input (passphrase copy) is wiped with Z1 as soon as the task has copied
it, and its output (KEK) as soon as the idle loop has taken it. Arena `reserve` and `Drop` run
only on `login-kdf` (IF = 1, preemption on). v1 computes the p = 4 lanes **sequentially, in
slice-major order** (pass → slice → lane), which is what makes a sequential run equal to a
parallel one; parallel lanes are ID-6 (§16).

## 7. Threat model for login

**Assumption (Kerckhoffs):** the adversary knows the kernel image, this spec, the on-disk
format, the KDF parameters of every slot, the salts and the keyring layout. The only secrets are
the user's passphrase or recovery key and the random keys they protect. Nothing depends on a
layout, an offset or a label being hard to find.

### 7.1 Adversaries

| # | Adversary | Capability | v1 outcome |
|---|---|---|---|
| L1 | **Offline disk thief** | Has the disk (or an image), powered off or sealed; unlimited offline compute | Must run Argon2id per guess at the slot's parameters (64 MiB × 3 passes on the dev class, more on hardware). A recovery key is 128 random bits. Before FS-E, **file data is plaintext on disk**: v1's login protects the KeyAgent seed and the tree key, not the files (§16, FS-E row). After FS-E: shape, sizes, counts and timing leak (SentinelFS §10), content and names do not. |
| L2 | **Evil maid** | Repeated physical access while the owner is away: boots the machine, types guesses, edits the disk, may replace the kernel on the boot medium | Guessing at the lock screen is throttled by the persisted counter; resetting it means editing the disk, which reduces to L1. A write-blocked or lying disk (the counter commit "succeeds" but is not durable, or fails) also reduces to L1 cost: each guess still costs a full KDF, and a commit that fails outright refuses passphrase attempts (§8.5). Disk edits of the keyring are detected (block hashes) or fail the AEAD; a crafted slot cannot test many passwords at once (key commitment, §10.3). **Replacing the kernel image defeats login entirely**: no measured boot exists; stated, not mitigated (§7.4). Owner learns of guessing: the first successful unlock shows "N failed attempts since your last unlock", recorded in a signed IntegrityLog record once ID-4 lands. |
| L3 | **Malicious first-party bug** | A bug in reviewed kernel code: logs a key, prints the passphrase, leaves plaintext in a reused buffer | Secret types have no `Debug`/`Display`/`Clone`/`Copy`; the boot test asserts the test passphrase never reaches the serial log; wipes are guaranteed (Z1, M16). A bug with ring-0 write access can still read any key: that is TCB, not this model. |
| L4 | **Shoulder-surfer** | Watches the screen and keyboard | No echo, no length indicator (§11.3), no "show passphrase". The recovery key is shown once at setup behind an explicit reveal. Keyboard observation is not defended. |
| L5 | **Remote attacker** | Network access | No login service is reachable over the network; `kernel::net` answers ARP/ICMP only. No remote unlock. |
| L6 | **Local attacker with code execution** | Runs code in the unlocked session | **Boundary.** Native components are ring 0 and first-party only (threat model §2); such an attacker has every resident key. Login protects data **when sealed or powered off**, and protects the KeyAgent seed from components after the memory gate (it lives in kernel memory; components get signatures, not the seed). |

### 7.2 What login protects

- **Data at rest** once FS-E lands: everything SentinelFS §10 encrypts, against L1 and L2's
  disk edits.
- **KeyAgent signatures**: a signature now means "made by this device while unlocked by its
  owner", across boots, instead of "made by this boot" (component §18.1).
- **IntegrityLog continuity**: the signing key persists, so the log's chain continues across
  reboots and FS-5 can sign the superblock hash; an offline edit of a signed state is detected
  at the next unlock (SentinelFS §12 three cases).
- **The session**: a screen lock gates the UI (walk-up attacker), with a trusted input path.

### 7.3 What it does not protect

- Data written **before FS-E** (plaintext on disk).
- A **full-disk rollback** to an older, internally consistent, previously signed state
  (§13; needs an anchor the disk does not control).
- **A passphrase that leaked earlier, against an attacker who already copied the disk.** On our
  own disk, a slot change commits twice and then zeroes and flushes the freed keyring block(s)
  (B2, §10.4), so no superblock slot, and no free block we know of, still holds the old slot.
  That defeats an attacker who images the disk *after* the change. It does not defeat one who
  imaged it *before* (the copy wraps the same master and the same tree key), nor SSD/FTL
  remapping, which can keep the old physical block outside our reach (T-LOG-13). Changing a
  passphrase protects against *future* disk captures only (as in LUKS). True revocation needs
  a tree-key epoch and re-encryption (open question 6).
- **Cold-boot, DMA and side-channel attacks** on resident keys (threat model §1: physical and
  micro-architectural attacks out of scope). Argon2id's data-dependent second phase is a known
  cache-timing surface; accepted, as every Argon2id deployment does.
- **Hardware key loggers** and a compromised boot medium (§7.4).

### 7.4 The boot chain

Limine and the kernel image are trusted (hal-tcb §1). An evil maid who swaps the ISO or the ESP
for a kernel that records the passphrase wins. The defences are measured boot (TPM PCRs sealing
the keyring, §13) or a signed boot chain (Limine's secure-boot path plus a verified kernel);
both are their own specs. v1 says this loudly in the threat register (T-LOG-9) rather than
implying otherwise.

### 7.5 Threat register

Each entry lands in `docs/security/threat-model.md` **with the PR that implements it**, before
that PR's code (the threat model's own rule), not in one batch at ID-3 (D14).

| ID | Threat | Mechanism | Evidence (PR) |
|---|---|---|---|
| T-LOG-1 | Offline guessing | Argon2id at calibrated parameters ≥ floor; params authenticated as AD; decode refuses passphrase slots below the absolute floor (`BelowFloor`) | host KAT + tamper tests (ID-1, ID-3) |
| T-LOG-2 | Parameter downgrade on disk | Params, salt, kind, user in the wrap's AD (a per-slot downgrade fails the unwrap). The superblock floor is attested state **only after FS-5**, and even then not against a rollback to a previously signed state | host test, Kani decode (ID-3) |
| T-LOG-3 | Online guessing / reboot-to-reset | Counter persisted before the KDF starts; backoff from the count; a counter that cannot be persisted refuses passphrase attempts | boot `persisted-before-verdict=yes`, Kani (ID-3, ID-5) |
| T-LOG-4 | Partitioning-oracle slot (one slot valid under many passwords) | Key commitment tag per slot, checked in constant time before the AEAD open | host test with a crafted multi-key ciphertext (ID-3) |
| T-LOG-5 | Passphrase or keys in logs, residue in buffers | No `Debug` on secret types; Z1 wipes; xtask log scan | boot + xtask (ID-3) |
| T-LOG-6 | Keystrokes reach a component or the desktop | Single keyboard consumer; router by `LoginState`; typeahead dropped | boot `typeahead-dropped=yes` (ID-3) |
| T-LOG-7 | Fake lock screen | Kernel-owned lock layer; SAK (Ctrl+Alt+Del); no component surface composited while locked | boot `sak=ok` (ID-5); after the gate, the compositor rule |
| T-LOG-8 | OOM halt during unlock | Fallible arena; pre-spawned KDF task; fixed buffers | boot `heap-delta=0 heap-allocs=0 frames-returned=yes` (ID-2, ID-3) |
| T-LOG-9 | Kernel image replaced (evil maid) | **Not defended in v1** | — (measured-boot spec) |
| T-LOG-10 | Full-disk rollback resurrects an old slot or resets the counter | **Detected only with an anchor**; v1 `anchor: None` | — (§13) |
| T-LOG-11 | Weak or predictable keys | RDRAND → HMAC-DRBG with health tests; keyring creation refused without entropy | boot `[rng] … health=ok` (ID-0) |
| T-LOG-12 | Nonce reuse after a crash before commit or an offline image restore (FS-E) | 192-bit XChaCha nonce = gen ‖ counter ‖ per-transaction random salt; AD binds object id, block position, gen | Kani `NonceSeq` (FS-E) |
| T-LOG-13 | Stale keyring residue: a freed keyring block still holds a removed slot | Two commits per slot change, then the freed block(s) zeroed and flushed; `keys` never restored by snapshot or rollback. **Residual:** SSD/FTL remapping | boot `old-keyring-scrubbed=yes`, host test (ID-3) |
| T-LOG-14 | The test KDF profile reaches a production image | Test slots use `kdf.alg = 0xF0`, refused by the production decoder; `BelowFloor` for real Argon2id below 19 MiB / t = 2; `compile_error!` on `login-test` without `debug_assertions` or in the release/ISO profile; xtask asserts `profile=prod` on the `make run` image | boot + xtask (ID-3) |
| T-LOG-15 | The user believes files are encrypted before FS-E | Setup screen and Security Center say "Files on disk are not encrypted yet"; boot line `data-at-rest=plaintext` until FS-E | boot (ID-3) |

## 8. The secret and the KDF

### 8.1 Which secrets

**Decision.** v1 ships **passphrase** and **recovery key** slots. PIN, FIDO2 and TPM are
reserved slot kinds, refused by the v1 decoder.

**Why.** A passphrase needs only the keyboard we already own and the KDF this spec builds. A
recovery key needs no KDF at all (it has 128 bits of entropy) and is the escape hatch for a
forgotten passphrase and for a machine too small to run the passphrase's Argon2id. A **PIN** is
safe only behind hardware rate limiting (a TPM's dictionary-attack lockout); offline, a 6-digit
PIN falls to Argon2id in minutes. **FIDO2** (`hmac-secret`) needs a USB HID stack, which does not
exist. Passphrases are US-QWERTY printable ASCII, 8 to 256 bytes (the layout id is recorded in
the slot, so a future layout switch can warn before a passphrase stops being typeable).

**Minds change on:** a TPM driver (PIN slots behind TPM lockout become reasonable); a USB stack
(FIDO2 as a second factor, wrapped as `KEK = HKDF(Argon2id(pw) ‖ hmac_secret)`).

### 8.2 Argon2id parameters and calibration

**Decision.**

- `alg = Argon2id`, `ver = 0x13`, `p = 4` lanes always (the output is defined by `p`, not by how
  many cores compute it), tag length 32, salt 16 random bytes per slot, associated data
  `X = "sentinelos/kek/v1" ‖ fs_uuid ‖ le16(user) ‖ u8(slot kind)` (domain separation).
- **Target: 2 s** (`TARGET_TICKS = 200`; Veeti, P1). All three reviewers preferred 1 s,
  because a screen-lock unlock runs the full KDF many times a day; the decision is 2 s,
  LUKS2's default, and the dissent is recorded in §19.
- **Calibration at slot creation** (setup or passphrase change), never at unlock — **memory
  first, then passes** (C9):
  1. `usable = total_frames × 4 KiB` (`hal::mm::stats`). Start at
     `m = min(1 GiB, the largest power of two ≤ usable / 3)`; if that is < 32 MiB,
     `m = usable / 3` rounded down to a MiB.
  2. Measure one pass at `m` (`t = 1`) on the login-kdf task over **≥ 10 ticks** (repeat the
     pass if shorter): `pass_ticks = max(measured, 1)`, so there is no division by zero.
  3. **Step memory down rather than overshoot**: while `t_min × pass_ticks > TARGET_TICKS` and
     `m > 64 MiB`, halve `m` and re-measure (`t_min = 3`; alternatively `t_min = 2` is allowed
     at `m ≥ 256 MiB`). `m` never drops below 64 MiB by stepping (below that only because the
     machine is small) until ID-6's parallel lanes land.
  4. `t = clamp(floor(TARGET_TICKS / pass_ticks), t_min, 10)`; if `m < 64 MiB`,
     `t = max(t, 4)` (RFC 9106: trade memory for passes when memory-bound).
  5. Kani (ID-2): calibration is total over any `(usable, pass_ticks)`; its result satisfies
     `m ≥ floor`, `t ∈ [2, 10]`, and `params → pages` agrees exactly with what
     `FrameArena::reserve` is asked for.
- **Absolute floor**: `m ≥ 19 MiB` (OWASP's minimum) and `t ≥ 2`. Refused at creation **and at
  decode** (`BelowFloor`) for real Argon2id passphrase slots, so a below-floor slot can never be
  accepted by a production kernel, whoever wrote it (B1). Below 19 MiB usable/3, setup creates a
  **recovery-key-only** keyring with a warning (the recovery key is then mandatory, P5).
- **Re-wrap upward** (should): after a successful unlock, a passphrase slot whose parameters are
  below what calibration would now choose (moved to a bigger machine, or set up under TCG) is
  re-wrapped at the new parameters in the background, with the passphrase still in `SecretBuf`.
- **Resulting classes.** QEMU `-m 256M` (xtask): `m = 64 MiB, t ≥ 3, p = 4`, RFC 9106's second
  recommended option. QEMU default 128 MiB: `m = 32 MiB, t ≥ 4`. A 16 GiB laptop: starts at
  1 GiB and steps down only if 3 passes exceed 2 s. The superblock records the creation-time
  parameters as the volume's floor (§10.2).
- **Latency, honestly (estimates; ID-2 measures and records them).** Scalar Argon2id at
  `opt-level = 3`, one core, ~0.5–1 GiB/s of block processing: 64 MiB × 3 ≈ 0.2–0.4 s on KVM or
  hardware, which calibration then raises toward 2 s. Under TCG, 10–30× slower: 3–10 s for the
  same parameters. A disk set up under TCG calibrates to TCG speed (`t = 3`), then unlocks in a
  fraction of a second under KVM, and is re-wrapped upward there. Unoptimised (`dev`) Argon2id
  would be another 10–50× slower, which is why `crates/crypto` gets
  `[profile.dev.package.crypto] opt-level = 3, overflow-checks = true` (§8.3).
- **Boot tests** use a test-only setup profile (`--features login-test`, compiled only into
  the `make test` kernel) with **its own algorithm id**, `kdf.alg = 0xF0` ("Argon2id-test":
  Argon2id at `m = 8 MiB, t = 1, p = 4`), which the production decoder refuses (B1). So a test
  slot cannot be unlocked by a production kernel, and a production slot cannot be below the
  floor. Guards: `compile_error!` if `login-test` is enabled without `debug_assertions` or in
  the release/ISO profile; the `[login]` lines print `kdf-profile=test`, and xtask asserts that
  the `make run` image prints `profile=prod`. **Stated honestly:** the test profile bypasses
  setup's floor check by design; the defences are the distinct `alg`, the decode refusal and
  the build guards. The production calibration line (`[kdf] calibrate: m=… pass-ticks=N t=T`,
  informational) runs only in `test-kvm` and `boot-timing`, on one boot, not in every TCG test.

**Why.** OWASP's 19 MiB is a floor for servers hashing many logins; a disk unlock protects
everything, so it should spend what the machine can afford. A third of usable RAM leaves the rest
of the kernel (heap, stacks, page tables, caches) at least 2/3 while the arena is held, and it is
held for about two seconds. Choosing memory before passes keeps the memory-hardness that is the
point of Argon2id, instead of letting a fast machine buy latency with fewer bytes or a slow one
overshoot the target. Power-of-two steps keep the parameters recognisable. `p = 4` is fixed so a
disk moves between a 1-core and a 4-core machine unchanged.

**Alternatives.** *Fixed parameters for everyone* (too weak on hardware or unusable on 128 MiB).
*Calibrate at every unlock* (meaningless: the slot's parameters are what they are). *Target
1 s* (the reviewers' preference; declined by P1).

**Minds change on:** measured ID-2 numbers far from the estimate (re-tune the ladder); a product
reversal to 1 s (`TARGET_TICKS = 100`); parallel lanes (ID-6) landing (4× the work fits the
same latency, and the 64 MiB stepping floor can rise).

### 8.3 Implementation: in-tree, safe, zero-dependency

**Decision.** Argon2id (with BLAKE2b), ChaCha20, Poly1305, XChaCha20-Poly1305, HMAC-SHA-256,
HKDF and HMAC-DRBG are written in-tree in `kernel/crates/crypto`, `#![no_std]`,
`#![forbid(unsafe_code)]`, no dependencies, scalar only. RustCrypto is used as a **differential
test oracle** in a separate host workspace, never as a kernel dependency.

**The spike (2026-10-04, costed like the `wasmi` spike in component §19).** `argon2 = "0.5"`
(`default-features = false, features = ["zeroize"]`), `chacha20poly1305 = "0.10"`,
`hkdf = "0.12"`, `sha2 = "0.10"`, all `default-features = false`, `cargo build --release
--target x86_64-unknown-none` on rustc 1.97:

- **23 packages** in the tree (`argon2 0.5.3`, `blake2 0.10.6`, `base64ct`, `chacha20 0.9.1`,
  `poly1305 0.8.0`, `chacha20poly1305 0.10.1`, `cipher`, `aead`, `universal-hash`, `hkdf`,
  `hmac`, `sha2 0.10.9`, `digest`, `block-buffer`, `crypto-common`, `generic-array 0.14.7`,
  `typenum`, `inout`, `cpufeatures`, `subtle`, `zeroize`, `opaque-debug`, `cfg-if`) against
  `kernel/Cargo.lock`'s 6 today.
- **~45 k lines** of third-party source (`typenum` alone 19 k); **273 `unsafe`** sites by grep
  (`generic-array` 78, `poly1305` 50, `sha2` 29, `blake2` 26, `chacha20` 23, `inout` 22,
  `zeroize` 20, `cpufeatures` 9, `base64ct` 5, `block-buffer` 4, `argon2`, `cipher`, `subtle` 2
  each, `universal-hash` 1). Six of 23 are `#![forbid(unsafe_code)]`.
- `argon2 0.5.3` carries an **AVX2 compression path** behind `cpufeatures` runtime detection
  (`#[target_feature(enable = "avx2")]` + `unsafe`). The objection is **policy and TCB**, not
  live vector state: it is `unsafe` outside `hal` and vector code outside `hal::simd`, which
  `check-no-vector` exists to forbid. The primary argument is hal-tcb §2j: `core::arch`
  intrinsics do not lower on this soft-float target, and `__m256i` across the soft-float ABI
  corrupts values — vector code belongs in `hal::simd` or nowhere.
- **`poly1305 0.8.0` did not build** for `x86_64-unknown-none` in the spike: rustc died with
  SIGILL compiling it. **Unreproduced and not root-caused**; recorded as observed, not as a
  property of the crate. `argon2` + `hkdf` + `sha2` alone built. For a fair record the spike
  should be re-run with `--cfg poly1305_force_soft --cfg chacha20_force_soft`; the decision
  stands either way (P2).
- In-tree estimate: BLAKE2b ~200 lines, Argon2id ~350, ChaCha20 + HChaCha20 ~150, Poly1305
  (5 × 26-bit limbs) ~200, the AEAD composition ~100, HMAC/HKDF/HMAC-DRBG ~200, `ct` ~30:
  **~1 200 lines, zero `unsafe`**, every primitive pinned by its RFC's vectors.
- **Signing: Ed25519 (C2), costed the same way.** SHA-512 ~150 lines; field arithmetic mod
  2²⁵⁵ − 19 in 5 × 51-bit limbs with 128-bit products ~400; extended-coordinate group law,
  constant-time fixed-window scalar multiplication and a variable-time double-scalar verify
  ~450; scalar reduction mod ℓ, encoding and RFC 8032 strict decoding (canonical `S`, small-order
  rejection) ~200: **~1 200 lines**, RFC 8032 §7.1 vectors plus Wycheproof EdDSA. It lands in
  `crates/crypto` as stage **ID-1b**, after ID-0 and before PR-3 merges (PR-3 signs with it).
  Seed form: a 32-byte seed → keypair (RFC 8032 §5.1.5); key id =
  `SHA-256("sentinelos:keyid:v1" ‖ pubkey)`. **Minds change on:** if it runs well over ~1.5 k
  lines or fails constant-time review, §8.3 reopens **for signatures only** and one audited
  crate is vendored under `kernel/docs/external-tcb.md`.

**Why.** The TCB argument that admitted `limine` and is weighing `wasmi` applies here, with a
cheaper alternative: these primitives are small, completely specified, and have exhaustive
public test vectors; the third-party stack is 37× larger than what we would write, mostly
generic plumbing, a quarter of it `unsafe`, partly vector code our target rules forbid. In-tree
code is also Kani-able and Miri-able as written, and runs identically on the host. **Decided
(Veeti, P2): crypto stays in-tree.**

**The honest cost.** Home-grown crypto is how projects get burned. Mitigations, all merge
conditions on the PR named:

- **Vectors.** RFC vectors as KATs on the host and **at boot** (catches target-specific
  miscompilation, e.g. the soft-float ABI); Wycheproof vectors for ChaCha20-Poly1305,
  XChaCha20-Poly1305, HKDF, HMAC, EdDSA; for Argon2id the phc-winner reference vectors plus a
  differential sweep that crosses the H′ variable-length-hash edges (output lengths around 64
  bytes and block-size multiples).
- **CI lanes (D1).** kernel.yml runs `cargo test -p crypto`; verify.yml runs `cargo kani -p
  crypto` (60 s per harness) and adds `keyring:: login:: kdf:: rng::` to the kernel Miri filter;
  Miri runs on `crypto` once, on the RFC 9106 §5.3 vector only (Argon2 under Miri is slow). A new
  **`crypto-oracle` host job** (committed lock, timeout) runs a deterministic seeded differential
  against RustCrypto, ~10⁵ inputs per primitive (Argon2id at `m ≤ 64 KiB`), and a second
  independent oracle (libsodium or the reference C) for Argon2id and XChaCha20-Poly1305. It
  **gates before ID-3 merges**.
- **Constant time (D2).** A ctgrind-style gate in `crypto-oracle`: Valgrind memcheck with
  secrets marked undefined, over `ct::eq`, ChaCha20, Poly1305, the AEAD, HMAC/HKDF, BLAKE2b,
  Ed25519 signing and the Argon2i (data-independent) half of Argon2id, with the data-dependent
  half suppressed and the suppression documented. dudect runs informationally. A source lint
  (`check-ct`) rejects table indexing and branches on values typed as secret. **Residual:** the
  gate checks host codegen, not the `x86_64-unknown-none` binary; the soft-float target emits
  the same scalar integer ops, but that is an argument, not a measurement.
- **Fuzz (D3).** Differential fuzz targets per primitive join the lane (§16).
- **External review (D13)** of `crates/crypto` before **whichever comes first**: FS-E merges,
  the first image that holds a real user's keyring, or the first non-first-party component.

Constant-time on this machine: ChaCha20 is add/rotate/xor; Poly1305 with 26-bit limbs and
Ed25519 with 51-bit limbs use 64-bit and 128-bit multiplies, constant-time on x86-64; BLAKE2b
is add/rotate/xor; there is **no AES**, hence no table-timing or AES-NI question (§10.6).

**Alternatives.** *RustCrypto as a dependency* (audited code; the spike's numbers and the build
failure stand against it today). *A single audited C library* (no: C in the kernel is worse than
either). *Argon2 only, borrow AEAD from a crate* (the AEAD crate is the one that did not build).

**Minds change on:** a RustCrypto release set that builds for the target with SIMD compiled out
and fits an external-TCB row at a few thousand lines; or an external review that finds the
in-tree code materially weaker than the oracle (then vendor the oracle under
`kernel/docs/external-tcb.md`, component A5).

### 8.4 Constant-time comparisons and oracles

- There is **no stored password hash**. The check is the AEAD open of the slot: Poly1305 tag
  and the key-commitment tag (§10.3) are compared with `crypto::ct::eq` (XOR-fold over the
  full length, no early exit, result passed through `core::hint::black_box`).
- A wrong passphrase and a tampered slot are the **same** outcome (`Unauthentic`) and the
  same message. A keyring that fails its block hash is `Corrupt` *before* any KDF runs: a
  structural fact about the disk, not about the secret, so naming it is not an oracle.
- The KDF runs to completion on every attempt with the slot's parameters; time depends on the
  parameters (public), not on how wrong the guess is.
- Recovery-key checksums (§10.5) are checked before the KDF and **do not** count as a failed
  attempt: the checksum is a function of what was typed, not of the real key, so it reveals
  nothing about the secret.

### 8.5 Failure delays and the persisted counter

**Decision.**

- The keyring header holds `failures: u32` (attempts since the last successful unlock,
  incremented with `saturating_add`) and `last_attempt_gen: u64`.
- **Ordering**: on Enter (one Enter = one counted attempt = one KDF, §10.3), the login state
  machine enters `Persisting { ticket }` and requests a commit of `failures + 1` (the keyring
  replacement: keyring + bitmaps + index + superblock, §10.4), *then*, only when the commit
  completes, starts the KDF, *then* shows the verdict. Success commits `failures = 0`
  (`Resetting`) and shows "N failed attempts since your last unlock" when N > 0. A power cut
  after a wrong guess leaves the count incremented; a power cut during a right guess leaves it
  incremented by one, which is harmless.
- **The pure transition function** `step(state, event) -> (state, action)` takes commit
  completion as an input event (`Persisted(n)`, `PersistFailed`, `KdfDone(r)`, `Key(k)`,
  `Tick(t)`). Kani (ID-3) proves: no `KdfStart` action without a preceding `Persisted(n + 1)`;
  no verdict without `KdfDone`; `PersistFailed` leads to `Locked` with no KDF; `backoff` is
  total, monotone and capped.
- **When the counter cannot be persisted (B3).** The counter write is the **one** metadata
  write allowed while SentinelFS is read-only for data (a failed commit, a scrub with `bad > 0`,
  `EntropyUnavailable`: none of those stop a metadata commit by themselves). If it still cannot
  be persisted (I/O error, disk full past the metadata reserve, `Corrupt`), **passphrase
  attempts are refused** ("Can't record attempts on this disk — use your recovery key"); a
  **recovery-key unlock is still allowed**, because 128 bits make the counter irrelevant.
  *Alternative recorded* (security): allow passphrase attempts against an in-RAM floor of 5 with
  an "attempts not recorded" banner. Declined: it reopens reboot-to-reset exactly when the disk
  misbehaves, and the recovery key covers the owner.
- **Backoff** (pure function, Kani: total, monotone, capped): attempts 1–4 free (beyond the
  KDF's own ~2 s); from the 5th, `delay = 30 s × 2^(failures − 5)`, capped at 1 h. The delay
  runs on the mono clock from the later of the failure and the current boot, so a reboot
  restarts the full delay instead of skipping it. **No wipe-after-N** (a denial of service
  against the owner, and an L2 can always reset by editing the disk).
- **Attestability.** The counter is metadata in the clear, covered by the block hash and so by
  the superblock hash. Before unlock there is no signing key; at the first successful unlock
  after ID-4, the kernel appends a signed IntegrityLog record `{ unlock, failures_since_last,
  gen }`. An offline reset of the counter is an L1 action (it needs a disk edit) and is
  detectable only through the anchor (§13).

**Alternatives.** *Counter in the superblock* (no free bytes below 512 that are not reserved);
*counter in memory only* (reboot resets it; this is the hole the ordering closes); *counter in
TPM NV* (later, with the TPM anchor: then it is also rollback-proof).

**Minds change on:** a product decision for wipe-after-N (would need the TPM, or it is
theatre); evidence that two commits per attempt wear real flash (then batch: one commit before
the KDF, the reset folded into the next routine commit).

## 9. Memory: the KDF arena

### 9.1 Options

| Option | TCB delta | Memory | Verdict |
|---|---|---|---|
| **A. Parameters that fit the heap** (≤ ~2 MiB) | none | none extra | **Rejected.** 2 MiB Argon2id is 10× below OWASP's floor; the heap's other users would OOM-halt alongside. |
| **B. Static reservation** (`static ARENA: SpinMutex<[u64; N]>` in BSS) | none (safe Rust) | **N pinned forever**: 64 MiB is a quarter of the QEMU machine, for one second per boot | Rejected for v1; the fallback if reviewers refuse every new row. Fixes `m` at build time: no calibration upward, a 128 MiB machine cannot boot a 64 MiB build. |
| **C. Grow the heap** | text only | pinned forever, and a 64 MiB first-fit block in an infallible allocator | Rejected: same waste as B plus fragmentation and an OOM halt path. |
| **D. Frame arena via the HHDM** | **one row (M16)** | held for one attempt, wiped, returned | **Chosen.** |
| E. Frame arena mapped into a new VA window | one row + mapping | contiguous VA | Rejected: no unmap exists, so frames could never be returned without leaving a live mapping to reused memory. |

### 9.2 Decision: `hal::mm::FrameArena`

All usable RAM is already HHDM-mapped read-write, so an arena needs **no page-table change**:
it is a set of frames popped from the frame allocator, an index of their physical addresses,
and safe accessors. Argon2id's memory is 1 KiB blocks; four per 4 KiB page; the safe adapter in
`kernel::kdf` maps block `j` to page `j / 4`, offset `(j % 4) × 128` words.

- **Index without the heap.** `1 ≤ pages ≤ MAX_PAGES = 262 144` (1 GiB; `pages == 0` and
  anything larger return `TooLarge`/`Empty` before touching the allocator). Two levels: a
  **root frame** (512 physical addresses of index frames) and index frames (512 data-frame
  addresses each), all owned by the arena and stored as `u64` physical addresses, so `Send` is
  automatic; `!Sync` comes from a `PhantomData<Cell<()>>`. 64 MiB = 16 384 data frames + 32
  index frames + 1 root = 0.2 % overhead.
- **Reservation (B6).** `reserve` is generic over a `FrameSource` (the real allocator in the
  kernel; a modelled one for Kani and Miri) plus the HHDM offset, so the verifiers check the
  code that runs. It calls `alloc_frame()` **once per frame** (no new batched operation), root
  first, then for each index frame its data frames. The free-count precheck
  (`free_frames ≥ need + keep_free`, `checked_add`) is **advisory only** — it saves a doomed
  attempt; all-or-nothing comes from **rolling back** the moment `alloc_frame()` returns `None`:
  every data, index and root frame taken so far is returned, and `Insufficient { need, free }`
  is reported. `keep_free` = 8 MiB is re-checked per index frame. `reserve` returns
  `ArenaError::WrongContext` if `!interrupts_enabled()` (hal-tcb §5e's allocator rule: never
  allocate with IF = 0 while another task may sit in the allocator); it runs only on
  `login-kdf` (IF = 1, preemption on).
- **Access**: `page(&self, i) -> Option<&[u64; 512]>` and `page_mut(&mut self, i) ->
  Option<&mut [u64; 512]>`; the borrow checker does the aliasing proof. The Argon2id adapter
  copies the previous and reference blocks into two caller-owned scratch buffers (wiped,
  §6) and writes the new block through `page_mut`, so no two live references into the arena
  ever overlap. Pointers are formed with `ptr::with_exposed_provenance_mut(phys + hhdm)`.
- **Wipe and Drop (B6, B7).** `wipe(&mut self)` zeroes every data frame with Z1 and sets a
  `wiped` flag. `Drop` runs only on `login-kdf` (IF = 1, preemption on), and in this order: for
  each index frame, read its entries, wipe (unless `wiped`) and `dealloc_frame` each data frame;
  then wipe and free the index frame; finally the root. The order matters because
  `dealloc_frame` overwrites word 0 of the frame it frees with the free-list link: an index
  frame must not be freed while its entries are still needed. Rollback in `reserve` uses the
  same routine, so the three kinds of frame are always all returned.
- **Proof hook.** Under `login-test` the ID-2 proof calls `wipe()`, reads every page back with
  volatile reads (`hal::mem::read_volatile_words`, test-only, part of Z1's module), asserts zero,
  then drops; `Drop` skips the second wipe. Read-back proves the zeroes landed, not that a
  production build cannot elide them; that is construction (volatile stores, a language
  guarantee) plus Miri.
- v1 has one user; ID-6's parallel lanes need a shared atomic view, which is a new row then.

**Frame uniqueness is a precondition M16 cannot check (B5).** M16's soundness rests on "no one
else can reach an arena frame except through the HHDM, and no one else returns it". Today safe
code could break that: `FRAME_ALLOCATOR` is a `pub static`, `dealloc_frame` is a safe `pub fn`
whose precondition ("a frame you own") is unchecked, and `map_mmio` and `ActivePageTable::new`
accept any physical address, so a second mapping of a USABLE frame is a safe call away. ID-2
closes this, owned by hal-specialist: `dealloc_frame` (or the static) becomes `pub(crate)`;
`map_mmio` refuses any range overlapping a USABLE region (`MmioError::UsableRam`);
`ActivePageTable`'s constructor becomes `pub(crate)`. New hal-tcb §4 invariant: **"a free or
arena-owned frame has no mapping except the HHDM; only its owner returns it."** M5's evidence is
amended to cite the visibility change instead of "the heap only ever frees frames it allocated".

### 9.3 New `hal` rows (exact)

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|---|---|---|---|---|
| **M16** | `mm/arena.rs` · `FrameArena::frame_ref` / `frame_mut` (private; used by `reserve`, `page`, `page_mut`, `wipe`, `Drop`) | form `&[u64; 512]` / `&mut [u64; 512]` from `ptr::with_exposed_provenance(_mut)(phys + hhdm)` for a frame the arena owns | Argon2id needs tens to hundreds of MiB that the 4 MiB heap cannot hold; the HHDM is the only path to a frame's bytes | Every `phys` was returned by `alloc_frame` (4 KiB-aligned USABLE RAM) and is owned by this arena until `Drop` returns it; by the §4 invariant above (B5) no other mapping or owner exists; Limine HHDM-maps all RAM RW, so `phys + hhdm` is valid, writable and 4 KiB-aligned for 4096 bytes. The reference's lifetime is tied to `&self` / `&mut self`, so it cannot outlive ownership, and `&mut` is exclusive by the borrow. Index and root frames are reached the same way; `i < pages` is checked before any lookup; Drop reads an index frame's entries before freeing it. | **Kani** at shrunken fanout (4 entries per root/index frame): index decomposition in range; all-or-nothing against a nondeterministically failing `FrameSource`; frame conservation (every frame taken is returned exactly once, on rollback and on Drop); `TooLarge`/`pages == 0`. **Miri** on the model under Stacked and Tree Borrows. **QEMU** line (`match=yes wiped=yes frames-returned=yes`). The HHDM cast itself stays **Reasoned + QEMU**, like §5b. |
| **Z1** | `mem.rs` · `secure_zero(&mut [u8])`, `secure_zero_words(&mut [u64])` (+ test-only `read_volatile_words` under `login-test`) | `core::ptr::write_volatile` per element, then `compiler_fence(SeqCst)` | Wipes the compiler may not elide: keys, passphrase buffer, KDF slot, crypto state, arena frames, payload arenas (component A9), the SentinelFS plaintext cache (SentinelFS §10) | Writes only within the borrowed slice (index < len), each element aligned by type; the fence orders them before any later reuse or free. Takes `&mut`, so no aliasing. | Non-elision: **Reasoned (language guarantee** of volatile accesses). Bounds and result: Miri (host) + Kani (writes stay in bounds; the slice reads zero afterwards) (D6) |
| **R1** | `rng.rs` · `rdrand64() -> Option<u64>` = `retry::<10>(raw_rdrand)` | `rdrand r64` + `setc` (`asm!` with `nomem, nostack` — **not** `preserves_flags`, since it writes CF) | The kernel has no entropy source; keys, salts and nonces must not come from tick counters | Called only when `cpuid.1:ECX.RDRAND` is set (checked once, cached in an atomic); writes one register and the flags, touches no memory. The retry policy is a pure generic `retry::<N>(f)` that Kani and Miri check with a modelled `f`; up to 10 tries on CF = 0 (Intel's guidance), then `None`. Output is untrusted input to the DRBG, never used raw. | Reasoned + QEMU: xtask passes `-cpu Haswell,+rdrand,…` explicitly; a **negative boot** with `-cpu Haswell,-rdrand` asserts `EntropyUnavailable` and that keyring creation is refused; KVM. Kani on `retry` and on the health tests (D6) |

**Not new rows**: frame pops and pushes are M4/M5 (M5's evidence amended, B5). ID-2 adds to the
heap an in-use byte counter and a monotone **`alloc_calls()`** counter (safe arithmetic inside
M11's existing blocks; **row text amended**, no new op) so the proof can assert
`heap-delta=0 heap-allocs=0`. ID-3 amends the K-row text: the keyboard ring's consumer zeroes
each entry after reading it (D9; atomics, no new op). ID-5 may send the i8042 LED command for
Caps Lock through the existing K2 `outb` (row K4 text amended).

**Against hal-tcb's discipline.** Each row is the smallest primitive its consumer needs, of a
class the registry already holds (M16 is M3/M15's "owned frame through the HHDM", made
borrow-scoped; Z1 is one volatile store loop; R1 is one instruction, like C-rows in §2).
Nothing about policy, parameters, parsing or key handling enters `hal`. RDSEED is deliberately
**not** wrapped (decided, D16): one more instruction for marginal benefit to a DRBG seed.

### 9.4 OOM, peak memory and small machines

- **The login path allocates nothing from the heap.** The login-kdf task, its stack and
  `XsaveArea` exist from boot; `SecretBuf` is a fixed `[u8; 256]` in the static login state (its
  only home); the keyring block is a 4 KiB buffer in the static login state (decoded from the FS
  cache slab's verified copy); KEK, master and subkeys live in the static key store; the commit
  uses SentinelFS's fixed slabs. The arena is the only memory taken, and it is fallible.
  **Asserted** (`heap-delta=0 heap-allocs=0`) over the window **from Enter to keys installed,
  before the WM is created** (B7).
- **Who may run in that window, and why each is heap-quiet:** the BSP idle loop (draws from
  fixed state; its WM is not yet created); `login-kdf` (fixed slot, arena from frames);
  `sfs-commit` (fixed slabs, SentinelFS principle 7); the AP idle tasks and the network poll
  path (fixed rings). Any new pre-unlock task that allocates breaks the assertion **by design**:
  it has to justify itself or move after unlock.
- **Peak** during a QEMU-class unlock: arena 64 MiB + 132 KiB index; heap 4 MiB (unchanged);
  KDF stack 64 KiB. Under `-m 256M` (~245 MiB usable, ~230 MiB free at the lock screen) that
  leaves ~165 MiB.
- **A machine smaller than the one that set up the slot**: `reserve` fails `Insufficient`; the
  lock screen says "This device needs 64 MiB free to unlock with your passphrase. Use your
  recovery key." The recovery slot needs no arena (§10.5), so the disk is never stranded on a
  small machine as long as a recovery slot exists — which is why setup offers one by default.
- **Not enough RAM at setup** (< 57 MiB usable): recovery-key-only keyring, recovery key
  mandatory (P5).

## 10. Key hierarchy and the keyring block

### 10.1 Hierarchy and labels

```
passphrase ──Argon2id(m,t,p, salt_slot, X)──► KEK ─┐
recovery key ──HKDF-Extract(salt_slot)────────► KEK ─┤   (one per slot)
                                                    ▼
          prk_slot = HKDF-Extract(salt = keyring_id, ikm = KEK)
          slot_wrap   = Expand(prk_slot, "sentinelos/keyring/v1/slot-wrap", 32)
          slot_commit = Expand(prk_slot, "sentinelos/keyring/v1/slot-commit", 32)
                                                    │  XChaCha20-Poly1305 unwrap (AD = slot header)
                                                    ▼
                                  master key (32 random bytes)
          prk_m = HKDF-Extract(salt = keyring_id, ikm = master)
          subkey_wrap = Expand(prk_m, "sentinelos/keyring/v1/subkey-wrap", 32)
                                                    │  unwrap each subkey (AD = subkey header)
                    ┌───────────────────────────────┼──────────────────────────────┐
                    ▼                               ▼                              ▼
         tree key (32 random)            device seed (32 random)          reserved: user(n) keys,
         prk_t = Extract(fs_uuid, tree)  → Ed25519 keypair (ID-1b),         object-key tree wrap
           "sentinelfs/v1/name-hash"       held and used in kernel::secrets;
           "sentinelfs/v1/name-enc"        key id = SHA-256("sentinelos:keyid:v1" ‖ pubkey)
           "sentinelfs/v1/data-wrap"   → wraps per-object random data keys (FS-E)
           "sentinelfs/v1/dedup"       → keyed hash for User(n) blob domains
```

- **Subkeys are random and wrapped, not derived.** Derivation (`tree = HKDF(master, "tree")`)
  would save 72 bytes and make every subkey's lifetime equal the master's: no independent
  rotation of the device key after a suspected signing-key compromise, no future
  hardware-held subkey, no tree-key epoch. Wrapping costs one AEAD open per subkey.
- **Why a master key at all**, rather than each slot wrapping the subkeys directly: slots stay
  one wrap each (152 bytes) however many subkeys exist, and rotating the master (re-wrap the
  subkeys, rebuild the slots the user re-enters) never touches data.
- The names map onto SentinelFS §10's chain: `unlock_key` = KEK; `tree_key` = tree key; the
  §10 labels `{name-hash, name-enc, data, dedup}` are the four above (`data` becomes
  `data-wrap`, because per-object keys are random and wrapped, so crypto-shred works, §10.6).
- **Per-object keys** (FS-E) live in an **object-key tree** whose root Pointer is in the
  keyring block, not in the snapshotted `root`/`blobs` trees: deleting an entry shreds that
  object even in snapshots that still hold its ciphertext (SentinelFS's "deletion is not
  erasure" answer). Snapshot reads of a shredded object fail `Shredded`. Replay determinism
  (SentinelFS principle 4) holds with the RNG as an input: host tests seed it.

### 10.2 The superblock's 32 bytes at [352, 384)

**Decision.** Same byte layout SentinelFS §7.1 reserved, read as follows (C7). The first field,
named `alg` in SentinelFS §7.1, is read as **`keyring_format`**, and the 16-byte `salt` is
renamed **`keyring_id`** (a request to SentinelFS §7.1, §18):

```text
352  2  keyring_format  1 = keyring v1 (0 = volume not keyed: every byte of the field zero
                        and keys null, exactly the v2 rule)
354  2  ver             0x13 (the Argon2 version the floor refers to)
356  4  m_kib   ┐ the volume's FLOOR for passphrase slots: the parameters chosen by
360  4  t       │ calibration at setup. A new slot below it is refused; raising it is a
364  4  p       ┘ superblock commit. m/t/p == 0 is allowed: no passphrase floor
                  (a recovery-only keyring, §9.4)
368 16  keyring_id      16 random bytes; equal to the keyring block's keyring_id
                        (mismatch = Corrupt); the HKDF salt for every slot and the master
```

**Decode rule:** `keys` is non-null **⇔** the field is non-zero. Either without the other is
`Corrupt`. After FS-E lands, `keyring_format == 0` together with any encrypted item is also
`Corrupt` (C12).

**Why not "the" KDF parameters?** There is more than one slot, each with its own salt and
parameters (a recovery slot has no Argon2id at all), and they live in the keyring block. What
belongs in the superblock is what must be **state of the volume**: that it is keyed (so a kernel
without login refuses it: v2's non-zero refusal is unchanged), the policy floor (so an offline
edit that lowers it is visible to FS-5 attestation — after FS-5, and not against a rollback,
T-LOG-2), and the keyring's identity (so a keyring block from another volume, or a reformatted
one, is refused before any KDF runs). Downgrade of an individual slot's parameters needs no
superblock help: they are the wrap's associated data (§10.3), and the decoder's absolute floor
(`BelowFloor`) bounds them anyway. All 32 bytes stay inside the reservation; the `keys` Pointer
at [392,440) names the keyring block. Bytes **[440,512) are 72 unreserved, validated-zero bytes
and this spec leaves them unclaimed** (C12). The first-sector torn-write argument of SentinelFS
§7.1 is untouched. **No SentinelFS version bump**: a pre-login kernel already refuses a keyed
volume. (A future multi-user keyring is a keyring `version` bump, not a SentinelFS bump, C12.)

### 10.3 The keyring block (kind 6)

The standard 64-byte metadata header (`hash`, `gen`, `kind = 6`, **`tree_id = 5` (keys)**,
`fs_uuid`), then:

```text
off   len  field
 64     4  magic "SKR1"
 68     2  version = 1
 70     2  slot_count        number of non-empty slots (≤ MAX_SLOTS = 8)
 72    16  keyring_id        = superblock keyring_id
 88     4  failures          attempts since the last successful unlock (§8.5), saturating
 92     4  flags             bit 0: recovery slot offered and declined at setup (UI only)
 96     8  last_attempt_gen
104     8  master_epoch      +1 on every master rotation
112    48  objkeys: Pointer  root of the object-key tree (tree_id 6, FS-E); NULL in v1
160  1216  slots[8] × 152    (§ below); empty slot = all zero
1376  480  subkeys[4] × 120  (§ below); empty = all zero
1856 2240  zero              validated zero (a non-zero byte is Corrupt)
```

**Tree ids (C8).** SentinelFS `tree_id` 5 = keys (the keyring block) and 6 = objkeys are
reserved here. ID-3 extends SentinelFS's pointer validation and scrub/bitmap reachability to the
keyring block (it is a live metadata block like any other); FS-E does the same for the
object-key tree.

**At most one passphrase slot and one recovery slot per user (C7).** Enforced by decode
(`DuplicateKind`). This removes multi-slot trial and its timing leak: "Use recovery key" is an
explicit lock-screen mode, so **one Enter is one counted attempt and one KDF** over exactly one
slot. `MAX_SLOTS = 8` stays as format room (FIDO2, TPM, other users).

**Slot (152 bytes).** All fields before `nonce` are the wrap's associated data, prefixed by
`"sentinelos/keyring/v1/slot" ‖ fs_uuid ‖ keyring_id ‖ le64(master_epoch)`:

```text
 0   1  kind         0 empty · 1 passphrase · 2 recovery · 3 FIDO2 (reserved) ·
                     4 TPM (reserved) · 5 PIN (reserved); v1 refuses 3–5
 1   1  layout       0 = US-QWERTY (passphrase slots)
 2   2  user         1 = owner (the only user in v1, §14)
 4   4  slot_id      unique within the keyring, strictly monotone, never reused
 8  32  kdf          alg u16 | ver u16 | m_kib u32 | t u32 | p u32 | salt[16]
                     passphrase: alg 1 = Argon2id (production); alg 0xF0 = Argon2id-test,
                     accepted only by a `login-test` kernel (B1)
                     recovery: alg 2 = HKDF-SHA-256, m/t/p zero
40   8  created_gen
48  24  nonce        random (XChaCha20)
72  32  wrapped      master key ciphertext
104 16  tag          Poly1305
120 32  commit       slot_commit (key commitment, T-LOG-4)
```

**Subkey (120 bytes)**: `kind u8 (1 tree, 2 device seed) | alg u8 (1 XChaCha20-Poly1305) |
reserved u16 | user u16 | reserved u16 | created_gen u64 | key_id [32] (device seed: the public
key id; tree: zero) | nonce [24] | wrapped [32] | tag [16]`, AD = the fields before `nonce`
prefixed by `"sentinelos/keyring/v1/subkey" ‖ fs_uuid ‖ keyring_id ‖ le64(master_epoch)`.

**Decode** is a total `&[u8; 4096] -> Result<KeyringView, KeyringError>`: block hash checked by
`blk` before the bytes are parsed (the verified-cache rule); magic, version, `slot_count` equal
to the number of non-empty slots, every slot kind known (or refused), KDF fields valid (`alg`
matches kind; for Argon2id `p ∈ 1..=16`, `t ∈ 1..=64`, `8·p ≤ m_kib ≤ 1 GiB`, **and the
absolute floor `m_kib ≥ 19 456`, `t ≥ 2` → else `BelowFloor`**; `alg 0xF0` refused unless built
with `login-test`), unique and per-user-unique kinds, unique slot ids, at least one owner slot,
zero tail, `keyring_id` equal to the superblock's. Loops are bounded by `MAX_SLOTS`, never by an
on-disk count. For Kani the codec is split (D4): header decode; `decode_slot(&[u8; 152])`;
`decode_slots::<N>` checked at N = 3; a generic zero-tail check; a `well_formed` predicate; and
an encode → decode round trip at N ≤ 3.

**Unwrap order**: compute KEK → `slot_wrap`, `slot_commit` → `ct::eq(commit)` → AEAD open →
master. The commitment check makes a crafted slot that opens under many KEKs useless: each slot
commits to exactly one KEK (Len, Grubbs, Ristenpart's partitioning oracles).

### 10.4 Slot operations

Each requires `Keyring<Unlocked>` (the master key in hand) and is the named SentinelFS operation
kind **`replace_keyring`** (C8): write the new keyring block, update bitmaps and the group index,
write the superblock — an asserted footprint of **4–5 blocks** inside FS-1b's ≤ 13-block budget
(a request to FS-1b, §18).

**Scrubbing the old keyring (B2).** A single commit leaves the *previous* superblock slot naming
the *old* keyring block, which still holds the removed or replaced slot. So add, remove, replace
and rotate **commit twice** (the second commit is an otherwise empty commit that rewrites the
other superblock slot, so both slots name the new keyring), then **zero and flush the freed old
keyring block(s)** — the blocks the two commits freed — before reporting success. The boot proof
carries `old-keyring-scrubbed=yes`, and a host test scans the whole `MemDevice` after the
operation and asserts no block decodes to (or contains the wrap of) the removed slot.
**Residual (T-LOG-13):** SSD/FTL remapping can keep an old physical copy we cannot address.
**Invariant:** snapshots and rollback **never** restore the `keys` pointer — `snapshot` records
`root`/`blobs` only (SentinelFS §7.5) and `rollback` keeps the current `keys`; host test: change
a passphrase, roll back to an earlier snapshot, the old passphrase is still refused.

- **Add** (new passphrase where none exists, a new recovery key): fresh salt, calibrated
  parameters ≥ floor, fresh nonce, new `slot_id`; refused if a slot of that kind already exists
  for the user (use replace) or `MAX_SLOTS` is reached.
- **Replace** (change passphrase, regenerate recovery key): the new slot is written **at the old
  slot's index** with a new `slot_id`, in the same block, so there is no committed state with
  neither and none with both.
- **Remove**: refused (`LastSlot`) if it would leave the owner without a slot. Removing the
  passphrase slot while a recovery slot remains is allowed after an explicit confirmation;
  removing the recovery slot below the Argon2id threshold is refused (P5).
- **Rotate master** (after a suspected compromise): new master, every subkey re-wrapped,
  `master_epoch + 1`; slots are rebuilt for secrets the user re-enters now; the recovery slot is
  kept (rebuilt by generating a new recovery key) unless the user explicitly declines it, and
  the old owner slot is not dropped before a rebuilt one exists. Data is not re-encrypted (the
  tree key is unchanged; §7.3 says what that does and does not buy).
- **Kani (D4):** slot operations sit behind a `trait Wrap`, with a model in which the tag equals
  the master's identity; bounded sequences of depth 3–4 of add / replace / remove / rotate from
  any well-formed keyring prove: the result is well-formed with ≥ 1 owner slot; every non-empty
  slot wraps the current master; an `Err` **or a failed commit** leaves the keyring bit-identical;
  rotate never removes the last owner slot before a rebuilt slot exists; `slot_id`s are strictly
  monotone; a recovery slot survives rotation unless explicitly declined.

### 10.5 Recovery key

- 128 random bits + a 32-bit check (the first 4 bytes of `SHA-256("sentinelos:recovery:v1" ‖
  key)`), encoded in **Crockford base32** (32 symbols) **plus Crockford's mod-37 check symbol**
  (D5): 33 symbols, shown as 8 groups of 4 and the check symbol (`7H2K-9QXD-…-W`).
  Case-insensitive; `I`/`L` read as `1`, `O` as `0`; hyphens and spaces ignored. The mod-37
  symbol **detects every single-symbol substitution and every adjacent transposition**
  (deterministically, 37 being prime); the truncated hash catches other random errors with
  probability 1 − 2⁻³² (a probabilistic claim, stated as one). A mistyped key fails locally and
  is not counted as an attempt.
- `KEK = HKDF-Extract(salt = slot salt, ikm = key)`: no Argon2id, because 128 bits of entropy
  cannot be guessed; no arena, so it works on any machine. It is the one secret that unlocks
  when memory is short or when the failure counter cannot be persisted (§8.5).
- Shown **once** at setup, full screen, behind a "reveal" action, with "write it down; it is
  the only way in if you forget your passphrase". Never stored, never logged, never
  re-displayable (a new one can be generated while unlocked, replacing the old slot).
- **Decided (Veeti, P5): optional, default-on.** Setup offers it by default; declining needs an
  explicit second confirmation and sets the header flag (so the System panel can nag). It is
  **mandatory** on a machine below the Argon2id threshold, where it is the only slot (§9.4) —
  as the reviewers noted, already implied.
- Kani (ID-5): decode is total over N symbols with the checksum stubbed; the mod-37 symbol's
  single-error detection is checked exhaustively on the host.

### 10.6 The AEAD and nonce discipline

**Decision.** **XChaCha20-Poly1305** for every wrap and, in FS-E, for data. Keyring wraps use a
fresh random 24-byte nonce per wrap (stored). FS-E uses
`nonce = le64(gen) ‖ le32(counter) ‖ txn_salt[12]`, where `counter` is a per-transaction,
per-key monotone `NonceSeq` (exhaustion is `NeedCommit`, never a wrap) and `txn_salt` is drawn
from the DRBG once per transaction. FS-E's associated data binds **object id, block position and
gen** (D8), so a valid ciphertext cannot be moved to another object or offset.

**Why not just `gen ‖ counter` (corrected, D8).** It is unique as long as no generation number
is ever used for two different transactions. Two real cases break that: a **crash before
commit** (the next boot re-runs generation `g`, encrypting different plaintext with the same
counters, while the crashed transaction's ciphertext may already be on disk in freed blocks),
and an **offline image restore** (an L1/L2 restores an older image; the next transaction reuses
a generation the attacker already saw). A privileged SentinelFS rollback is *not* such a case:
it writes a new, higher generation. Reuse would be the stream-cipher AEAD catastrophe (keystream
reuse, Poly1305 key recovery and forgery). The per-transaction 96-bit salt makes a repeat a
2⁻⁹⁶ event, while `gen ‖ counter` keeps uniqueness within a transaction provable (Kani) and
auditable.

**PR-3 from day one.** `kernel::secrets` (component PR-3) encrypts with **random 192-bit
XChaCha nonces** (or the FS-E construction), not the bare `generation ‖ counter` of SentinelFS
§10 item 1, whose text should change accordingly (a request, §18).

**Why XChaCha20-Poly1305 over AES-256-GCM-SIV or AES-GCM.** AES in safe Rust without AES-NI is
either table-based (secret-dependent cache access: not constant-time) or bitsliced (complex,
~10× slower); AES-NI and PCLMULQDQ would be new `hal` rows in the `hal::simd` class, and TCG
emulates them slowly. AES-GCM's 96-bit nonce is catastrophic on reuse; GCM-SIV fixes misuse but
not the AES problem. ChaCha20 is constant-time in plain scalar code, fast without SIMD, and the
192-bit nonce makes random nonces safe. Every wrap carries an `alg` byte, so a hardware AES-GCM-SIV
tier can be added later without a format bump.

**Minds change on:** a DMA-speed SentinelFS where ChaCha20 dominates the commit path (then an
AES-GCM-SIV tier with AES-NI rows, behind the `alg` byte); a standard committing AEAD with a
vetted construction (then drop the separate commitment tag).

### 10.7 Entropy

`kernel::rng` is an **HMAC-DRBG (SP 800-90A, SHA-256)** seeded from 64 RDRAND words, the mono
tick count and the PIT phase, reseeded every 2¹⁶ requests and at every unlock. Every generate
call that produces a **salt, nonce or key** passes fresh RDRAND words as SP 800-90A
*additional input* (D7), so a DRBG state captured once does not predict later keys. Health tests
on the raw RDRAND output (repetition count; reject all-zero and all-ones words, the
AMD-after-resume failure mode) run before seeding and continuously. Without RDRAND, or with a
failed health test, the kernel **refuses to create a keyring, wrap or re-wrap a slot or write
encrypted data** (`EntropyUnavailable`); **metadata commits are still allowed** (the failure
counter, B3), and an existing volume still unlocks (unwrapping needs no randomness) and stays
read-only for data. ID-0's DRBG also gives SentinelFS A26 its format seed and PR-3 its ephemeral
key.

## 11. Trusted input path and lock screen

### 11.1 Who reads the keyboard

**Decision.** `hal::keyboard`'s ring keeps **exactly one consumer**, the `kernel::input`
router on the BSP idle loop. The router forwards by `LoginState`:

- `Setup | Locked | Persisting | Deriving | Resetting | Delay | Ephemeral`: every decoded event
  goes to `kernel::login`; nothing else sees it. Mouse packets go only to lock-screen
  hit-testing.
- `Unlocked`: the window manager, as today; after the memory gate, components receive key
  events only through the compositor service for the focused surface.
- **Always first**: the SAK chord, before any routing.

Rules (review checklist and a source guard, `cargo xtask check-keyboard-consumers`: only
`kernel::input` may name `hal::keyboard::poll_scancode`, like `check-ata-callers`): no key
event is logged while not `Unlocked`; no component API exposes raw scancodes; when `Deriving`
ends, the ring is drained and **discarded** before the state changes, so keys typed during the
KDF never reach the terminal (`typeahead-dropped=yes`). **Residue (D9):** the ring's consumer
zeroes each entry after reading it (K-row text amendment; atomics), the decoder holds no
history, and the `KdfSlot` input copy is wiped with Z1 as soon as `login-kdf` has taken it.

**What the boot tests drive (D10).** The PS/2 ring is 32 bytes, so xtask never bursts: it waits
for a `[login] ready: state=<setup|locked>` marker, then types over QMP paced at ≥ 20 ms per
key. Under `login-test` the router reports `[login] nav-key-unlock=refused` when xtask sends →
and Enter on an empty field (the old gesture), and the `Deriving` state is held for at least N
ticks after `[login] deriving`, so keys xtask types during it are deterministically dropped. The
test passphrase is distinctive and ≥ 24 characters; the leak scan searches both serial logs
**and the disk image** for it as ASCII, case-folded, hex, and as its scancode byte sequence. A
third boot kills QEMU on `[login] deriving` after a wrong passphrase, and the next boot asserts
the counter went up by exactly one.

### 11.2 Secure-attention key

**Decision.** **Ctrl+Alt+Del** is the SAK: in `Unlocked` it locks immediately (screen lock) and
shows the genuine lock screen; in any locked state it clears the field. The decoder gains Ctrl
(`0x1D`, `E0 1D`), Alt (`0x38`, `E0 38`), Delete (`E0 53`) and Caps Lock (`0x3A`).

**Native-first honesty.** Today every drawing component is first-party ring-0 code, so a fake
lock screen is a first-party bug, not an attack; the SAK is cheap insurance and trains the
habit. **After the memory-boundary gate**, three rules make it an enforcement point: (1) the
lock screen is a kernel-owned layer above every surface, and while locked the compositor
composites **no** component surface at all; (2) components never receive the SAK chord; (3)
consent prompts (PolicyAgent, KeyAgent confirmations) use the same kernel-owned layer and the
same input lock. A component can still draw a lookalike *while unlocked*; the SAK is the user's
way to know they are talking to the kernel (open question 3: a per-user anti-phishing mark).

### 11.3 The Cyber Dusk lock screen

Within the design language (§3 tokens, §5 reference screen):

- The glass card keeps the wordmark and the `private · secure · yours` line; the "press →"
  pill becomes the **passphrase pill** (pill radius, glass fill, cyan focus ring).
- **Masking without length.** No dots per character (that tells a shoulder-surfer the length).
  Each keystroke moves a soft pink shimmer one step along the pill (position = (random start +
  keystrokes) mod 8; the start is drawn per attempt, so even the first frames say nothing, D9);
  Backspace moves it back, and Esc clears with a fade. The user sees that keys register; an
  observer sees nothing countable.
- **Caps Lock**: a cyan chip "Caps Lock is on" under the pill, from the decoder's own Caps state
  (ID-5 syncs the keyboard LED at boot so the two agree).
- **Deriving**: the pill becomes a progress ring (Argon2id's pass/slice count is known up front,
  so progress is honest); input is ignored.
- **Failure**: the card does a short springy shake (the design language's ease-out motion) and
  says **"That didn't unlock. Try again."** — the same text for a wrong passphrase and a
  tampered slot. From the 5th failure: "Too many attempts. Try again in 0:30", counting down.
  `Corrupt` and `Insufficient` have their own plain messages (§8.4, §9.4).
- **Setup** (no keyring): "Create a passphrase", typed twice, a strength hint by length only
  (no dictionary in the kernel), then the recovery-key screen (§10.5). Until FS-E the setup
  screen says plainly **"Files on disk are not encrypted yet"** (T-LOG-15). Setup on an unkeyed
  volume that already holds data warns that existing files stay as they are (C12).
- **After unlock**: "Welcome back" plus, when non-zero, "3 failed attempts since your last
  unlock" on the desktop's first frame.

### 11.4 Lock levels, idle lock, lid close

**Decision.** Two levels.

- **Screen lock** (idle timeout, SAK, the shell's `lock`): the UI is gated and the input path
  locked; keys stay resident, so background work (commits, IntegrityLog, components) continues.
  On entry the SentinelFS plaintext cache is flushed and every clean entry wiped (SentinelFS
  §10 "flush and zeroize on lock"; FS-E makes this meaningful). Unlock needs the passphrase and
  runs the full KDF (there is no cheaper "screen PIN" in v1).
- **Seal** (the lock screen's "Lock & seal", the shell's `seal`, later suspend and lid close):
  everything in screen lock, then the tree key, object keys, device seed and master are wiped
  (Z1) — `secrets::seal()` is a kernel-local wipe, since the KeyAgent never holds the seed
  (§12.3) — the KeyAgent answers `locked`, and SentinelFS returns to the locked mount. Unlocking is a cold unlock.
- **Idle**: no keyboard or mouse input for `IDLE_LOCK = 5 min` on the mono clock → **screen
  lock** (decided, Veeti P3). Security's proposed second timer — an idle **seal** after 60 min —
  is open question 4, not v1. **Lid close / suspend**: needs ACPI events (after the IOAPIC/MADT
  work); when it exists it seals.

**Why two levels.** Wiping the cache while the keys stay resident defends only against a
bounded memory-disclosure bug; wiping the keys stops background integrity logging. The user,
not the kernel, should choose which they want when they walk away; the default is the
convenient one, and "seal" is one action away.

## 12. Boot and unlock sequence

### 12.1 Sequence

```
kmain: interrupts · mm · sched · smp · proofs (as today)
  │
  ├─ rng::init (ID-0)             RDRAND health → DRBG seeded, or EntropyUnavailable
  ├─ crypto KATs (ID-1)           boot self-test of every primitive
  ├─ spawn login-kdf (ID-2)       stack + XsaveArea allocated now, never at unlock
  ├─ sfs::prove_mount             mount LOCKED: superblocks, free space, keyring block
  │                               verified and decoded; no key; (FS-E) encrypted payload
  │                               reads return Locked
  ▼
idle_loop: LoginState
  Ephemeral (no disk) ── bannered session; never reaches the keyring path (D15)
  Setup (keyring_format == 0 / Unformatted) ── passphrase ×2 ─► calibrate ─► keyring +
  │                    superblock commit (×2) ─► recovery key screen ─► Unlocked
  Locked ── Enter ─► Persisting{ticket} (failures+1; poll once per frame)
        │              ├─ PersistFailed ─► Locked ("use your recovery key"), no KDF
        │              └─ Persisted ─► Deriving (login-kdf: arena, Argon2id, wipe)
        ◄─ denied ── verdict (Delay if backoff applies)
                     └─ ok ─► unwrap master → subkeys ─► Resetting{ticket} (failures=0)
                              ─► sfs: install tree key (full mount, FS-E)
                              ─► secrets::provision(device seed) (ID-4)
                              ─► drain + discard typeahead ─► Unlocked (WM created, as today)
```

### 12.2 What runs before unlock

**Decision.** Before unlock: the kernel, its boot proofs, the scheduler, `sfs-commit` (writing
only metadata: the keyring's counter), the network stack (ARP/ICMP), and the lock screen.
**Not** before unlock: the window manager, the shell, the Files app, any component that needs a
key (the KeyAgent instance may exist but answers `locked`). **No pre-unlock recovery console.**
Recovery is the recovery key, typed into the same lock screen ("Use recovery key").

**Why.** SentinelFS's security seat named exactly one thing that would keep names in the clear:
a pre-unlock console that must list files (SentinelFS §15 "minds change on"). Nothing in v1
needs one: the recovery key covers a forgotten passphrase, the `format` built-in (FS-2) is an
unlocked-shell action, and a `Corrupt` disk mounts read-only for an unlocked user to inspect.
So **names stay encrypted** (FS-E, SentinelFS §10 unchanged). The serial log must never print
a filename or file content before unlock (a review rule; before FS-E nothing prints any today).

**Decided (Veeti, P4): no pre-unlock console for now.**

**Minds change on:** a field need for pre-unlock repair (then a console that can scrub, roll
back and format but **not list**, which keeps names sealed).

**No disk attached (D15).** The kernel enters an explicit **`Ephemeral`** login state: a
bannered session ("No disk — nothing you do here is saved; this session has no keys"), no
passphrase, no keyring, no device seed (the KeyAgent stays `locked`). `Ephemeral` is a separate
state of the pure transition function with no transition into `Setup`, `Locked` or any
keyring-touching action (Kani: unreachable), and a boot without a disk asserts
`[login] ephemeral: disk=none keyring-path=unreachable ok`. xtask's normal boots always attach
a disk.

### 12.3 KeyAgent: from ephemeral to persistent

- **Where the seed lives (C3).** The device seed **and the signing operation** stay in
  `kernel::secrets` (kernel memory, the static key store's sibling). The KeyAgent is the
  **policy delegate**: it decides whether a request may be signed (its allow-list over the
  kernel-stamped `from`) and asks the kernel to sign; no key material ever crosses the bus, and
  seal is a kernel-local wipe. This refines component §9 ("holds the device identity keypair");
  that spec's text changes with PR-3 (a request, §18).
- **The seam (C4).** Not a `KeySource` enum but a provisioning state machine:
  `secrets::provision(DeviceSeed)` / `secrets::seal()`, and a KeyAgent that is `Locked | Ready`.
- **PR-3 (before this lands)** ships the KeyAgent and `kernel::secrets` with an ephemeral seed
  drawn from ID-0's DRBG and signs with ID-1b's Ed25519; it calls `provision` **late in boot**,
  after the KeyAgent instance exists, so `Locked` is genuinely reachable and asserted
  (`before-provision=locked`), then `sealing=none secrets-persist=no`, nothing on disk. PR-3 must
  not derive its seed from anything but the DRBG and must not write key material to disk.
- **ID-4 (after ID-3 and PR-3)** changes only **who calls `provision`**: at setup the device seed
  is drawn from the DRBG and wrapped as a subkey; at every unlock `kernel::login` unwraps it and
  calls `secrets::provision`; seal calls `secrets::seal()`. The key id is
  `SHA-256("sentinelos:keyid:v1" ‖ pubkey)`, the `signing_key_id` of component A6 and SentinelFS
  §9. Before unlock and after seal, the KeyAgent answers `locked`. The boot line becomes
  `sealing=passphrase secrets-persist=yes`, and the second boot proves the same key id.
- Component §18.1's question is then answered: passphrase sealing with a memory-hard KDF and a
  trusted input path. A TPM reopens it (§13).

## 13. Rollback anchor (FS-5)

**Decision.** v1 ships **`anchor: None`**. The field stays in the FS-5 record format.

**Honestly, what exists.** No TPM driver (no TIS/CRB MMIO, no command marshalling: a sizeable
`hal` spec of its own). No paired device (IdentityDir sync is a later component). So
`Tpm(counter)` and `PairedDevice(counter)` would be claims, not mechanisms.

**What an offline rollback attacker (L1/L2 with the disk) can still do in v1:**

1. Restore an older, internally consistent, previously signed image: undetectable (the
   IntegrityLog rolls back with it). Data written since is lost to the owner, not revealed.
2. Splice an **old keyring block** (with a slot for a since-changed passphrase) into the current
   volume — **only from a copy taken before the change**: our own disk no longer holds the old
   block after the double commit and scrub (§10.4), barring SSD remapping. With such a copy the
   superblock is re-hashed by the attacker, the `keyring_id` matches, the old slot unwraps the
   same master; with the old passphrase, the attacker reads current data (§7.3); without it,
   nothing.
3. **Reset the failure counter**: an L1 action; the attacker is then guessing at full Argon2id
   cost per guess, through our UI or offline.
4. Roll back a privileged SentinelFS rollback or a crypto-shred (resurrecting a shredded
   object's key entry).

**What is detected in v1 (after ID-4 + FS-5):** any offline modification that is *not* a
rollback to a previously signed state (SentinelFS §12's "gen ≤ last signed with a different
hash" case), at the first unlock, because the signing key is now persistent and the attacker
cannot sign.

**The path to an anchor.** A TPM spec: NV monotonic counter bound into the FS-5 record and the
keyring header (`failures` then lives in TPM NV with hardware lockout, and PIN slots become
reasonable), and optionally PCR-sealed slots (measured boot, §7.4). A paired-device spec: the
IntegrityLog's head exchanged with a second device. Either changes the decision to
`Tpm(counter)` / `PairedDevice(counter)`; neither blocks v1.

## 14. Accounts

**Decision.** v1 is **single-user**: one owner, `user = 1`, the `User(1)` blob domain. The
format is multi-user-ready (every slot and subkey carries `user`; per-user keys are a subkey
kind; `User(n)` domains exist on disk), so multi-user is additive (a keyring version bump). The lock
screen has no user picker and shows no name (a name before unlock is a free fact for a thief).

**Decided (Veeti, P6): single user in v1; re-decide before FS-E.**

**What v1 commits to:** `user` fields are validated and only `1` is accepted; the tree key
protects all of v1's data; a multi-user keyring is a keyring `version` bump, not a SentinelFS
format bump (C12). **What multi-user would add** (its own spec): one master per user,
per-user subkeys keyed to `User(n)` domains, a user picker, `dedup` keyed per user (already
SentinelFS §7.3), and the question of who may add users (PolicyAgent).

**Minds change on:** a concrete second-user need (family machine) before FS-E ships, since FS-E
should then key data per user from day one rather than migrate.

## 15. Public interface (sketches, not implementations)

```rust
// ── hal (TCB) ────────────────────────────────────────────────────────────────
pub mod rng {
    /// One RDRAND word; `None` without RDRAND or after 10 failed tries. Untrusted input.
    pub fn rdrand64() -> Option<u64>;                 // = retry::<10>(raw_rdrand)
    pub fn retry<const N: usize>(f: impl FnMut() -> Option<u64>) -> Option<u64>; // pure, Kani
}
pub mod mem {
    /// Volatile wipe the compiler may not elide, then a SeqCst compiler fence.
    pub fn secure_zero(buf: &mut [u8]);
    pub fn secure_zero_words(buf: &mut [u64]);
    #[cfg(feature = "login-test")]
    pub fn read_volatile_words(buf: &[u64], out: &mut dyn FnMut(u64)); // proof read-back only
}
pub mod mm {
    pub const PAGE_WORDS: usize = 512;
    pub trait FrameSource { fn alloc_frame(&self) -> Option<u64>; fn dealloc_frame(&self, p: u64);
                            fn free_frames(&self) -> usize; }
    pub struct FrameArena { /* root: u64, pages, wiped; PhantomData<Cell<()>>: Send, !Sync */ }
    pub enum ArenaError { NotInitialised, Empty, TooLarge, WrongContext,
                          Insufficient { need: usize, free: usize } }
    impl FrameArena {
        pub const MAX_PAGES: usize = 262_144;                   // 1 GiB
        /// IF must be 1 (else WrongContext); rolls back on the first `None`.
        pub fn reserve(pages: usize, keep_free: usize) -> Result<Self, ArenaError>;
        pub fn pages(&self) -> usize;
        pub fn page(&self, i: usize) -> Option<&[u64; PAGE_WORDS]>;
        pub fn page_mut(&mut self, i: usize) -> Option<&mut [u64; PAGE_WORDS]>;
        pub fn wipe(&mut self);                                 // sets `wiped`
    }
    // reserve/Drop are written once, generic over `FrameSource` + hhdm, for Kani and Miri.
    impl Drop for FrameArena { /* per index frame: read entries, wipe+free data; index; root */ }
    impl LockedHeap { pub fn in_use(&self) -> usize; pub fn alloc_calls(&self) -> u64; }
}

// ── crates/crypto (safe, no deps) ────────────────────────────────────────────
/// Every secret-bearing state implements Wipe; the caller owns it and wipes it (Z1).
pub trait Wipe { fn wipe_slices(&mut self, f: &mut dyn FnMut(&mut [u8])); }
pub type Block = [u64; 128];                                    // Argon2 1 KiB block
pub trait Argon2Memory {
    fn blocks(&self) -> usize;
    fn load(&self, i: usize, out: &mut Block);
    fn store(&mut self, i: usize, b: &Block);
}
pub struct Argon2Params { pub m_kib: u32, pub t: u32, pub p: u32 }
pub struct Argon2Scratch { /* h0, prev, refb, tmp blocks; impl Wipe */ }
impl Argon2Params { pub fn decode(b: &[u8; 32]) -> Result<(Self, [u8; 16]), ParamError>;
                    pub fn blocks(&self) -> usize; }                 // m' = 4p·⌊m/4p⌋
pub fn argon2id(p: &Argon2Params, pwd: &[u8], salt: &[u8; 16], ad: &[u8],
                mem: &mut impl Argon2Memory, scratch: &mut Argon2Scratch,
                progress: &dyn Fn(u32), out: &mut [u8; 32])
    -> Result<(), KdfError>;            // MemoryTooSmall if mem.blocks() < m', checked first
pub mod aead {   // XChaCha20-Poly1305; counter exhaustion refuses, never wraps
    pub fn seal(key: &[u8; 32], nonce: &[u8; 24], ad: &[u8], pt: &[u8],
                ct: &mut [u8], tag: &mut [u8; 16], st: &mut AeadState) -> Result<(), AeadError>;
    pub fn open(key: &[u8; 32], nonce: &[u8; 24], ad: &[u8], ct: &[u8],
                tag: &[u8; 16], pt: &mut [u8], st: &mut AeadState) -> Result<(), Unauthentic>;
}
pub mod hkdf { pub fn extract(salt: &[u8], ikm: &[u8], prk: &mut Prk);      // Prk: Wipe
               pub fn expand(prk: &Prk, info: &[u8], out: &mut [u8]) -> Result<(), LenError>; }
pub mod ed25519 { pub fn keypair(seed: &[u8; 32], kp: &mut Keypair);           // ID-1b
                  pub fn sign(kp: &Keypair, msg: &[u8], sig: &mut [u8; 64]);
                  pub fn verify(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool; }
pub mod ct { pub fn eq(a: &[u8], b: &[u8]) -> bool; }   // total; unequal lengths → false

// ── kernel::keyring (safe) ───────────────────────────────────────────────────
pub struct Locked; pub struct Unlocked;
/// Holds the decoded view and, when Unlocked, a token for the static key store.
pub struct Keyring<S> { /* view, KeyToken (Unlocked only) */ }
pub enum Secret<'a> { Passphrase(&'a SecretBuf), Recovery(&'a RecoveryKey) }
impl Keyring<Locked> {
    pub fn decode(block: &[u8; 4096], sb_field: &[u8; 32], fs_uuid: &[u8; 16])
        -> Result<Self, KeyringError>;          // BelowFloor, DuplicateKind, Corrupt, …
    pub fn unlock(self, s: Secret<'_>, kdf: &mut KdfRunner)
        -> Result<Keyring<Unlocked>, (Keyring<Locked>, UnlockError)>;
}
impl Keyring<Unlocked> {
    pub fn with_tree_key<R>(&self, f: impl FnOnce(&[u8; 32]) -> R) -> R;
    pub fn with_device_seed<R>(&self, f: impl FnOnce(&[u8; 32]) -> R) -> R;
    pub fn replace_keyring(&mut self, op: SlotOp<'_>, kdf: &mut KdfRunner, rng: &mut Drbg)
        -> Result<PendingCommit, SlotError>;   // two commits + scrub, then success (B2)
    pub fn encode(&self, out: &mut [u8; 4096]);
    pub fn seal(self) -> Keyring<Locked>;      // Z1 over the key store
}
pub enum SlotOp<'a> { Add(Secret<'a>), Replace(SlotId, Secret<'a>), Remove(SlotId),
                      RotateMaster { keep_recovery: bool } }
pub enum UnlockError { Unauthentic, Insufficient { need_mib: u32 }, EntropyUnavailable,
                       Corrupt, CounterUnpersisted }

// ── kernel::secrets (component PR-3, shaped here, C3/C4) ────────────────────
pub fn provision(seed: DeviceSeed);            // PR-3: DRBG seed late in boot; ID-4: keyring
pub fn seal();                                 // kernel-local wipe
pub fn sign(caller: Sender, msg: &[u8], sig: &mut [u8; 64]) -> Result<(), SignError>; // Locked

// ── kernel::login (safe) ─────────────────────────────────────────────────────
pub struct SecretBuf { /* [u8; 256], len; !Clone !Debug; one static home; Drop = Z1 */ }
pub enum LoginState { Ephemeral, Setup(SetupStep), Locked { failures: u32 },
                      Persisting { ticket: Ticket }, Deriving, Resetting { ticket: Ticket },
                      Delay { until: Tick }, Unlocked { since: Tick } }
pub enum Event { Key(KeyEvent), Tick(Tick), Persisted(u32), PersistFailed, KdfDone(KdfOutcome) }
pub fn step(s: LoginState, e: Event) -> (LoginState, Action);   // pure; Kani (B3)
pub fn backoff(failures: u32) -> Ticks;                          // pure; total, monotone, capped
```

Misuse made hard by construction: key bytes are reachable only through closures on
`Keyring<Unlocked>`; sealing consumes it; secret types cannot be copied, printed or compared
except through `ct::eq`; every secret-bearing crypto state is a caller-owned `Wipe` type; the
arena cannot outlive its frames; the `ui` crate sees a `LockView`, never a `SecretBuf`.

## 16. Staging, boot proofs and verification

Each PR is independently bootable, adds hard assertions to `cargo xtask test`, discharges its
Kani harnesses locally (≤ 60 s each, measured), and runs its host tests under Miri where they
touch `hal` models. Threat-register entries land with the PR that implements them (D14).

| PR | Lands | `hal` rows | Kani | Boot-proof line (asserted) |
|---|---|---|---|---|
| **ID-0** entropy + wipe + crypto crate | `crates/crypto` with `sha256` (moved from `kernel::hash`, API re-exported, `check-crypto-imports`), `hmac`, `hkdf`, `hmac_drbg`, `ct`, `trait Wipe`; `hal::rng` (R1), `hal::mem` (Z1); `kernel::rng` (health tests, DRBG with additional input); crypto dev profile `opt-level = 3, overflow-checks = true`; crate lints; CI: `cargo test -p crypto`, `cargo kani -p crypto` (SHA-padding harness moves here); new `boot-timing` baselines. Merges on kernel-reviewer sign-off for R1/Z1 + the crate boundary (C1). **After PR-2b, before PR-3 and FS-2.** | **R1, Z1** (+2) | HKDF expand length total; DRBG refuses when unseeded, reseeds at the limit; repetition-count and all-0/all-1 health tests; `retry::<N>`; Z1 in bounds and reads zero; `ct::eq` total on unequal lengths; SHA padding | `[rng] source=rdrand health=ok drbg=hmac-sha256 kat=ok seeded=yes secure-zero=ok ok`; negative boot (`-cpu Haswell,-rdrand`): `[rng] source=none entropy=unavailable ok` |
| **ID-1** primitives | `blake2b`, `argon2id` (generic `Argon2Memory`, caller scratch, slice-major lanes, `MemoryTooSmall`), `chacha20`, `poly1305`, `xchacha20poly1305`; boot KATs; `kernel/crypto-oracle/` job (two oracles, ctgrind gate). Gated on security-engineer sign-off of the in-tree primitives (C1). | 0 | `Argon2Params::decode` total; `ref_index` pure with symbolic j1/j2 over concrete geometry (p ∈ {1, 2}, m′ ∈ {8p, 16p}, t ≤ 2), always inside the reference set incl. cross-lane at p = 2; every index `< blocks()`; lemma `x·y >> 32 < y` if needed for 60 s; ChaCha/AEAD counter exhaustion refuses; Poly1305 carry step in bounds | `[crypto] kat: blake2b=ok argon2id=ok chacha20poly1305=ok xchacha20poly1305=ok hkdf=ok hmac=ok ok` |
| **ID-1b** signatures (C2) | `sha512`, `ed25519` (RFC 8032, strict decoding); KATs + Wycheproof EdDSA; ctgrind on signing. **After ID-0, before PR-3 merges**; independent of ID-1. | 0 | scalar reduction and field-limb carry bounds at shrunken limb counts; strict-decode totality | `[crypto] kat: sha512=ok ed25519=ok ok` |
| **ID-2** KDF arena | `hal::mm::FrameArena` (M16, generic `FrameSource`, `wipe`); B5 visibility fixes (`dealloc_frame`/`FRAME_ALLOCATOR` `pub(crate)`, `map_mmio` refuses USABLE, `ActivePageTable::new` `pub(crate)`), hal-tcb §4 invariant, M5 evidence; heap `in_use()` + `alloc_calls()` (M11 text); `kernel::kdf` (pre-spawned, parking `login-kdf`; `KdfSlot` rules); calibration (informational line only in `test-kvm`/`boot-timing`). **After sched park/unpark** (C6). | **M16** (+1) | hal: index decomposition at fanout 4/4; all-or-nothing vs a nondeterministically failing allocator; frame conservation; `TooLarge`/`Empty`. kernel: calibration total, `m ≥ floor`, `t` in range, `params → pages` = what `reserve` gets | `[kdf] arena: pages=2048 index=5 argon2id=<8 hex> match=yes wiped=yes frames-returned=yes heap-delta=0 heap-allocs=0 slot-wiped=yes ok` (m = 8 MiB, t = 1, p = 4, fixed inputs; expected tag pinned by a host test against both oracles) |
| **ID-3** keyring + setup + unlock | kind-6 codec (split for Kani); `kernel::keyring` (static key store + token), `kernel::login` (`step`, polled `Persisting`/`Resetting`, passphrase only, one slot per kind); superblock field accepted as `keyring_format` (`keys` non-null ⇔ field non-zero); `tree_id` 5 validated and scrubbed; `replace_keyring` with double commit + scrub; persisted counter with refuse-on-unpersisted; test `alg 0xF0`, `BelowFloor`, `compile_error!` guard; `Ephemeral` (no disk); decoder Caps/Ctrl/Alt/Delete; K-row ring zeroing; `check-keyboard-consumers`; xtask QMP typing (paced, marker-driven), leak scan of logs and image, `profile=prod` check on the `make run` image, crash-on-deriving boot, no-RDRAND and no-disk boots; fuzz targets (D3). **Needs FS-1b, ID-2, and the `crypto-oracle` job gating.** | 0 | keyring decode (header, `decode_slot`, `decode_slots::<3>`, zero tail, `well_formed`, round trip N ≤ 3); slot ops behind `trait Wrap`, depth 3–4 (D4 properties); `step`: no `KdfStart` without `Persisted(n+1)`, no verdict without `KdfDone`, `PersistFailed` → `Locked` without KDF; `Ephemeral` never reaches a keyring action; superblock field decode total | boot 1: `[login] ready: state=setup profile=test`, `[login] nav-key-unlock=refused`, `[login] setup: user=1 slot=passphrase kdf=argon2id-test m=8192 t=1 p=4 kdf-profile=test keyring=<8 hex> gen=N old-keyring-scrubbed=yes data-at-rest=plaintext ok` · boot 2: `[login] attempt: n=1 verdict=denied failures=1 persisted-before-verdict=yes`, then `[login] unlock: n=2 verdict=ok failures-since-last=1 keyring=<boot 1's> commit-tag=ok heap-delta=0 heap-allocs=0 slot-wiped=yes typeahead-dropped=yes ok` · boot 3 (killed on `[login] deriving`) → boot 4 `failures=<+1>`; no-RDRAND boot: `keyring-create=refused`; no-disk boot: `[login] ephemeral: disk=none keyring-path=unreachable ok`; xtask: passphrase absent (ASCII, case-folded, hex, scancodes) from every log and the image |
| **PR-3** delegates (component track) | KeyAgent as policy delegate; `kernel::secrets` holds the seed and signs (C3); `provision`/`seal` seam, provisioned late in boot from the DRBG (C4); Ed25519 from ID-1b; random-nonce XChaCha for secrets at rest (D8); Z1 for payload arenas (A9). Memory-boundary gate merges first. | 0 | (component spec) | `[delegate] keyagent: before-provision=locked signed=ok verified=yes secret-readable=no sealing=none secrets-persist=no ok` |
| **ID-4** persistent KeyAgent key | device-seed subkey; `kernel::login` calls `secrets::provision` at unlock and `secrets::seal` at seal; signed `{unlock, failures_since_last}` IntegrityLog record once PR-4 exists. **After ID-3 and PR-3.** | 0 | no `sign` path reachable from `Locked` | boot 1: `[delegate] keyagent: before-unlock=locked signed=ok verified=yes secret-readable=no sealing=passphrase secrets-persist=yes key-id=<8 hex> ok` · boot 2: same with `key-id=<boot 1's>` |
| **ID-5** recovery, slot ops, lock levels | recovery key (Crockford + mod-37 check symbol), replace/remove passphrase, master rotation keeping recovery, backoff delays (scaled under `login-test`: 30 s → 3 ticks), SAK, idle lock (test timeout), seal, Caps LED (K4 text), upward re-wrap (should) | 0 | recovery decode total (checksum stubbed); backoff total, monotone, capped | `[login] slots: recovery=added via-recovery=ok passphrase-changed=ok old-refused=yes old-keyring-scrubbed=yes last-slot-remove=refused delay-armed=yes delay-enforced=yes ok` and `[login] lock: sak=ok idle=ok seal=wiped keyagent=locked relock-unlock=ok ok` |
| **FS-E** SentinelFS encryption (FS track, SentinelFS §10.2) | data, inline, dirent names, xattr values; object-key tree (`tree_id` 6, validated and scrubbed); `NonceSeq`; AD = object id ‖ block position ‖ gen; locked mount reads `Locked`; cache wipe on lock; `keyring_format == 0` with encrypted items = `Corrupt`. **After FS-4 and ID-3; blocks nothing.** External crypto review before it merges (D13). | 0 | `NonceSeq` never repeats within a transaction, exhaustion refuses; nonce encoding injective in `(gen, counter)` | `[sfs] crypt: data=sealed names=sealed locked-read=refused unlocked-read=ok plaintext-on-disk=no ok` (xtask scans the image for a known plaintext marker); `data-at-rest=plaintext` disappears |
| **ID-6** parallel lanes (optional) | Argon2id lanes on up to 4 cores; shared atomic arena view (a new row then) | +1 (then) | lane/segment barrier ordering | `[kdf] lanes: cores=4 match=yes ok` |

**Total new `hal` rows for v1 (ID-0 … ID-5): three** — R1, Z1 (ID-0), M16 (ID-2) — plus
amended text for M5 (B5), M10/M11 (ID-2), the K rows (ring zeroing, ID-3) and K4 (ID-5), and a
new hal-tcb §4 invariant (frame uniqueness, B5). Z1's module also carries a `login-test`-only
volatile read-back used by proofs.

**Placement in the existing queue (C5, redrawn).**

```
PR-2b ─► ID-0 ─┬─► ID-1b ──────────────► PR-3 ◄── memory-boundary gate (merges before PR-3)
               │                           │
               ├─► ID-1 ─► ID-2 ◄── sched park/unpark (A25)
               │             │             │
FS-1b ─────────┼─────────────┴─► ID-3 ─┬──┴─► ID-4 ─┐
               │                       └─► ID-5     ├─► FS-5 (signed superblock, anchor=none)
               └─► FS-2 ─► FS-4 ────────────────────┘
                             └──────► FS-E  (needs FS-4 + ID-3; blocks nothing)
```

- **ID-0** is small and unblocks three tracks (PR-3's key, A26, everything here); it goes first
  and does not wait on the in-tree crypto debate (C1). **ID-1b** follows directly, because PR-3
  signs with it.
- **ID-1 and ID-2** touch no FS or component code and run in parallel with FS-1b / FS-2; ID-2
  waits for park/unpark (C6).
- **ID-3** needs FS-1b's transactions (and the `replace_keyring` footprint in its budget table),
  ID-2, and the `crypto-oracle` job gating; not FS-2's files or FS-4's blobs. The fuzz lane must
  exist before FS-2 **or** ID-3, whichever merges first (D3).
- **FS-5** needs ID-4 (a persistent signing key) **and** FS-4. **FS-E** needs FS-4 and ID-3 and
  blocks nothing.
- **What PR-3 can ship before this lands**: KeyAgent as the policy delegate; `kernel::secrets`
  holding an ephemeral DRBG seed and signing with Ed25519; `provision`/`seal` with
  `before-provision=locked` asserted; `sealing=none secrets-persist=no`; the
  `cold-boot-recovered=no` probe; random-nonce XChaCha for secrets at rest; Z1 for payload
  arenas (component A9). **What changes after ID-4**: only who calls `provision` (the keyring at
  unlock); the line reads `sealing=passphrase secrets-persist=yes` with a stable key id across
  boots; `before-unlock=locked`; FS-5 can start.

**CI and fuzz (D1, D3, D11).**

- kernel.yml: `cargo test -p crypto`; the new source guards (`check-keyboard-consumers`,
  `check-crypto-imports`, `check-ct`). verify.yml: `cargo kani -p crypto` (60 s rule), the kernel
  Miri filter gains `keyring:: login:: kdf:: rng::`, Miri on `crypto` for the RFC 9106 §5.3
  vector only, Miri on the arena model under Stacked and Tree Borrows.
- `crypto-oracle` job (committed lock, timeout): seeded differential, ~10⁵ inputs per primitive
  against RustCrypto (Argon2id at `m ≤ 64 KiB`), second oracle for Argon2id and
  XChaCha20-Poly1305, phc-winner vectors and the H′ sweep, ctgrind gate, dudect informational.
  Gates before ID-3.
- **Fuzz lane deadline (amends SentinelFS A20):** before FS-2 or ID-3, whichever merges first.
  Targets: kind 6 in the kind-selected parser target; `recovery_key_parse` with a round trip;
  KDF field / `keys` decode through the mount target; differential `aead_open` (mutated valid
  ciphertexts), `chacha20` near the 2³² block counter, `poly1305`, `blake2b` (variable output),
  `hkdf`, `argon2id` (tiny parameters).
- **CI time.** `login-test` scales backoff ticks (30 s → 3 ticks) and asserts the delay is armed
  and enforced without waiting it out; the production calibration runs on one boot of
  `test-kvm`/`boot-timing` only; every ID PR re-measures the kernel-ci job and states the delta.

**Host coverage.** Every PR: RFC vectors (RFC 7693 BLAKE2b, RFC 9106 §5.3 Argon2id, RFC 8439
ChaCha20-Poly1305, draft-irtf-cfrg-xchacha, RFC 5869 HKDF, RFC 4231 HMAC, RFC 8032 Ed25519,
NIST CAVP HMAC-DRBG); Wycheproof AEAD/HKDF/HMAC/EdDSA vectors; keyring adversarial corpus
(every field flipped, truncated counts, duplicate ids and kinds, foreign `keyring_id`, unknown
kinds, below-floor parameters, `alg 0xF0` on a production build) that lifts into the fuzz lane
unchanged; tamper tests (each AD field flipped → `Unauthentic`); crafted two-key ciphertext →
refused by the commitment; whole-device scan after every slot operation (no block holds the
removed slot); snapshot/rollback never restores `keys`; every secret type implements `Wipe`;
mod-37 exhaustive single-substitution and adjacent-transposition detection; the login `step`
function driven by scripted event sequences.

## 17. Open questions

Decided in review round 1 (kept for the record): unlock target **2 s** (P1); recovery key
**optional, default-on**, mandatory below the Argon2id threshold (P5); idle → **screen lock**
(P3); **no** pre-unlock console (P4); **single user** in v1 (P6); no disk → an explicit
**ephemeral** session (D15); **RDSEED: no** (D16); external review trigger (D13).

1. **Idle seal timer** (security): after 60 min idle, seal rather than screen-lock. Not v1.
2. **Anti-phishing mark** after the memory gate: a per-user visual shown only by the genuine
   lock screen (needs storage the kernel can read before unlock but components cannot).
3. **Keyring mirroring** (security #13): the keyring block is a media single point of failure —
   one bad sector strands every key. A second copy (mirrored keyring block, or a superblock-
   adjacent backup pointer) needs a format decision before real users.
4. **Tree-key epochs**: to truly revoke a leaked passphrase, new writes need a new tree key and
   old data background re-encryption. FS-E should reserve an epoch field in object-key entries.
5. **Keyboard layouts**: v1 is US-QWERTY; a layout switch must not lock a user out (the slot
   records the layout; the UI warns). Unicode passphrases need NFC normalization first.
6. **Who does the external crypto review** (the trigger is decided, D13).
7. **Multi-user timing**: re-decide before FS-E (P6); if yes, FS-E keys per user from day one.
8. **Commit wear**: two commits per counted attempt plus two per slot change are fine on QEMU and
   SSDs; revisit for raw flash.
9. **Calibration's `t_min = 2` at `m ≥ 256 MiB`**: allowed by C9 as an alternative; ID-2's
   measurements decide whether it is ever chosen.

## 18. What this changes elsewhere (pointers and requests, not edits)

Other tracks are editing these files in parallel, so this spec records requests rather than
editing them; each lands with the PR named.

- **SentinelFS §7.1**: the field at 352 reads as `keyring_format`, the salt is renamed
  `keyring_id`, `keys` non-null ⇔ field non-zero, [440,512) stays unclaimed (ID-3). **§4/§7**:
  `tree_id` 5 = keys, 6 = objkeys (ID-3, FS-E). **§10**: `data` becomes `data-wrap` (random
  per-object keys), the object-key tree root lives in the keyring block, the FS-E nonce and AD of
  §10.6; **item 1's** `generation ‖ counter` nonce for `kernel::secrets` becomes random 192-bit
  XChaCha nonces (PR-3). **§8 / FS-1b budget table**: `replace_keyring` as a named operation kind,
  4–5 blocks (FS-1b). **FS-2**: `Unsupported(feature)` when slot hash/magic/version are valid but
  a reserved field is non-zero, and `format` refuses it without force (C10). **A20**: fuzz-lane
  deadline "before FS-2 or ID-3, whichever merges first" (D3). **§14 items 2–4** are answered
  here (§13, §9, §12.2); **A22** by §9; **A26** by ID-0. Principle 4's replay determinism takes
  the RNG as an input once FS-E exists. The snapshot/rollback invariant "never restores `keys`"
  (§10.4) is to be stated in SentinelFS §7.5.
- **Component §9**: the KeyAgent is the policy delegate; the seed and signing stay in
  `kernel::secrets` (C3); the text change lands with PR-3. **§18.1** is answered by ID-4;
  **A9** gets its wipe primitive (Z1) in ID-0. The IdentityAgent (pairing) is not the login
  service — login is kernel-native because it must own the input path and the keyring.
- **Threat model**: T-LOG-1 … T-LOG-15 land in `docs/security/threat-model.md` §5 with the PR
  that implements each (security-engineer), with adversary A5 (disk/offline) pointing here.
- **hal-tcb**: new §5h (`FrameArena`, M16), §10 (`hal::rng`, R1), §11 (`hal::mem`, Z1); §4 gains
  the frame-uniqueness invariant; text amendments to M5, M10/M11, the K rows and K4.
- **sched (A25)**: park/unpark must refuse or debug-assert when called by the BSP idle task.

## 19. Review round 1 (2026-10-04): verdicts and amendments

Four seats read the spec independently: kernel-architect, kernel-reviewer, security-engineer,
verification-engineer. **All four: APPROVE WITH CONDITIONS.** Veeti then made the six product
decisions (P1–P6), which are final.

| Question | architect | reviewer | security | verification | **Consensus** |
|---|---|---|---|---|---|
| `hal` rows and the arena | M16 right-sized; frame source must be generic for the verifiers | **M16 unsound as stated**: safe code can free or double-map an arena frame; Drop order vs `dealloc_frame`'s link word; precheck is not all-or-nothing; R1 must not claim `preserves_flags` | — | Kani at shrunken fanout, Miri under both borrow models; read-back cannot prove non-elision | **Three rows stand, with B5 (visibility + §4 invariant), B6 (reserve/Drop), B7 (wipe + heap proofs), D6 (R1/Z1 evidence)** |
| In-tree crypto | keep; split ID-0 from the crypto debate; name and cost the signature scheme; crypto cannot wipe | AVX2 objection is policy not live state; cite hal-tcb §2j; SIGILL unreproduced; crypto lints | in-tree acceptable only with two oracles, ctgrind, external review trigger; crypto state must be wipeable | CI lanes; Argon2 infallibility and lane order; harness shapes | **In-tree (P2), with C1, C2, B4, B8, D1, D2, D12, D13** |
| Argon2id parameters and calibration | — | 1 s preferred; division by zero in calibration; overshoot | 1 s preferred; test profile can reach production (#1); never step below 64 MiB | 1 s preferred; calibration totality harness; test profile guards; CI time | **2 s (P1; three reviewers preferred 1 s, recorded); memory-first calibration (C9); B1; D11** |
| Keyring, superblock field, AEAD, nonces | rename the field; `keys` ⇔ field; tree ids; keyring transaction footprint; `Unsupported` for FS-2 | multi-slot trial; C12 corrections | old keyring copies survive (#2); one slot per kind (#5); DRBG additional input (#8); nonce rationale (#9, #10); recovery survives rotation and mirroring (#13) | codec split for Kani; slot-op model; recovery checksum honesty | **C7, C8, C10, C12, B2, D4, D5, D7, D8** |
| Login state machine and counter | counter commit failure path (A11); polled states, BSP never parks (A6) | park/unpark ordering; `KdfSlot` rules (#8) | counter commit failure (#4); input residue (#6) | transition function with commit events; QMP pacing and determinism | **B3, C6, D9, D10** |
| Trusted input, lock levels, no disk | no-disk session | no-disk session (OQ5) | 60-min idle seal timer; product honesty before FS-E (#14) | — | **Screen lock (P3); idle seal → open question; D14; D15** |
| Rollback anchor `None` | agree | agree | agree, with the §7.3/§13 claims corrected | — | **`anchor: None` stands; §7.3 and §13 corrected (B2)** |
| Staging | ID-0 first; FS-5 needs ID-4 + FS-4; FS-E blocks nothing; PR-3 seam as a provisioning machine | ID-2 after park/unpark | — | fuzz-lane deadline; oracle job gating before ID-3 | **C1, C4, C5, C6, D3** |

**Product decisions (Veeti, 2026-10-04; final).**

| # | Decision | Where | Status |
|---|---|---|---|
| P1 | Unlock target **2 s**, not 1 s. Dissent: all three reviewers preferred 1 s, because a screen-lock unlock runs the full KDF many times a day. Calibration still steps memory down rather than overshooting (C9). | §1, §2, §8.2 | applied |
| P2 | Crypto stays in-tree. | §8.3 | applied |
| P3 | Idle → screen lock for now; security's 60-min idle seal becomes an open question. | §11.4, §17 | applied |
| P4 | No pre-unlock console for now. | §12.2 | applied |
| P5 | Recovery key optional: default-on, declinable with a second confirmation; mandatory below the Argon2id threshold (already implied). | §10.5, §9.4 | applied |
| P6 | Single user in v1; re-decide before FS-E. | §14, §17 | applied |

**Amendments.** "Applied" = applied to this spec's text; the code lands in the PR named.

| # | Source | Where | Amendment | Status |
|---|---|---|---|---|
| B1 | security #1, reviewer #10, verification V15 | §8.2, §10.3, §7.5 | Test KDF profile cannot reach production: `kdf.alg = 0xF0` refused by the production decoder; `BelowFloor` at decode (19 MiB, t ≥ 2); `compile_error!` on `login-test` without `debug_assertions` or in release/ISO; `kdf-profile=test` and xtask `profile=prod` check; bypass of setup's floor stated; T-LOG-14 | applied; code **ID-3** |
| B2 | security #2 | §10.4, §7.3, §13, §7.5 | Slot changes commit twice so both superblock slots name the new keyring, then zero and flush the freed old block(s); `old-keyring-scrubbed=yes`; whole-device host scan; SSD residual; snapshot/rollback never restore `keys` (tested); §7.3 claim fixed; T-LOG-13 | applied; code **ID-3** |
| B3 | security #4, verification V3, architect A11 | §8.5, §10.7, §7.1, §15 | Counter write is the one metadata write allowed in read-only-for-data modes; if unpersistable, passphrase attempts refused, recovery key allowed (in-RAM floor of 5 recorded as the declined alternative); `saturating_add`; pure `step` with commit events; Kani properties; no entropy ⇒ no wraps or encrypted writes, metadata commits allowed; write-blocked / lying disk ⇒ L1 cost | applied; code **ID-3** (backoff delays **ID-5**) |
| B4 | security #7, reviewer #4, architect A14 | §6, §5.4, §15 | Caller-owned `Wipe` types for every secret-bearing crypto state (H0, BLAKE2b, HMAC pads, HKDF PRK, ChaCha, Poly1305, scratch passed in); one static key store, typestate holds a token; one home for `SecretBuf`; `login-kdf` stack scrub; principle 4 scoped (register/stack spills); host test that every secret type implements `Wipe` | applied; code **ID-0** (trait), **ID-1** (types), **ID-3** (key store) |
| B5 | reviewer #1 | §9.2, §9.3, §18 | Frame uniqueness: `dealloc_frame`/static `pub(crate)`, `map_mmio` refuses USABLE, `ActivePageTable` constructor `pub(crate)`; hal-tcb §4 invariant; M5 evidence amended | applied; code **ID-2** (hal-specialist) |
| B6 | reviewer #2, verification V10 | §9.2, §9.3, §15 | Drop order (entries → data → index → root); rollback frees all three kinds; precheck advisory, all-or-nothing by rollback on `None`, `checked_add`; one `alloc_frame()` per frame; `u64` addresses, `!Sync` via `PhantomData`; generic `FrameSource` + hhdm; `with_exposed_provenance_mut`; `WrongContext` if IF = 0; `TooLarge`/`Empty`; Kani 4/4, Miri SB + TB, QEMU; HHDM cast Reasoned + QEMU | applied; code **ID-2** |
| B7 | reviewer #3, #5, verification V12, V13 | §9.2, §9.4, §5.3–4, §16 | `FrameArena::wipe` + flag, volatile read-back under `login-test`, Drop skips second wipe; `slot-wiped=yes`; non-elision evidence = construction + Miri; `alloc_calls()` and `heap-allocs=0`; window Enter → keys installed, before WM; heap-quiet task list | applied; code **ID-2**, **ID-3** |
| B8 | reviewer #6, #7, verification V5 | §6, §15, §16 | `argon2id` checks `mem.blocks() ≥ m′` first (`MemoryTooSmall`), Kani: every index `< blocks()`; slice-major sequential lanes, p = 2 cross-lane harness; `ref_index` harness geometry and the lemma fallback; crate lints and `overflow-checks = true`; harnesses for `ct::eq`, counter exhaustion, Poly1305 carry | applied; code **ID-0**, **ID-1** |
| C1 | architect A1 | header, §16 | ID-0 merges on reviewer sign-off for R1/Z1 + crate boundary; in-tree sign-off gates ID-1 | applied |
| C2 | architect A2 | §8.3, §10.1, §16 | Ed25519 named and costed (~1.2 k lines), stage **ID-1b** in `crates/crypto` before PR-3; seed → keypair; key id; minds-change rule | applied; code **ID-1b** |
| C3 | architect A3 | §12.3, §6, §18 | Seed and signing stay in `kernel::secrets`; KeyAgent is the policy delegate; seal is kernel-local; component §9 text changes with PR-3 | applied; component text **PR-3** |
| C4 | architect A4 | §12.3, §15, §16 | Provisioning machine `provision`/`seal`, KeyAgent `Locked | Ready`; PR-3 provisions late, asserts `before-provision=locked`; ID-4 changes only the caller | applied; code **PR-3**, **ID-4** |
| C5 | architect A5 | §16 | Staging diagram redrawn: FS-5 needs ID-4 + FS-4; FS-E blocks nothing | applied |
| C6 | architect A6, reviewer #8 | §6, §12.1, §16, §18 | ID-2 after park/unpark (fallback: spawn after AP proofs); BSP idle never parks; polled `Persisting`/`Resetting` with `request_commit`/`poll`; `KdfSlot` rules; arena only on `login-kdf`; publish-then-unpark | applied; code **ID-2**, **ID-3**; A25 refusal requested of **sched** |
| C7 | architect A7, reviewer #11, security #5 | §10.2, §10.3, §8.5 | Field read as `keyring_format`; m/t/p = 0 = no floor; `keys` ⇔ field; salt → `keyring_id`; one passphrase + one recovery slot per user, enforced in decode; explicit recovery mode; one Enter = one attempt = one KDF; replace reuses the slot index | applied; code **ID-3**; SentinelFS §7.1 rename requested |
| C8 | architect A8, A9 | §10.3, §10.4, §18 | `tree_id` 5 = keys, 6 = objkeys; ID-3 extends pointer validation and scrub/bitmap reachability (FS-E for objkeys); `replace_keyring` with a 4–5-block footprint in FS-1b's budget table | applied; code **ID-3**, **FS-E**; footprint requested of **FS-1b** |
| C9 | security #3, reviewer #9, verification V4 | §8.2 | `max(pass_ticks, 1)` over ≥ 10 ticks; memory first, step down to the target, never below 64 MiB until ID-6 (or t = 2 at ≥ 256 MiB); Kani on calibration; upward re-wrap (should); calibration line only in `test-kvm`/`boot-timing` | applied; code **ID-2** (re-wrap **ID-5**) |
| C10 | architect A12 | §18 | FS-2 `Unsupported(feature)`, `format` refuses it without force | requested of **FS-2** |
| C11 | architect A13 | §6, §16 | `kernel::hash` the only import path (`check-crypto-imports`); SHA-padding harness to `-p crypto`; `opt-level = 3` changes `boot-timing` baselines | applied; code **ID-0** |
| C12 | architect, reviewer | §10.2, §11.3, §14 | [440,512) left unclaimed; multi-user = keyring version bump; setup on a volume with data warns; after FS-E `keyring_format == 0` with encrypted items = `Corrupt` | applied; code **ID-3**, **FS-E** |
| D1 | security #12, verification V6–V8 | §8.3, §16 | CI lanes: `cargo test -p crypto`; `cargo kani -p crypto`; Miri filter; `crypto-oracle` job (RustCrypto differential + second oracle) gating before ID-3; phc-winner vectors + H′ sweep; Miri on crypto for one vector | applied; code **ID-0**, **ID-1** |
| D2 | security #12, verification V9 | §8.3 | ctgrind gate (scope listed, data-dependent half suppressed and documented), dudect informational, `check-ct` lint, host-vs-target residual stated | applied; code **ID-1** |
| D3 | verification V11 | §16, §18 | Fuzz lane deadline "before FS-2 or ID-3, whichever first" (amends SentinelFS A20); target list | applied; code **FS-2 / ID-3** |
| D4 | verification V1, V2, security #13 | §10.3, §10.4 | Codec split for Kani; `trait Wrap` model; depth 3–4 sequences; bit-identical on `Err` / failed commit; rotate keeps an owner slot; monotone `slot_id`; recovery survives rotation unless declined | applied; code **ID-3**, **ID-5** |
| D5 | verification V9 | §10.5 | Decode total with checksum stubbed; truncated-hash detection stated as probabilistic; Crockford mod-37 check symbol added | applied; code **ID-5** |
| D6 | verification V11, reviewer #14 | §9.3 | R1 = `retry::<10>(raw_rdrand)`, `nomem, nostack` without `preserves_flags`; explicit `+rdrand`; negative `-rdrand` boot; Z1 non-elision "Reasoned (language guarantee)"; Kani on health tests | applied; code **ID-0** |
| D7 | security #8 | §10.7 | Fresh RDRAND words as SP 800-90A additional input for salt/nonce/key generation | applied; code **ID-0** |
| D8 | security #9, #10 | §10.6, §7.5, §18 | Nonce rationale corrected (crash before commit, offline restore; privileged rollback writes a new gen); FS-E AD binds object id, position, gen; PR-3 uses random 192-bit nonces | applied; code **FS-E**, **PR-3**; SentinelFS §10 item 1 text requested |
| D9 | security #6 | §11.1, §11.3, §9.3 | Ring consumer zeroes entries (K-row text); `KdfSlot` input wiped; randomised shimmer start (should) | applied; code **ID-3** |
| D10 | verification V14, reviewer #12 | §11.1, §16 | Marker-driven, ≥ 20 ms/key QMP typing; `nav-key-unlock=refused`; held `Deriving`; ≥ 24-char passphrase; leak scan of logs and image (ASCII, case-folded, hex, scancodes); crash-on-deriving boot | applied; code **ID-3** |
| D11 | verification V15 | §16 | Scaled backoff ticks under `login-test`; calibration on one boot; re-measure kernel-ci per PR | applied; code **ID-3**, **ID-5** |
| D12 | reviewer #13 | §8.3 | Cite hal-tcb §2j and `check-no-vector`; AVX2 reworded as policy/TCB; SIGILL unreproduced; recommend a `*_force_soft` re-run | applied (re-run: recommended, not blocking) |
| D13 | security | §8.3 | External crypto review before FS-E, the first real user's keyring, or the first non-first-party component, whichever first | applied |
| D14 | security #11, #14 | §1, §7.5, §10.2, §11.3 | T-LOG entries land with their PRs; T-LOG-2 qualified; T-LOG-13/14/15; "Files on disk are not encrypted yet" in setup and Security Center; `data-at-rest=plaintext` | applied; code **ID-3** onward |
| D15 | architect, reviewer OQ5 | §12.2, §12.1, §15 | No disk → `Ephemeral` state, bannered, cannot reach the keyring path, asserted | applied; code **ID-3** |
| D16 | security #13 | §17 | Open questions: 60-min idle seal, keyring mirroring, tree-key epochs; RDSEED decided no | applied |

**Not applied as edits** (recorded as requests in §18, because other tracks own those files and
are editing them now): the SentinelFS §7.1 rename, §7.5 `keys` invariant, §10 item 1 nonce text,
A20 deadline; FS-1b's budget-table row; FS-2's `Unsupported`; component §9's text (lands with
PR-3); sched's park/unpark refusal on the BSP idle task.

**Minds change on.** Architect: Ed25519 well over ~1.5 k lines or failing constant-time review
(reopen §8.3 for signatures only). Reviewer: a design that removes the need for the B5
visibility changes (e.g. a typed frame-ownership token from the allocator) would be preferred
over convention-plus-invariant. Security: a TPM anchor (counter in NV, PIN slots, rollback
protection); a measured ID-2 latency that makes 1 s achievable at ≥ 64 MiB. Verification: the
`ref_index` harness or the 4/4 arena harness exceeding 60 s (then the lemma split, or a
smaller fanout with a host test at production size, as the cap-table precedent).

## 20. References

- RFC 9106, *Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications*
  (§4 parameter choice, §5.3 Argon2id test vector).
- OWASP Password Storage Cheat Sheet (Argon2id minimum: 19 MiB, t = 2, p = 1).
- cryptsetup / LUKS2 on-disk format and `--pbkdf argon2id` defaults (2 s target, 1 GiB cap,
  keyslots wrapping one volume key).
- RFC 7693 (BLAKE2), RFC 8439 (ChaCha20-Poly1305), draft-irtf-cfrg-xchacha (XChaCha20),
  RFC 2104 / RFC 4231 (HMAC), RFC 5869 (HKDF), RFC 8032 (Ed25519), NIST SP 800-90A (HMAC-DRBG).
- The Argon2 reference implementation and its phc-winner test vectors; ctgrind (A. Langley) and
  dudect (Reparaz, Balasch, Verbauwhede) for constant-time checking.
- J. Len, P. Grubbs, T. Ristenpart, *Partitioning Oracle Attacks*, USENIX Security 2021 (why a
  slot carries a key commitment).
- Project Wycheproof test vectors.
- Apple Platform Security: Data Protection classes and per-file keys (the crypto-shred model);
  Windows Ctrl+Alt+Del secure attention sequence.
- Crockford's Base32.
- `docs/specs/2026-09-18-sentinelfs-design.md` §7.1, §9, §10, §12, §15;
  `docs/specs/2026-09-18-component-model-design.md` §9, §18.1, §19 (the `wasmi` spike method);
  `docs/security/threat-model.md`; `kernel/docs/hal-tcb.md` §2g, §5, §5e;
  `docs/specs/2026-06-03-ui-design-language.md` §3, §5.
