# Identity and login: one unlock secret, a keyring, a trusted input path

Status: **proposed (2026-10-04)** · review round 1 pending (§19: architect, kernel-reviewer,
security-engineer, verification-engineer) · Track A (kernel core) + D (security subsystem) ·
Author: kernel-architect
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
FS-1a for exactly this (§10.2). Needs kernel-reviewer sign-off on the `hal` rows and
security-engineer sign-off on the in-tree crypto decision before ID-0 merges. Direction from
Veeti (2026-09-18): filesystem and login are the next big tracks, "aim for perfection". This
spec says what perfection means for a login on this machine, and where it stops.

## 1. Summary

Today the Cyber Dusk lock screen checks nothing: the right arrow unlocks. This spec replaces it
with a **passphrase** that unwraps a random 256-bit **master key** from a CoW **keyring block**
(SentinelFS block kind 6). The master key in turn unwraps the SentinelFS **tree key** and the
KeyAgent's **device signing seed**, so one secret, typed once, opens the data at rest *and*
gives the IntegrityLog a signing key that survives a reboot. That resolves component §18.1
(`sealing=none` becomes `sealing=passphrase`) and unblocks SentinelFS FS-5.

The passphrase is stretched by **Argon2id** at parameters calibrated per machine (64 MiB, t = 3,
p = 4 on the QEMU dev machine; up to 1 GiB on hardware). That memory cannot come from the 4 MiB
heap, so it comes from a **frame arena** in `hal::mm`: physical frames reached through the
HHDM, reserved all-or-nothing (and failing cleanly, never by an OOM halt), wiped and returned
after every attempt. The kernel owns the PS/2 path while locked: keystrokes go to the
passphrase field and nowhere else, never to a log, never to a component. Ctrl+Alt+Del is the
secure-attention key. Failed attempts are counted **on disk before the verdict is shown**, so
pulling the plug on a wrong guess does not reset the delay.

What this spec does not claim: protection against an evil maid who replaces the kernel (there
is no measured boot), against a full-disk rollback (there is no TPM driver, so v1 ships
`anchor: None`), or against code already running in the unlocked session (ring 0, first-party
only until the memory-boundary gate).

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
   either fixed-size or fallible; asserted by `heap-delta=0`.
5. **A trusted input path.** While locked, only the kernel reads the keyboard; the
   passphrase never reaches a log, a component or the desktop's typeahead.
6. **Passphrase changes without re-encryption.** Add, remove and replace a slot by rewrapping
   one 32-byte master key; never a state with no usable slot (Kani).
7. **A recovery key** that unlocks without Argon2id, so a machine with too little memory, or
   a forgotten passphrase, is not a brick.
8. **Persistent device identity** for the KeyAgent, same key id on every boot after unlock.
9. **Calibrated, honest latency**: ~1 s on hardware/KVM, stated (not hidden) under TCG.

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
   fixed-size and pre-allocated. Proof: `heap-delta=0` on every unlock line; `frames-returned=yes`.
4. **What the kernel derives, it wipes.** KEK, master, passphrase buffer and arena are wiped
   with a primitive the compiler cannot elide. Proof: `wiped=yes` (the arena's frames read back
   zero before they return to the allocator, checked in the boot proof).
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
│      ▲ device seed provisioned once per unlock via kernel::secrets (§12.3)       │
├──────┴──────────────────────────────────────────────────────────────────────────┤
│  kernel (#![forbid(unsafe_code)])                                                │
│   kernel::login    lock-screen state machine · SecretBuf · backoff · SAK · idle  │
│   kernel::keyring  kind-6 codec · slots · wrap/unwrap · subkeys · typestate      │
│   kernel::kdf      the login-kdf task · arena adapter · progress                 │
│   kernel::rng      HMAC-DRBG seeded from hal::rng · health tests                 │
│   kernel::input    decoder (+ Caps Lock, Ctrl, Alt, Delete) · the one router     │
│   kernel::sfs      accepts kdf_params / keys; locked mount (FS-E later)          │
│   kernel::secrets  (component PR-3) sealing backend: Ephemeral → Keyring         │
├─────────────────────────────────────────────────────────────────────────────────┤
│  crates/crypto (#![no_std], #![forbid(unsafe_code)], zero dependencies)          │
│   sha256 (moved from kernel::hash) · hmac · hkdf · hmac_drbg · blake2b ·         │
│   argon2id (generic over Argon2Memory) · chacha20 · poly1305 · xchacha20poly1305 │
│   · ct (constant-time eq)                                                        │
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
| `crates/crypto` | safe crate | kernel-engineer (security-engineer reviews) | Pure functions over byte slices; host-testable, Miri-able, Kani-able; no `hal`, no `alloc` needed. A crate, not a kernel module, so it can have `opt-level = 3` in the dev profile and be tested on the host without the kernel. |
| `kernel::keyring`, `kernel::kdf`, `kernel::login`, `kernel::rng` | safe kernel | kernel-engineer | Policy, codecs, state machines. Everything decidable is here. |
| Lock-screen drawing (`ui`) | safe crate | ui-engineer | Pixels only; receives a view model (`LockView`), never a secret. |

**Dependency graph** (new edges only; no cycles): `kernel → crypto`, `kernel → hal` (existing).
`crypto` depends on nothing (not `hal`, not `alloc`): host tests and Kani see it whole.
`ui` does not gain `crypto` or `keyring`; it receives `LockView { shimmer_step: u8, caps:
bool, message: LockMessage, progress: Option<u8> }` (no length, §11.3). `kernel::hash` keeps its
public API (`Sha256`, `sha256`, `ComponentId` framing) and re-exports `crypto::sha256` (ID-0,
after PR-2b merges, so the move does not collide with PR-2b's v2 framing work in `hash.rs`).
`xtask` (own workspace) gains a QMP client; a new host-only workspace `kernel/crypto-oracle/`
holds differential tests against RustCrypto as a **test oracle**, never linked into the kernel
(`kernel/Cargo.lock` stays at 6 packages plus `crypto`).

**Execution.** Argon2id runs on a dedicated `login-kdf` task, spawned **once at boot** (its
stack and `XsaveArea` are allocated then, not at unlock), pinned to CPU 1 when an AP is online,
else the BSP. The BSP idle loop keeps drawing the lock screen and the progress ring while it
runs; the task is preemptive like every task and never holds a lock across the computation. Job
hand-off is a fixed `SpinMutex<KdfSlot>` (input: borrowed `SecretBuf` copy, params, salt, AD;
output: KEK or error); the task yield-polls today and parks on A25's park/unpark when it lands.
v1 computes the p = 4 lanes **sequentially** on one core (the output is identical by
construction); parallel lanes are ID-6 (§16).

## 7. Threat model for login

**Assumption (Kerckhoffs):** the adversary knows the kernel image, this spec, the on-disk
format, the KDF parameters of every slot, the salts and the keyring layout. The only secrets are
the user's passphrase or recovery key and the random keys they protect. Nothing depends on a
layout, an offset or a label being hard to find.

### 7.1 Adversaries

| # | Adversary | Capability | v1 outcome |
|---|---|---|---|
| L1 | **Offline disk thief** | Has the disk (or an image), powered off or sealed; unlimited offline compute | Must run Argon2id per guess at the slot's parameters (64 MiB × 3 passes on the dev class, more on hardware). A recovery key is 128 random bits. Before FS-E, **file data is plaintext on disk**: v1's login protects the KeyAgent seed and the tree key, not the files (§16, FS-E row). After FS-E: shape, sizes, counts and timing leak (SentinelFS §10), content and names do not. |
| L2 | **Evil maid** | Repeated physical access while the owner is away: boots the machine, types guesses, edits the disk, may replace the kernel on the boot medium | Guessing at the lock screen is throttled by the persisted counter; resetting it means editing the disk, which reduces to L1. Disk edits of the keyring are detected (block hashes) or fail the AEAD; a crafted slot cannot test many passwords at once (key commitment, §10.3). **Replacing the kernel image defeats login entirely**: no measured boot exists; stated, not mitigated (§7.4). Owner learns of guessing: the first successful unlock shows "N failed attempts since your last unlock", recorded in a signed IntegrityLog record once ID-4 lands. |
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
- **A passphrase that leaked earlier**: an attacker holding a copy of the keyring from before a
  passphrase change, plus the old passphrase, still unwraps the same master key and the same
  tree key. Changing a passphrase protects against *future* disk captures only (as in LUKS).
  True revocation needs a tree-key epoch and re-encryption (open question 6).
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

### 7.5 Threat register (moves to `docs/security/threat-model.md` when ID-3's code lands)

| ID | Threat | Mechanism | Evidence (PR) |
|---|---|---|---|
| T-LOG-1 | Offline guessing | Argon2id at calibrated parameters ≥ floor; params authenticated as AD | host KAT + tamper tests (ID-1, ID-3) |
| T-LOG-2 | Parameter downgrade on disk | Params, salt, kind, user in the wrap's AD; superblock floor is attested state | host test, Kani decode (ID-3) |
| T-LOG-3 | Online guessing / reboot-to-reset | Counter persisted before verdict; backoff from the count | boot `persisted-before-verdict=yes`, Kani (ID-3, ID-5) |
| T-LOG-4 | Partitioning-oracle slot (one slot valid under many passwords) | Key commitment tag per slot, checked in constant time before the AEAD open | host test with a crafted multi-key ciphertext (ID-3) |
| T-LOG-5 | Passphrase or keys in logs, residue in buffers | No `Debug` on secret types; Z1 wipes; xtask log scan | boot + xtask (ID-3) |
| T-LOG-6 | Keystrokes reach a component or the desktop | Single keyboard consumer; router by `LoginState`; typeahead dropped | boot `typeahead-dropped=yes` (ID-3) |
| T-LOG-7 | Fake lock screen | Kernel-owned lock layer; SAK (Ctrl+Alt+Del); no component surface composited while locked | boot `sak=ok` (ID-5); after the gate, the compositor rule |
| T-LOG-8 | OOM halt during unlock | Fallible arena; pre-spawned KDF task; fixed buffers | boot `heap-delta=0 frames-returned=yes` (ID-2, ID-3) |
| T-LOG-9 | Kernel image replaced (evil maid) | **Not defended in v1** | — (measured-boot spec) |
| T-LOG-10 | Full-disk rollback resurrects an old slot or resets the counter | **Detected only with an anchor**; v1 `anchor: None` | — (§13) |
| T-LOG-11 | Weak or predictable keys | RDRAND → HMAC-DRBG with health tests; keyring creation refused without entropy | boot `[rng] … health=ok` (ID-0) |
| T-LOG-12 | Nonce reuse after a rollback (FS-E) | 192-bit XChaCha nonce = gen ‖ counter ‖ per-transaction random salt | Kani `NonceSeq` (FS-E) |

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
- **Calibration at slot creation** (setup or passphrase change), never at unlock:
  1. `usable = total_frames × 4 KiB` (`hal::mm::stats`). Ladder:
     `m = min(1 GiB, the largest power of two ≤ usable / 3)`; if that is < 32 MiB,
     `m = usable / 3` rounded down to a MiB.
  2. Measure one pass at `m` (`t = 1`) on the login-kdf task: `pass_ticks`.
  3. `t = clamp(ceil(TARGET_TICKS / pass_ticks), 3, 10)` with `TARGET_TICKS = 100` (1 s); if
     `m < 64 MiB`, `t = max(t, 4)` (RFC 9106: trade memory for passes when memory-bound).
- **Floor** (refused at creation): `m ≥ 19 MiB` (OWASP's minimum) and `t ≥ 2`. Below 19 MiB
  usable/3, setup offers a **recovery-key-only** keyring with a warning; a passphrase slot is
  refused.
- **Resulting classes.** QEMU `-m 256M` (xtask): `m = 64 MiB, t = 3–4, p = 4`, which is RFC
  9106's second recommended option. QEMU default 128 MiB: `m = 32 MiB, t ≥ 4`. A 16 GiB laptop:
  `m = 1 GiB`, `t = 3` (LUKS2's ceiling, about 2 s). The superblock records the creation-time
  parameters as the volume's floor (§10.2).
- **Latency, honestly (estimates; ID-2 measures and records them).** Scalar Argon2id at
  `opt-level = 3`, one core, ~0.5–1 GiB/s of block processing: 64 MiB × 3 ≈ 0.2–0.4 s on KVM or
  hardware; the calibration then raises `t` toward 1 s. Under TCG, 10–30× slower: 3–10 s for
  the same parameters. A disk set up under TCG calibrates to TCG speed (the minimum `t = 3`),
  then unlocks in a fraction of a second under KVM. Unoptimised (`dev`) Argon2id would be
  another 10–50× slower, which is why `crates/crypto` gets `[profile.dev.package.crypto]
  opt-level = 3` (§8.3).
- **Boot tests** use a test-only setup profile (`--features login-test`, compiled only into
  the `make test` kernel): `m = 8 MiB, t = 1, p = 4`. It changes what *setup* writes, never what
  *unlock* accepts (unlock trusts the authenticated slot parameters, §10.3), so no production
  path is weakened. The production calibration runs once per boot test as an informational
  line (`[kdf] calibrate: m=65536 pass-ticks=N t=T`, not gated).

**Why.** OWASP's 19 MiB is a floor for servers hashing many logins; a disk unlock happens once
per boot and protects everything, so it should spend what the machine can afford. A third of
usable RAM leaves the rest of the kernel (heap, stacks, page tables, caches) at least 2/3 while
the arena is held, and the arena is held for one second. Power-of-two steps keep the parameters
recognisable and make calibration deterministic for a given RAM size. `p = 4` is fixed so a disk
moves between a 1-core and a 4-core machine unchanged.

**Alternatives.** *Fixed parameters for everyone* (simple; either too weak on hardware or
unusable on 128 MiB). *Calibrate at every unlock* (meaningless: the slot's parameters are what
they are). *Target 2 s like LUKS2* (defensible; 1 s chosen because the lock screen is used many
times a day once screen lock exists; a product call, flagged).

**Minds change on:** measured ID-2 numbers far from the estimate (re-tune the target or the
ladder); a product decision that unlock may take 2 s (raise `TARGET_TICKS`); parallel lanes
(ID-6) landing (then 4× the work fits the same latency, and the target stays 1 s while `t`
rises).

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
  (`#[target_feature(enable = "avx2")]` + `unsafe`): in our kernel it would execute AVX2 outside
  `hal::simd`'s vector-state discipline.
- **`poly1305 0.8.0` did not build** for `x86_64-unknown-none`: rustc died with SIGILL compiling
  it (its AVX2 backend on a soft-float target; not root-caused). `argon2` + `hkdf` + `sha2`
  alone built.
- In-tree estimate: BLAKE2b ~200 lines, Argon2id ~350, ChaCha20 + HChaCha20 ~150, Poly1305
  (5 × 26-bit limbs) ~200, the AEAD composition ~100, HMAC/HKDF/HMAC-DRBG ~200, `ct` ~30:
  **~1 200 lines, zero `unsafe`**, every primitive pinned by its RFC's vectors.

**Why.** The TCB argument that admitted `limine` and is weighing `wasmi` applies here, with a
cheaper alternative: these primitives are small, completely specified, and have exhaustive
public test vectors; the third-party stack is 37× larger than what we would write, mostly
generic plumbing, a quarter of it `unsafe`, partly SIMD we could not run under our vector-state
rules, and part of it does not compile for the target today. In-tree code is also Kani-able and
Miri-able as written, and runs identically on the host.

**The honest cost.** Home-grown crypto is how projects get burned. Mitigations, all merge
conditions: RFC vectors as KATs both on the host and **at boot** (catches target-specific
miscompilation, e.g. the soft-float ABI); Wycheproof vectors for ChaCha20-Poly1305 /
XChaCha20-Poly1305 / HKDF / HMAC; a differential fuzz target per primitive against RustCrypto in
`kernel/crypto-oracle/` (random inputs, byte-identical outputs, gating once the fuzz lane
exists); no data-dependent branches or table lookups on secret data outside Argon2id's
specified data-dependent addressing (review checklist + `ct` module); and an external review of
`crates/crypto` before any non-first-party component exists. Constant-time on this machine:
ChaCha20 is add/rotate/xor; Poly1305 with 26-bit limbs uses 64-bit multiplies, which are
constant-time on x86-64; BLAKE2b is add/rotate/xor; there is **no AES**, hence no table-timing
or AES-NI question (§10.6).

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

- The keyring header holds `failures: u32` (attempts since the last successful unlock) and
  `last_attempt_gen: u64`.
- **Ordering**: on Enter, the login state machine first commits `failures + 1` (a one-block
  CoW commit of the keyring plus the superblock: ~3 block writes, 2 flushes), *then* runs the
  KDF, *then* shows the verdict. Success commits `failures = 0` and shows "N failed attempts
  since your last unlock" when N > 0. A power cut after a wrong guess therefore leaves the
  count incremented; a power cut during a right guess leaves it incremented by one, which is
  harmless.
- **Backoff** (pure function, Kani: monotone in `failures`): attempts 1–4 free (beyond the
  KDF's own ~1 s); from the 5th, `delay = 30 s × 2^(failures − 5)`, capped at 1 h. The delay
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

- **Index without the heap.** Up to `MAX_PAGES = 262 144` (1 GiB). Two levels: a **root frame**
  (512 physical addresses of index frames) and index frames (512 data-frame addresses each), all
  owned by the arena. 64 MiB = 16 384 data frames + 32 index frames + 1 root = 0.2 % overhead.
- **Reservation** pops frames in chunks of 512 under the allocator's own lock (`alloc_frame`,
  M4) and checks `free_frames ≥ remaining + keep_free` before each chunk; on any shortfall it
  returns every frame taken so far and fails with `Insufficient { need, free }`. `keep_free` =
  8 MiB, so the rest of the kernel (page tables, stacks, the commit task) is never starved.
  Called only from the preemptible login-kdf task (`IF = 1`, preemption on: hal-tcb §5e's
  allocator rule).
- **Access**: `page(&self, i) -> Option<&[u64; 512]>` and `page_mut(&mut self, i) ->
  Option<&mut [u64; 512]>`; the borrow checker does the aliasing proof. The Argon2id adapter
  copies the previous and reference blocks into two stack buffers (2 KiB) and writes the new
  block through `page_mut`, so no two live references into the arena ever overlap.
- **Drop**: every data, index and root frame is wiped with `secure_zero` (Z1) through
  `page_mut`-equivalent access, then returned with `dealloc_frame` (M5). The boot proof reads a
  sample of pages back as zero before drop completes (`wiped=yes`).
- `FrameArena` is `!Clone`, `Send`, `!Sync` (v1 has one user; ID-6's parallel lanes need a
  shared atomic view, which is a new row then, not now).

### 9.3 New `hal` rows (exact)

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|---|---|---|---|---|
| **M16** | `mm/arena.rs` · `FrameArena::frame_ref` / `frame_mut` (private; used by `reserve`, `page`, `page_mut`, `Drop`) | form `&[u64; 512]` / `&mut [u64; 512]` from `(phys + hhdm) as *const/*mut` for a frame the arena owns | Argon2id needs tens to hundreds of MiB that the 4 MiB heap cannot hold; the HHDM is the only path to a frame's bytes | Every `phys` was returned by `alloc_frame` (4 KiB-aligned USABLE RAM) and is owned by this arena until `Drop` returns it; Limine HHDM-maps all RAM RW, so `phys + hhdm` is valid, writable and 4 KiB-aligned for 4096 bytes. The reference's lifetime is tied to `&self` / `&mut self`, so it cannot outlive ownership, and `&mut` access is exclusive by the borrow. Index and root frames are reached the same way; indices are bounds-checked against `pages` before any lookup. No other code holds these frames (they left the free list). | Kani (index arithmetic: page `i < pages` → root slot `< 512`, index slot `< 512`; all-or-nothing reservation over a modelled allocator) + QEMU boot proof (`match=yes wiped=yes frames-returned=yes`) + Miri on the host model with a `Vec`-backed frame source |
| **Z1** | `mem.rs` · `secure_zero(&mut [u8])`, `secure_zero_words(&mut [u64])` | `core::ptr::write_volatile` per element, then `compiler_fence(SeqCst)` | Wipes the compiler may not elide: keys, passphrase buffer, arena frames, payload arenas (component A9), the SentinelFS plaintext cache (SentinelFS §10) | Writes only within the borrowed slice (index < len), each element aligned by type; volatile stores are never removed or merged away; the fence orders them before any later reuse or free. Takes `&mut`, so no aliasing. | Miri (host) + Kani (writes stay in bounds; the slice reads zero afterwards) |
| **R1** | `rng.rs` · `rdrand64() -> Option<u64>` | `rdrand r64` + carry-flag read (`asm!`) | The kernel has no entropy source; keys, salts and nonces must not come from tick counters | Called only when `cpuid.1:ECX.RDRAND` is set (checked once, cached in an atomic); writes one register, reads CF, touches no memory (`nomem`, `nostack`); up to 10 retries on CF = 0 (Intel's guidance), then `None`. Output is treated as untrusted input to the DRBG, never used raw. | Reasoned + QEMU (TCG emulates RDRAND; the Haswell model advertises it — **to verify in ID-0**) + KVM; health tests in safe code |

**Not new rows**: the frame pops and pushes are M4/M5 unchanged; ID-2 adds an in-use byte
counter to the heap (`LockedHeap::in_use()`, safe arithmetic inside M10/M11's existing blocks;
**row text amended**, no new op) so the boot proof can assert `heap-delta=0`. ID-5 may send the
i8042 LED command for Caps Lock through the existing K2 `outb` (row K4 text amended).

**Against hal-tcb's discipline.** Each row is the smallest primitive its consumer needs, of a
class the registry already holds (M16 is M3/M15's "owned frame through the HHDM", made
borrow-scoped; Z1 is one volatile store loop; R1 is one instruction, like C-rows in §2).
Nothing about policy, parameters, parsing or key handling enters `hal`. RDSEED is deliberately
**not** wrapped (one more instruction for marginal benefit to a DRBG seed); added only if a
reviewer requires full-entropy seeding.

### 9.4 OOM, peak memory and small machines

- **The login path allocates nothing from the heap.** The login-kdf task, its stack and
  `XsaveArea` exist from boot; `SecretBuf` is a fixed `[u8; 256]` inside the static login
  state; the keyring block is a 4 KiB buffer in the static login state (decoded from the FS
  cache slab's verified copy); the KEK, master and subkeys are fixed arrays in typestate
  structs; the commit uses SentinelFS's fixed slabs. The arena is the only memory taken, and it
  is fallible. **Asserted** (`heap-delta=0`).
- **Peak** during a QEMU-class unlock: arena 64 MiB + 132 KiB index; heap 4 MiB (unchanged);
  KDF stack 64 KiB. Under `-m 256M` (~245 MiB usable, ~230 MiB free at the lock screen) that
  leaves ~165 MiB.
- **A machine smaller than the one that set up the slot**: `reserve` fails `Insufficient`; the
  lock screen says "This device needs 64 MiB free to unlock with your passphrase. Use your
  recovery key." The recovery slot needs no arena (§10.5), so the disk is never stranded on a
  small machine as long as a recovery slot exists — which is why setup offers one by default.
- **Not enough RAM at setup** (< 57 MiB usable): recovery-key-only keyring, with a warning.

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
         prk_t = Extract(fs_uuid, tree)  → KeyAgent (algorithm: PR-3,       object-key tree wrap
           "sentinelfs/v1/name-hash"       Ed25519 expected);
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

**Decision.** Same encoding SentinelFS §7.1 reserved, with this meaning:

```text
352  2  alg     1 = Argon2id (0 = volume not keyed; then keys must be null and every
                byte of the field zero, exactly the v2 rule)
354  2  ver     0x13
356  4  m_kib   ┐ the volume's FLOOR for passphrase-class slots: the parameters chosen by
360  4  t       │ calibration at setup. A new slot below the floor is refused; raising it
364  4  p       ┘ is a superblock commit (attested state once FS-5 signs superblocks)
368 16  salt    keyring_id: 16 random bytes; equal to the keyring block's keyring_id
                (mismatch = Corrupt); the HKDF salt for every slot and the master
```

**Why not "the" KDF parameters?** There is more than one slot, each with its own salt and
parameters (a recovery slot has no Argon2id at all), and they live in the keyring block. What
belongs in the superblock is what must be **attested state of the volume**: that it is keyed
(so a kernel without login refuses it: v2's non-zero refusal is unchanged), the policy floor
(so an offline edit that lowers the floor is visible to FS-5 attestation), and the keyring's
identity (so a keyring block from another volume, or a reformatted one, is refused before any
KDF runs). Downgrade of an individual slot's parameters needs no superblock help: they are the
wrap's associated data (§10.3). All 32 bytes stay inside the reservation; the `keys` Pointer at
[392,440) names the keyring block; nothing moves past byte 440, so the first-sector torn-write
argument of SentinelFS §7.1 is untouched. **No version bump**: a pre-login kernel already
refuses a keyed volume.

### 10.3 The keyring block (kind 6)

The standard 64-byte metadata header (`hash`, `gen`, `kind = 6`, `tree_id = 0`, `fs_uuid`),
then:

```text
off   len  field
 64     4  magic "SKR1"
 68     2  version = 1
 70     2  slot_count        number of non-empty slots (≤ MAX_SLOTS = 8)
 72    16  keyring_id        = superblock salt
 88     4  failures          attempts since the last successful unlock (§8.5)
 92     4  flags             bit 0: recovery slot offered and declined at setup (UI only)
 96     8  last_attempt_gen
104     8  master_epoch      +1 on every master rotation
112    48  objkeys: Pointer  root of the object-key tree (FS-E); NULL in v1
160  1216  slots[8] × 152    (§ below); empty slot = all zero
1376  480  subkeys[4] × 120  (§ below); empty = all zero
1856 2240  zero              validated zero (a non-zero byte is Corrupt)
```

**Slot (152 bytes).** All fields before `nonce` are the wrap's associated data, prefixed by
`"sentinelos/keyring/v1/slot" ‖ fs_uuid ‖ keyring_id ‖ le64(master_epoch)`:

```text
 0   1  kind         0 empty · 1 passphrase · 2 recovery · 3 FIDO2 (reserved) ·
                     4 TPM (reserved) · 5 PIN (reserved); v1 refuses 3–5
 1   1  layout       0 = US-QWERTY (passphrase slots)
 2   2  user         1 = owner (the only user in v1, §14)
 4   4  slot_id      unique within the keyring, never reused (monotone)
 8  32  kdf          alg u16 | ver u16 | m_kib u32 | t u32 | p u32 | salt[16]
                     (passphrase: alg 1 Argon2id; recovery: alg 2 = HKDF-SHA-256,
                     m/t/p zero)
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
matches kind; for Argon2id `p ∈ 1..=16`, `t ∈ 1..=64`, `8·p ≤ m_kib ≤ 1 GiB`), unique slot ids,
at least one owner slot, zero tail, `keyring_id` equal to the superblock's. Loops are bounded by
`MAX_SLOTS`, never by an on-disk count.

**Unwrap order**: compute KEK → `slot_wrap`, `slot_commit` → `ct::eq(commit)` → AEAD open →
master. The commitment check makes a crafted slot that opens under many KEKs useless: each slot
commits to exactly one KEK (Len, Grubbs, Ristenpart's partitioning oracles).

### 10.4 Slot operations

All are **one CoW commit** of the keyring block plus the superblock, so they are atomic by
SentinelFS's commit rule; each requires `Keyring<Unlocked>` (the master key in hand).

- **Add** (new passphrase, new recovery key): fresh salt, calibrated parameters ≥ floor, fresh
  nonce, new `slot_id`; refused if `MAX_SLOTS` is reached.
- **Replace** (change passphrase): the new slot is written and the old one cleared in the same
  block, so there is no committed state with neither and none with both.
- **Remove**: refused (`LastSlot`) if it would leave the owner without a slot. Removing the last
  *passphrase* slot while a recovery slot remains is allowed after an explicit confirmation.
- **Rotate master** (after a suspected compromise): new master, every subkey re-wrapped,
  `master_epoch + 1`; slots are rebuilt only for secrets the user re-enters now; the others are
  dropped, with consent. Data is not re-encrypted (the tree key is unchanged; §7.3 says what
  that does and does not buy).
- **Invariant (Kani):** for every bounded sequence of add / replace / remove / rotate applied to
  a valid keyring, the result decodes, has ≥ 1 owner slot, and every non-empty slot wraps the
  current master (modelled as the master's identity tag in the AD-checked wrap).

### 10.5 Recovery key

- 128 random bits + a 32-bit check (the first 4 bytes of `SHA-256("sentinelos:recovery:v1" ‖
  key)`), encoded in **Crockford base32**: 32 symbols, shown as 8 groups of 4
  (`7H2K-9QXD-…`). Case-insensitive; `I`/`L` read as `1`, `O` as `0`; hyphens and spaces
  ignored. A mistyped key fails the check locally and is not counted as an attempt.
- `KEK = HKDF-Extract(salt = slot salt, ikm = key)`: no Argon2id, because 128 bits of entropy
  cannot be guessed; no arena, so it works on any machine. It is the one secret that unlocks
  when memory is short.
- Shown **once** at setup, full screen, behind a "reveal" action, with "write it down; it is
  the only way in if you forget your passphrase". Never stored, never logged, never
  re-displayable (a new one can be generated while unlocked, replacing the old slot).
- Setup offers it by default; declining needs an explicit second confirmation and sets the
  header flag (so the System panel can nag). **Product call**: mandatory or optional.

### 10.6 The AEAD and nonce discipline

**Decision.** **XChaCha20-Poly1305** for every wrap and, in FS-E, for data. Keyring wraps use a
fresh random 24-byte nonce per wrap (stored). FS-E uses
`nonce = le64(gen) ‖ le32(counter) ‖ txn_salt[12]`, where `counter` is a per-transaction,
per-key monotone `NonceSeq` (exhaustion is `NeedCommit`, never a wrap) and `txn_salt` is drawn
from the DRBG once per transaction.

**Why not just `gen ‖ counter`.** It is unique as long as history only moves forward. A
rollback (privileged rollback, a crash before commit, or an L2 restoring an old image) makes the
next transaction reuse a generation number that already encrypted different plaintext under
the same key — the nonce-reuse catastrophe for any stream-cipher AEAD (keystream reuse,
Poly1305 key recovery and forgery). The per-transaction 96-bit salt makes a repeat after any
rollback a 2⁻⁹⁶ event, while `gen ‖ counter` keeps uniqueness within a transaction provable
(Kani) and auditable.

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
tick count and the PIT phase, reseeded every 2¹⁶ requests and at every unlock. Health tests on
the raw RDRAND output (repetition count; reject all-zero and all-ones words, the AMD-after-resume
failure mode) run before seeding and continuously. Without RDRAND, or with a failed health test,
the kernel **refuses to create a keyring, re-wrap a slot or write encrypted data**
(`EntropyUnavailable`); an existing volume still unlocks (unwrapping needs no randomness) and
stays read-only. ID-0's DRBG also gives SentinelFS A26 its format seed and PR-3 its ephemeral
key.

## 11. Trusted input path and lock screen

### 11.1 Who reads the keyboard

**Decision.** `hal::keyboard`'s ring keeps **exactly one consumer**, the `kernel::input`
router on the BSP idle loop. The router forwards by `LoginState`:

- `Setup | Locked | Deriving | Delay`: every decoded event goes to `kernel::login`; nothing
  else sees it. Mouse packets go only to lock-screen hit-testing.
- `Unlocked`: the window manager, as today; after the memory gate, components receive key
  events only through the compositor service for the focused surface.
- **Always first**: the SAK chord, before any routing.

Rules (review checklist and a source guard, `cargo xtask check-keyboard-consumers`: only
`kernel::input` may name `hal::keyboard::poll_scancode`, like `check-ata-callers`): no key
event is logged while not `Unlocked`; no component API exposes raw scancodes; when `Deriving`
ends, the ring is drained and **discarded** before the state changes, so keys typed during the
KDF never reach the terminal (`typeahead-dropped=yes`).

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
  Each keystroke moves a soft pink shimmer one step along the pill (position = keystrokes mod 8);
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
  (no dictionary in the kernel), then the recovery-key screen (§10.5).
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
  (Z1), the KeyAgent is told to wipe its copy (§12.3) and answers `locked`, SentinelFS returns
  to the locked mount. Unlocking is a cold unlock.
- **Idle**: no keyboard or mouse input for `IDLE_LOCK = 5 min` on the mono clock → screen lock.
  **Lid close / suspend**: needs ACPI events (after the IOAPIC/MADT work); when it exists it
  seals. **Product call**: whether idle should seal rather than screen-lock (more secure, kills
  background signing while away).

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
  Setup (alg == 0 / Unformatted) ── passphrase ×2 ─► calibrate ─► keyring + superblock
  │                                                    commit ─► recovery key screen ─► Unlocked
  Locked ── Enter ─► commit failures+1 ─► Deriving (login-kdf: arena, Argon2id, wipe)
        ◄─ denied ── verdict (Delay if backoff applies)
                     └─ ok ─► unwrap master → subkeys ─► commit failures=0
                              ─► sfs: install tree key (full mount, FS-E)
                              ─► secrets: provision device seed → KeyAgent (ID-4)
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

**Minds change on:** a field need for pre-unlock repair (then a console that can scrub, roll
back and format but **not list**, which keeps names sealed).

### 12.3 KeyAgent: from ephemeral to persistent

- **PR-3 (before this lands)** ships the KeyAgent and `kernel::secrets` exactly as the component
  spec says: an ephemeral key drawn from ID-0's DRBG, `sealing=none secrets-persist=no`, nothing
  on disk. It should shape `kernel::secrets` around a sealing backend
  (`enum KeySource { Ephemeral, Keyring }`) and give the KeyAgent a `Locked` answer (never
  reachable with `Ephemeral`), so ID-4 is a backend swap, not an API change. PR-3 must not
  derive its key from anything but the DRBG and must not write any key material to disk.
- **ID-4 (after ID-3 and PR-3)**: at setup, the device seed is drawn from the DRBG and wrapped as
  a subkey; at every unlock, `kernel::login` passes it to `kernel::secrets` (kernel memory),
  which provisions the KeyAgent instance over the kernel control channel (`bus::call`, stamped
  `from = KERNEL`) and wipes its own transfer buffer. The key id is
  `SHA-256("sentinelos:keyid:v1" ‖ pubkey)`, the `signing_key_id` of component A6 and SentinelFS
  §9. Before unlock and after seal, `sign` answers `locked`. The boot line becomes
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
   volume: the superblock is re-hashed by the attacker, the `keyring_id` matches, the old slot
   unwraps the same master. With the old passphrase, the attacker reads current data (§7.3);
   without it, nothing.
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
kind; `User(n)` domains exist on disk), so multi-user is additive, not a format bump. The lock
screen has no user picker and shows no name (a name before unlock is a free fact for a thief).

**What v1 commits to:** `user` fields are validated and only `1` is accepted; the tree key
protects all of v1's data. **What multi-user would add** (its own spec): one master per user,
per-user subkeys keyed to `User(n)` domains, a user picker, `dedup` keyed per user (already
SentinelFS §7.3), and the question of who may add users (PolicyAgent).

**Minds change on:** a concrete second-user need (family machine) before FS-E ships, since FS-E
should then key data per user from day one rather than migrate.

## 15. Public interface (sketches, not implementations)

```rust
// ── hal (TCB) ────────────────────────────────────────────────────────────────
pub mod rng {
    /// One RDRAND word; `None` without RDRAND or after 10 failed tries. Untrusted input.
    pub fn rdrand64() -> Option<u64>;
}
pub mod mem {
    /// Volatile wipe the compiler may not elide, then a SeqCst compiler fence.
    pub fn secure_zero(buf: &mut [u8]);
    pub fn secure_zero_words(buf: &mut [u64]);
}
pub mod mm {
    pub const PAGE_WORDS: usize = 512;
    pub struct FrameArena { /* root frame, page count; !Clone, Send, !Sync */ }
    pub enum ArenaError { NotInitialised, TooLarge, Insufficient { need: usize, free: usize } }
    impl FrameArena {
        pub const MAX_PAGES: usize = 262_144;                   // 1 GiB
        pub fn reserve(pages: usize, keep_free: usize) -> Result<Self, ArenaError>;
        pub fn pages(&self) -> usize;
        pub fn page(&self, i: usize) -> Option<&[u64; PAGE_WORDS]>;
        pub fn page_mut(&mut self, i: usize) -> Option<&mut [u64; PAGE_WORDS]>;
    }
    impl Drop for FrameArena { /* secure_zero every frame, then dealloc_frame */ }
}

// ── crates/crypto (safe, no deps) ────────────────────────────────────────────
pub type Block = [u64; 128];                                    // Argon2 1 KiB block
pub trait Argon2Memory {
    fn blocks(&self) -> usize;
    fn load(&self, i: usize, out: &mut Block);
    fn store(&mut self, i: usize, b: &Block);
}
pub struct Argon2Params { pub m_kib: u32, pub t: u32, pub p: u32 }
impl Argon2Params { pub fn decode(b: &[u8; 32]) -> Result<(Self, [u8; 16]), ParamError>; }
pub fn argon2id(p: &Argon2Params, pwd: &[u8], salt: &[u8; 16], ad: &[u8],
                mem: &mut impl Argon2Memory, progress: &dyn Fn(u32),
                out: &mut [u8; 32]) -> Result<(), KdfError>;
pub mod aead {   // XChaCha20-Poly1305
    pub fn seal(key: &[u8; 32], nonce: &[u8; 24], ad: &[u8], pt: &[u8],
                ct: &mut [u8], tag: &mut [u8; 16]) -> Result<(), AeadError>;
    pub fn open(key: &[u8; 32], nonce: &[u8; 24], ad: &[u8], ct: &[u8],
                tag: &[u8; 16], pt: &mut [u8]) -> Result<(), Unauthentic>;
}
pub mod hkdf { pub fn extract(salt: &[u8], ikm: &[u8]) -> Prk;
               pub fn expand(prk: &Prk, info: &[u8], out: &mut [u8]) -> Result<(), LenError>; }
pub mod ct { pub fn eq(a: &[u8], b: &[u8]) -> bool; }

// ── kernel::keyring (safe) ───────────────────────────────────────────────────
pub struct Locked; pub struct Unlocked;
pub struct Keyring<S> { /* decoded view + (Unlocked only) master and subkeys */ }
pub struct TreeKey(/* [u8; 32] */);   // !Clone !Copy !Debug; Drop = secure_zero
pub struct DeviceSeed(/* [u8; 32] */); // same
pub enum Secret<'a> { Passphrase(&'a SecretBuf), Recovery(&'a RecoveryKey) }
impl Keyring<Locked> {
    pub fn decode(block: &[u8; 4096], sb_kdf: &[u8; 32], fs_uuid: &[u8; 16])
        -> Result<Self, KeyringError>;
    /// Needs an arena only for passphrase slots; returns the locked keyring on failure.
    pub fn unlock(self, s: Secret<'_>, kdf: &mut KdfRunner)
        -> Result<Keyring<Unlocked>, (Keyring<Locked>, UnlockError)>;
}
impl Keyring<Unlocked> {
    pub fn tree_key(&self) -> &TreeKey;
    pub fn device_seed(&self) -> &DeviceSeed;
    pub fn add_slot(&mut self, s: Secret<'_>, kdf: &mut KdfRunner, rng: &mut Drbg)
        -> Result<SlotId, SlotError>;
    pub fn replace_slot(&mut self, old: SlotId, s: Secret<'_>, kdf: &mut KdfRunner,
                        rng: &mut Drbg) -> Result<SlotId, SlotError>;
    pub fn remove_slot(&mut self, id: SlotId) -> Result<(), SlotError>; // LastSlot refused
    pub fn encode(&self, out: &mut [u8; 4096]);
    pub fn seal(self) -> Keyring<Locked>;                    // wipes master + subkeys
}
pub enum UnlockError { Unauthentic, Insufficient { need_mib: u32 }, EntropyUnavailable,
                       Corrupt }

// ── kernel::login (safe) ─────────────────────────────────────────────────────
pub struct SecretBuf { /* [u8; 256], len; !Clone !Debug; Drop = secure_zero */ }
pub enum LoginState { Setup(SetupStep), Locked { failures: u32 }, Delay { until: Tick },
                      Deriving, Unlocked { since: Tick } }
pub fn backoff(failures: u32) -> Ticks;                      // pure; Kani: monotone
```

Misuse made hard by construction: subkeys are reachable only from `Keyring<Unlocked>`; sealing
consumes it; secret types cannot be copied, printed or compared except through `ct::eq`; the
arena cannot outlive its frames; the `ui` crate sees a `LockView`, never a `SecretBuf`.

## 16. Staging, boot proofs and verification

Each PR is independently bootable, adds hard assertions to `cargo xtask test`, discharges its
Kani harnesses locally (≤ 60 s each, measured), and runs its host tests under Miri where they
touch `hal` models.

| PR | Lands | `hal` rows | Kani | Boot-proof line (asserted) |
|---|---|---|---|---|
| **ID-0** entropy + wipe + crypto crate | `crates/crypto` with `sha256` (moved from `kernel::hash`, API re-exported), `hmac`, `hkdf`, `hmac_drbg`, `ct`; `hal::rng` (R1), `hal::mem` (Z1); `kernel::rng` (health tests, DRBG). Serves SentinelFS A26 and PR-3's ephemeral key. **After PR-2b** (the `hash.rs` move), **before PR-3 and FS-2.** | **R1, Z1** (+2) | HKDF expand length arithmetic total; DRBG refuses when unseeded and reseeds at the limit; repetition-count health test; Z1 stays in bounds and reads zero | `[rng] source=rdrand health=ok drbg=hmac-sha256 kat=ok seeded=yes secure-zero=ok ok` |
| **ID-1** primitives | `blake2b`, `argon2id` (generic `Argon2Memory`), `chacha20`, `poly1305`, `xchacha20poly1305`; boot KATs; `[profile.dev.package.crypto] opt-level = 3`; `kernel/crypto-oracle/` host workspace (differential tests; fuzz targets join the lane at FS-2). | 0 | `Argon2Params::decode` total; Argon2 reference-index computation always inside the reference set (never the current or previous block, only finished segments) at `p ≤ 2`, small `m` | `[crypto] kat: blake2b=ok argon2id=ok chacha20poly1305=ok xchacha20poly1305=ok hkdf=ok hmac=ok ok` |
| **ID-2** KDF arena | `hal::mm::FrameArena` (M16); heap `in_use()` (M10/M11 text); `kernel::kdf` (pre-spawned `login-kdf` task, adapter, progress); production calibration line (informational). | **M16** (+1) | arena index arithmetic in range; reservation all-or-nothing over a modelled allocator (hal crate) | `[kdf] arena: pages=2048 index=5 argon2id=<8 hex> match=yes wiped=yes frames-returned=yes heap-delta=0 ok` (m = 8 MiB, t = 1, p = 4, fixed inputs; the expected tag is pinned by a host test against the oracle) |
| **ID-3** keyring + setup + unlock | kind-6 codec; `kernel::keyring`, `kernel::login` (passphrase only); superblock `kdf_params`/`keys` accepted (`kernel::sfs::superblock`; a pre-login kernel still refuses); persisted counter; the lock screen with a real check; decoder Caps/Ctrl/Alt/Delete; `check-keyboard-consumers`; xtask QMP typing. **Needs FS-1b** (transactions for the keyring commit). Boot 1 (blank disk) sends → first and asserts the screen stays locked, then types the test passphrase twice; boot 2 types a wrong one, then the right one. | 0 | keyring decode total (generic `MAX_SLOTS`, shrunken block); slot add/replace/remove/rotate never lose the master; login machine: verdict reachable only after `Persisted`; superblock KDF field decode total | boot 1: `[login] setup: user=1 slot=passphrase kdf=argon2id m=8192 t=1 p=4 keyring=<8 hex> gen=N ok` · boot 2: `[login] attempt: n=1 verdict=denied failures=1 persisted-before-verdict=yes` then `[login] unlock: n=2 verdict=ok failures-since-last=1 keyring=<boot 1's> commit-tag=ok heap-delta=0 typeahead-dropped=yes ok`; xtask: test passphrase absent from the log on both boots |
| **ID-4** persistent KeyAgent key | device seed subkey; `kernel::secrets` `KeySource::Keyring`; provisioning, `locked` before unlock, wipe on seal. **After ID-3 and PR-3.** | 0 | provisioning typestate: no `sign` path reachable from `Locked` | boot 1: `[delegate] keyagent: signed=ok verified=yes secret-readable=no sealing=passphrase secrets-persist=yes key-id=<8 hex> ok` · boot 2: `… before-unlock=locked key-id=<boot 1's> ok` |
| **ID-5** recovery, slot ops, lock levels | recovery key (encode/decode, slot, UI), change/remove passphrase, master rotation, backoff delays, SAK, idle lock (test timeout), seal, Caps LED (K4 text) | 0 | recovery decode total + check; backoff monotone and capped | `[login] slots: recovery=added via-recovery=ok passphrase-changed=ok old-refused=yes last-slot-remove=refused delay-enforced=yes ok` and `[login] lock: sak=ok idle=ok seal=wiped keyagent=locked relock-unlock=ok ok` |
| **FS-E** SentinelFS encryption (FS track, SentinelFS §10.2) | data, inline, dirent names, xattr values; object-key tree; `NonceSeq`; locked mount reads `Locked`; cache wipe on lock. **After FS-4 and ID-3.** | 0 | `NonceSeq`: never repeats within a transaction, exhaustion refuses; nonce encoding injective in `(gen, counter)` | `[sfs] crypt: data=sealed names=sealed locked-read=refused unlocked-read=ok plaintext-on-disk=no ok` (xtask scans the image for a known plaintext marker) |
| **ID-6** parallel lanes (optional) | Argon2id lanes on up to 4 cores; shared atomic arena view (a new row then); park/unpark | +1 (then) | lane/segment barrier ordering | `[kdf] lanes: cores=4 match=yes ok` |

**Total new `hal` rows for v1 (ID-0 … ID-5): three** — R1, Z1 (ID-0), M16 (ID-2) — plus
amended text for M10/M11 (ID-2) and K4 (ID-5).

**Placement in the existing queue.**

```
PR-2b ─► ID-0 ─► PR-3 (ephemeral key from ID-0's DRBG; memory gate merges before it)
           │       │
           │       └──────────────────────────────┐
           ├─► ID-1 ─► ID-2 ──┐                     ▼
FS-1c, FS-1b ─────────────────┴─► ID-3 ─► ID-4 ─► FS-5 (signed superblock, anchor=none)
           └─► FS-2 (A26 seed from ID-0) ─► FS-4 ─► FS-E ─┘      ID-5 any time after ID-3
```

- ID-0 is small and unblocks three tracks (PR-3's key, A26, everything here); it goes first.
- ID-1 and ID-2 touch no FS or component code and run in parallel with FS-1b / FS-2.
- ID-3 needs FS-1b's transactions (the keyring is a CoW block written in a commit) but not
  FS-2's files or FS-4's blobs.
- **What PR-3 can ship before this lands**: KeyAgent, `kernel::secrets`, signatures with an
  ephemeral DRBG key, `sealing=none secrets-persist=no`, the `cold-boot-recovered=no` probe,
  zeroization of payload arenas with Z1 (component A9), and the `KeySource` seam. **What
  changes after ID-4**: the backend becomes `Keyring`; the line reads `sealing=passphrase
  secrets-persist=yes` with a stable key id across boots; `cold-boot-recovered` becomes
  "recovered after unlock, `locked` before"; FS-5 can start.
- SentinelFS's "minds change on" (security seat): this spec ships the user-secret-wrapped
  device key (ID-4) before FS-5, so FS-5 can move up to right after ID-4 if FS-4 is done.

**Host coverage.** Every PR: RFC vectors (RFC 7693 BLAKE2b, RFC 9106 §5.3 Argon2id, RFC 8439
ChaCha20-Poly1305, draft-irtf-cfrg-xchacha, RFC 5869 HKDF, RFC 4231 HMAC, NIST CAVP HMAC-DRBG);
Wycheproof AEAD/HKDF/HMAC vectors; keyring adversarial corpus (every field flipped, truncated
counts, duplicate ids, foreign `keyring_id`, unknown kinds) that lifts into the fuzz lane
unchanged; tamper tests (each AD field flipped → `Unauthentic`); crafted two-key ciphertext →
refused by the commitment; recovery-key exhaustive single-symbol substitutions and adjacent
transpositions detected; the login state machine driven by a scripted key sequence on the host.

## 17. Open questions

1. **Unlock latency vs strength** (product): 1 s target (chosen) or LUKS2's 2 s? Under TCG the
   dev loop pays 3–10 s per unlock at production parameters either way.
2. **Recovery key mandatory or optional** at setup (product). Chosen: offered by default,
   declinable with a second confirmation.
3. **Anti-phishing mark** after the memory gate: a per-user visual shown only by the genuine
   lock screen (needs storage the kernel can read before unlock but components cannot).
4. **Idle lock vs seal** (product): screen lock (chosen default) keeps background signing alive;
   seal is stronger.
5. **No disk attached**: allow an explicitly ephemeral session (banner, nothing persists, no
   unlock) or refuse to leave the lock screen? xtask always attaches a disk.
6. **Tree-key epochs**: to truly revoke a leaked passphrase, new writes need a new tree key and
   old data background re-encryption. FS-E should reserve an epoch field in object-key entries.
7. **RDSEED**: add the row (full-entropy seeds) or stay with RDRAND + DRBG (chosen)?
8. **Keyboard layouts**: v1 is US-QWERTY; a layout switch must not lock a user out (the slot
   records the layout; the UI warns). Unicode passphrases need NFC normalization first.
9. **External review** of `crates/crypto`: who, and before which milestone (chosen: before the
   first non-first-party component).
10. **Multi-user timing**: if a second user is wanted, FS-E must key per user from day one.
11. **Commit wear**: two commits per failed attempt is fine on QEMU and SSDs; revisit for raw
    flash.

## 18. What this changes elsewhere (pointers, not edits)

- **SentinelFS §7.1**: `kdf_params` and `keys` acquire the meaning of §10.2–§10.3 in ID-3; the
  zero rule stays for `alg = 0`. **§10**: `data` becomes `data-wrap` (random per-object keys),
  object-key tree root in the keyring block, the FS-E nonce of §10.6. **§14 items 2–4** are
  answered here (§13, §9, §12.2). **A22** is resolved by §9; **A26** by ID-0. Principle 4's
  replay determinism takes the RNG as an input once FS-E exists.
- **Component §18.1** is answered by ID-4; **A9** gets its wipe primitive (Z1) in ID-0; **§9**:
  the IdentityAgent (pairing) is not the login service — login is kernel-native because it must
  own the input path and the keyring.
- **Threat model**: T-LOG-1 … T-LOG-12 move to `docs/security/threat-model.md` §5 when ID-3's
  code lands (security-engineer), with adversary A5 (disk/offline) pointing here.
- **hal-tcb**: new §5h (`FrameArena`, M16), §10 (`hal::rng`, R1), §11 (`hal::mem`, Z1); text
  amendments to M10/M11 and K4.

## 19. Review round 1 (placeholder)

To be run by the four roles independently: kernel-architect, kernel-reviewer,
security-engineer, verification-engineer.

| Question | architect | reviewer | security | verification | **Consensus** |
|---|---|---|---|---|---|
| `hal` rows (M16, Z1, R1) and the arena vs static-reservation choice | | | | | |
| In-tree crypto vs RustCrypto (§8.3) | | | | | |
| Argon2id parameters, calibration, test profile (§8.2) | | | | | |
| Keyring layout, superblock field meaning, AEAD + nonces (§10) | | | | | |
| Trusted input path, SAK, lock levels (§11) | | | | | |
| Rollback anchor `None` (§13) | | | | | |
| Staging and Kani targets (§16) | | | | | |

**Amendments.** *(none yet)*

**Minds change on.** *(to be filled by each role)*

## 20. References

- RFC 9106, *Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications*
  (§4 parameter choice, §5.3 Argon2id test vector).
- OWASP Password Storage Cheat Sheet (Argon2id minimum: 19 MiB, t = 2, p = 1).
- cryptsetup / LUKS2 on-disk format and `--pbkdf argon2id` defaults (2 s target, 1 GiB cap,
  keyslots wrapping one volume key).
- RFC 7693 (BLAKE2), RFC 8439 (ChaCha20-Poly1305), draft-irtf-cfrg-xchacha (XChaCha20),
  RFC 2104 / RFC 4231 (HMAC), RFC 5869 (HKDF), NIST SP 800-90A (HMAC-DRBG).
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
