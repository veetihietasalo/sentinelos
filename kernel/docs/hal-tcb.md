# HAL TCB Registry — SentinelOS

This document is the authoritative registry of **every `unsafe` operation** in
the SentinelOS Trusted Computing Base. The `hal` crate is the *only* crate
permitted to use `unsafe`; the `kernel` crate carries `#![forbid(unsafe_code)]`.
Each entry below names the unsafe primitive, why it is necessary, why it is
sound, and its formal-verification status.

- **Owner:** hal-specialist
- **Scope:** sub-project #1 (boot bring-up) — serial console + CPU primitives
- **Crate lints:** `#![deny(unsafe_op_in_unsafe_fn)]`,
  `#![warn(clippy::undocumented_unsafe_blocks)]` — every `unsafe` block is
  forced to carry a `// SAFETY:` comment.
- **Verification legend:** Miri / Kani / fuzz are marked **pending** — they come
  online in sub-project #2 (per design spec §9). "Reasoned" = argued sound by
  construction in the `// SAFETY:` comment and reviewed.

> Note: inline `in`/`out` and most privileged instructions are **not**
> Miri-executable (Miri has no model for x86 port I/O or `hlt`/`cli`/`sti`).
> For those, verification is by manual review + QEMU boot evidence, not Miri.

---

## 1. `hal::serial` — 16550 UART on COM1 (`0x3F8`)

The serial driver is the only source of device I/O in the bring-up TCB. All
hardware access is funnelled through two private primitives, `inb`/`outb`, each
documented with a `# Safety` rustdoc section.

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| S1 | `serial.rs` · `inb()` | `in al, dx` (port read) | Only way to read 16550 status/data registers | `unsafe fn` whose `# Safety` requires a read-safe UART port; all callers pass a COM1 register offset (`base + 0..=5`). Pure device read, `nomem`/`nostack`. | Reasoned + QEMU (Miri/Kani/fuzz **pending**) |
| S2 | `serial.rs` · `outb()` | `out dx, al` (port write) | Only way to program/transmit on the 16550 | `unsafe fn` whose `# Safety` requires a write-safe UART port; all callers pass a COM1 register offset with a defined value. Device-only effect, `nomem`/`nostack`. | Reasoned + QEMU (Miri/Kani/fuzz **pending**) |
| S3 | `serial.rs` · `Serial::init()` | block of `outb` calls | 8N1 + FIFO programming sequence | Each `outb` targets a constant COM1 register offset with a standard, well-defined value; affects only the UART device, cannot alias Rust memory. Satisfies `outb`'s contract per call. | Reasoned + QEMU (**pending**) |
| S4 | `serial.rs` · `Serial::is_transmit_ready()` | `inb(base + LSR)` | Poll Transmit-Holding-Register-Empty before writing | Reads the read-only Line Status Register; no side effect relevant to memory safety. Satisfies `inb`'s contract. | Reasoned + QEMU (**pending**) |
| S5 | `serial.rs` · `Serial::write_byte()` | `outb(base + DATA, byte)` | Transmit one byte | Reached only after the LSR reports THR empty, so no overrun; writes the data register, device-only effect. Satisfies `outb`'s contract. | Reasoned + QEMU (**pending**) |
| S6 | `serial.rs` · `interrupts_enabled()` | `pushfq; pop {}` (read RFLAGS) | Read IF so the console guard can restore prior interrupt state | Balanced push/pop reads RFLAGS into a register; `nomem`, `preserves_flags`, stack-balanced (no `nostack`). Reading flags cannot violate memory safety. | Reasoned (**pending**) |

### Concurrency note

The global console (`static CONSOLE: Serial`) is shared, but `Serial` has no
interior mutability — all UART state lives in the device. Writes go through
`with_console`, which masks maskable interrupts (`cli`) for the duration of the
write and restores the prior `IF` state (`sti` only if it had been set). This
prevents an interrupt handler from re-entering the UART mid-byte. It is **not**
an SMP lock; multi-core synchronisation is a sub-project #2 concern (single-core
at bring-up).

---

## 2. `hal::cpu` — CPU primitives

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| C1 | `cpu.rs` · `disable_interrupts()` | `cli` | Mask maskable interrupts for critical sections | Clears RFLAGS.IF only; affects interrupt-delivery timing, never memory validity/aliasing. `nomem`/`nostack`; not `preserves_flags` (modifies IF). | Reasoned (**pending**) |
| C2 | `cpu.rs` · `enable_interrupts()` | `sti` | Re-open the interrupt window after a critical section | Sets RFLAGS.IF only; not itself UB. At bring-up no IDT/handlers exist, so this is for symmetry; handler safety is the IDT owner's responsibility (sub-project #2). | Reasoned (**pending**) |
| C3 | `cpu.rs` · `halt()` | `hlt` (single) | Idle the core until the next interrupt | Idles the CPU; accesses no memory/registers; `preserves_flags`. Cannot violate memory safety. | Reasoned (**pending**) |
| C4 | `cpu.rs` · `halt_loop()` | `hlt` (in a `loop`) | Terminal park for boot path + panic handler (`-> !`) | Same as C3; re-halts on every wake so the core never spins hot and never falls through. Diverging, safe wrapper. | Reasoned (**pending**) |

---

## 3. Verification roadmap (sub-project #2+)

| Tool | Applicable to | Status |
|------|---------------|--------|
| Manual review + adversarial review (kernel-reviewer) | all entries | scheduled (build sequence step 6) |
| QEMU boot evidence | S1–S5, C3–C4 (serial output + clean halt) | via `cargo xtask test` (test-engineer) |
| Miri | pure logic helpers only (cannot model port I/O / `hlt`/`cli`/`sti`) | **pending** |
| Kani (bounded model checking) | bit-level helpers (e.g. IF/LSR masks, newline translation) | **pending** |
| Fuzzing | `Serial::write_bytes` newline translation over arbitrary inputs | **pending** |

## 4. Invariants the rest of the kernel relies on

1. `serial::init()` is called exactly once before the first `print!`/`println!`.
2. No `panic!`/`unwrap` on the normal print path — `_print` drops the
   (infallible) formatting `Result` to stay panic-free (spec §8).
3. `cpu::halt_loop()` never returns and never unwinds (`panic = "abort"`).
4. The `kernel` crate touches hardware *only* through these safe wrappers; it
   never writes `unsafe` itself.
