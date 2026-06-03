# SentinelOS Kernel — Boot Bring-up Design Spec

- **Date:** 2026-06-03 · **Status:** Draft for review
- **Component of:** SentinelOS · **Sub-project:** #1 of the kernel decomposition
- **Owner agent:** kernel-architect

## 1. Summary

Sub-project #1 brings a `#![no_std]` Rust kernel from power-on to a running entry point: it **boots via Limine in QEMU, prints to a serial console, handles panics gracefully, and is covered by an automated boot test.** It is deliberately small — the tracer-bullet that proves the whole toolchain → boot → test loop and establishes the **framekernel discipline** (a tiny `unsafe` TCB) from the very first line. Everything else in the kernel is built on top of this.

## 2. Goals

- A bootable SentinelOS kernel image that runs in QEMU and prints a boot banner over serial.
- A panic handler that reports the panic over serial and halts.
- A **host-side, stable-toolchain QEMU boot test** that asserts the banner + a clean exit (CI-friendly).
- The **framekernel TCB boundary** established as a crate split: one small `unsafe` crate, the rest `#![forbid(unsafe_code)]`.
- A reproducible build on macOS (and Linux CI) using **stable Rust, no nightly**.

## 3. Non-goals (→ sub-project #2 and later)

Paging / virtual memory, heap allocation, interrupts (GDT/IDT/IRQs), the scheduler, drivers beyond serial, userland, and the `sentinel-core` security subsystem integration. Bring-up does the *minimum* to prove the loop.

## 4. Locked decisions

| Decision | Choice |
|---|---|
| Architecture | **x86_64** (aarch64 added later as a second HAL target) |
| Bootloader | **Limine** (`limine` Rust crate for the boot protocol) |
| Target | built-in **`x86_64-unknown-none`** on **stable** — no nightly, no `-Z build-std` (prebuilt `core`) |
| Architecture style | **Framekernel** — `unsafe` confined to a tiny HAL crate (the TCB) |
| Repo | same `sentinelos` repo, under **`kernel/`** as its own nested Cargo workspace |
| Discipline | Rust best practices: clippy-clean, `-D warnings`, `// SAFETY:` on every `unsafe`, `Result` errors, doc comments |

## 5. Architecture

Framekernel from line one. Two crates with a hard safety boundary:

- **`hal`** — the **only** crate permitted to use `unsafe`. It is the entire TCB for sub-project #1. It owns the Limine boot entry/shim, 16550 serial port I/O, and CPU primitives (`hlt`, `cli`/`sti`). Every capability is exposed behind a **safe** API.
- **`kernel`** — `#![no_std] #![no_main] #![forbid(unsafe_code)]`. The actual kernel logic (`kmain`, banner, panic handler) written entirely in **safe** Rust, consuming `hal`'s safe APIs.

The boot entry point and any setup that requires `unsafe` live in `hal` and then call into safe `kernel::kmain(boot_info)`, so the `kernel` crate can truthfully carry `#![forbid(unsafe_code)]`.

## 6. Components / file structure

```
kernel/                              ← nested Cargo workspace (excluded from the std root workspace)
  Cargo.toml                         [workspace] members = ["crates/hal","crates/kernel","xtask"]
  rust-toolchain.toml                pin stable channel + targets = ["x86_64-unknown-none"] + llvm-tools
  .cargo/config.toml                 build.target, rustflags (lld linker, linker script), xtask alias
  linker.ld                          higher-half layout (.text/.rodata/.data/.bss/stack)
  limine.conf                        boot entry → the kernel ELF

  crates/hal/                        ← the ONLY unsafe crate (the TCB)
    Cargo.toml                       deps: limine
    src/lib.rs                       re-exports + TCB module docs
    src/boot.rs                      Limine requests + `_start` entry shim → calls kernel::kmain
    src/serial.rs                    16550 UART (unsafe port I/O) behind a safe `Serial`/`fmt::Write`
    src/cpu.rs                       `halt_loop()`, `disable_interrupts()` — safe wrappers over unsafe

  crates/kernel/                     ← #![no_std] #![no_main] #![forbid(unsafe_code)]
    Cargo.toml                       deps: hal   (sentinel-core added in sub-project #6)
    src/main.rs                      `kmain(boot_info)`: print banner, optional framebuffer pixel, halt
    src/panic.rs                     `#[panic_handler]` → serial + halt

  xtask/                             ← std host binary: build image, run/test in QEMU
    Cargo.toml
    src/main.rs                      build → assemble bootable image (Limine) → launch qemu-system-x86_64

  tests/boot.rs (or xtask test)      host-side integration test (see §9)

  docs/hal-tcb.md                    registry of every unsafe op + its verification status
```

## 7. Boot flow (data flow)

```
power-on → QEMU firmware → Limine
   → loads the kernel ELF (higher-half) + provides BootInfo (memory map, framebuffer, HHDM)
   → calls hal::boot _start shim
        → hal initializes the 16550 serial port
        → calls  kernel::kmain(boot_info)            [safe Rust from here]
              → serial.println!("SentinelOS … booted")
              → (optional) write one framebuffer pixel to prove the framebuffer request
              → hal::cpu::halt_loop()                 // hlt forever
on panic anywhere → kernel::panic handler → serial.println!(panic info) → hal::cpu::halt_loop()
```

## 8. Error handling

- **No panics on normal paths.** The panic handler is the *last resort*: it prints the `PanicInfo` (location + message) over serial, then halts in a `hlt` loop (never returns, never unwinds — `panic = "abort"`).
- HAL constructors/operations that can fail return `Result`; at bring-up the surface is tiny (serial init is infallible on QEMU's COM1), but the pattern is established.
- The boot test treats "no banner within timeout" or a non-clean exit code as failure.

## 9. Testing

- **Host-side boot integration test (the key deliverable):** `cargo xtask test` (or a `tests/boot.rs`) builds the kernel image and runs `qemu-system-x86_64 -serial stdio -device isa-debug-exit,iobase=0xf4,iosize=0x04 -display none -no-reboot`, captures serial output, and asserts (a) the boot banner string appears and (b) QEMU exits with the success code the kernel writes via `isa-debug-exit`. Runs on **stable**, headless, deterministic → CI-ready. No `custom_test_frameworks` (nightly); use `harness = false` if a kernel-side runner is needed.
- **Unit tests (host):** any pure logic (e.g. serial formatting helpers) tested with `cargo test` on the host target.
- **Verification gate:** at bring-up the `unsafe` surface is tiny (serial port I/O, `hlt`). Each block is documented in `docs/hal-tcb.md` with a `// SAFETY:` justification. Miri/Kani/fuzz come online as the HAL grows in sub-project #2; the gate (verification-engineer) is wired into CI now so it is ready.

## 10. Toolchain (macOS + Linux CI)

- `rustup target add x86_64-unknown-none` · `rustup component add llvm-tools` (provides `ld.lld`).
- `brew install qemu` · `brew install xorriso` (for the ISO route) — or a UEFI HDD image + OVMF.
- Limine: pin a specific stable release tag; `xtask` fetches/uses the `limine` binary to install the bootloader onto the image.
- `rust-toolchain.toml` pins the exact stable Rust version; `Cargo.lock` is committed.

## 11. Acceptance criteria

1. `cargo xtask run` boots SentinelOS in QEMU and serial prints a `SentinelOS …` banner.
2. A deliberate `panic!()` prints the panic info over serial and halts (no reboot loop).
3. `cargo xtask test` passes: the boot integration test asserts the banner + clean exit code.
4. `crates/kernel` compiles with `#![forbid(unsafe_code)]`; every `unsafe` in `crates/hal` has a `// SAFETY:` comment and an entry in `docs/hal-tcb.md`.
5. Builds clean with `-D warnings` and `cargo clippy` on **stable**, on macOS and in Linux CI.

## 12. Open questions

- Separate `hal` crate vs. a module — **spec assumes a separate crate** (cleaner `#![forbid(unsafe_code)]` boundary). Confirm.
- Image format: ISO (`xorriso`) vs. UEFI HDD image (+OVMF) — toolchain-engineer to choose for best macOS ergonomics.
- Exact higher-half base + whether to demo a framebuffer pixel in #1 (optional, nice proof the framebuffer request works).

## 13. Build sequence (becomes the implementation plan)

1. **toolchain-engineer:** `kernel/` workspace skeleton, `rust-toolchain.toml`, `.cargo/config.toml`, `linker.ld`, `limine.conf`, `xtask` build/run.
2. **hal-specialist:** `hal` crate — Limine boot shim, 16550 serial, `cpu` primitives (with `// SAFETY:` + `docs/hal-tcb.md`).
3. **kernel-engineer:** `kernel` crate — `kmain` banner + panic handler (safe Rust, `#![forbid(unsafe_code)]`).
4. **test-engineer:** host-side QEMU boot test + `xtask test`.
5. **verification-engineer:** wire the (currently minimal) verification gate into CI; review the TCB registry.
6. **kernel-reviewer:** adversarial review of the HAL `unsafe` and the boundary → approve.
