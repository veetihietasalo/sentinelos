<div align="center">

# 🌆 SentinelOS

### A private, security-first operating system — built from scratch in Rust.

[![Language](https://img.shields.io/badge/Rust-stable-orange?logo=rust)](https://www.rust-lang.org/)
[![Arch](https://img.shields.io/badge/arch-x86__64-blue)](#)
[![Boot](https://img.shields.io/badge/bootloader-Limine-7ad7ff)](https://github.com/limine-bootloader/limine)
[![Kernel](https://img.shields.io/badge/kernel-framekernel-ff5fae)](#architecture--the-framekernel)
[![unsafe](https://img.shields.io/badge/kernel-forbid(unsafe__code)-success)](#architecture--the-framekernel)
[![Status](https://img.shields.io/badge/status-pre--alpha-c43e8f)](#it-actually-boots)

<img src="docs/images/lock-screen.png" width="760" alt="SentinelOS — the Cyber Dusk lock screen running in QEMU"/>

**`private · secure · yours`**

</div>

---

## What is this?

**SentinelOS is a from-scratch operating system written in Rust** — no Linux fork, no inherited C kernel. A new OS that boots on real x86_64 hardware, with privacy and security designed into its *architecture* rather than bolted on after the fact.

Its foundation is a **framekernel**: a tiny `unsafe` core — the entire Trusted Computing Base — is the *only* place unsafe code is permitted, and **every other line is `#![forbid(unsafe_code)]` safe Rust.** A memory-safety bug in the safe kernel isn't "unlikely" — it's a *compile error*.

The interface language is **"Cyber Dusk"** — a Y2K-Aero, dusk-toned aesthetic meant to feel personal and alive, while staying calm and trustworthy.

> ⚠️ **Status: pre-alpha.** SentinelOS boots, paints a GUI, and runs an interactive shell — in QEMU, today. It's early, it's honest about that, and it's being **built in public.**

---

## It actually boots

From power-on to an interactive desktop — all real, all verified in QEMU:

- ✅ **Boots** via Limine on x86_64 — stable Rust, `no_std`, the built-in `x86_64-unknown-none` target (no nightly, no `-Z build-std`)
- ✅ **Interrupts** — GDT / TSS / IST, a 256-entry IDT, exception handling with `#PF` CR2 reporting and a runtime `int3` IDT self-test
- ✅ **Timer** — 8259 PIC remap + 8254 PIT → a **live, ticking clock**
- ✅ **Memory** — physical frame allocator + paging + a kernel **heap** with a `#[global_allocator]` (`Box` / `Vec` / `String` all work)
- ✅ **Input** — a PS/2 keyboard driver, full US-QWERTY ASCII
- ✅ **GUI** — the **Cyber Dusk** boot/lock screen → press <kbd>→</kbd> to unlock (with an animation) → a desktop
- ✅ **Shell** — an interactive terminal: `help` · `about` · `mem` · `echo` · `uptime` · `ls` · `cat` · `cpuinfo` · …
- ✅ **Filesystem** — an in-memory FS that persists to an IDE disk and survives reboot
- ✅ **Networking** — e1000 NIC + ARP / IPv4 / ICMP: it pings its gateway at boot
- ✅ **Scheduler** — cooperative + timer-preemptive kernel threads, proven bit-exact under preemption
- ✅ **Multi-core** — every application processor online with its own descriptor tables, vector state, LAPIC and timer tick; a per-CPU scheduler places tasks on any core, wakes it by IPI, and preempts them there
- ✅ **AI/ML compute** — int8 GEMM on scalar / AVX2 / AVX-512 / VNNI tiers, self-tested per core at boot
- ✅ **Components + capabilities** — content-addressed components on a kernel bus; the kernel stamps the sender, capabilities are deny by default and proven never to amplify
- ✅ **SentinelFS core** — copy-on-write tree with SHA-256 on every pointer and two superblock slots; a commit torn mid-write in QEMU mounts the previous one intact
- ✅ **IOAPIC routing** — interrupts routed from the ACPI MADT, legacy PIC masked
- ✅ **Verified TCB** — Miri + Kani gate every `hal` change in CI

🚧 **In flight:** SentinelFS FS-2 (files on the new tree), login and identity (spec proposed), component delegates (PR-3, waits on the memory-boundary decision), the AMX inference tier, and a richer windowed desktop.

<div align="center">
<img src="docs/images/shell.png" width="720" alt="The SentinelOS interactive shell — typing 'about' and getting real output"/>
<br/>
<em>The shell, responding to a real keystroke-injected <code>about</code> command.</em>
</div>

---

## Architecture — the framekernel

```
┌──────────────────────────────────────────────────────────────┐
│  kernel   ·  ui      →   #![forbid(unsafe_code)]   safe Rust   │
│  (logic, shell, GUI, drivers' safe halves, protocol stacks)    │
├──────────────────────────────────────────────────────────────┤
│  hal  ·  boot         →   the TCB — the ONLY unsafe code       │
│  (port I/O, paging, the ISR stubs, the framebuffer surface)    │
└──────────────────────────────────────────────────────────────┘
```

- **Tiny, audited TCB.** Every `unsafe` operation in the HAL is catalogued in [`kernel/docs/hal-tcb.md`](kernel/docs/hal-tcb.md) with a `// SAFETY:` argument and a verification status. The `kernel` and `ui` crates carry `#![forbid(unsafe_code)]` — the compiler enforces the boundary.
- **Stable Rust, end to end.** No nightly features. Lints (`deny(unsafe_op_in_unsafe_fn)`, `warn(clippy::undocumented_unsafe_blocks)`) make undocumented unsafety a hard error.
- **Verifiable by design.** The roadmap brings Miri / Kani / fuzzing online over the TCB — its surface is small enough that this is actually tractable.

---

## The Sentinel Security Center

Before the kernel, there was **Sentinel** — a cross-platform desktop Security Center (Tauri + Rust) that continuously monitors a machine's integrity across **20 forensic vectors** (persistence, network beacons, TCC/permission grants, remote access, kernel extensions, and more) and surfaces findings in a calm, matte dashboard. It's read-only by default and built on the principle that **"clean" is a valid result — never a reason to invent threats.**

Its logic lives in one portable Rust crate, `sentinel-core`, deliberately built to port *into* SentinelOS as the OS's **native security subsystem** — continuous integrity monitoring as a first-class kernel citizen, not an app you install. The security mission predates the kernel; the kernel is how we deliver it without compromise.

---

## Quick start

**Prerequisites:** a stable Rust toolchain, the bare-metal target, plus `qemu` and `xorriso`.

```bash
rustup target add x86_64-unknown-none
# macOS:  brew install qemu xorriso
# Debian: sudo apt install qemu-system-x86 xorriso
```

**Build, boot, and screenshot it:**

```bash
cd kernel
make build        # cross-compiles the boot ELF for x86_64-unknown-none
make test         # builds the ISO, boots headless in QEMU, asserts the boot bring-up
make screenshot   # boots and captures a PNG of the framebuffer
```

`make` detects your host triple so these work on Linux and macOS alike. `make test`
should finish with `TEST PASSED` and a serial log ending in `boot-bringup-ok`.

---

## Roadmap

The spine, from bare metal toward a usable, private desktop OS:

- [x] **1 — Boot bring-up** · serial, panic, the framekernel HAL
- [x] **2 — Core kernel** · interrupts, the PIT timer, paging + heap
- [x] **3 — Input + GUI** · keyboard, the Cyber Dusk boot screen, an interactive shell
- [x] **4 — A real shell** · persistent filesystem, more built-ins
- [x] **5 — Networking** · e1000 driver + ARP / IPv4 / ICMP *(TCP/UDP still to come)*
- [x] **5b — SMP** · every core online, per-CPU scheduler, IPI wake-ups, per-core timer preemption, IOAPIC routing
- [ ] **6 — A windowed desktop** · compositor, launcher, multiple apps *(first slice landed)*
- [ ] **7 — Component model** · content-addressed components, kernel-attested messaging, capabilities, delegates *(PR-1, PR-2, PR-2b landed: SHA-256 ids, bus, capabilities, routed services; delegates next)*
- [ ] **8 — Sentinel as components** · `sentinel-core` unchanged as a component, a signed integrity log, PolicyAgent
- [ ] **9 — The long road** · our own browser engine, broader hardware & app support

---

## Why?

Every mainstream OS asks you to trade privacy for capability. SentinelOS is a bet that you shouldn't have to — and that the only way to *mean* it is to build security into the kernel's architecture, in a language that makes whole classes of vulnerabilities impossible.

It's a long road, and we're honest about that: broad app and game compatibility, GPU acceleration, and running on every laptop are **long-horizon** goals, not near-term promises. What's real today is what's in [It actually boots](#it-actually-boots) — and it grows every commit.

---

## Built in public

SentinelOS is being built one verifiable milestone at a time, out in the open — watch it go from "prints text on a serial line" to a real desktop. ⭐ the repo to follow along; issues, ideas, and contributors are welcome as it opens up.

## License

**TBD** — licensing is being finalized for the public release. Until then, all rights reserved.

<div align="center">
<br/>
<sub>SentinelOS · a private OS, built from scratch, in Rust.</sub>
</div>
