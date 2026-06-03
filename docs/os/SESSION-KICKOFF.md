# SentinelOS Kernel — Session Kickoff (separate track)

The from-scratch Rust OS is a **separate, long-horizon effort**. Start it in a **fresh `claude` session** pointed at this file — keep it decoupled from the dashboard and the security-audit work.

## Read first (hard dependency)
- The **AI-augmented-engineering research report** (deep-research run `wf_5905daaa-a05`, produced in the parent session) defines the **build methodology, verification strategy, and toolchain** for this OS. **Do not start coding the kernel before incorporating it.** It is the reason we paused to "look before we leap."

## What's already decided
- **Language:** Rust. **Name:** SentinelOS.
- The **Security Center dashboard** (this repo) is the OS's first userland app. Its **`sentinel-core` crate is reused verbatim** inside the OS's security subsystem — write the security logic once.
- The **matte design tokens** carry over to the OS GUI.
- Architecture principle from the dashboard spec: OS-specifics live behind one `SecurityProvider` trait; the core + look are portable.

## Rough decomposition (each gets its own spec → plan → build cycle)
1. **Target & toolchain** — pick arch (x86_64 and/or aarch64), `no_std`, custom target JSON, QEMU loop.
2. **Boot** — bootloader (`bootloader` crate or Limine) → reach a Rust `_start`.
3. **Core kernel** — paging/heap, GDT/IDT + interrupts, a scheduler.
4. **Drivers** — serial/console, timer, keyboard → later storage/display.
5. **Userland & syscalls.**
6. **Display/compositor → GUI stack.**
7. **Port Sentinel** — native `SecurityProvider` + render the Security Center with a Rust-native GUI (iced/egui/Slint) using the shared tokens.

> Scope discipline: build #1 first and get it running in QEMU before anything else. Don't design the whole OS up front.

## How to begin the OS session
Open a fresh `claude` session in this repo and say:

> "Read `docs/os/SESSION-KICKOFF.md` and the AI-augmented-engineering report, then let's brainstorm SentinelOS — start with **target & toolchain** (decomposition step 1)."

## Reference
- Dashboard repo: **this repo** (`sentinelos`). Design: `docs/specs/`. MVP plan: `docs/plans/`.
- Portable shared crate: `sentinel-core`.
