# SentinelOS — Vision & Strategy

## Vision
SentinelOS aims to combine the best of **Windows** (apps, games, hardware), **Linux** (openness, flexibility, deep customization), and **macOS** (polish, UX) — a flexible, customizable desktop OS with great coding support and, in the long run, broad app/game and big-brand compatibility — built on a foundation of **better privacy and security** than any of them.

## North star: privacy & security (the differentiator)
Privacy/security is the one goal that is both achievable now and uniquely ours, and it is delivered **architecturally**, not bolted on:
- A **framekernel** — a tiny `unsafe` HAL/arch core (the TCB), everything else safe Rust (`#![forbid(unsafe_code)]`).
- A **native security subsystem** reusing the `sentinel-core` crate (continuous integrity monitoring as a first-class kernel citizen).
- Stable Rust + a CI verification gate (Miri + Kani + fuzz) over the TCB.

The matte "security-ops" aesthetic established in the dashboard is the UI/UX design language.

## Strategy: Path A — pure from-scratch  (decided 2026-06-03)
SentinelOS is built **from scratch in Rust** (x86_64 first, Limine boot). This **maximizes privacy and control** at the cost of compatibility speed.

**Honest, accepted scope:**
- Broad compatibility — "runs all games", big-brand proprietary apps (Adobe/Office) — is a **long-horizon** goal, not near-term. The hard walls (kernel-level **anti-cheat**, **GPU drivers**, proprietary Win/macOS apps) block *every* non-Windows OS, not just us. There is no honest promise of "everything."
- The realistic compatibility path, much later, is a Windows/Linux compatibility layer + Vulkan — a growing *subset*, never a guarantee.

**Considered and not chosen (kept on record):**
- **B — hardened privacy Linux distro:** fastest to "runs software" (Proton/drivers), but it's "a distro," and privacy is hardening-based, not architectural.
- **C — Linux-ABI-compatible Rust framekernel (Asterinas-style):** would ride the Linux software trajectory while staying safe-Rust. Not chosen, but the current boot/kernel work is compatible with it, so a future pivot to C remains open if compatibility ever outweighs purity.

## Build order (kernel decomposition)
1. **Boot bring-up** — serial, panic, framekernel HAL ← *in progress*
2. Core kernel — memory (paging/heap), interrupts, scheduler
3. Drivers — serial → timer → keyboard → storage/display
4. Userland + syscalls
5. Display/compositor → GUI (the polished UI)
6. Port the Sentinel security subsystem (`sentinel-core` native)
… then the long road toward apps, games, and compatibility.
