# SentinelOS — Vision & Strategy

## Vision
SentinelOS aims to combine the best of **Windows** (apps, games, hardware), **Linux** (openness, flexibility, deep customization), and **macOS** (polish, UX) — a flexible, customizable desktop OS with great coding support and, in the long run, broad app/game and big-brand compatibility — built on a foundation of **better privacy and security** than any of them.

## North star: privacy & security (the differentiator)
Privacy/security is the one goal that is both achievable now and uniquely ours, and it is delivered **architecturally**, not bolted on:
- A **framekernel** — a tiny `unsafe` HAL/arch core (the TCB), everything else safe Rust (`#![forbid(unsafe_code)]`).
- A **native security subsystem** reusing the `sentinel-core` crate (continuous integrity monitoring as a first-class kernel citizen).
- Stable Rust + a CI verification gate (Miri + Kani + fuzz) over the TCB.

The OS UI design language is **"Cyber Dusk"** — Y2K Aero glass in a dark, privacy-forward palette (see `docs/specs/2026-06-03-ui-design-language.md`). The matte "security-ops" aesthetic is the **dev-tooling** theme (the agent dashboard), not the OS itself.

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

## Hardware & compatibility (Path A reality — reaffirmed 2026-06-03)
SentinelOS aims to run broadly, but pure-from-scratch demands an honest, staged scope:
- **CPU — Intel + AMD:** ✅ covered now. Both are x86_64 (our target); SentinelOS boots on any Intel/AMD PC.
- **GPU 2D — NVIDIA + AMD + Intel:** ✅ via the firmware linear framebuffer (UEFI GOP / Limine) — no vendor driver. The Cyber Dusk UI renders on all three brands.
- **GPU *acceleration* (3D / compute / video) — NVIDIA + AMD + Intel:** ⏳ long-horizon. AMD (open `amdgpu`) and Intel are tractable but multi-year; **NVIDIA is proprietary/closed (Nouveau-class) — possibly never** without their cooperation.
- **Apple Silicon (aarch64) Macs:** ⏳ far off — Asahi-class reverse-engineering of a proprietary boot chain; a future aarch64 HAL target.
- **Linux / macOS apps:** ⏳ a future compatibility layer (deferred; this is what Path C would have made native — not chosen).

The user reaffirmed Path A knowing this: we get **Intel/AMD CPU + 2D Cyber Dusk UI on all GPU brands now**; GPU acceleration, Apple Silicon, and app compatibility are accepted as long-horizon.
