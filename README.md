# SentinelOS

A security-first operating system project — **starting with its Security Center**.

SentinelOS is a long-horizon vision for a from-scratch, Rust-based operating system. The first concrete artifact is **Sentinel**, a cross-platform desktop **Security Center** that continuously monitors a machine's integrity across **20 forensic vectors** and surfaces threats and anomalies in a calm, matte, Linux-styled dashboard.

Sentinel is built so its security logic ports *into* the future OS: the core is one Rust crate shared by the desktop app today and the OS's security subsystem later.

> Status: **early — design phase.** This repo currently holds the design; code lands next.

## Why

A security tool should be trustworthy, legible, and honest — "clean" is a valid result, not a reason to invent threats. Sentinel monitors the places real surveillance and persistence actually live, tiers findings by severity, and never takes destructive action on its own (read-only by default).

## Architecture (three layers)

```
① UI layer        web (HTML/CSS/JS) — matte "Security Center"     [portable]
② sentinel-core   Rust crate: 20-vector model, findings schema,   [portable, shared with the OS]
                  scan orchestrator, live-monitor loop, diff/alerts
③ providers       the actual checks, behind one SecurityProvider trait
                  macOS ✓   Linux ✓   sentinelos ⟳ (later, native syscalls)
```

Only the **provider** layer is rewritten per operating system. The core logic and the design language carry over unchanged. On macOS/Linux the UI renders via **Tauri**; on the bare-metal Rust OS it renders via a Rust-native GUI (iced/egui/Slint) — no webview required.

## The 20 vectors

- **System integrity** — kernel extensions · system extensions · SIP/secure-boot · profiles/MDM
- **Persistence** — launch agents/daemons (or systemd units) · login items/BTM · cron/timers · automation & mail hooks
- **Network** — listening ports · outbound connections / beacons
- **Privacy** — permission grants (TCC) · mic/camera usage · audio capture taps
- **Access & software** — SSH / remote access · accounts & sudoers · browser extensions · unsigned apps · downloads/quarantine · recently modified binaries

## Roadmap

1. **MVP — tracer-bullet slice:** full pipeline (UI → core → macOS provider → live monitor → tray) for 4 vectors: permission grants, outbound network, launch persistence, kernel extensions.
2. Fill in the remaining 16 vectors (each ≈ one provider function).
3. Linux provider.
4. `sentinelos` native provider + GUI renderer once the OS has a userland.

## Stack

Tauri 2 · Rust (stable) · minimal web UI (dependency-light by design — it's a security tool).

## License

TBD.
