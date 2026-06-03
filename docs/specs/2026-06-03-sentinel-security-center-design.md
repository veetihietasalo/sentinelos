# Sentinel Security Center — Design Spec

- **Date:** 2026-06-03
- **Status:** Draft for review
- **Component of:** SentinelOS
- **Working name:** Sentinel (Security Center)

## 1. Summary

Sentinel is a cross-platform desktop **security dashboard** that continuously monitors a machine across 20 forensic vectors and surfaces findings in a matte, Linux-styled "Security Center" UI. It is the first concrete component of SentinelOS (a planned from-scratch Rust OS) and is architected so its core security logic ports into that OS later.

## 2. Goals

- Continuously (live) monitor 20 security vectors and flag changes as they happen.
- Cross-platform: **macOS + Linux** now; portable to the future Rust OS.
- Calm, honest UX: severity-tiered findings; "clean" is a first-class result; no invented threats.
- **Read-only by default** — Sentinel observes and flags; it does not remediate in v1.
- A shared Rust core (`sentinel-core`) reusable inside the OS's security subsystem.

## 3. Non-goals (v1)

- Remediation / auto-fix / killing processes (view + flag only).
- The OS itself — a separate, decomposed effort.
- Windows (Tauri supports it, but not a target now).
- EDR-grade detection of advanced/nation-state implants. Sentinel checks where real-world surveillance and persistence *usually* live; it is explicit about this limitation and does not imply it can defeat memory-only, zero-day-class implants.

## 4. Users & context

Single user: the machine owner. Same tool on their Mac today, their Linux machine, and eventually SentinelOS.

## 5. Architecture

Three layers (see README diagram):

1. **UI layer** — web (HTML/CSS/JS), the matte Security Center. Portable.
2. **`sentinel-core`** — Rust crate: vector model, findings schema, scan orchestrator, live-monitor loop, snapshot/diff/alert logic. OS-agnostic. Shared with the OS.
3. **Providers** — implement `trait SecurityProvider`; one per OS (`macos`, `linux`, later `sentinelos`).

The Tauri layer bridges UI ⇄ core (commands + events). On the bare-metal OS, the same `sentinel-core` is driven by a native provider and rendered by a Rust-native GUI — no webview.

## 6. Data model (`sentinel-core`)

```
Vector       { id, group, title, platforms }
Severity     = Clear | Info | Review | Threat
VectorStatus = Clear | Review | Threat | Unavailable      // Unavailable = check blocked/errored
Finding      { id, vector_id, severity, title, detail, evidence?, first_seen, last_seen, status }
Snapshot     { taken_at, statuses: Map<VectorId, VectorStatus>, findings: [Finding] }
Event        = FindingNew | FindingCleared | StatusChanged | ScanStarted | ScanCompleted | CheckError
```

Findings are content-addressed by a stable key (vector + identity of the thing) so the same finding across ticks is recognized, not duplicated. `first_seen`/`last_seen` track persistence.

## 7. The 20 vectors

| Group | Vector | macOS source (example) | Linux source (example) |
|---|---|---|---|
| Integrity | Kernel extensions | `kmutil showloaded` | `lsmod` / `/proc/modules` |
| Integrity | System extensions | `systemextensionsctl list` | — |
| Integrity | SIP / secure boot | `csrutil status` | Secure Boot / IMA |
| Integrity | Profiles / MDM | `profiles status` | (n/a) / management agents |
| Persistence | Launch agents/daemons | LaunchAgents/Daemons plists | systemd units / xdg autostart |
| Persistence | Login items / BTM | `sfltool dumpbtm` | desktop autostart |
| Persistence | Scheduled jobs | cron / periodic | cron / systemd timers |
| Persistence | Automation & mail hooks | login hooks, mail rules | — / mail rules |
| Network | Listening ports | `lsof -iTCP -sTCP:LISTEN` | `ss -tlnp` |
| Network | Outbound / beacons | `lsof -iTCP -sTCP:ESTABLISHED` | `ss -tnp` |
| Privacy | Permission grants | TCC databases | polkit / portal grants |
| Privacy | Mic / camera usage | unified log | PipeWire / kernel logs |
| Privacy | Audio capture taps | HAL plugins | PipeWire/PulseAudio modules |
| Access | SSH / remote access | sshd, authorized_keys | sshd, authorized_keys |
| Access | Accounts / sudoers | `dscl` / sudoers | `/etc/passwd` / sudoers |
| Software | Browser extensions | profile dirs | profile dirs |
| Software | Unsigned apps | `codesign` / `spctl` | (signing where present) |
| Software | Downloads / quarantine | LaunchServices quarantine | — |
| Software | Recently modified binaries | mtime in bin dirs | mtime in bin dirs |
| Software | Persistent helper daemons | app-support / `launchctl list` | systemd user services |

(Sources are illustrative; exact commands live in each provider.)

## 8. Live monitor & data flow

```
interval tick ─▶ core runs provider checks (per-check timeout)
  ─▶ Snapshot ─▶ diff vs previous Snapshot
  ─▶ Events (new / cleared / status-changed)
  ─▶ Tauri emits ─▶ UI updates + tray dot recolors
"Run sweep" = same pipeline, on demand.
```

- Default interval: configurable (proposed 5 min); a few critical vectors may poll faster.
- Debounce/coalesce rapid changes; back off on repeated provider errors.
- The monitor loop never crashes on a single check failure (see §9).

## 9. Error handling

- A failing/blocked check sets that vector to **Unavailable** with a reason (e.g., "needs Full Disk Access") — **never silently reported as Clear.** Honesty over false reassurance.
- Per-check timeouts; partial snapshots are valid.
- Permission requirements surfaced in-UI with a guided fix (e.g., grant FDA).

## 10. Permissions & privacy

- Read-only. No data leaves the machine. No telemetry. Findings/history stored locally only.
- macOS: reading the TCC database needs Full Disk Access — detected and prompted, not assumed.
- Secrets are never read into findings or logs.

## 11. Testing

- `sentinel-core`: unit tests for model, diff, severity, finding identity.
- Providers: golden-file tests against captured command outputs (no live system needed in CI).
- Monitor loop: integration test driving a fake provider through new/cleared/changed transitions.
- UI: snapshot tests of the matte components.

## 12. Aesthetic / design language

Matte, Linux-styled. Flat panels, desaturated palette (sage `#8aa978` clear, amber `#c2a25e` review, muted red `#bf6b6b` threat, steel `#6d93a8` info), mono+sans typography, waybar-style top strip, grouped 20-vector sidebar, findings feed, summary strip, tray/menubar status dot. Tokens shared with the future OS GUI.

## 13. Portability to SentinelOS

`sentinel-core` is reused verbatim. Porting = (1) write a native `SecurityProvider` against the OS's syscalls, (2) render the UI with a Rust-native GUI using the shared design tokens. Security logic and look are unchanged.

## 14. MVP — tracer-bullet slice

Full pipeline end-to-end on macOS for **4 vectors**: permission grants (TCC), outbound network, launch persistence, kernel extensions — with live monitoring and the tray dot working. Proves the Tauri + Rust + permissions plumbing before fanning out the other 16.

**Acceptance:** app launches; runs a live sweep of the 4 vectors; shows real statuses + findings; tray recolors on a simulated change; a blocked check shows Unavailable (not Clear).

## 15. Open questions

- Monitor interval default + which vectors poll faster?
- Persist a local history/audit log? Format and retention?
- First Linux target distro(s) for the Linux provider?
- Primary surface: full window vs tray-first?
- License choice for the repo.
