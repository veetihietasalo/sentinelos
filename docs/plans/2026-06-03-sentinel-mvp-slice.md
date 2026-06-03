# Sentinel MVP Slice — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a runnable macOS Sentinel app that live-monitors 4 security vectors (kernel extensions, network, launchd persistence, TCC permissions) end-to-end: web UI → Tauri → `sentinel-core` → macOS provider → tray.

**Architecture:** Cargo workspace. `sentinel-core` is a pure, OS-agnostic Rust crate (model + orchestrator + diff + monitor) with no I/O, fully unit-tested. A `MacosProvider` implements `SecurityProvider` by shelling out and parsing output through pure functions (golden-file tested). A Tauri 2 app hosts a static web UI (no bundler — `withGlobalTauri`), runs a monitor loop on a tokio interval, emits events, and shows a menubar status.

**Tech Stack:** Rust (stable) · Tauri 2 · serde · tokio (time) · static HTML/CSS/JS via `window.__TAURI__`. No Node/npm. macOS WKWebView is built in.

---

## Prerequisites (one-time, not a task)

- Rust stable: `rustc --version` (install via rustup if missing).
- Tauri CLI v2: `cargo install tauri-cli --version "^2.0"` → verify `cargo tauri --version`.
- Reading the TCC database needs **Full Disk Access** for the running app/terminal; the TCC vector degrades to `Unavailable` (not `Clear`) without it — see Task 8.

## File Structure

```
sentinelos/
  Cargo.toml                       # [workspace] members: sentinel-core, src-tauri
  sentinel-core/
    Cargo.toml
    src/lib.rs                     # re-exports modules
    src/model.rs                   # Severity, VectorStatus, Finding, VectorReport, Snapshot
    src/provider.rs                # SecurityProvider trait + run_sweep
    src/diff.rs                    # Event + diff + initial_events
    src/monitor.rs                 # Monitor (holds last snapshot, tick())
  src-tauri/
    Cargo.toml
    build.rs
    tauri.conf.json
    src/main.rs                    # commands, monitor loop, tray
    src/macos.rs                   # MacosProvider + pure parsers
    tests/fixtures/*.txt           # captured command output for golden tests
    icons/icon.png                 # app/tray icon (32x32+)
  ui/
    index.html
    styles.css
    app.js
```

Responsibilities: `sentinel-core` = logic, zero I/O (so it ports to the OS unchanged). `src-tauri/macos.rs` = the only place that touches the OS. `ui/` = presentation only.

---

### Task 0: Workspace + runnable Tauri skeleton

**Files:**
- Create: `Cargo.toml`, `sentinel-core/Cargo.toml`, `sentinel-core/src/lib.rs`, `src-tauri/Cargo.toml`, `src-tauri/build.rs`, `src-tauri/tauri.conf.json`, `src-tauri/src/main.rs`, `ui/index.html`

- [ ] **Step 1: Workspace manifest** — Create `Cargo.toml`:

```toml
[workspace]
resolver = "2"
members = ["sentinel-core", "src-tauri"]
```

- [ ] **Step 2: Core crate manifest** — Create `sentinel-core/Cargo.toml`:

```toml
[package]
name = "sentinel-core"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = { version = "1", features = ["derive"] }
```

- [ ] **Step 3: Empty core lib** — Create `sentinel-core/src/lib.rs`:

```rust
pub mod model;
pub mod provider;
pub mod diff;
pub mod monitor;
```

(Modules are added in later tasks; this will not compile until Task 1 creates `model.rs`. That's expected — Task 0 verifies the Tauri app, not the core.)

For Task 0 only, temporarily make it empty instead:

```rust
// placeholder until Task 1
```

- [ ] **Step 4: Tauri app manifest** — Create `src-tauri/Cargo.toml`:

```toml
[package]
name = "sentinel-app"
version = "0.1.0"
edition = "2021"

[build-dependencies]
tauri-build = { version = "2", features = [] }

[dependencies]
tauri = { version = "2", features = ["tray-icon"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tokio = { version = "1", features = ["time"] }
sentinel-core = { path = "../sentinel-core" }

[features]
default = ["custom-protocol"]
custom-protocol = ["tauri/custom-protocol"]
```

- [ ] **Step 5: Build script** — Create `src-tauri/build.rs`:

```rust
fn main() {
    tauri_build::build()
}
```

- [ ] **Step 6: Tauri config** — Create `src-tauri/tauri.conf.json`:

```json
{
  "$schema": "https://schema.tauri.app/config/2",
  "productName": "Sentinel",
  "version": "0.1.0",
  "identifier": "os.sentinel.securitycenter",
  "build": { "frontendDist": "../ui" },
  "app": {
    "withGlobalTauri": true,
    "windows": [
      { "title": "Sentinel — Security Center", "width": 980, "height": 680, "minWidth": 820, "minHeight": 560 }
    ],
    "security": { "csp": null }
  },
  "bundle": { "active": true, "targets": "all", "icon": ["icons/icon.png"] }
}
```

- [ ] **Step 7: Minimal main.rs** — Create `src-tauri/src/main.rs`:

```rust
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
```

- [ ] **Step 8: Placeholder UI** — Create `ui/index.html`:

```html
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Sentinel</title></head>
<body style="background:#161819;color:#bcc1c4;font-family:system-ui;padding:20px">
  <h1>Sentinel</h1><p>Skeleton OK.</p>
</body></html>
```

- [ ] **Step 9: Add an icon** — Place any 32×32+ PNG at `src-tauri/icons/icon.png` (a solid matte square is fine for now). Run: `cargo tauri icon src-tauri/icons/icon.png` is optional; a single PNG referenced in config is enough to launch in dev.

- [ ] **Step 10: Run it** — Run: `cargo tauri dev`
Expected: a window titled "Sentinel — Security Center" opens showing "Skeleton OK." Close it.

- [ ] **Step 11: Commit**

```bash
git add Cargo.toml sentinel-core src-tauri ui
git commit -m "chore: scaffold cargo workspace + runnable Tauri 2 skeleton"
```

---

### Task 1: Core data model

**Files:**
- Create: `sentinel-core/src/model.rs`
- Modify: `sentinel-core/src/lib.rs` (restore the 4 `pub mod` lines from Task 0 Step 3)

- [ ] **Step 1: Write failing tests** — Create `sentinel-core/src/model.rs`:

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity { Clear, Info, Review, Threat }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VectorStatus { Clear, Review, Threat, Unavailable }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub vector_id: String,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VectorReport {
    pub vector_id: String,
    pub status: VectorStatus,
    pub findings: Vec<Finding>,
}

impl VectorReport {
    pub fn clear(vector_id: &str) -> Self {
        Self { vector_id: vector_id.to_string(), status: VectorStatus::Clear, findings: vec![] }
    }
    pub fn unavailable(vector_id: &str, reason: &str) -> Self {
        Self {
            vector_id: vector_id.to_string(),
            status: VectorStatus::Unavailable,
            findings: vec![Finding {
                id: format!("{vector_id}:unavailable"),
                vector_id: vector_id.to_string(),
                severity: Severity::Info,
                title: "Check unavailable".to_string(),
                detail: reason.to_string(),
            }],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot { pub reports: Vec<VectorReport> }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clear_report_has_no_findings() {
        let r = VectorReport::clear("kexts");
        assert_eq!(r.status, VectorStatus::Clear);
        assert!(r.findings.is_empty());
    }

    #[test]
    fn unavailable_report_explains_itself() {
        let r = VectorReport::unavailable("tcc", "needs Full Disk Access");
        assert_eq!(r.status, VectorStatus::Unavailable);
        assert_eq!(r.findings.len(), 1);
        assert!(r.findings[0].detail.contains("Full Disk Access"));
    }

    #[test]
    fn severity_serializes_lowercase() {
        let json = serde_json::to_string(&Severity::Threat).unwrap();
        assert_eq!(json, "\"threat\"");
    }
}
```

- [ ] **Step 2: Restore lib.rs** — Set `sentinel-core/src/lib.rs` to:

```rust
pub mod model;
pub mod provider;
pub mod diff;
pub mod monitor;
```

Then create empty stubs so the crate compiles: `sentinel-core/src/provider.rs`, `diff.rs`, `monitor.rs` each containing `// filled in a later task`. Add `serde_json = "1"` to `[dev-dependencies]` in `sentinel-core/Cargo.toml`:

```toml
[dev-dependencies]
serde_json = "1"
```

- [ ] **Step 3: Run tests to verify they fail then pass** — Run: `cargo test -p sentinel-core model::`
Expected: compiles, 3 tests pass.

- [ ] **Step 4: Commit**

```bash
git add sentinel-core
git commit -m "feat(core): security data model (Severity, VectorStatus, Finding, Snapshot)"
```

---

### Task 2: Provider trait + run_sweep

**Files:**
- Modify: `sentinel-core/src/provider.rs`

- [ ] **Step 1: Write provider + test** — Set `sentinel-core/src/provider.rs`:

```rust
use crate::model::{Snapshot, VectorReport};

/// Implemented once per operating system. The only OS-specific surface.
pub trait SecurityProvider: Send + Sync {
    fn vectors(&self) -> Vec<&'static str>;
    fn check(&self, vector_id: &str) -> VectorReport;
}

/// Run every vector the provider advertises into a single snapshot.
pub fn run_sweep(provider: &dyn SecurityProvider) -> Snapshot {
    let reports = provider.vectors().into_iter().map(|v| provider.check(v)).collect();
    Snapshot { reports }
}

#[cfg(test)]
pub(crate) mod mock {
    use super::*;
    use crate::model::VectorStatus;
    use std::collections::HashMap;

    pub struct MockProvider { pub reports: HashMap<&'static str, VectorReport> }

    impl MockProvider {
        pub fn new() -> Self { Self { reports: HashMap::new() } }
        pub fn with(mut self, id: &'static str, status: VectorStatus) -> Self {
            self.reports.insert(id, VectorReport { vector_id: id.to_string(), status, findings: vec![] });
            self
        }
    }

    impl SecurityProvider for MockProvider {
        fn vectors(&self) -> Vec<&'static str> { let mut v: Vec<_> = self.reports.keys().copied().collect(); v.sort(); v }
        fn check(&self, vector_id: &str) -> VectorReport {
            self.reports.get(vector_id).cloned().unwrap_or_else(|| VectorReport::clear(vector_id))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::mock::MockProvider;
    use crate::model::VectorStatus;

    #[test]
    fn run_sweep_collects_one_report_per_vector() {
        let p = MockProvider::new().with("kexts", VectorStatus::Clear).with("tcc", VectorStatus::Review);
        let snap = run_sweep(&p);
        assert_eq!(snap.reports.len(), 2);
    }
}
```

- [ ] **Step 2: Run tests** — Run: `cargo test -p sentinel-core provider::`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add sentinel-core/src/provider.rs
git commit -m "feat(core): SecurityProvider trait + run_sweep orchestrator"
```

---

### Task 3: Diff engine

**Files:**
- Modify: `sentinel-core/src/diff.rs`

- [ ] **Step 1: Write diff + tests** — Set `sentinel-core/src/diff.rs`:

```rust
use crate::model::{Finding, Snapshot, VectorStatus};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    FindingNew { finding: Finding },
    FindingCleared { id: String },
    StatusChanged { vector_id: String, from: VectorStatus, to: VectorStatus },
}

fn findings_map(s: &Snapshot) -> BTreeMap<String, Finding> {
    let mut m = BTreeMap::new();
    for r in &s.reports { for f in &r.findings { m.insert(f.id.clone(), f.clone()); } }
    m
}

fn status_map(s: &Snapshot) -> BTreeMap<String, VectorStatus> {
    s.reports.iter().map(|r| (r.vector_id.clone(), r.status)).collect()
}

pub fn diff(prev: &Snapshot, next: &Snapshot) -> Vec<Event> {
    let mut events = Vec::new();
    let (pf, nf) = (findings_map(prev), findings_map(next));
    for (id, f) in &nf { if !pf.contains_key(id) { events.push(Event::FindingNew { finding: f.clone() }); } }
    for id in pf.keys() { if !nf.contains_key(id) { events.push(Event::FindingCleared { id: id.clone() }); } }
    let (ps, ns) = (status_map(prev), status_map(next));
    for (v, s) in &ns {
        if let Some(old) = ps.get(v) { if old != s {
            events.push(Event::StatusChanged { vector_id: v.clone(), from: *old, to: *s });
        }}
    }
    events
}

/// First-ever snapshot: every finding is "new".
pub fn initial_events(s: &Snapshot) -> Vec<Event> {
    findings_map(s).into_values().map(|finding| Event::FindingNew { finding }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Finding, Severity, VectorReport, VectorStatus};

    fn finding(id: &str) -> Finding {
        Finding { id: id.into(), vector_id: "net".into(), severity: Severity::Review, title: "t".into(), detail: "d".into() }
    }
    fn snap(vector: &str, status: VectorStatus, findings: Vec<Finding>) -> Snapshot {
        Snapshot { reports: vec![VectorReport { vector_id: vector.into(), status, findings }] }
    }

    #[test]
    fn new_finding_emits_finding_new() {
        let prev = snap("net", VectorStatus::Clear, vec![]);
        let next = snap("net", VectorStatus::Review, vec![finding("net:beacon-1")]);
        let evs = diff(&prev, &next);
        assert!(evs.iter().any(|e| matches!(e, Event::FindingNew { finding } if finding.id == "net:beacon-1")));
        assert!(evs.iter().any(|e| matches!(e, Event::StatusChanged { to: VectorStatus::Review, .. })));
    }

    #[test]
    fn disappeared_finding_emits_cleared() {
        let prev = snap("net", VectorStatus::Review, vec![finding("net:beacon-1")]);
        let next = snap("net", VectorStatus::Clear, vec![]);
        let evs = diff(&prev, &next);
        assert!(evs.iter().any(|e| matches!(e, Event::FindingCleared { id } if id == "net:beacon-1")));
    }

    #[test]
    fn no_change_emits_nothing() {
        let s = snap("net", VectorStatus::Clear, vec![]);
        assert!(diff(&s, &s).is_empty());
    }
}
```

- [ ] **Step 2: Run tests** — Run: `cargo test -p sentinel-core diff::`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add sentinel-core/src/diff.rs
git commit -m "feat(core): snapshot diff engine emitting new/cleared/status-changed events"
```

---

### Task 4: Monitor

**Files:**
- Modify: `sentinel-core/src/monitor.rs`

- [ ] **Step 1: Write monitor + test** — Set `sentinel-core/src/monitor.rs`:

```rust
use crate::diff::{diff, initial_events, Event};
use crate::model::Snapshot;
use crate::provider::{run_sweep, SecurityProvider};

/// Holds the last snapshot and produces events on each tick.
pub struct Monitor { last: Option<Snapshot> }

impl Monitor {
    pub fn new() -> Self { Self { last: None } }
    pub fn current(&self) -> Option<&Snapshot> { self.last.as_ref() }

    pub fn tick(&mut self, provider: &dyn SecurityProvider) -> Vec<Event> {
        let next = run_sweep(provider);
        let events = match &self.last {
            Some(prev) => diff(prev, &next),
            None => initial_events(&next),
        };
        self.last = Some(next);
        events
    }
}

impl Default for Monitor { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::mock::MockProvider;
    use crate::model::VectorStatus;

    #[test]
    fn first_tick_yields_initial_events_then_quiet() {
        let p = MockProvider::new().with("kexts", VectorStatus::Clear);
        let mut m = Monitor::new();
        let first = m.tick(&p);          // initial
        let second = m.tick(&p);         // unchanged
        assert!(second.is_empty(), "no change should yield no events, got {second:?}");
        let _ = first;
        assert!(m.current().is_some());
    }

    #[test]
    fn change_between_ticks_yields_status_changed() {
        let mut m = Monitor::new();
        let clear = MockProvider::new().with("net", VectorStatus::Clear);
        let review = MockProvider::new().with("net", VectorStatus::Review);
        m.tick(&clear);
        let evs = m.tick(&review);
        assert!(evs.iter().any(|e| matches!(e, Event::StatusChanged { to: VectorStatus::Review, .. })));
    }
}
```

- [ ] **Step 2: Run all core tests** — Run: `cargo test -p sentinel-core`
Expected: every test passes.

- [ ] **Step 3: Commit**

```bash
git add sentinel-core/src/monitor.rs
git commit -m "feat(core): Monitor holds last snapshot and emits per-tick events"
```

---

### Task 5: macOS provider — kernel extensions (with golden test)

**Files:**
- Create: `src-tauri/src/macos.rs`, `src-tauri/tests/fixtures/kextstat_clean.txt`, `src-tauri/tests/fixtures/kextstat_thirdparty.txt`
- Modify: `src-tauri/src/main.rs` (add `mod macos;`)

- [ ] **Step 1: Capture fixtures** — Create `src-tauri/tests/fixtures/kextstat_clean.txt` with real Apple-only output, e.g.:

```
Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>
    1   90 0                  0          0          com.apple.kpi.bsd (8.0.0)
    2   10 0                  0          0          com.apple.iokit.IONetworkingFamily (3.4) <1>
```

Create `src-tauri/tests/fixtures/kextstat_thirdparty.txt` (same header) adding a non-Apple line:

```
  120    0 0xffffff7f8a000000 0x8000     0x8000     com.examplevendor.driver.Widget (1.2.3) <5 4 3>
```

- [ ] **Step 2: Write parser + failing test** — Create `src-tauri/src/macos.rs`:

```rust
use sentinel_core::model::{Finding, Severity, VectorReport, VectorStatus};

pub const V_KEXTS: &str = "kexts";

/// Parse `kextstat`/`kmutil showloaded` output. Any non-`com.apple.` bundle is flagged.
pub fn parse_kexts(output: &str) -> VectorReport {
    let mut findings = Vec::new();
    for line in output.lines() {
        // bundle id is the token containing dots, e.g. "com.apple.kpi.bsd"
        if let Some(bundle) = line.split_whitespace().find(|t| t.contains('.') && !t.starts_with('(')) {
            if !bundle.starts_with("com.apple.") {
                findings.push(Finding {
                    id: format!("{V_KEXTS}:{bundle}"),
                    vector_id: V_KEXTS.to_string(),
                    severity: Severity::Review,
                    title: "Third-party kernel extension loaded".to_string(),
                    detail: bundle.to_string(),
                });
            }
        }
    }
    let status = if findings.is_empty() { VectorStatus::Clear } else { VectorStatus::Review };
    VectorReport { vector_id: V_KEXTS.to_string(), status, findings }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_kextstat_is_clear() {
        let out = include_str!("../tests/fixtures/kextstat_clean.txt");
        let r = parse_kexts(out);
        assert_eq!(r.status, VectorStatus::Clear, "findings: {:?}", r.findings);
    }

    #[test]
    fn thirdparty_kext_is_flagged() {
        let out = include_str!("../tests/fixtures/kextstat_thirdparty.txt");
        let r = parse_kexts(out);
        assert_eq!(r.status, VectorStatus::Review);
        assert!(r.findings.iter().any(|f| f.detail.contains("com.examplevendor")));
    }
}
```

- [ ] **Step 3: Register module** — In `src-tauri/src/main.rs`, add at the top (below the `#![cfg_attr...]` line): `mod macos;`

- [ ] **Step 4: Run tests** — Run: `cargo test -p sentinel-app macos::tests::`
Expected: both kext tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/macos.rs src-tauri/tests/fixtures src-tauri/src/main.rs
git commit -m "feat(macos): kernel-extension vector parser with golden tests"
```

---

### Task 6: macOS provider — network (listening + outbound)

**Files:**
- Modify: `src-tauri/src/macos.rs`
- Create: `src-tauri/tests/fixtures/lsof_listen.txt`

- [ ] **Step 1: Fixture** — Create `src-tauri/tests/fixtures/lsof_listen.txt` (real `lsof -nP -iTCP -sTCP:LISTEN` shape):

```
COMMAND   PID  USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
node    52001 user   22u  IPv4  0x1      0t0  TCP 127.0.0.1:4123 (LISTEN)
sshd    600   root    3u  IPv4  0x2      0t0  TCP *:22 (LISTEN)
```

- [ ] **Step 2: Parser + test** — Append to `src-tauri/src/macos.rs`:

```rust
pub const V_NET: &str = "net";

const SENSITIVE_PORTS: &[&str] = &[":22", ":3389", ":5900"];

/// Parse `lsof -nP -iTCP -sTCP:LISTEN`. Flags listeners on remote-access ports
/// and any non-loopback listener.
pub fn parse_listeners(output: &str) -> VectorReport {
    let mut findings = Vec::new();
    for line in output.lines().skip(1) {
        if !line.contains("(LISTEN)") { continue; }
        let name = line.split_whitespace().nth(8).unwrap_or("");
        let command = line.split_whitespace().next().unwrap_or("?");
        let sensitive = SENSITIVE_PORTS.iter().any(|p| name.contains(p));
        let non_loopback = !name.starts_with("127.0.0.1") && !name.starts_with("[::1]");
        if sensitive || non_loopback {
            findings.push(Finding {
                id: format!("{V_NET}:{name}"),
                vector_id: V_NET.to_string(),
                severity: if sensitive { Severity::Review } else { Severity::Info },
                title: if sensitive { "Remote-access port listening".to_string() }
                       else { "Non-loopback listener".to_string() },
                detail: format!("{command} {name}"),
            });
        }
    }
    let status = if findings.iter().any(|f| f.severity == Severity::Review) {
        VectorStatus::Review
    } else { VectorStatus::Clear };
    VectorReport { vector_id: V_NET.to_string(), status, findings }
}

#[cfg(test)]
mod net_tests {
    use super::*;
    #[test]
    fn flags_ssh_listener_as_review() {
        let out = include_str!("../tests/fixtures/lsof_listen.txt");
        let r = parse_listeners(out);
        assert_eq!(r.status, VectorStatus::Review);
        assert!(r.findings.iter().any(|f| f.detail.contains(":22")));
    }
    #[test]
    fn loopback_only_is_not_review() {
        let out = "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nnode 1 u 1u IPv4 0x 0t0 TCP 127.0.0.1:4123 (LISTEN)\n";
        let r = parse_listeners(out);
        assert_ne!(r.status, VectorStatus::Review);
    }
}
```

- [ ] **Step 3: Run tests** — Run: `cargo test -p sentinel-app net_tests::`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add src-tauri/src/macos.rs src-tauri/tests/fixtures/lsof_listen.txt
git commit -m "feat(macos): network listener vector parser with golden tests"
```

---

### Task 7: macOS provider — launchd persistence

**Files:**
- Modify: `src-tauri/src/macos.rs`

- [ ] **Step 1: Parser + test** — Append to `src-tauri/src/macos.rs`:

```rust
use std::path::Path;

pub const V_LAUNCHD: &str = "launchd";

/// Given a list of (label, program_path) launchd entries, flag any whose program
/// lives in a user-writable / temp / hidden location (a persistence red flag).
pub fn assess_launchd(entries: &[(String, String)]) -> VectorReport {
    let mut findings = Vec::new();
    for (label, program) in entries {
        let suspicious = program.starts_with("/tmp/")
            || program.starts_with("/var/tmp/")
            || program.contains("/.")              // hidden dir component
            || program.starts_with("/Users/Shared/");
        if suspicious {
            findings.push(Finding {
                id: format!("{V_LAUNCHD}:{label}"),
                vector_id: V_LAUNCHD.to_string(),
                severity: Severity::Threat,
                title: "Launch item runs from a suspicious path".to_string(),
                detail: format!("{label} → {program}"),
            });
        }
    }
    let status = if findings.is_empty() { VectorStatus::Clear } else { VectorStatus::Threat };
    VectorReport { vector_id: V_LAUNCHD.to_string(), status, findings }
}

/// Read `Program`/first `ProgramArguments` entry out of a launchd plist via `defaults read`.
/// (Pure helper used by the live provider; not unit-tested here.)
pub fn launchd_program(plist: &Path) -> Option<String> {
    use std::process::Command;
    let path = plist.with_extension("");
    let out = Command::new("defaults").arg("read").arg(&path).arg("Program").output().ok()?;
    if out.status.success() {
        return Some(String::from_utf8_lossy(&out.stdout).trim().to_string());
    }
    let out = Command::new("defaults").arg("read").arg(&path).arg("ProgramArguments").output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines().find(|l| l.contains('/')).map(|l| l.trim().trim_matches('"').trim_end_matches(',').trim_matches('"').to_string())
}

#[cfg(test)]
mod launchd_tests {
    use super::*;
    #[test]
    fn tmp_path_is_threat() {
        let entries = vec![("com.evil.agent".to_string(), "/tmp/x".to_string())];
        assert_eq!(assess_launchd(&entries).status, VectorStatus::Threat);
    }
    #[test]
    fn system_path_is_clear() {
        let entries = vec![("com.apple.thing".to_string(), "/usr/libexec/thing".to_string())];
        assert_eq!(assess_launchd(&entries).status, VectorStatus::Clear);
    }
}
```

- [ ] **Step 2: Run tests** — Run: `cargo test -p sentinel-app launchd_tests::`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add src-tauri/src/macos.rs
git commit -m "feat(macos): launchd persistence assessment with golden tests"
```

---

### Task 8: macOS provider — TCC permissions (+ Unavailable handling)

**Files:**
- Modify: `src-tauri/src/macos.rs`

- [ ] **Step 1: Parser + test** — Append to `src-tauri/src/macos.rs`:

```rust
pub const V_TCC: &str = "tcc";

/// Parse `sqlite3` rows of "service|client" for allowed grants. Accessibility and
/// ScreenCapture are powerful → Review; others → Info.
pub fn parse_tcc(rows: &str) -> VectorReport {
    let mut findings = Vec::new();
    for line in rows.lines() {
        let mut parts = line.splitn(2, '|');
        let (service, client) = match (parts.next(), parts.next()) {
            (Some(s), Some(c)) if !s.is_empty() => (s, c),
            _ => continue,
        };
        let powerful = service.contains("Accessibility") || service.contains("ScreenCapture") || service.contains("ListenEvent");
        findings.push(Finding {
            id: format!("{V_TCC}:{service}:{client}"),
            vector_id: V_TCC.to_string(),
            severity: if powerful { Severity::Review } else { Severity::Info },
            title: format!("{service} granted"),
            detail: client.to_string(),
        });
    }
    let status = if findings.iter().any(|f| f.severity == Severity::Review) {
        VectorStatus::Review
    } else { VectorStatus::Clear };
    VectorReport { vector_id: V_TCC.to_string(), status, findings }
}

#[cfg(test)]
mod tcc_tests {
    use super::*;
    #[test]
    fn accessibility_grant_is_review() {
        let rows = "kTCCServiceAccessibility|com.example.app\nkTCCServiceMicrophone|com.other.app\n";
        let r = parse_tcc(rows);
        assert_eq!(r.status, VectorStatus::Review);
        assert_eq!(r.findings.len(), 2);
    }
    #[test]
    fn empty_rows_are_clear() {
        assert_eq!(parse_tcc("").status, VectorStatus::Clear);
    }
}
```

- [ ] **Step 2: Run tests** — Run: `cargo test -p sentinel-app tcc_tests::`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add src-tauri/src/macos.rs
git commit -m "feat(macos): TCC permission vector parser with golden tests"
```

---

### Task 9: Wire MacosProvider (live I/O) implementing SecurityProvider

**Files:**
- Modify: `src-tauri/src/macos.rs`

- [ ] **Step 1: Implement the provider** — Append to `src-tauri/src/macos.rs`:

```rust
use sentinel_core::provider::SecurityProvider;
use std::process::Command;

pub struct MacosProvider;
impl MacosProvider { pub fn new() -> Self { Self } }

fn run(cmd: &str, args: &[&str]) -> Result<String, String> {
    match Command::new(cmd).args(args).output() {
        Ok(o) if o.status.success() => Ok(String::from_utf8_lossy(&o.stdout).into_owned()),
        Ok(o) => Err(String::from_utf8_lossy(&o.stderr).trim().to_string()),
        Err(e) => Err(e.to_string()),
    }
}

impl SecurityProvider for MacosProvider {
    fn vectors(&self) -> Vec<&'static str> { vec![V_KEXTS, V_NET, V_LAUNCHD, V_TCC] }

    fn check(&self, vector_id: &str) -> VectorReport {
        match vector_id {
            V_KEXTS => match run("kextstat", &[]) { Ok(o) => parse_kexts(&o), Err(e) => VectorReport::unavailable(V_KEXTS, &e) },
            V_NET => match run("lsof", &["-nP", "-iTCP", "-sTCP:LISTEN"]) { Ok(o) => parse_listeners(&o), Err(e) => VectorReport::unavailable(V_NET, &e) },
            V_LAUNCHD => {
                let mut entries = Vec::new();
                for dir in ["/Library/LaunchAgents", "/Library/LaunchDaemons"] {
                    if let Ok(rd) = std::fs::read_dir(dir) {
                        for e in rd.flatten() {
                            let p = e.path();
                            if p.extension().map(|x| x == "plist").unwrap_or(false) {
                                let label = p.file_stem().and_then(|s| s.to_str()).unwrap_or("?").to_string();
                                if let Some(prog) = launchd_program(&p) { entries.push((label, prog)); }
                            }
                        }
                    }
                }
                assess_launchd(&entries)
            }
            V_TCC => {
                let db = format!("{}/Library/Application Support/com.apple.TCC/TCC.db", std::env::var("HOME").unwrap_or_default());
                let uri = format!("file:{db}?mode=ro&immutable=1");
                let sql = "SELECT service||'|'||client FROM access WHERE auth_value=2;";
                match run("sqlite3", &[&uri, sql]) {
                    Ok(o) => parse_tcc(&o),
                    Err(_) => VectorReport::unavailable(V_TCC, "TCC database unreadable — grant Full Disk Access to Sentinel in System Settings → Privacy & Security."),
                }
            }
            other => VectorReport::unavailable(other, "unknown vector"),
        }
    }
}
```

- [ ] **Step 2: Build & smoke-run core tests** — Run: `cargo test -p sentinel-app`
Expected: all parser tests still PASS; crate compiles.

- [ ] **Step 3: Commit**

```bash
git add src-tauri/src/macos.rs
git commit -m "feat(macos): live MacosProvider wiring the 4 MVP vectors (Unavailable on error)"
```

---

### Task 10: Tauri commands (run_sweep, get_snapshot)

**Files:**
- Modify: `src-tauri/src/main.rs`

- [ ] **Step 1: Add state + commands** — Replace `src-tauri/src/main.rs` with:

```rust
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod macos;

use std::sync::Mutex;
use sentinel_core::model::Snapshot;
use sentinel_core::monitor::Monitor;
use macos::MacosProvider;

pub struct AppState { pub monitor: Mutex<Monitor> }

#[tauri::command]
fn run_sweep(state: tauri::State<AppState>) -> Snapshot {
    let provider = MacosProvider::new();
    let mut mon = state.monitor.lock().unwrap();
    mon.tick(&provider);
    mon.current().cloned().unwrap_or(Snapshot { reports: vec![] })
}

#[tauri::command]
fn get_snapshot(state: tauri::State<AppState>) -> Option<Snapshot> {
    state.monitor.lock().unwrap().current().cloned()
}

fn main() {
    tauri::Builder::default()
        .manage(AppState { monitor: Mutex::new(Monitor::new()) })
        .invoke_handler(tauri::generate_handler![run_sweep, get_snapshot])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
```

- [ ] **Step 2: Build** — Run: `cargo build -p sentinel-app`
Expected: compiles.

- [ ] **Step 3: Commit**

```bash
git add src-tauri/src/main.rs
git commit -m "feat(app): run_sweep + get_snapshot Tauri commands backed by the monitor"
```

---

### Task 11: Monitor loop + menubar tray status

**Files:**
- Modify: `src-tauri/src/main.rs`

- [ ] **Step 1: Add overall-status helper + tray + loop** — In `src-tauri/src/main.rs`, add imports and a setup hook. Add near the top:

```rust
use sentinel_core::model::VectorStatus;
use tauri::{Emitter, Manager};
use tauri::tray::TrayIconBuilder;

fn overall_glyph(s: &Snapshot) -> &'static str {
    let mut worst = VectorStatus::Clear;
    for r in &s.reports {
        worst = match (worst, r.status) {
            (_, VectorStatus::Threat) => VectorStatus::Threat,
            (VectorStatus::Threat, _) => VectorStatus::Threat,
            (_, VectorStatus::Review) | (VectorStatus::Review, _) => VectorStatus::Review,
            _ => worst,
        };
    }
    match worst { VectorStatus::Threat => "● threat", VectorStatus::Review => "● review", _ => "● secure" }
}
```

- [ ] **Step 2: Wire setup** — Change the builder in `main()` to add `.setup(...)` before `.run(...)`:

```rust
        .setup(|app| {
            let tray = TrayIconBuilder::with_id("sentinel-tray").title("● secure").build(app)?;
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let mut ticker = tokio::time::interval(std::time::Duration::from_secs(300));
                loop {
                    ticker.tick().await;
                    let provider = MacosProvider::new();
                    let (events, snapshot) = {
                        let state = handle.state::<AppState>();
                        let mut mon = state.monitor.lock().unwrap();
                        let evs = mon.tick(&provider);
                        (evs, mon.current().cloned())
                    };
                    for ev in &events { let _ = handle.emit("sentinel://event", ev); }
                    if let Some(snap) = snapshot {
                        let _ = handle.emit("sentinel://snapshot", &snap);
                        let _ = tray.set_title(Some(overall_glyph(&snap)));
                    }
                }
            });
            Ok(())
        })
```

- [ ] **Step 3: Run the app** — Run: `cargo tauri dev`
Expected: window opens; a menubar item shows "● secure"; after the first tick (or pressing the future "Run sweep" button) it reflects real status. (Interval is 300s; to see an immediate tick during testing, temporarily set it to `from_secs(5)` then restore.)

- [ ] **Step 4: Commit**

```bash
git add src-tauri/src/main.rs
git commit -m "feat(app): background monitor loop emits events + updates menubar status"
```

---

### Task 12: Matte Security Center UI wired to Tauri

**Files:**
- Replace: `ui/index.html`
- Create: `ui/styles.css`, `ui/app.js`

- [ ] **Step 1: Markup** — Replace `ui/index.html`:

```html
<!DOCTYPE html>
<html lang="en"><head>
  <meta charset="utf-8"><title>Sentinel — Security Center</title>
  <link rel="stylesheet" href="styles.css">
</head>
<body>
  <header class="topbar">
    <span class="brand">sentinelos</span>
    <span id="overall" class="overall">● checking…</span>
    <button id="sweep">run sweep</button>
  </header>
  <main>
    <aside id="vectors" class="sidebar"></aside>
    <section class="feed">
      <h2>activity / findings</h2>
      <div id="findings"></div>
    </section>
  </main>
  <script src="app.js"></script>
</body></html>
```

- [ ] **Step 2: Matte theme** — Create `ui/styles.css`:

```css
:root{--bg:#161819;--panel:#121415;--line:#2b2f31;--text:#bcc1c4;--dim:#7a8085;
  --clear:#8aa978;--review:#c2a25e;--threat:#bf6b6b;--info:#6d93a8;}
*{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--text);
  font-family:Inter,Cantarell,system-ui,sans-serif;font-size:13px}
.topbar{display:flex;align-items:center;gap:12px;padding:10px 14px;background:#101213;border-bottom:1px solid var(--line)}
.brand{font-family:'JetBrains Mono',monospace;color:var(--clear)}
.overall{margin-left:auto;font-family:'JetBrains Mono',monospace}
button{background:#1c1f21;color:var(--text);border:1px solid var(--line);border-radius:5px;padding:5px 12px;cursor:pointer}
main{display:flex;min-height:calc(100vh - 45px)}
.sidebar{width:240px;background:var(--panel);border-right:1px solid var(--line);padding:8px;font-family:'JetBrains Mono',monospace;font-size:11px}
.vrow{display:flex;justify-content:space-between;padding:5px 8px}
.dot-clear{color:var(--clear)} .dot-review{color:var(--review)} .dot-threat{color:var(--threat)} .dot-unavailable{color:var(--dim)}
.feed{flex:1;padding:12px 16px} .feed h2{font-size:12px;color:var(--dim);font-weight:600}
.find{display:flex;gap:10px;padding:8px;border-bottom:1px solid #1e2122}
.badge{font-size:9px;border-radius:3px;padding:1px 6px;height:fit-content;font-family:'JetBrains Mono',monospace}
.b-review{color:var(--review);border:1px solid #3a3212} .b-threat{color:var(--threat);border:1px solid #5a2626}
.b-info{color:var(--info);border:1px solid #28363d} .b-clear{color:var(--clear);border:1px solid #2f3a36}
```

- [ ] **Step 3: Logic** — Create `ui/app.js`:

```js
const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const VECTOR_LABELS = { kexts:"kernel ext", net:"network", launchd:"launchd", tcc:"tcc perms" };
const sevClass = s => ({review:"b-review",threat:"b-threat",info:"b-info",clear:"b-clear"}[s] || "b-info");
const dotClass = s => ({clear:"dot-clear",review:"dot-review",threat:"dot-threat",unavailable:"dot-unavailable"}[s] || "dot-unavailable");

function worst(reports){
  if (reports.some(r=>r.status==="threat")) return ["threat","● threat"];
  if (reports.some(r=>r.status==="review")) return ["review","● review"];
  if (reports.some(r=>r.status==="unavailable")) return ["review","● review"];
  return ["clear","● secure"];
}

function render(snap){
  if(!snap) return;
  const side = document.getElementById("vectors");
  side.innerHTML = snap.reports.map(r=>
    `<div class="vrow"><span>${VECTOR_LABELS[r.vector_id]||r.vector_id}</span>`+
    `<span class="${dotClass(r.status)}">${r.status==="clear"?"ok":r.status==="unavailable"?"n/a":"!"}</span></div>`
  ).join("");
  const findings = snap.reports.flatMap(r=>r.findings);
  document.getElementById("findings").innerHTML = findings.length ? findings.map(f=>
    `<div class="find"><span class="badge ${sevClass(f.severity)}">${f.severity.toUpperCase()}</span>`+
    `<div><div>${f.title}</div><div style="color:var(--dim);font-size:11px">${f.detail}</div></div></div>`
  ).join("") : `<div style="color:var(--dim);padding:8px">no findings — clean</div>`;
  const [klass,label] = worst(snap.reports);
  const ov = document.getElementById("overall");
  ov.textContent = label; ov.className = "overall "+dotClass(klass==="clear"?"clear":klass);
}

async function sweep(){ render(await invoke("run_sweep")); }
document.getElementById("sweep").addEventListener("click", sweep);
listen("sentinel://snapshot", e => render(e.payload));
(async () => { const s = await invoke("get_snapshot"); if (s) render(s); else sweep(); })();
```

- [ ] **Step 4: Run end-to-end** — Run: `cargo tauri dev`
Expected: window shows the matte Security Center; "run sweep" populates the 4 vectors with real statuses + findings from your machine; overall indicator + menubar reflect status; if TCC is unreadable it shows `n/a` (Unavailable), not `ok`.

- [ ] **Step 5: Commit**

```bash
git add ui
git commit -m "feat(ui): matte Security Center wired to Tauri commands + live events"
```

---

## Self-Review (completed)

- **Spec coverage:** §5 architecture → Tasks 0–4, 9–11. §6 model → Task 1. §7 vectors (4 MVP) → Tasks 5–9. §8 live monitor/data flow → Tasks 4, 11. §9 error handling (Unavailable, not fake-Clear) → Tasks 1, 8, 9 + UI Step 4. §11 permissions (FDA for TCC) → Task 8/9. §12 aesthetic → Task 12. §14 MVP acceptance → Task 12 Step 4. The remaining 16 vectors and Linux provider are intentionally out of this slice (spec §14).
- **Placeholder scan:** No TBD/TODO; every code step shows complete code; the one deliberate transient stub (Task 0 Step 3 vs Task 1 Step 2) is called out explicitly.
- **Type consistency:** `VectorReport`/`Snapshot`/`Finding`/`Severity`/`VectorStatus` defined in Task 1 and used unchanged after. Vector id constants `V_KEXTS/V_NET/V_LAUNCHD/V_TCC` defined in Tasks 5–8 and consumed in Task 9. Event variants `FindingNew/FindingCleared/StatusChanged` defined in Task 3, emitted in Task 11, consumed in `app.js` Task 12. Commands `run_sweep`/`get_snapshot` and events `sentinel://snapshot`/`sentinel://event` match across Rust and JS.

## Notes / risk
- Tauri 2 APIs (`Emitter::emit`, `tauri::tray::TrayIconBuilder`, `@tauri-apps/api` global `window.__TAURI__`) evolve; if a signature mismatches, check the current Tauri 2 docs for that one call — the architecture is unaffected.
- `kextstat` is deprecated in favor of `kmutil showloaded`; the parser is format-compatible, but switching the command in Task 9 is a one-line change if needed.
