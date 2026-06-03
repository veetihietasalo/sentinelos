//! macOS `SecurityProvider` for Sentinel.
//!
//! The parsing logic is pure (string in → `VectorReport` out) so it is fully
//! unit-tested against captured fixtures, with no live system required. The
//! `MacosProvider` impl wires those parsers to real commands and degrades to
//! `Unavailable` (never a false `Clear`) when a check is blocked or errors.

use sentinel_core::model::{Finding, Severity, VectorReport, VectorStatus};
use sentinel_core::provider::SecurityProvider;
use std::path::Path;
use std::process::Command;

pub const V_KEXTS: &str = "kexts";
pub const V_NET: &str = "net";
pub const V_LAUNCHD: &str = "launchd";
pub const V_TCC: &str = "tcc";

const SENSITIVE_PORTS: &[&str] = &[":22", ":3389", ":5900"];

// ---------------------------------------------------------------------------
// Pure parsers
// ---------------------------------------------------------------------------

/// Parse `kextstat` / `kmutil showloaded` output. Any non-`com.apple.` bundle is flagged.
pub fn parse_kexts(output: &str) -> VectorReport {
    let mut findings = Vec::new();
    for line in output.lines() {
        if let Some(bundle) = line
            .split_whitespace()
            .find(|t| t.contains('.') && !t.starts_with('('))
        {
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

/// Parse `lsof -nP -iTCP -sTCP:LISTEN`. Flags remote-access ports and non-loopback listeners.
pub fn parse_listeners(output: &str) -> VectorReport {
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for line in output.lines().skip(1) {
        if !line.contains("(LISTEN)") {
            continue;
        }
        let name = line.split_whitespace().nth(8).unwrap_or("");
        let command = line.split_whitespace().next().unwrap_or("?");
        let sensitive = SENSITIVE_PORTS.iter().any(|p| name.contains(p));
        let non_loopback = !name.starts_with("127.0.0.1") && !name.starts_with("[::1]");
        if (sensitive || non_loopback) && seen.insert(format!("{command} {name}")) {
            findings.push(Finding {
                id: format!("{V_NET}:{name}"),
                vector_id: V_NET.to_string(),
                severity: if sensitive { Severity::Review } else { Severity::Info },
                title: if sensitive {
                    "Remote-access port listening".to_string()
                } else {
                    "Non-loopback listener".to_string()
                },
                detail: format!("{command} {name}"),
            });
        }
    }
    let status = if findings.iter().any(|f| f.severity == Severity::Review) {
        VectorStatus::Review
    } else {
        VectorStatus::Clear
    };
    VectorReport { vector_id: V_NET.to_string(), status, findings }
}

/// Flag any launchd entry whose program lives in a user-writable / temp / hidden location.
pub fn assess_launchd(entries: &[(String, String)]) -> VectorReport {
    let mut findings = Vec::new();
    for (label, program) in entries {
        let suspicious = program.starts_with("/tmp/")
            || program.starts_with("/var/tmp/")
            || program.contains("/.")
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

/// Strip the `kTCCService` prefix for readable titles.
fn short_service(s: &str) -> &str {
    s.strip_prefix("kTCCService").unwrap_or(s)
}

/// Map a TCC service to a severity, or `None` to drop it as security-irrelevant
/// noise (e.g. iMessage/continuity `Liverpool`, AddressBook). The powerful grants
/// — control, screen capture, keystroke monitoring, full-disk — are Review.
fn tcc_severity(service: &str) -> Option<Severity> {
    if service.contains("Accessibility")
        || service.contains("ScreenCapture")
        || service.contains("ListenEvent")
        || service.contains("SystemPolicyAllFiles")
        || service.contains("PostEvent")
    {
        Some(Severity::Review)
    } else if service.contains("Microphone") || service.contains("Camera") {
        Some(Severity::Info)
    } else {
        None
    }
}

/// Parse `sqlite3` rows of "service|client" (allowed grants), keeping only the
/// security-relevant ones and de-duping (the system + user databases overlap).
pub fn parse_tcc(rows: &str) -> VectorReport {
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for line in rows.lines() {
        let mut parts = line.splitn(2, '|');
        let (service, client) = match (parts.next(), parts.next()) {
            (Some(s), Some(c)) if !s.is_empty() => (s, c),
            _ => continue,
        };
        if let Some(severity) = tcc_severity(service) {
            let id = format!("{V_TCC}:{service}:{client}");
            if !seen.insert(id.clone()) {
                continue;
            }
            findings.push(Finding {
                id,
                vector_id: V_TCC.to_string(),
                severity,
                title: format!("{} granted", short_service(service)),
                detail: client.to_string(),
            });
        }
    }
    let status = if findings.iter().any(|f| f.severity == Severity::Review) {
        VectorStatus::Review
    } else {
        VectorStatus::Clear
    };
    VectorReport { vector_id: V_TCC.to_string(), status, findings }
}

// ---------------------------------------------------------------------------
// Live provider
// ---------------------------------------------------------------------------

/// Read `Program` (or first path in `ProgramArguments`) from a launchd plist via `defaults read`.
pub fn launchd_program(plist: &Path) -> Option<String> {
    let path = plist.with_extension("");
    if let Ok(out) = Command::new("defaults").arg("read").arg(&path).arg("Program").output() {
        if out.status.success() {
            return Some(String::from_utf8_lossy(&out.stdout).trim().to_string());
        }
    }
    let out = Command::new("defaults")
        .arg("read")
        .arg(&path)
        .arg("ProgramArguments")
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .find(|l| l.contains('/'))
        .map(|l| l.trim().trim_matches('"').trim_end_matches(',').trim_matches('"').to_string())
}

fn run(cmd: &str, args: &[&str]) -> Result<String, String> {
    match Command::new(cmd).args(args).output() {
        Ok(o) if o.status.success() => Ok(String::from_utf8_lossy(&o.stdout).into_owned()),
        Ok(o) => Err(String::from_utf8_lossy(&o.stderr).trim().to_string()),
        Err(e) => Err(e.to_string()),
    }
}

pub struct MacosProvider;

impl MacosProvider {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MacosProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityProvider for MacosProvider {
    fn vectors(&self) -> Vec<&'static str> {
        vec![V_KEXTS, V_NET, V_LAUNCHD, V_TCC]
    }

    fn check(&self, vector_id: &str) -> VectorReport {
        match vector_id {
            V_KEXTS => match run("kextstat", &[]) {
                Ok(o) => parse_kexts(&o),
                Err(e) => VectorReport::unavailable(V_KEXTS, &e),
            },
            V_NET => match run("lsof", &["-nP", "-iTCP", "-sTCP:LISTEN"]) {
                Ok(o) => parse_listeners(&o),
                Err(e) => VectorReport::unavailable(V_NET, &e),
            },
            V_LAUNCHD => {
                let mut entries = Vec::new();
                for dir in ["/Library/LaunchAgents", "/Library/LaunchDaemons"] {
                    if let Ok(rd) = std::fs::read_dir(dir) {
                        for e in rd.flatten() {
                            let p = e.path();
                            if p.extension().map(|x| x == "plist").unwrap_or(false) {
                                let label =
                                    p.file_stem().and_then(|s| s.to_str()).unwrap_or("?").to_string();
                                if let Some(prog) = launchd_program(&p) {
                                    entries.push((label, prog));
                                }
                            }
                        }
                    }
                }
                assess_launchd(&entries)
            }
            V_TCC => {
                // Accessibility / ScreenCapture / FDA live in the SYSTEM database;
                // Microphone / Camera in the USER one. Read both and merge.
                let home = std::env::var("HOME").unwrap_or_default();
                let dbs = [
                    "/Library/Application Support/com.apple.TCC/TCC.db".to_string(),
                    format!("{home}/Library/Application Support/com.apple.TCC/TCC.db"),
                ];
                let sql = "SELECT service||'|'||client FROM access WHERE auth_value IN (2,3);";
                let mut rows = String::new();
                let mut any_ok = false;
                for db in &dbs {
                    let uri = format!("file:{db}?mode=ro&immutable=1");
                    if let Ok(o) = run("sqlite3", &[&uri, sql]) {
                        any_ok = true;
                        rows.push_str(&o);
                    }
                }
                if any_ok {
                    parse_tcc(&rows)
                } else {
                    VectorReport::unavailable(
                        V_TCC,
                        "TCC databases unreadable — grant Full Disk Access to Sentinel in System Settings → Privacy & Security.",
                    )
                }
            }
            other => VectorReport::unavailable(other, "unknown vector"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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

    #[test]
    fn tmp_launchd_path_is_threat() {
        let entries = vec![("com.evil.agent".to_string(), "/tmp/x".to_string())];
        assert_eq!(assess_launchd(&entries).status, VectorStatus::Threat);
    }

    #[test]
    fn system_launchd_path_is_clear() {
        let entries = vec![("com.apple.thing".to_string(), "/usr/libexec/thing".to_string())];
        assert_eq!(assess_launchd(&entries).status, VectorStatus::Clear);
    }

    #[test]
    fn accessibility_grant_is_review() {
        let rows = "kTCCServiceAccessibility|com.example.app\nkTCCServiceMicrophone|com.other.app\n";
        let r = parse_tcc(rows);
        assert_eq!(r.status, VectorStatus::Review);
        assert_eq!(r.findings.len(), 2);
    }

    #[test]
    fn empty_tcc_rows_are_clear() {
        assert_eq!(parse_tcc("").status, VectorStatus::Clear);
    }

    #[test]
    fn apple_internal_tcc_grants_are_dropped() {
        let rows = "kTCCServiceLiverpool|com.apple.imagent\nkTCCServiceAddressBook|com.example.app\n";
        let r = parse_tcc(rows);
        assert_eq!(r.status, VectorStatus::Clear);
        assert!(r.findings.is_empty(), "noise should be dropped: {:?}", r.findings);
    }

    #[test]
    fn full_disk_access_grant_is_review() {
        let r = parse_tcc("kTCCServiceSystemPolicyAllFiles|com.example.tool\n");
        assert_eq!(r.status, VectorStatus::Review);
        assert_eq!(r.findings.len(), 1);
    }

    #[test]
    fn duplicate_tcc_grants_dedupe() {
        let rows = "kTCCServiceAccessibility|com.example.app\nkTCCServiceAccessibility|com.example.app\n";
        assert_eq!(parse_tcc(rows).findings.len(), 1);
    }

    #[test]
    fn duplicate_listeners_dedupe() {
        let out = "H\nrapportd 1 u 1u IPv4 0x 0t0 TCP *:61714 (LISTEN)\nrapportd 1 u 1u IPv6 0x 0t0 TCP *:61714 (LISTEN)\n";
        assert_eq!(parse_listeners(out).findings.len(), 1);
    }
}
