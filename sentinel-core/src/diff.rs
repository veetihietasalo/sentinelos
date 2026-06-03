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
    for r in &s.reports {
        for f in &r.findings {
            m.insert(f.id.clone(), f.clone());
        }
    }
    m
}

fn status_map(s: &Snapshot) -> BTreeMap<String, VectorStatus> {
    s.reports.iter().map(|r| (r.vector_id.clone(), r.status)).collect()
}

pub fn diff(prev: &Snapshot, next: &Snapshot) -> Vec<Event> {
    let mut events = Vec::new();
    let (pf, nf) = (findings_map(prev), findings_map(next));
    for (id, f) in &nf {
        if !pf.contains_key(id) {
            events.push(Event::FindingNew { finding: f.clone() });
        }
    }
    for id in pf.keys() {
        if !nf.contains_key(id) {
            events.push(Event::FindingCleared { id: id.clone() });
        }
    }
    let (ps, ns) = (status_map(prev), status_map(next));
    for (v, s) in &ns {
        if let Some(old) = ps.get(v) {
            if old != s {
                events.push(Event::StatusChanged { vector_id: v.clone(), from: *old, to: *s });
            }
        }
    }
    events
}

/// First-ever snapshot: every finding is "new".
pub fn initial_events(s: &Snapshot) -> Vec<Event> {
    findings_map(s)
        .into_values()
        .map(|finding| Event::FindingNew { finding })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Finding, Severity, VectorReport, VectorStatus};

    fn finding(id: &str) -> Finding {
        Finding {
            id: id.into(),
            vector_id: "net".into(),
            severity: Severity::Review,
            title: "t".into(),
            detail: "d".into(),
        }
    }

    fn snap(vector: &str, status: VectorStatus, findings: Vec<Finding>) -> Snapshot {
        Snapshot { reports: vec![VectorReport { vector_id: vector.into(), status, findings }] }
    }

    #[test]
    fn new_finding_emits_finding_new() {
        let prev = snap("net", VectorStatus::Clear, vec![]);
        let next = snap("net", VectorStatus::Review, vec![finding("net:beacon-1")]);
        let evs = diff(&prev, &next);
        assert!(evs
            .iter()
            .any(|e| matches!(e, Event::FindingNew { finding } if finding.id == "net:beacon-1")));
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
