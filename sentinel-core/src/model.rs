use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Clear,
    Info,
    Review,
    Threat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VectorStatus {
    Clear,
    Review,
    Threat,
    /// Check could not run (e.g. blocked by permissions). Never reported as Clear.
    Unavailable,
}

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
pub struct Snapshot {
    pub reports: Vec<VectorReport>,
}

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
