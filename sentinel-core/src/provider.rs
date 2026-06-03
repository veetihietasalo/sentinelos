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

    pub struct MockProvider {
        pub reports: HashMap<&'static str, VectorReport>,
    }

    impl MockProvider {
        pub fn new() -> Self {
            Self { reports: HashMap::new() }
        }

        pub fn with(mut self, id: &'static str, status: VectorStatus) -> Self {
            self.reports.insert(
                id,
                VectorReport { vector_id: id.to_string(), status, findings: vec![] },
            );
            self
        }
    }

    impl SecurityProvider for MockProvider {
        fn vectors(&self) -> Vec<&'static str> {
            let mut v: Vec<_> = self.reports.keys().copied().collect();
            v.sort();
            v
        }

        fn check(&self, vector_id: &str) -> VectorReport {
            self.reports
                .get(vector_id)
                .cloned()
                .unwrap_or_else(|| VectorReport::clear(vector_id))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::MockProvider;
    use super::*;
    use crate::model::VectorStatus;

    #[test]
    fn run_sweep_collects_one_report_per_vector() {
        let p = MockProvider::new()
            .with("kexts", VectorStatus::Clear)
            .with("tcc", VectorStatus::Review);
        let snap = run_sweep(&p);
        assert_eq!(snap.reports.len(), 2);
    }
}
