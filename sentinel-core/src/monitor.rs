use crate::diff::{diff, initial_events, Event};
use crate::model::Snapshot;
use crate::provider::{run_sweep, SecurityProvider};

/// Holds the last snapshot and produces events on each tick.
pub struct Monitor {
    last: Option<Snapshot>,
}

impl Monitor {
    pub fn new() -> Self {
        Self { last: None }
    }

    pub fn current(&self) -> Option<&Snapshot> {
        self.last.as_ref()
    }

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

impl Default for Monitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::VectorStatus;
    use crate::provider::mock::MockProvider;

    #[test]
    fn first_tick_yields_initial_then_quiet() {
        let p = MockProvider::new().with("kexts", VectorStatus::Clear);
        let mut m = Monitor::new();
        let _first = m.tick(&p); // initial
        let second = m.tick(&p); // unchanged
        assert!(second.is_empty(), "no change should yield no events, got {second:?}");
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
