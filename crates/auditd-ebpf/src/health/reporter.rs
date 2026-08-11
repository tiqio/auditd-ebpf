use super::{
    counters::HealthCounters,
    state::{HealthState, HealthStateMachine},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionPolicyState {
    NotRequested,
    Passed,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthSnapshot {
    pub state: HealthState,
    pub production_policy: ProductionPolicyState,
    pub counters: HealthCounters,
    pub final_record: bool,
}

pub struct HealthReporter {
    state: HealthStateMachine,
    production_policy: ProductionPolicyState,
    counters: HealthCounters,
}

impl HealthReporter {
    #[must_use]
    pub fn new(production_policy: ProductionPolicyState) -> Self {
        Self {
            state: HealthStateMachine::new(),
            production_policy,
            counters: HealthCounters::default(),
        }
    }

    pub fn ready(&mut self) {
        self.state.ready();
    }

    pub fn fail(&mut self, reason: impl Into<String>) {
        self.state.fail(reason);
    }

    #[must_use]
    pub fn snapshot(&self, final_record: bool) -> HealthSnapshot {
        HealthSnapshot {
            state: self.state.state(),
            production_policy: self.production_policy,
            counters: self.counters.clone(),
            final_record,
        }
    }
}
