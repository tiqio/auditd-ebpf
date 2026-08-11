use std::time::Duration;

use super::{
    counters::{CounterError, HealthCounters, KernelCounterSample},
    state::{HealthState, HealthStateMachine},
};

const STATUS_INTERVAL: Duration = Duration::from_secs(10);

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
    pub reason: Option<String>,
    pub final_record: bool,
}

pub struct HealthReporter {
    state: HealthStateMachine,
    production_policy: ProductionPolicyState,
    counters: HealthCounters,
    last_report_at: Option<Duration>,
    state_changed: bool,
}

impl HealthReporter {
    #[must_use]
    pub fn new(production_policy: ProductionPolicyState) -> Self {
        Self {
            state: HealthStateMachine::new(),
            production_policy,
            counters: HealthCounters::default(),
            last_report_at: None,
            state_changed: true,
        }
    }

    pub fn ready(&mut self) {
        self.state.ready();
        self.state_changed = true;
    }

    pub fn record_gap(&mut self, reason: impl Into<String>, now: Duration) {
        self.state.record_gap_at(reason, now);
        self.state_changed = true;
    }

    pub fn record_unclean_shutdown(&mut self, now: Duration) -> Result<(), CounterError> {
        self.counters.record_unclean_shutdown()?;
        self.record_gap("unclean_shutdown", now);
        Ok(())
    }

    pub fn update_kernel_counters(
        &mut self,
        sample: &KernelCounterSample,
    ) -> Result<(), CounterError> {
        if let Err(error) = self.counters.apply_kernel_sample(sample) {
            self.fail("counter_invariant");
            return Err(error);
        }
        Ok(())
    }

    pub fn fail(&mut self, reason: impl Into<String>) {
        self.state.fail(reason);
        self.state_changed = true;
    }

    pub fn stop(&mut self) {
        self.state.stop();
        self.state_changed = true;
    }

    pub fn poll(&mut self, now: Duration) -> Option<HealthSnapshot> {
        if self.state.recover_if_quiet(now) {
            self.state_changed = true;
        }
        let periodic_due = self
            .last_report_at
            .is_none_or(|last| now.saturating_sub(last) >= STATUS_INTERVAL);
        if !self.state_changed && !periodic_due {
            return None;
        }
        self.last_report_at = Some(now);
        self.state_changed = false;
        Some(self.snapshot(false))
    }

    #[must_use]
    pub fn snapshot(&self, final_record: bool) -> HealthSnapshot {
        HealthSnapshot {
            state: self.state.state(),
            production_policy: self.production_policy,
            counters: self.counters.clone(),
            reason: self.state.last_reason().map(str::to_owned),
            final_record,
        }
    }

    pub fn counters_mut(&mut self) -> &mut HealthCounters {
        &mut self.counters
    }
}
