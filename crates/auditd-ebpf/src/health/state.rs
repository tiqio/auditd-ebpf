#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HealthState {
    Starting,
    Healthy,
    Degraded,
    Unhealthy,
    Stopping,
}

pub struct HealthStateMachine {
    state: HealthState,
    last_reason: Option<String>,
}

impl HealthStateMachine {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: HealthState::Starting,
            last_reason: None,
        }
    }
    pub fn ready(&mut self) {
        self.state = HealthState::Healthy;
    }
    pub fn record_gap(&mut self, reason: impl Into<String>) {
        self.last_reason = Some(reason.into());
        self.state = HealthState::Degraded;
    }
    pub fn fail(&mut self, reason: impl Into<String>) {
        self.last_reason = Some(reason.into());
        self.state = HealthState::Unhealthy;
    }
    pub fn stop(&mut self) {
        self.state = HealthState::Stopping;
    }
    #[must_use]
    pub const fn state(&self) -> HealthState {
        self.state
    }
}

impl Default for HealthStateMachine {
    fn default() -> Self {
        Self::new()
    }
}
