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
    last_gap_at: Option<Duration>,
}

impl HealthStateMachine {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: HealthState::Starting,
            last_reason: None,
            last_gap_at: None,
        }
    }
    pub fn ready(&mut self) {
        self.state = HealthState::Healthy;
    }
    pub fn record_gap(&mut self, reason: impl Into<String>) {
        self.record_gap_at(reason, Duration::ZERO);
    }
    pub fn record_gap_at(&mut self, reason: impl Into<String>, now: Duration) {
        self.last_reason = Some(reason.into());
        self.last_gap_at = Some(now);
        self.state = HealthState::Degraded;
    }
    pub fn recover_if_quiet(&mut self, now: Duration) -> bool {
        if self.state != HealthState::Degraded {
            return false;
        }
        let Some(last_gap_at) = self.last_gap_at else {
            return false;
        };
        if now.saturating_sub(last_gap_at) < DEGRADED_RECOVERY_WINDOW {
            return false;
        }
        self.state = HealthState::Healthy;
        self.last_reason = None;
        true
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

    #[must_use]
    pub fn last_reason(&self) -> Option<&str> {
        self.last_reason.as_deref()
    }
}

impl Default for HealthStateMachine {
    fn default() -> Self {
        Self::new()
    }
}
use std::time::Duration;

const DEGRADED_RECOVERY_WINDOW: Duration = Duration::from_secs(5 * 60);
