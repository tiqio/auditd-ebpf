use thiserror::Error;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HealthCounters {
    pub events_seen_total: u64,
    pub events_submitted_total: u64,
    pub ring_reserve_failed_total: u64,
    pub events_consumed_total: u64,
    pub events_matched_total: u64,
    pub events_unmatched_total: u64,
    pub events_output_total: u64,
    pub exec_argv_captured_total: u64,
    pub exec_argv_suppressed_total: u64,
    pub queue_dropped_total: u64,
    pub path_resolution_failed_total: u64,
    pub unclean_shutdown_detected_total: u64,
    pub event_parse_failed_total: u64,
    pub stdout_write_failed_total: u64,
    pub rule_reload_success_total: u64,
    pub rule_reload_failed_total: u64,
    pub gap_records_generated_total: u64,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum CounterError {
    #[error("首版每次启动最多记录一次历史 dirty 标记")]
    DuplicateUncleanShutdown,
}

impl HealthCounters {
    #[must_use]
    pub fn kernel_invariant_holds(&self) -> bool {
        self.events_seen_total
            == self
                .events_submitted_total
                .saturating_add(self.ring_reserve_failed_total)
    }

    #[must_use]
    pub fn all_invariants_hold(&self) -> bool {
        self.kernel_invariant_holds()
            && self.events_consumed_total <= self.events_submitted_total
            && self
                .events_output_total
                .saturating_add(self.queue_dropped_total)
                <= self
                    .events_consumed_total
                    .saturating_add(self.gap_records_generated_total)
            && self.exec_argv_suppressed_total <= self.exec_argv_captured_total
    }

    pub fn record_unclean_shutdown(&mut self) -> Result<(), CounterError> {
        if self.unclean_shutdown_detected_total != 0 {
            return Err(CounterError::DuplicateUncleanShutdown);
        }
        self.unclean_shutdown_detected_total = 1;
        Ok(())
    }
}
