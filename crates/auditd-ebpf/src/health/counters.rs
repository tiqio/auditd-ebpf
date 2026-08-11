use thiserror::Error;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HealthCounters {
    pub events_seen_total: u64,
    pub events_submitted_total: u64,
    pub ring_reserve_failed_total: u64,
    pub inflight_dropped_total: u64,
    pub correlation_missed_total: u64,
    pub exec_argv_dropped_total: u64,
    pub internal_dropped_total: u64,
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

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct KernelCounterSample {
    pub events_seen_per_cpu: Vec<u64>,
    pub events_submitted_per_cpu: Vec<u64>,
    pub ring_reserve_failed_per_cpu: Vec<u64>,
    pub inflight_dropped_per_cpu: Vec<u64>,
    pub correlation_missed_per_cpu: Vec<u64>,
    pub exec_argv_captured_per_cpu: Vec<u64>,
    pub exec_argv_dropped_per_cpu: Vec<u64>,
    pub internal_dropped_per_cpu: Vec<u64>,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum CounterError {
    #[error("首版每次启动最多记录一次历史 dirty 标记")]
    DuplicateUncleanShutdown,
    #[error("eBPF per-CPU 计数求和溢出或违反内核不变量")]
    InvalidKernelSample,
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

    pub fn apply_kernel_sample(
        &mut self,
        sample: &KernelCounterSample,
    ) -> Result<(), CounterError> {
        let events_seen_total = checked_sum(&sample.events_seen_per_cpu)?;
        let events_submitted_total = checked_sum(&sample.events_submitted_per_cpu)?;
        let ring_reserve_failed_total = checked_sum(&sample.ring_reserve_failed_per_cpu)?;
        let inflight_dropped_total = checked_sum(&sample.inflight_dropped_per_cpu)?;
        let correlation_missed_total = checked_sum(&sample.correlation_missed_per_cpu)?;
        let exec_argv_captured_total = checked_sum(&sample.exec_argv_captured_per_cpu)?;
        let exec_argv_dropped_total = checked_sum(&sample.exec_argv_dropped_per_cpu)?;
        let internal_dropped_total = checked_sum(&sample.internal_dropped_per_cpu)?;
        if events_seen_total != events_submitted_total.saturating_add(ring_reserve_failed_total) {
            return Err(CounterError::InvalidKernelSample);
        }
        self.events_seen_total = events_seen_total;
        self.events_submitted_total = events_submitted_total;
        self.ring_reserve_failed_total = ring_reserve_failed_total;
        self.inflight_dropped_total = inflight_dropped_total;
        self.correlation_missed_total = correlation_missed_total;
        self.exec_argv_captured_total = exec_argv_captured_total;
        self.exec_argv_dropped_total = exec_argv_dropped_total;
        self.internal_dropped_total = internal_dropped_total;
        Ok(())
    }

    #[must_use]
    pub fn kernel_lost_total(&self) -> u64 {
        self.ring_reserve_failed_total
            .saturating_add(self.inflight_dropped_total)
            .saturating_add(self.correlation_missed_total)
            .saturating_add(self.exec_argv_dropped_total)
            .saturating_add(self.internal_dropped_total)
    }
}

fn checked_sum(values: &[u64]) -> Result<u64, CounterError> {
    values.iter().try_fold(0_u64, |total, value| {
        total
            .checked_add(*value)
            .ok_or(CounterError::InvalidKernelSample)
    })
}
