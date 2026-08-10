#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HealthCounters {
    pub events_seen_total: u64,
    pub events_submitted_total: u64,
    pub ring_reserve_failed_total: u64,
    pub unclean_shutdown_detected_total: u64,
}

impl HealthCounters {
    #[must_use]
    pub fn kernel_invariant_holds(&self) -> bool {
        self.events_seen_total
            == self
                .events_submitted_total
                .saturating_add(self.ring_reserve_failed_total)
    }
}
