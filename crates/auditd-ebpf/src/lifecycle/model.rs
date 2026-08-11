use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LifecycleState {
    Clean,
    Dirty,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleMarker {
    pub version: u16,
    pub state: LifecycleState,
    pub boot_id: String,
    pub invocation_id: String,
    pub pid: u32,
    pub process_start_time: u64,
    pub rule_version: Option<u64>,
    pub updated_at: String,
    pub final_counters: Option<BTreeMap<String, u64>>,
}

impl LifecycleMarker {
    pub fn dirty(
        boot_id: impl Into<String>,
        invocation_id: impl Into<String>,
        pid: u32,
        process_start_time: u64,
    ) -> Self {
        Self {
            version: 1,
            state: LifecycleState::Dirty,
            boot_id: boot_id.into(),
            invocation_id: invocation_id.into(),
            pid,
            process_start_time,
            rule_version: None,
            updated_at: crate::lifecycle::state_file::rfc3339_now(),
            final_counters: None,
        }
    }
    #[must_use]
    pub fn into_clean(mut self, counters: BTreeMap<String, u64>) -> Self {
        self.state = LifecycleState::Clean;
        self.updated_at = crate::lifecycle::state_file::rfc3339_now();
        self.final_counters = Some(counters);
        self
    }
}
