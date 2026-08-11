//! 只测采集成本：两种实现都写入完整消费但不持久化的本地 sink。

use super::{PhasePlan, RunPhase};

pub const SINK_DESCRIPTION: &str = "完整消费记录的非持久本地 pipe；不 fsync、不远传";

pub fn plan(measurement_seconds: u64) -> Vec<PhasePlan> {
    vec![
        PhasePlan {
            phase: RunPhase::Baseline,
            seconds: 30,
        },
        PhasePlan {
            phase: RunPhase::Warmup,
            seconds: 30,
        },
        PhasePlan {
            phase: RunPhase::Measurement,
            seconds: measurement_seconds,
        },
        PhasePlan {
            phase: RunPhase::Cooldown,
            seconds: 30,
        },
    ]
}
