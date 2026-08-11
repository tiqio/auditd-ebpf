//! 生产日志模式，报告必须显式记录两种方案的 sink 差异。

use serde::{Deserialize, Serialize};

use super::{PhasePlan, RunPhase};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoggingDifference {
    pub auditd: String,
    pub auditd_ebpf: String,
    pub interpretation_limit: String,
}

pub fn logging_difference() -> LoggingDifference {
    LoggingDifference {
        auditd: "auditd 标准本地文件日志配置".into(),
        auditd_ebpf: "stdout -> journald -> rsyslog 本地 action queue".into(),
        interpretation_limit: "该模式包含日志栈差异，不得解释为纯采集开销".into(),
    }
}

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
