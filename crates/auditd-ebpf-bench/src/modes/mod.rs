//! 基准模式的阶段计划。

pub mod capture_only;
pub mod operational;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunPhase {
    Baseline,
    Warmup,
    Measurement,
    Cooldown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhasePlan {
    pub phase: RunPhase,
    pub seconds: u64,
}
