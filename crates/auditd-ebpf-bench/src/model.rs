//! 基准协议使用的数据模型。

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// 当前基准产物协议版本。版本变化意味着报告不能直接合并比较。
pub const BENCHMARK_PROTOCOL_VERSION: u32 = 1;

/// 可跨 auditd 与 auditd-ebpf 比较的规范化事件。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NormalizedEvent {
    pub operation_id: String,
    pub rule_key: String,
    pub syscall: String,
    pub success: bool,
    pub identity: String,
    pub path: Option<String>,
}

/// 一个确定性 workload 操作及其必须产生的事件集合。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadOperation {
    pub sequence: u64,
    pub id: String,
    pub kind: String,
    pub expected_events: Vec<NormalizedEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Scenario {
    Syscall,
    Path,
    Mixed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BenchmarkMode {
    CaptureOnly,
    Operational,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Implementation {
    Auditd,
    AuditdEbpf,
}

/// 原始样本必须保留其失败原因，禁止只输出成功数据。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "reason", rename_all = "kebab-case")]
pub enum SampleStatus {
    Valid,
    Invalid(String),
    Contaminated(String),
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkSample {
    pub id: String,
    pub raw_path: String,
    pub status: SampleStatus,
    pub operations_per_second: f64,
    pub agent_cpu_percent: f64,
    pub p95_latency_us: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkReport {
    pub protocol_version: u32,
    pub samples: Vec<BenchmarkSample>,
    pub raw_artifacts: Vec<String>,
    pub valid_samples: usize,
    pub invalid_samples: usize,
}

/// CLI 解析后供 runner 使用的稳定配置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BenchmarkConfig {
    pub scenario: Scenario,
    pub mode: BenchmarkMode,
    pub seed: u64,
    pub samples: usize,
    pub warmup_seconds: u64,
    pub duration_seconds: u64,
    pub output: PathBuf,
}
