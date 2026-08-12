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

/// path workload 的逐操作账本。即使操作失败也必须保留条目，防止报告只统计成功事件。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathLedgerEntry {
    pub target_path: String,
    pub operation_id: String,
    pub expected_permission: String,
    pub completed: bool,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WatchMode {
    Disabled,
    Enabled,
}

/// 同版本 auditd-ebpf 在 watch 关闭/开启时的独立样本。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WatchBenchmarkSample {
    pub id: String,
    pub mode: BenchmarkMode,
    pub watch: WatchMode,
    pub status: SampleStatus,
    pub operations_per_second: f64,
    pub agent_cpu_percent: f64,
    pub process_rss_kib: u64,
    pub p95_latency_us: f64,
    pub lost_events: u64,
    pub ledger_entries: usize,
    pub matched_entries: usize,
    pub raw_path: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WatchBenchmarkReport {
    pub protocol_version: u32,
    pub samples: Vec<WatchBenchmarkSample>,
    pub valid_disabled_samples: usize,
    pub valid_enabled_samples: usize,
    pub invalid_samples: usize,
    pub performance_claim_allowed: bool,
    pub reasons: Vec<String>,
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
