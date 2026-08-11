//! auditd 与 auditd-ebpf 公平对照基准的可复用核心。
//!
//! 本 crate 把工作负载、事件正确性、环境证据和统计报告拆开，避免 runner 在失败后
//! 选择性隐藏样本。所有性能结论都必须先通过 [`correctness`] 门禁。

pub mod cli;
pub mod correctness;
pub mod environment;
pub mod model;
pub mod report;
pub mod statistics;
pub mod workloads;
