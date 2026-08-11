//! 报告聚合与固定 seed 运行顺序。

use std::{fs, path::Path};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::{
    model::{BENCHMARK_PROTOCOL_VERSION, BenchmarkReport, BenchmarkSample, SampleStatus},
    workloads::StableRng,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReportStatus {
    Passed,
    Failed,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScenarioComparison {
    pub scenario: String,
    pub cpu_improvement: f64,
    pub throughput_improvement: f64,
    pub p95_latency_improvement: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerformanceConclusion {
    pub status: ReportStatus,
    pub reproduced_by_second_maintainer: bool,
    pub comparisons: Vec<ScenarioComparison>,
    pub reasons: Vec<String>,
}

pub fn randomized_order(seed: u64, count: usize) -> Vec<String> {
    let auditd_count = count / 2;
    let mut order = Vec::with_capacity(count);
    order.extend(std::iter::repeat_n("auditd".to_owned(), auditd_count));
    order.extend(std::iter::repeat_n(
        "auditd-ebpf".to_owned(),
        count - auditd_count,
    ));
    let mut rng = StableRng::new(seed);
    for index in (1..order.len()).rev() {
        let target = rng.index(index + 1);
        order.swap(index, target);
    }
    order
}

pub fn build_report(samples: Vec<BenchmarkSample>) -> BenchmarkReport {
    let raw_artifacts = samples
        .iter()
        .map(|sample| sample.raw_path.clone())
        .collect();
    let valid_samples = samples
        .iter()
        .filter(|sample| matches!(sample.status, SampleStatus::Valid))
        .count();
    BenchmarkReport {
        protocol_version: BENCHMARK_PROTOCOL_VERSION,
        invalid_samples: samples.len() - valid_samples,
        valid_samples,
        raw_artifacts,
        samples,
    }
}

/// 严格实现基准协议的发布门禁；未复现时不得返回 passed。
pub fn assess_performance(
    report: &BenchmarkReport,
    comparisons: Vec<ScenarioComparison>,
    reproduced_by_second_maintainer: bool,
) -> PerformanceConclusion {
    let mut reasons = Vec::new();
    let status = if report.invalid_samples != 0 {
        reasons.push(format!("存在 {} 个非有效样本", report.invalid_samples));
        ReportStatus::Invalid
    } else {
        if comparisons.len() != 3 {
            reasons.push("必须同时包含 syscall/path/mixed 三类比较".into());
        }
        for comparison in &comparisons {
            if comparison.cpu_improvement < 0.20 {
                reasons.push(format!("{} CPU 改善低于 20%", comparison.scenario));
            }
            if comparison.throughput_improvement < -0.02 {
                reasons.push(format!("{} 吞吐下降超过 2%", comparison.scenario));
            }
        }
        let strong_categories = comparisons
            .iter()
            .filter(|comparison| {
                comparison.throughput_improvement >= 0.10
                    || comparison.p95_latency_improvement >= 0.10
            })
            .count();
        if strong_categories < 2 {
            reasons.push("至少两类需吞吐提升或 p95 延迟改善 10%".into());
        }
        if !reproduced_by_second_maintainer {
            reasons.push("尚无第二名维护者复现签字".into());
        }
        if reasons.is_empty() {
            ReportStatus::Passed
        } else {
            ReportStatus::Failed
        }
    };
    PerformanceConclusion {
        status,
        reproduced_by_second_maintainer,
        comparisons,
        reasons,
    }
}

pub fn write_report(
    directory: &Path,
    report: &BenchmarkReport,
    conclusion: &PerformanceConclusion,
) -> Result<()> {
    fs::create_dir_all(directory)?;
    fs::write(
        directory.join("summary.json"),
        serde_json::to_vec_pretty(&(report, conclusion))?,
    )?;
    let mut markdown = format!(
        "# auditd 对照基准报告\n\n- 协议版本：{}\n- 状态：`{:?}`\n- 有效样本：{}\n- 非有效样本：{}\n\n## 原始数据\n",
        report.protocol_version, conclusion.status, report.valid_samples, report.invalid_samples
    );
    for artifact in &report.raw_artifacts {
        markdown.push_str(&format!("- `{artifact}`\n"));
    }
    markdown.push_str("\n## 门禁原因\n");
    if conclusion.reasons.is_empty() {
        markdown.push_str("- 全部协议门禁通过。\n");
    } else {
        for reason in &conclusion.reasons {
            markdown.push_str(&format!("- {reason}\n"));
        }
    }
    fs::write(directory.join("report.md"), markdown)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 没有第二维护者复现绝不通过() {
        let report = build_report(Vec::new());
        let comparisons = ["syscall", "path", "mixed"]
            .into_iter()
            .map(|scenario| ScenarioComparison {
                scenario: scenario.into(),
                cpu_improvement: 0.2,
                throughput_improvement: 0.1,
                p95_latency_improvement: 0.1,
            })
            .collect();
        assert_eq!(
            assess_performance(&report, comparisons, false).status,
            ReportStatus::Failed
        );
    }
}
