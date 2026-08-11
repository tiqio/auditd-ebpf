//! 固定随机顺序、样本配额与污染判定。

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::{
    model::{BenchmarkSample, SampleStatus},
    report::randomized_order,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduledRun {
    pub sequence: usize,
    pub implementation: String,
    pub attempt: usize,
}

pub fn schedule(seed: u64, valid_samples_per_implementation: usize) -> Result<Vec<ScheduledRun>> {
    anyhow::ensure!(
        valid_samples_per_implementation >= 5,
        "每个实现至少需要 5 个有效样本"
    );
    let count = valid_samples_per_implementation * 2;
    let mut attempts = std::collections::BTreeMap::new();
    Ok(randomized_order(seed, count)
        .into_iter()
        .enumerate()
        .map(|(sequence, implementation)| {
            let attempt = attempts.entry(implementation.clone()).or_insert(0);
            *attempt += 1;
            ScheduledRun {
                sequence,
                implementation,
                attempt: *attempt,
            }
        })
        .collect())
}

pub fn contamination_reason(
    load_one: f64,
    cpu_count: usize,
    temperature_c: Option<f64>,
) -> Option<String> {
    if cpu_count == 0 || load_one > cpu_count as f64 * 0.25 {
        return Some(format!("背景负载过高: load1={load_one:.2}"));
    }
    if temperature_c.is_some_and(|temperature| temperature >= 85.0) {
        return Some(format!(
            "CPU 温度过高: {}C",
            temperature_c.unwrap_or_default()
        ));
    }
    None
}

/// 每轮结束后无条件执行恢复；运行或恢复失败都作为可见 Failed 样本返回。
pub fn orchestrate<Run, Recover>(
    schedule: &[ScheduledRun],
    mut run: Run,
    mut recover: Recover,
) -> Vec<BenchmarkSample>
where
    Run: FnMut(&ScheduledRun) -> Result<BenchmarkSample>,
    Recover: FnMut(&ScheduledRun) -> Result<()>,
{
    schedule
        .iter()
        .map(|scheduled| {
            let run_result = run(scheduled);
            let recovery_result = recover(scheduled);
            match (run_result, recovery_result) {
                (Ok(sample), Ok(())) => sample,
                (Err(error), Ok(())) => failed_sample(scheduled, format!("runner: {error:#}")),
                (Ok(mut sample), Err(error)) => {
                    sample.status = SampleStatus::Failed(format!("恢复环境失败: {error:#}"));
                    sample
                }
                (Err(run_error), Err(recovery_error)) => failed_sample(
                    scheduled,
                    format!("runner: {run_error:#}; 恢复: {recovery_error:#}"),
                ),
            }
        })
        .collect()
}

fn failed_sample(run: &ScheduledRun, reason: String) -> BenchmarkSample {
    BenchmarkSample {
        id: format!("{}-{:02}", run.implementation, run.attempt),
        raw_path: format!("raw/{}-{:02}.json", run.implementation, run.attempt),
        status: SampleStatus::Failed(reason),
        operations_per_second: 0.0,
        agent_cpu_percent: 0.0,
        p95_latency_us: 0.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 每种实现至少五次且顺序可复现() {
        let runs = schedule(42, 5).unwrap();
        assert_eq!(runs, schedule(42, 5).unwrap());
        assert_eq!(
            runs.iter()
                .filter(|run| run.implementation == "auditd")
                .count(),
            5
        );
        assert!(schedule(42, 4).is_err());
    }

    #[test]
    fn 失败样本和恢复失败都不会被隐藏() {
        let runs = schedule(42, 5).unwrap();
        let samples = orchestrate(
            &runs[..1],
            |_| anyhow::bail!("boom"),
            |_| anyhow::bail!("restore"),
        );
        assert!(matches!(samples[0].status, SampleStatus::Failed(_)));
    }
}
