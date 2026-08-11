//! 可直接运行的确定性 workload。
//!
//! 这里测量的是业务操作本身；审计代理的 CPU/RSS 与事件正确性由外层 runner 独立采集，
//! 避免在热路径中加入日志或全局锁而污染结果。

use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::PathBuf,
    process::Command,
    thread,
    time::{Duration, Instant},
};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::cli::ScenarioArg;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkloadResult {
    pub scenario: String,
    pub seed: u64,
    pub threads: u16,
    pub duration_seconds: f64,
    pub operations: u64,
    pub failures: u64,
    pub operations_per_second: f64,
    pub p50_latency_us: f64,
    pub p95_latency_us: f64,
    pub p99_latency_us: f64,
}

pub fn execute(
    scenario: ScenarioArg,
    duration_seconds: u64,
    threads: u16,
    seed: u64,
) -> Result<WorkloadResult> {
    let start = Instant::now();
    let deadline = start + Duration::from_secs(duration_seconds);
    let mut handles = Vec::with_capacity(threads as usize);
    for thread_index in 0..threads {
        handles.push(thread::spawn(move || {
            run_thread(
                scenario,
                deadline,
                seed ^ u64::from(thread_index),
                thread_index,
            )
        }));
    }
    let mut operations = 0;
    let mut failures = 0;
    let mut latencies = Vec::new();
    for handle in handles {
        let result = handle
            .join()
            .map_err(|_| anyhow::anyhow!("workload 线程 panic"))??;
        operations += result.0;
        failures += result.1;
        latencies.extend(result.2);
    }
    let elapsed = start.elapsed().as_secs_f64();
    latencies.sort_unstable();
    Ok(WorkloadResult {
        scenario: format!("{scenario:?}").to_lowercase(),
        seed,
        threads,
        duration_seconds: elapsed,
        operations,
        failures,
        operations_per_second: operations as f64 / elapsed,
        p50_latency_us: percentile(&latencies, 0.50),
        p95_latency_us: percentile(&latencies, 0.95),
        p99_latency_us: percentile(&latencies, 0.99),
    })
}

fn run_thread(
    scenario: ScenarioArg,
    deadline: Instant,
    seed: u64,
    thread_index: u16,
) -> Result<(u64, u64, Vec<u64>)> {
    let root = PathBuf::from(format!(
        "/tmp/auditd-ebpf-bench-{}-{thread_index}",
        std::process::id()
    ));
    fs::create_dir_all(&root)?;
    let mut sequence = 0_u64;
    let mut failures = 0_u64;
    let mut latencies = Vec::with_capacity(65_536);
    while Instant::now() < deadline {
        let operation_start = Instant::now();
        let result = match scenario {
            ScenarioArg::Syscall => syscall_operation(sequence ^ seed),
            ScenarioArg::Path => path_operation(&root, sequence),
            ScenarioArg::Mixed => match sequence % 10 {
                0..=4 => syscall_operation(sequence ^ seed),
                5..=7 => path_operation(&root, sequence),
                _ => exec_operation(),
            },
        };
        if result.is_err() {
            failures += 1;
        }
        if latencies.len() < 1_000_000 {
            latencies.push(
                operation_start
                    .elapsed()
                    .as_micros()
                    .min(u128::from(u64::MAX)) as u64,
            );
        }
        sequence += 1;
    }
    let _ = fs::remove_dir_all(root);
    Ok((sequence, failures, latencies))
}

fn syscall_operation(value: u64) -> Result<()> {
    let mut bytes = value.to_le_bytes();
    // SAFETY: getpid 不接收指针且没有前置条件；这里只为确保产生真实 syscall。
    unsafe { libc::getpid() };
    let mut sink = std::io::sink();
    sink.write_all(&bytes)?;
    std::io::empty().read_exact(&mut bytes[..0])?;
    Ok(())
}

fn path_operation(root: &std::path::Path, sequence: u64) -> Result<()> {
    let path = root.join(format!("entry-{}", sequence % 128));
    let renamed = root.join(format!("renamed-{}", sequence % 128));
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&path)?;
    file.write_all(b"auditd-ebpf-bench")?;
    drop(file);
    fs::rename(&path, &renamed)?;
    fs::remove_file(renamed)?;
    Ok(())
}

fn exec_operation() -> Result<()> {
    let status = Command::new("/usr/bin/true").status()?;
    anyhow::ensure!(status.success(), "true 命令失败");
    Ok(())
}

fn percentile(sorted: &[u64], percentile: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let index = ((sorted.len() - 1) as f64 * percentile).round() as usize;
    sorted[index] as f64
}

#[cfg(test)]
mod tests {
    use super::percentile;

    #[test]
    fn 百分位使用固定最近秩() {
        assert_eq!(percentile(&[1, 2, 3, 4, 5], 0.95), 5.0);
    }
}
