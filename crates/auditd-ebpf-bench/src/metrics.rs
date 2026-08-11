//! perf、进程、系统与日志队列指标采集。

use std::{collections::BTreeMap, fs, path::Path, process::Command};

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub perf: BTreeMap<String, f64>,
    pub process_rss_kib: u64,
    pub system_load_one: f64,
    pub journal_bytes: u64,
    pub rsyslog_queue_bytes: u64,
}

pub fn parse_perf_csv(input: &str) -> BTreeMap<String, f64> {
    input
        .lines()
        .filter_map(|line| {
            let columns: Vec<_> = line.split(',').collect();
            let value = columns.first()?.trim().replace(',', "").parse().ok()?;
            let name = columns.get(2)?.trim();
            (!name.is_empty()).then(|| (name.to_owned(), value))
        })
        .collect()
}

pub fn collect(pid: u32, perf_csv: &str, rsyslog_queue: &Path) -> Result<MetricsSnapshot> {
    let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
    let process_rss_kib = status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let system_load_one = fs::read_to_string("/proc/loadavg")?
        .split_whitespace()
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0.0);
    let journal_bytes = Command::new("journalctl")
        .arg("--disk-usage")
        .output()
        .ok()
        .and_then(|output| first_number(&String::from_utf8_lossy(&output.stdout)))
        .unwrap_or(0);
    Ok(MetricsSnapshot {
        perf: parse_perf_csv(perf_csv),
        process_rss_kib,
        system_load_one,
        journal_bytes,
        rsyslog_queue_bytes: directory_bytes(rsyslog_queue),
    })
}

fn first_number(value: &str) -> Option<u64> {
    value.split_whitespace().find_map(|part| part.parse().ok())
}

fn directory_bytes(path: &Path) -> u64 {
    fs::read_dir(path)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|entry| entry.metadata().ok())
        .map(|metadata| metadata.len())
        .sum()
}

#[cfg(test)]
mod tests {
    use super::parse_perf_csv;

    #[test]
    fn 解析perf机器格式并保留指标名() {
        let parsed = parse_perf_csv("1000,,cycles,1,100.0\n20,,context-switches,1,100.0\n");
        assert_eq!(parsed["cycles"], 1000.0);
        assert_eq!(parsed["context-switches"], 20.0);
    }
}
