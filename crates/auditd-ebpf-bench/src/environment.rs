//! 基准环境证据采集。

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::model::BENCHMARK_PROTOCOL_VERSION;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentSnapshot {
    pub protocol_version: u32,
    pub hostname: String,
    pub cpu_model: String,
    pub cpu_count: usize,
    pub memory_kib: u64,
    pub numa_nodes: usize,
    pub kernel_release: String,
    pub kernel_command_line: String,
    pub btf_sha256: Option<String>,
    pub cpu_governors: Vec<String>,
    pub process_affinity: String,
    pub git_commit: String,
    pub rust_version: String,
    pub auditd_version: Option<String>,
    pub journal_config_sha256: Option<String>,
    pub rsyslog_config_sha256: Option<String>,
}

pub fn collect() -> Result<EnvironmentSnapshot> {
    let cpuinfo = fs::read_to_string("/proc/cpuinfo").context("读取 /proc/cpuinfo")?;
    let meminfo = fs::read_to_string("/proc/meminfo").context("读取 /proc/meminfo")?;
    Ok(EnvironmentSnapshot {
        protocol_version: BENCHMARK_PROTOCOL_VERSION,
        hostname: command_output("hostname", &[]).unwrap_or_else(|_| "unknown".into()),
        cpu_model: cpuinfo
            .lines()
            .find_map(|line| line.strip_prefix("model name\t: "))
            .unwrap_or("unknown")
            .to_owned(),
        cpu_count: cpuinfo
            .lines()
            .filter(|line| line.starts_with("processor\t:"))
            .count(),
        memory_kib: meminfo
            .lines()
            .find_map(|line| line.strip_prefix("MemTotal:"))
            .and_then(|value| value.split_whitespace().next())
            .and_then(|value| value.parse().ok())
            .unwrap_or(0),
        numa_nodes: glob_count("/sys/devices/system/node", "node"),
        kernel_release: command_output("uname", &["-r"]).unwrap_or_else(|_| "unknown".into()),
        kernel_command_line: read_trimmed("/proc/cmdline").unwrap_or_else(|_| "unknown".into()),
        btf_sha256: hash_file("/sys/kernel/btf/vmlinux").ok(),
        cpu_governors: collect_governors(),
        process_affinity: command_output("taskset", &["-pc", &std::process::id().to_string()])
            .unwrap_or_else(|_| "unknown".into()),
        git_commit: command_output("git", &["rev-parse", "HEAD"])
            .unwrap_or_else(|_| "unknown".into()),
        rust_version: command_output("rustc", &["--version"]).unwrap_or_else(|_| "unknown".into()),
        auditd_version: command_output("auditd", &["-v"]).ok(),
        journal_config_sha256: hash_existing_configs(&[
            PathBuf::from("/etc/systemd/journald.conf"),
            PathBuf::from("/etc/systemd/journald.conf.d"),
        ]),
        rsyslog_config_sha256: hash_existing_configs(&[
            PathBuf::from("/etc/rsyslog.conf"),
            PathBuf::from("/etc/rsyslog.d"),
        ]),
    })
}

fn command_output(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program).args(args).output()?;
    anyhow::ensure!(
        output.status.success(),
        "{program} 退出状态为 {}",
        output.status
    );
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn read_trimmed(path: impl AsRef<Path>) -> Result<String> {
    Ok(fs::read_to_string(path)?.trim().to_owned())
}

fn hash_file(path: impl AsRef<Path>) -> Result<String> {
    let bytes = fs::read(path)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn glob_count(root: &str, prefix: &str) -> usize {
    fs::read_dir(root)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(prefix))
        .count()
}

fn collect_governors() -> Vec<String> {
    let mut governors = Vec::new();
    if let Ok(entries) = fs::read_dir("/sys/devices/system/cpu") {
        for entry in entries.flatten() {
            let path = entry.path().join("cpufreq/scaling_governor");
            if let Ok(value) = read_trimmed(path)
                && !governors.contains(&value)
            {
                governors.push(value);
            }
        }
    }
    governors.sort();
    governors
}

fn hash_existing_configs(paths: &[PathBuf]) -> Option<String> {
    let mut files = Vec::new();
    for path in paths {
        if path.is_file() {
            files.push(path.clone());
        } else if path.is_dir() {
            files.extend(
                fs::read_dir(path)
                    .ok()?
                    .flatten()
                    .map(|entry| entry.path())
                    .filter(|path| path.is_file()),
            );
        }
    }
    files.sort();
    if files.is_empty() {
        return None;
    }
    let mut digest = Sha256::new();
    for path in files {
        digest.update(path.to_string_lossy().as_bytes());
        digest.update([0]);
        digest.update(fs::read(path).ok()?);
        digest.update([0]);
    }
    Some(hex::encode(digest.finalize()))
}
