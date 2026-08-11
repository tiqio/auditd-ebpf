//! 最终性能证据的主机资格门禁。
//!
//! 主机是否真正隔离无法仅靠程序推断，因此除了机器状态外，还要求运维人员显式设置
//! `AUDITD_EBPF_BENCH_ISOLATED=1`。缺少任何证据时失败关闭。

use std::{fs, process::Command};

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QualificationInput {
    pub operator_attested_isolation: bool,
    pub cpu_count: usize,
    pub load_one: f64,
    pub governors: Vec<String>,
    pub interfering_services: Vec<String>,
    pub virtualization: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostQualification {
    pub qualified: bool,
    pub input: QualificationInput,
    pub issues: Vec<String>,
}

pub fn evaluate(input: QualificationInput) -> HostQualification {
    let mut issues = Vec::new();
    if !input.operator_attested_isolation {
        issues.push("缺少 AUDITD_EBPF_BENCH_ISOLATED=1 运维隔离声明".into());
    }
    if input.cpu_count == 0 || input.load_one > input.cpu_count as f64 * 0.25 {
        issues.push(format!(
            "背景负载过高: load1={:.2}, cpus={}",
            input.load_one, input.cpu_count
        ));
    }
    if input.governors.is_empty() {
        issues.push("无法读取 CPU governor，环境证据不完整".into());
    } else if input.governors.iter().any(|value| value != "performance") {
        issues.push(format!(
            "CPU governor 不是全 performance: {:?}",
            input.governors
        ));
    }
    if !input.interfering_services.is_empty() {
        issues.push(format!(
            "存在干扰服务: {}",
            input.interfering_services.join(",")
        ));
    }
    HostQualification {
        qualified: issues.is_empty(),
        input,
        issues,
    }
}

pub fn collect() -> Result<HostQualification> {
    let cpu_count = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(0);
    let load_one = fs::read_to_string("/proc/loadavg")?
        .split_whitespace()
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or(f64::INFINITY);
    Ok(evaluate(QualificationInput {
        operator_attested_isolation: std::env::var("AUDITD_EBPF_BENCH_ISOLATED").as_deref()
            == Ok("1"),
        cpu_count,
        load_one,
        governors: governors(),
        interfering_services: interfering_services(),
        virtualization: command_output("systemd-detect-virt").unwrap_or_else(|| "unknown".into()),
    }))
}

fn governors() -> Vec<String> {
    let mut values = Vec::new();
    if let Ok(cpus) = fs::read_dir("/sys/devices/system/cpu") {
        for cpu in cpus.flatten() {
            let path = cpu.path().join("cpufreq/scaling_governor");
            if let Ok(value) = fs::read_to_string(path) {
                let value = value.trim().to_owned();
                if !values.contains(&value) {
                    values.push(value);
                }
            }
        }
    }
    values.sort();
    values
}

fn interfering_services() -> Vec<String> {
    [
        "unattended-upgrades.service",
        "apt-daily.service",
        "apt-daily-upgrade.service",
    ]
    .into_iter()
    .filter(|service| {
        Command::new("systemctl")
            .args(["is-active", "--quiet", service])
            .status()
            .is_ok_and(|status| status.success())
    })
    .map(str::to_owned)
    .collect()
}

fn command_output(program: &str) -> Option<String> {
    let output = Command::new(program).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clean(attested: bool) -> QualificationInput {
        QualificationInput {
            operator_attested_isolation: attested,
            cpu_count: 8,
            load_one: 0.1,
            governors: vec!["performance".into()],
            interfering_services: Vec::new(),
            virtualization: "kvm".into(),
        }
    }

    #[test]
    fn 缺少人工隔离声明必须失败关闭() {
        assert!(!evaluate(clean(false)).qualified);
    }

    #[test]
    fn 全部隔离条件满足才通过() {
        assert!(evaluate(clean(true)).qualified);
    }
}
