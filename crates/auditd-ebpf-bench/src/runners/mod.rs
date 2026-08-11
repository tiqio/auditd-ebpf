//! 两种审计实现的进程生命周期封装。

pub mod auditd;
pub mod auditd_ebpf;

use std::process::{Command, Output};

use anyhow::{Context, Result};

/// 执行外部命令并把非零退出状态视为样本失败，而不是静默忽略。
pub(crate) fn checked_output(command: &mut Command) -> Result<Output> {
    let debug = format!("{command:?}");
    let output = command
        .output()
        .with_context(|| format!("执行命令失败: {debug}"))?;
    anyhow::ensure!(
        output.status.success(),
        "命令失败: {debug}; stderr={}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(output)
}
