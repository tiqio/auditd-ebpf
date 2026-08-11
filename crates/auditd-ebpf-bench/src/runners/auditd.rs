//! 传统 auditd 的可恢复控制器。

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result};

use super::checked_output;

#[derive(Debug, Clone)]
pub struct AuditdRunner {
    pub auditd_config: PathBuf,
    pub rules_file: PathBuf,
    pub backup_dir: PathBuf,
}

impl AuditdRunner {
    /// 在修改系统配置前保存原始字节，恢复时不重写或规范化管理员配置。
    pub fn backup(&self) -> Result<()> {
        fs::create_dir_all(&self.backup_dir)?;
        copy_if_exists(&self.auditd_config, &self.backup_dir.join("auditd.conf"))?;
        copy_if_exists(&self.rules_file, &self.backup_dir.join("audit.rules"))?;
        Ok(())
    }

    pub fn install_rules(&self, benchmark_rules: &Path) -> Result<()> {
        fs::copy(benchmark_rules, &self.rules_file)
            .with_context(|| format!("安装基准规则 {}", benchmark_rules.display()))?;
        checked_output(Command::new("auditctl").arg("-D"))?;
        checked_output(Command::new("auditctl").arg("-R").arg(&self.rules_file))?;
        Ok(())
    }

    pub fn start(&self) -> Result<()> {
        checked_output(Command::new("systemctl").args(["start", "auditd.service"]))?;
        Ok(())
    }

    pub fn stop(&self) -> Result<()> {
        checked_output(Command::new("systemctl").args(["stop", "auditd.service"]))?;
        Ok(())
    }

    pub fn collect_raw(&self, output_path: &Path) -> Result<()> {
        let output = checked_output(Command::new("ausearch").args(["--raw", "-ts", "boot"]))?;
        fs::write(output_path, output.stdout)?;
        Ok(())
    }

    /// 无论基准成功与否，调用方都应在 finally/Drop 等价路径执行恢复。
    pub fn restore(&self) -> Result<()> {
        restore_if_exists(&self.backup_dir.join("auditd.conf"), &self.auditd_config)?;
        restore_if_exists(&self.backup_dir.join("audit.rules"), &self.rules_file)?;
        checked_output(Command::new("systemctl").args(["restart", "auditd.service"]))?;
        Ok(())
    }
}

fn copy_if_exists(source: &Path, destination: &Path) -> Result<()> {
    if source.exists() {
        fs::copy(source, destination)?;
    }
    Ok(())
}

fn restore_if_exists(source: &Path, destination: &Path) -> Result<()> {
    if source.exists() {
        fs::copy(source, destination)?;
    }
    Ok(())
}
