//! auditd-ebpf runner，显式区分 capture-only 与 operational sink。

use std::{
    fs::File,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};

use anyhow::{Context, Result};

use crate::model::BenchmarkMode;

#[derive(Debug, Clone)]
pub struct AuditdEbpfRunner {
    pub binary: PathBuf,
    pub config: PathBuf,
    pub rules: PathBuf,
}

impl AuditdEbpfRunner {
    pub fn start(&self, mode: BenchmarkMode, capture_path: &Path) -> Result<Child> {
        let stdout = match mode {
            BenchmarkMode::CaptureOnly => Stdio::from(File::create(capture_path)?),
            BenchmarkMode::Operational => Stdio::inherit(),
        };
        Command::new(&self.binary)
            .args([
                "--config",
                path_text(&self.config)?,
                "--rules",
                path_text(&self.rules)?,
            ])
            .stdout(stdout)
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("启动 {}", self.binary.display()))
    }

    pub fn stop_and_collect(&self, child: &mut Child, counters_path: &Path) -> Result<()> {
        let pid = child.id().to_string();
        let status = Command::new("kill").args(["-TERM", &pid]).status()?;
        anyhow::ensure!(status.success(), "向 auditd-ebpf 发送 SIGTERM 失败");
        let status = child.wait()?;
        anyhow::ensure!(status.success(), "auditd-ebpf 非正常退出: {status}");
        let journal = Command::new("journalctl")
            .args(["-u", "auditd-ebpf.service", "-b", "--no-pager", "-o", "cat"])
            .output()?;
        std::fs::write(counters_path, journal.stdout)?;
        Ok(())
    }
}

fn path_text(path: &Path) -> Result<&str> {
    path.to_str().context("路径不是有效 UTF-8")
}
