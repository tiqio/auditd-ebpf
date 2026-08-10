use std::process::Command;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "cargo xtask",
    version,
    about = "auditd-ebpf 构建与特权测试工具"
)]
pub struct Cli {
    #[command(subcommand)]
    command: XtaskCommand,
}

#[derive(Debug, Subcommand)]
enum XtaskCommand {
    /// 使用固定 nightly 和 bpf-linker 构建 eBPF 程序。
    BuildEbpf {
        #[arg(long)]
        release: bool,
    },
    /// 构建用户态 workspace。
    Build {
        #[arg(long)]
        release: bool,
    },
    /// 运行指定内核版本的特权测试骨架。
    TestKernel {
        #[arg(long)]
        kernel: Option<String>,
    },
}

impl Cli {
    pub fn run(self) -> anyhow::Result<()> {
        match self.command {
            XtaskCommand::BuildEbpf { release } => build_ebpf(release),
            XtaskCommand::Build { release } => cargo_build(release),
            XtaskCommand::TestKernel { kernel } => {
                println!(
                    "特权测试驱动尚未实现，目标内核={}",
                    kernel.as_deref().unwrap_or("host")
                );
                Ok(())
            }
        }
    }
}

fn cargo_build(release: bool) -> anyhow::Result<()> {
    let mut command = Command::new("cargo");
    command.args(["build", "--workspace", "--exclude", "auditd-ebpf-ebpf"]);
    if release {
        command.arg("--release");
    }
    run(&mut command)
}

fn build_ebpf(release: bool) -> anyhow::Result<()> {
    let mut command = Command::new("cargo");
    command.env("RUSTUP_TOOLCHAIN", "nightly-2026-08-06").args([
        "build",
        "-p",
        "auditd-ebpf-ebpf",
        "--target",
        "bpfel-unknown-none",
        "-Z",
        "build-std=core",
    ]);
    if release {
        command.arg("--release");
    }
    run(&mut command).context("eBPF 构建失败；请确认 nightly、rust-src 和 bpf-linker 已安装")
}

fn run(command: &mut Command) -> anyhow::Result<()> {
    let status = command.status().context("无法启动子命令")?;
    if !status.success() {
        bail!("子命令以 {status} 退出");
    }
    Ok(())
}
