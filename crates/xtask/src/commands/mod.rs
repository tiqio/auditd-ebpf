use std::{path::Path, process::Command};

use anyhow::{Context, bail};
use aya::{Ebpf, programs::RawTracePoint};
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
            XtaskCommand::TestKernel { kernel } => test_kernel(kernel.as_deref()),
        }
    }
}

fn test_kernel(kernel: Option<&str>) -> anyhow::Result<()> {
    let release = String::from_utf8(Command::new("uname").arg("-r").output()?.stdout)?;
    let requested = kernel.unwrap_or("host");
    if requested != "host" && !release.starts_with(requested) {
        bail!(
            "当前内核 {} 与请求 {} 不匹配；请在对应 VM/runner 执行",
            release.trim(),
            requested
        );
    }
    build_ebpf(true)?;
    let object = Path::new("target/bpfel-unknown-none/release/auditd-ebpf-ebpf");
    let bytes = std::fs::read(object).with_context(|| format!("无法读取 {}", object.display()))?;
    let mut bpf = Ebpf::load(&bytes).context("Aya 加载 smoke eBPF 对象失败")?;
    let program: &mut RawTracePoint = bpf
        .program_mut("auditd_sys_enter")
        .context("对象缺少 auditd_sys_enter")?
        .try_into()?;
    program.load().context("加载 raw tracepoint 失败")?;
    let link = program
        .attach("sys_enter")
        .context("挂载 raw_syscalls:sys_enter 失败")?;
    program
        .detach(link)
        .context("清理 raw tracepoint link 失败")?;
    println!("内核 smoke PASS kernel={}", release.trim());
    Ok(())
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
