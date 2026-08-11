use std::{
    collections::BTreeMap,
    path::Path,
    process::Command,
    time::{Duration, Instant},
};

use anyhow::{Context, bail};
use auditd_ebpf::{
    collector::decode::{KernelRecord, decode_owned},
    loader::LoadedBpf,
};
use auditd_ebpf_rules::{RuleCompiler, parse_rules};
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
    let rules = parse_rules(
        "kernel-smoke.rules",
        "-a always,exit -F arch=b64 -S execve -k kernel-smoke\n",
    )?;
    let plan = RuleCompiler::compile(rules, 0, BTreeMap::new())?;
    let expected_version = u64::from_le_bytes(plan.version_hash[..8].try_into().unwrap());
    let mut loaded = LoadedBpf::load(object)?;
    loaded.stage_rules(&plan)?;
    loaded.attach_collection_programs()?;
    let mut ring = loaded.take_ring()?;

    Command::new("/bin/true")
        .status()
        .context("无法触发 execve smoke 事件")?;
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut saw_syscall = false;
    let mut saw_attempt = false;
    let mut saw_result = false;
    while Instant::now() < deadline && !(saw_syscall && saw_attempt && saw_result) {
        while let Some(item) = ring.next() {
            match decode_owned(&item)? {
                KernelRecord::Syscall(event)
                    if event.syscall_nr == 59
                        && event.return_value >= 0
                        && event.header.rule_version == expected_version =>
                {
                    saw_syscall = true;
                }
                KernelRecord::ExecAttempt(event)
                    if event.header.rule_version == expected_version && event.argc_captured > 0 =>
                {
                    saw_attempt = true;
                }
                KernelRecord::ExecResult(event)
                    if event.header.rule_version == expected_version && event.result >= 0 =>
                {
                    saw_result = true;
                }
                _ => {}
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if !(saw_syscall && saw_attempt && saw_result) {
        bail!("内核采集不完整 syscall={saw_syscall} attempt={saw_attempt} result={saw_result}");
    }
    println!(
        "内核采集 PASS kernel={} rule_version={expected_version}",
        release.trim()
    );
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
