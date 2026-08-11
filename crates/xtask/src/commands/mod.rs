use std::{
    collections::BTreeMap,
    fs,
    path::Path,
    process::Command,
    time::{Duration, Instant},
};

use anyhow::{Context, bail};
use auditd_ebpf::{
    collector::decode::{KernelRecord, decode_owned},
    loader::LoadedBpf,
};
use auditd_ebpf_common::event::{
    EXEC_ARGV_FLAG_ARGC_TRUNCATED, EXEC_ARGV_FLAG_ARGUMENT_TRUNCATED, PROCESS_EVENT_EXEC,
    PROCESS_EVENT_EXIT, PROCESS_EVENT_FORK,
};
use auditd_ebpf_rules::{ArgvOutput, RuleCompiler, parse_rules};
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
    cargo_build(false)?;
    let object = Path::new("target/bpfel-unknown-none/release/auditd-ebpf-ebpf");
    let rules = parse_rules(
        "kernel-smoke.rules",
        "-a always,exit -F arch=b64 -S execve,openat,82,264,316,87,263,80,161,165,166,308,272,155,429,442 -k kernel-smoke\n",
    )?;
    let plan = RuleCompiler::compile(
        rules,
        0,
        BTreeMap::from([("kernel-smoke".to_owned(), ArgvOutput::Disabled)]),
    )?;
    let expected_version = u64::from_le_bytes(plan.version_hash[..8].try_into().unwrap());
    let mut loaded = LoadedBpf::load(object)?;
    loaded.stage_rules(&plan)?;
    loaded.attach_collection_programs()?;
    let mut ring = loaded.take_ring()?;

    Command::new("/bin/true")
        .status()
        .context("无法触发 execve smoke 事件")?;
    Command::new("/bin/true")
        .args((0..32).map(|index| format!("arg-{index}")))
        .status()
        .context("无法触发 32 参数 execve")?;
    Command::new("/bin/true")
        .arg("x".repeat(300))
        .status()
        .context("无法触发长参数 execve")?;
    let _ = Command::new("/definitely/missing/auditd-ebpf-smoke").status();
    let original_cwd = std::env::current_dir()?;
    let path_root = std::env::temp_dir().join(format!("auditd-ebpf-kernel-{}", std::process::id()));
    fs::create_dir_all(&path_root)?;
    fs::write(path_root.join("absolute"), b"absolute")?;
    std::env::set_current_dir(&path_root)?;
    fs::write("relative", b"relative")?;
    fs::rename("relative", "renamed")?;
    fs::remove_file("renamed")?;
    std::env::set_current_dir(&original_cwd)?;
    if Command::new("python3").arg("--version").output().is_ok() {
        let script = format!(
            "import os; fd=os.open({root:?}, os.O_RDONLY); child=os.open('dirfd-file', os.O_CREAT|os.O_WRONLY, 0o600, dir_fd=fd); os.close(child); os.unlink('dirfd-file', dir_fd=fd); os.close(fd)",
            root = path_root
        );
        Command::new("python3").arg("-c").arg(script).status()?;
    }
    fs::remove_file(path_root.join("absolute"))?;
    fs::remove_dir(&path_root)?;

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut saw_syscall = false;
    let mut saw_attempt = false;
    let mut saw_result = false;
    let mut saw_failed_result = false;
    let mut saw_argc_truncation = false;
    let mut saw_argument_truncation = false;
    let mut saw_fork = false;
    let mut saw_process_exec = false;
    let mut saw_exit = false;
    let mut saw_path = false;
    while Instant::now() < deadline
        && !(saw_syscall
            && saw_attempt
            && saw_result
            && saw_failed_result
            && saw_argc_truncation
            && saw_argument_truncation
            && saw_fork
            && saw_process_exec
            && saw_exit
            && saw_path)
    {
        while let Some(item) = ring.next() {
            match decode_owned(&item)? {
                KernelRecord::Syscall(event)
                    if event.syscall_nr == 59
                        && event.return_value >= 0
                        && event.header.rule_version == expected_version =>
                {
                    saw_syscall = true;
                }
                KernelRecord::Syscall(event)
                    if event.header.rule_version == expected_version
                        && event.return_value >= 0
                        && event.path_len > 0 =>
                {
                    saw_path = true;
                }
                KernelRecord::ExecAttempt(event)
                    if event.header.rule_version == expected_version && event.argc_captured > 0 =>
                {
                    saw_attempt = true;
                    saw_argc_truncation |= event.argv_flags & EXEC_ARGV_FLAG_ARGC_TRUNCATED != 0
                        && event.argc_captured == 32;
                    saw_argument_truncation |=
                        event.argv_flags & EXEC_ARGV_FLAG_ARGUMENT_TRUNCATED != 0;
                }
                KernelRecord::ExecResult(event)
                    if event.header.rule_version == expected_version && event.result >= 0 =>
                {
                    saw_result = true;
                }
                KernelRecord::ExecResult(event)
                    if event.header.rule_version == expected_version && event.result < 0 =>
                {
                    saw_failed_result = true;
                }
                KernelRecord::Process(event) if event.event_kind == PROCESS_EVENT_FORK => {
                    saw_fork = true;
                }
                KernelRecord::Process(event) if event.event_kind == PROCESS_EVENT_EXEC => {
                    saw_process_exec = true;
                }
                KernelRecord::Process(event) if event.event_kind == PROCESS_EVENT_EXIT => {
                    saw_exit = true;
                }
                _ => {}
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if !(saw_syscall
        && saw_attempt
        && saw_result
        && saw_failed_result
        && saw_argc_truncation
        && saw_argument_truncation
        && saw_fork
        && saw_process_exec
        && saw_exit
        && saw_path)
    {
        bail!(
            "内核采集不完整 syscall={saw_syscall} attempt={saw_attempt} result={saw_result} failed={saw_failed_result} argc_truncated={saw_argc_truncation} arg_truncated={saw_argument_truncation} fork={saw_fork} process_exec={saw_process_exec} exit={saw_exit} path={saw_path}"
        );
    }

    Command::new("/bin/true").status()?;
    let reloaded_rules = parse_rules(
        "kernel-reloaded.rules",
        "-a always,exit -F arch=b64 -S execve,openat,82,264,316,87,263,80,161,165,166,308,272,155,429,442 -k kernel-reloaded\n",
    )?;
    let reloaded_plan = RuleCompiler::compile(
        reloaded_rules,
        1,
        BTreeMap::from([("kernel-reloaded".to_owned(), ArgvOutput::Disabled)]),
    )?;
    let reloaded_version = u64::from_le_bytes(reloaded_plan.version_hash[..8].try_into().unwrap());
    let worker = std::thread::spawn(|| {
        for _ in 0..16 {
            let _ = Command::new("/bin/true").status();
        }
    });
    std::thread::sleep(Duration::from_millis(5));
    loaded.stage_rules(&reloaded_plan)?;
    anyhow::ensure!(
        parse_rules("invalid.rules", "-a always,exit -S execve").is_err(),
        "无效候选规则必须在 staging 前失败"
    );
    Command::new("/bin/true").status()?;
    worker
        .join()
        .map_err(|_| anyhow::anyhow!("并发 exec worker panic"))?;

    let reload_deadline = Instant::now() + Duration::from_secs(5);
    let mut saw_old_version = false;
    let mut saw_new_version = false;
    while Instant::now() < reload_deadline && !(saw_old_version && saw_new_version) {
        while let Some(item) = ring.next() {
            if let KernelRecord::Syscall(event) = decode_owned(&item)?
                && event.syscall_nr == 59
            {
                match event.header.rule_version {
                    version if version == expected_version => saw_old_version = true,
                    version if version == reloaded_version => saw_new_version = true,
                    version => bail!("并发 reload 观察到非法中间 rule_version={version}"),
                }
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    anyhow::ensure!(
        saw_old_version && saw_new_version,
        "并发 reload 未同时观察到旧/新完整版本 old={saw_old_version} new={saw_new_version}"
    );
    println!(
        "内核采集 PASS kernel={} rule_version={expected_version} reloaded_version={reloaded_version}",
        release.trim(),
    );
    run(
        Command::new("tests/integration/logging_end_to_end.sh").args([
            "target/debug/auditd-ebpf",
            object.to_str().context("eBPF 对象路径不是 UTF-8")?,
        ]),
    )
    .context("US2 日志 quickstart 门禁失败")?;
    run(Command::new("tests/privileged/rule_reload.sh").args([
        "target/debug/auditd-ebpf",
        object.to_str().context("eBPF 对象路径不是 UTF-8")?,
    ]))
    .context("US1 运行时规则重载门禁失败")?;
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
