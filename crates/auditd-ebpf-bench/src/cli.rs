//! 基准命令行契约，与 quickstart 中的命令保持一致。

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ScenarioArg {
    Syscall,
    Path,
    Mixed,
}

#[derive(Debug, Parser)]
#[command(
    name = "auditd-ebpf-bench",
    version,
    about = "auditd 与 auditd-ebpf 公平对照基准驱动"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// 验证当前主机是否满足最终性能证据的隔离条件。
    Qualify {
        #[arg(long, default_value = "benchmarks/reports/final/qualification.json")]
        output: PathBuf,
    },
    /// 采集硬件、内核、日志栈和构建版本证据。
    Prepare {
        #[arg(long, default_value = "benchmarks/reports")]
        output: PathBuf,
    },
    /// 执行不启动审计代理的确定性业务负载。
    Workload {
        #[arg(long, value_enum)]
        scenario: ScenarioArg,
        #[arg(long, default_value = "120s", value_parser = parse_duration_seconds)]
        duration: u64,
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u16).range(1..))]
        threads: u16,
        #[arg(long, default_value_t = 42)]
        seed: u64,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// 生成完整比较计划；实际运行要求 root、两种代理和隔离主机。
    Compare {
        #[arg(long, value_delimiter = ',', value_enum)]
        scenarios: Vec<ScenarioArg>,
        #[arg(long, value_delimiter = ',')]
        modes: Vec<String>,
        #[arg(long, default_value_t = 5, value_parser = parse_sample_count)]
        repetitions: usize,
        #[arg(long, default_value = "30s", value_parser = parse_duration_seconds)]
        warmup: u64,
        #[arg(long, default_value = "120s", value_parser = parse_duration_seconds)]
        duration: u64,
        #[arg(long, default_value_t = 42)]
        seed: u64,
        #[arg(long, default_value = "benchmarks/reports")]
        output: PathBuf,
    },
}

fn parse_duration_seconds(value: &str) -> Result<u64, String> {
    let raw = value.strip_suffix('s').unwrap_or(value);
    let seconds = raw.parse::<u64>().map_err(|error| error.to_string())?;
    if seconds == 0 {
        return Err("持续时间必须大于 0 秒".into());
    }
    Ok(seconds)
}

fn parse_sample_count(value: &str) -> Result<usize, String> {
    let samples = value.parse::<usize>().map_err(|error| error.to_string())?;
    if samples < 5 {
        return Err("每个场景、模式和实现至少需要 5 个样本".into());
    }
    Ok(samples)
}
