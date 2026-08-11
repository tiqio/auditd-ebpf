//! 基准命令行契约。

use std::path::PathBuf;

use clap::{Parser, ValueEnum};

use crate::model::{BenchmarkConfig, BenchmarkMode, Scenario};

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ScenarioArg {
    Syscall,
    Path,
    Mixed,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ModeArg {
    CaptureOnly,
    Operational,
}

#[derive(Debug, Parser)]
#[command(
    name = "auditd-ebpf-bench",
    version,
    about = "auditd 与 auditd-ebpf 公平对照基准驱动"
)]
pub struct Cli {
    #[arg(long, value_enum, default_value_t = ScenarioArg::Syscall)]
    pub scenario: ScenarioArg,
    #[arg(long, value_enum, default_value_t = ModeArg::CaptureOnly)]
    pub mode: ModeArg,
    #[arg(long, default_value_t = 42)]
    pub seed: u64,
    #[arg(long, default_value_t = 5, value_parser = parse_sample_count)]
    pub samples: usize,
    #[arg(long, default_value_t = 30)]
    pub warmup_seconds: u64,
    #[arg(long, default_value_t = 120)]
    pub duration_seconds: u64,
    #[arg(long, default_value = "benchmarks/reports")]
    pub output: PathBuf,
}

fn parse_sample_count(value: &str) -> Result<usize, String> {
    let samples = value.parse::<usize>().map_err(|error| error.to_string())?;
    if samples < 5 {
        return Err("每个场景、模式和实现至少需要 5 个样本".into());
    }
    Ok(samples)
}

impl From<Cli> for BenchmarkConfig {
    fn from(value: Cli) -> Self {
        Self {
            scenario: match value.scenario {
                ScenarioArg::Syscall => Scenario::Syscall,
                ScenarioArg::Path => Scenario::Path,
                ScenarioArg::Mixed => Scenario::Mixed,
            },
            mode: match value.mode {
                ModeArg::CaptureOnly => BenchmarkMode::CaptureOnly,
                ModeArg::Operational => BenchmarkMode::Operational,
            },
            seed: value.seed,
            samples: value.samples,
            warmup_seconds: value.warmup_seconds,
            duration_seconds: value.duration_seconds,
            output: value.output,
        }
    }
}
