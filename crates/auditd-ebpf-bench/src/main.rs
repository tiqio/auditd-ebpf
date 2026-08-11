use std::fs;

use anyhow::Result;
use auditd_ebpf_bench::{
    cli::{Cli, Command},
    environment, executor, qualification, runner,
};
use clap::Parser;
use serde::Serialize;

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Qualify { output } => {
            let result = qualification::collect()?;
            write_json(&output, &result)?;
            println!(
                "qualification={} qualified={}",
                output.display(),
                result.qualified
            );
            anyhow::ensure!(result.qualified, "当前主机未通过隔离基准资格门禁");
        }
        Command::Prepare { output } => {
            fs::create_dir_all(&output)?;
            write_json(output.join("environment.json"), &environment::collect()?)?;
            println!("environment={}", output.join("environment.json").display());
        }
        Command::Workload {
            scenario,
            duration,
            threads,
            seed,
            output,
        } => {
            let result = executor::execute(scenario, duration, threads, seed)?;
            if let Some(path) = output {
                write_json(path, &result)?;
            }
            println!("{}", serde_json::to_string(&result)?);
        }
        Command::Compare {
            scenarios,
            modes,
            repetitions,
            warmup,
            duration,
            seed,
            output,
        } => {
            fs::create_dir_all(&output)?;
            let qualification = qualification::collect()?;
            write_json(output.join("qualification.json"), &qualification)?;
            let runs = runner::schedule(seed, repetitions)?;
            let plan = serde_json::json!({
                "protocol_version": auditd_ebpf_bench::model::BENCHMARK_PROTOCOL_VERSION,
                "scenarios": scenarios.iter().map(|value| format!("{value:?}").to_lowercase()).collect::<Vec<_>>(),
                "modes": modes, "warmup_seconds": warmup, "duration_seconds": duration, "runs": runs,
                "status": if qualification.qualified { "ready" } else { "blocked" },
                "qualification_issues": qualification.issues,
                "performance_claim_allowed": false
            });
            write_json(output.join("comparison-plan.json"), &plan)?;
            println!("plan={}", output.join("comparison-plan.json").display());
            anyhow::ensure!(
                qualification.qualified,
                "当前主机未通过隔离基准资格门禁，比较计划已记录但不会执行"
            );
        }
    }
    Ok(())
}

fn write_json(path: impl AsRef<std::path::Path>, value: &impl Serialize) -> Result<()> {
    if let Some(parent) = path.as_ref().parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}
