use std::fs;

use anyhow::Result;
use auditd_ebpf_bench::{
    cli::{Cli, Command},
    environment, executor, runner,
};
use clap::Parser;
use serde::Serialize;

fn main() -> Result<()> {
    match Cli::parse().command {
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
            let runs = runner::schedule(seed, repetitions)?;
            let plan = serde_json::json!({
                "protocol_version": auditd_ebpf_bench::model::BENCHMARK_PROTOCOL_VERSION,
                "scenarios": scenarios.iter().map(|value| format!("{value:?}").to_lowercase()).collect::<Vec<_>>(),
                "modes": modes, "warmup_seconds": warmup, "duration_seconds": duration, "runs": runs,
                "status": "planned", "performance_claim_allowed": false
            });
            write_json(output.join("comparison-plan.json"), &plan)?;
            println!("plan={}", output.join("comparison-plan.json").display());
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
