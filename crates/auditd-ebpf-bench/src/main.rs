use anyhow::Result;
use auditd_ebpf_bench::{cli::Cli, environment};
use clap::Parser;

fn main() -> Result<()> {
    let cli = Cli::parse();
    let output = cli.output.clone();
    let environment = environment::collect()?;
    std::fs::create_dir_all(&output)?;
    std::fs::write(
        output.join("environment.json"),
        serde_json::to_vec_pretty(&environment)?,
    )?;
    let config: auditd_ebpf_bench::model::BenchmarkConfig = cli.into();
    println!(
        "benchmark protocol={} scenario={:?} mode={:?} samples={} seed={} environment={}",
        auditd_ebpf_bench::model::BENCHMARK_PROTOCOL_VERSION,
        config.scenario,
        config.mode,
        config.samples,
        config.seed,
        output.join("environment.json").display()
    );
    Ok(())
}
