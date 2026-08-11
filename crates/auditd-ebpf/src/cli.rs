use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "auditd-ebpf", version, about = "Rust/Aya Linux 审计服务")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Run {
        #[arg(long)]
        node_name: Option<String>,
        #[arg(long, default_value = "/var/lib/auditd-ebpf/lifecycle.toml")]
        lifecycle_state_file: PathBuf,
    },
    CheckRules {
        #[arg(long, conflicts_with = "rules_dir")]
        rules_file: Option<PathBuf>,
        #[arg(long, conflicts_with = "rules_file")]
        rules_dir: Option<PathBuf>,
        #[arg(long)]
        print_normalized: bool,
    },
    CheckProduction {
        #[arg(long)]
        risk_acceptance_file: PathBuf,
    },
    PrintPolicyDigest,
    PrintCapabilities,
    BenchmarkInfo,
}
