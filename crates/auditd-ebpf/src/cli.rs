use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum DeploymentMode {
    NonProduction,
    Production,
}

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
        config: Option<PathBuf>,
        #[arg(long)]
        node_name: Option<String>,
        #[arg(long, default_value = "/var/lib/auditd-ebpf/lifecycle.toml")]
        lifecycle_state_file: PathBuf,
        #[arg(long, value_enum, default_value = "non-production")]
        deployment_mode: DeploymentMode,
        #[arg(long)]
        risk_acceptance_file: Option<PathBuf>,
        #[arg(long)]
        ebpf_object: Option<PathBuf>,
        #[arg(long, default_value = "/etc/audit/rules.d")]
        rules_dir: PathBuf,
        #[arg(long, conflicts_with = "no_emit_argv")]
        emit_argv: bool,
        #[arg(long, conflicts_with = "emit_argv")]
        no_emit_argv: bool,
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
    PrintPolicyDigest {
        #[arg(long)]
        value_only: bool,
    },
    PrintCapabilities,
    BenchmarkInfo,
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{Cli, Command};

    #[test]
    fn argv开关默认继承配置且显式关闭可解析() {
        let cli = Cli::try_parse_from(["auditd-ebpf", "run", "--no-emit-argv"]).unwrap();
        let Some(Command::Run {
            emit_argv,
            no_emit_argv,
            ..
        }) = cli.command
        else {
            panic!("应解析为 run 子命令");
        };
        assert!(!emit_argv);
        assert!(no_emit_argv);
    }

    #[test]
    fn argv开启和关闭不能同时指定() {
        assert!(
            Cli::try_parse_from(["auditd-ebpf", "run", "--emit-argv", "--no-emit-argv"]).is_err()
        );
    }
}
