use clap::Parser;

use crate::{
    capabilities::{CapabilityProbe, HostProbe},
    cli::{Cli, Command},
};

mod check_rules;

pub fn execute() -> i32 {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Run {
        node_name: None,
        lifecycle_state_file: "/var/lib/auditd-ebpf/lifecycle.toml".into(),
    }) {
        Command::Run {
            node_name,
            lifecycle_state_file,
        } => crate::runtime::run(node_name.as_deref(), &lifecycle_state_file),
        Command::CheckRules {
            rules_file,
            rules_dir,
            print_normalized,
        } => match check_rules::run(
            rules_file.as_deref(),
            rules_dir.as_deref(),
            print_normalized,
        ) {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("type=AUDITD_EBPF_DIAG level=error code=rule_invalid message={error:?}");
                3
            }
        },
        Command::CheckProduction {
            risk_acceptance_file,
        } => {
            println!("check-production file={}", risk_acceptance_file.display());
            0
        }
        Command::PrintPolicyDigest => {
            println!("policy_digest_version=1");
            0
        }
        Command::PrintCapabilities => {
            let report = CapabilityProbe::inspect(&HostProbe::detect());
            println!(
                "arch={} kernel={} supported={}",
                report.architecture,
                report.kernel_release,
                report.supported()
            );
            if report.supported() { 0 } else { 5 }
        }
        Command::BenchmarkInfo => {
            println!(
                "schema={} aya=0.14.0 rust=1.97.1",
                auditd_ebpf_common::schema_version()
            );
            0
        }
    }
}
