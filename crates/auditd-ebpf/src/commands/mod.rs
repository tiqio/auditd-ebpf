use clap::Parser;

use crate::{
    capabilities::{CapabilityProbe, HostProbe},
    cli::{Cli, Command},
};

mod check_production;
mod check_rules;
mod print_policy_digest;
mod run;

pub fn execute() -> i32 {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Run {
        node_name: None,
        lifecycle_state_file: "/var/lib/auditd-ebpf/lifecycle.toml".into(),
        deployment_mode: crate::cli::DeploymentMode::NonProduction,
        risk_acceptance_file: None,
        ebpf_object: None,
        rules_dir: "/etc/audit/rules.d".into(),
    }) {
        Command::Run {
            node_name,
            lifecycle_state_file,
            deployment_mode,
            risk_acceptance_file,
            ebpf_object,
            rules_dir,
        } => run::run(
            node_name.as_deref(),
            &lifecycle_state_file,
            deployment_mode,
            risk_acceptance_file.as_deref(),
            ebpf_object.as_deref(),
            &rules_dir,
        ),
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
        } => match check_production::run(&risk_acceptance_file) {
            Ok(()) => 0,
            Err(error) => {
                eprintln!(
                    "type=AUDITD_EBPF_DIAG level=error code={} component=policy message={:?}",
                    error.code, error.message
                );
                9
            }
        },
        Command::PrintPolicyDigest { value_only } => match print_policy_digest::run(value_only) {
            Ok(()) => 0,
            Err(error) => {
                eprintln!(
                    "type=AUDITD_EBPF_DIAG level=error code=policy_digest_invalid component=policy message={error:?}"
                );
                2
            }
        },
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
