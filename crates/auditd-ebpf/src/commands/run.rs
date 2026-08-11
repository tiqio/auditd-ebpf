use std::path::Path;

use crate::cli::DeploymentMode;

pub fn run(
    node_name: Option<&str>,
    lifecycle_path: &Path,
    deployment_mode: DeploymentMode,
    risk_acceptance_path: Option<&Path>,
) -> i32 {
    if deployment_mode == DeploymentMode::Production {
        let Some(path) = risk_acceptance_path else {
            eprintln!(
                "type=AUDITD_EBPF_DIAG level=error code=risk_acceptance_required component=policy message=\"production 模式必须提供风险接受文件\""
            );
            return 9;
        };
        if let Err(error) = super::check_production::run(path) {
            eprintln!(
                "type=AUDITD_EBPF_DIAG level=error code={} component=policy message={:?}",
                error.code, error.message
            );
            return 9;
        }
    }
    crate::runtime::run(node_name, lifecycle_path)
}
