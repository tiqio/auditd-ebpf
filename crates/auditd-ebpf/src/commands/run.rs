use std::path::Path;

use crate::{
    cli::DeploymentMode,
    config::{load::load_toml, model::Config},
};

pub struct RunOptions<'a> {
    pub config_path: Option<&'a Path>,
    pub node_name: Option<&'a str>,
    pub lifecycle_path: &'a Path,
    pub deployment_mode: DeploymentMode,
    pub risk_acceptance_path: Option<&'a Path>,
    pub ebpf_object: Option<&'a Path>,
    pub rules_dir: &'a Path,
    pub emit_argv: bool,
    pub no_emit_argv: bool,
}

pub fn run(options: RunOptions<'_>) -> i32 {
    let file_layer = match options.config_path.map(load_toml).transpose() {
        Ok(layer) => layer,
        Err(error) => {
            eprintln!(
                "type=AUDITD_EBPF_DIAG level=error code=config_invalid component=config message={error:?}"
            );
            return 2;
        }
    };
    let mut config = match Config::merge(Config::default(), file_layer.iter()) {
        Ok(config) => config,
        Err(error) => {
            eprintln!(
                "type=AUDITD_EBPF_DIAG level=error code=config_invalid component=config message={error:?}"
            );
            return 2;
        }
    };
    // 两个 CLI 开关互斥且仅在显式出现时覆盖配置文件；未指定时保留默认开启语义。
    if options.emit_argv {
        config.argv_enabled = true;
    } else if options.no_emit_argv {
        config.argv_enabled = false;
    }
    if options.deployment_mode == DeploymentMode::Production {
        let Some(path) = options.risk_acceptance_path else {
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
    crate::runtime::run(
        options.node_name,
        options.lifecycle_path,
        options.ebpf_object,
        options.rules_dir,
        config.argv_enabled,
        &config.argv_rules,
    )
}
