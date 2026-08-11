use std::path::PathBuf;

use auditd_ebpf::config::model::{
    ArgvConfigLayer, ArgvRuleConfig, Config, ConfigLayer, EffectiveConfig,
};

#[test]
fn higher_precedence_overrides_lower_layers() {
    let defaults = Config::default();
    let file = ConfigLayer {
        node_name: Some("file-node".into()),
        ..ConfigLayer::default()
    };
    let cli = ConfigLayer {
        node_name: Some("cli-node".into()),
        ..ConfigLayer::default()
    };
    let effective =
        EffectiveConfig::merge(defaults, [&file, &ConfigLayer::default(), &cli]).unwrap();
    assert_eq!(effective.node_name.as_deref(), Some("cli-node"));
    assert_eq!(
        effective.lifecycle_state_file,
        PathBuf::from("/var/lib/auditd-ebpf/lifecycle.toml")
    );
}

#[test]
fn rejects_queue_and_ring_capacity_out_of_range() {
    let layer = ConfigLayer {
        ring_buffer_bytes: Some(123),
        ..ConfigLayer::default()
    };
    assert!(EffectiveConfig::merge(Config::default(), [&layer]).is_err());
}

#[test]
fn argv全局和按key策略按层覆盖() {
    let file = ConfigLayer {
        argv: Some(ArgvConfigLayer {
            enabled: Some(false),
            rules: [("full-command".into(), ArgvRuleConfig { enabled: true })]
                .into_iter()
                .collect(),
        }),
        ..ConfigLayer::default()
    };

    let effective = EffectiveConfig::merge(Config::default(), [&file]).unwrap();
    assert!(!effective.argv_enabled);
    assert!(effective.argv_rules["full-command"]);
}

#[test]
fn argv策略toml结构可严格解析() {
    let layer: ConfigLayer =
        toml::from_str("[argv]\nenabled = false\n[argv.rules.full-command]\nenabled = true\n")
            .unwrap();
    let effective = EffectiveConfig::merge(Config::default(), [&layer]).unwrap();

    assert!(!effective.argv_enabled);
    assert!(effective.argv_rules["full-command"]);
    assert!(toml::from_str::<ConfigLayer>("[argv]\nunknown = true\n").is_err());
}
