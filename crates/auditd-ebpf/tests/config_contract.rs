use std::path::PathBuf;

use auditd_ebpf::config::model::{Config, ConfigLayer, EffectiveConfig};

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
