use std::{collections::BTreeMap, path::PathBuf};

use serde::Deserialize;
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct Config {
    pub node_name: Option<String>,
    pub lifecycle_state_file: PathBuf,
    pub ring_buffer_bytes: usize,
    pub queue_initial_bytes: usize,
    pub queue_max_bytes: usize,
    pub argv_enabled: bool,
    pub argv_rules: BTreeMap<String, bool>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            node_name: None,
            lifecycle_state_file: PathBuf::from("/var/lib/auditd-ebpf/lifecycle.toml"),
            ring_buffer_bytes: 16 * 1024 * 1024,
            queue_initial_bytes: 64 * 1024 * 1024,
            queue_max_bytes: 512 * 1024 * 1024,
            argv_enabled: true,
            argv_rules: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigLayer {
    pub node_name: Option<String>,
    pub lifecycle_state_file: Option<PathBuf>,
    pub ring_buffer_bytes: Option<usize>,
    pub queue_initial_bytes: Option<usize>,
    pub queue_max_bytes: Option<usize>,
    pub argv: Option<ArgvConfigLayer>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArgvConfigLayer {
    pub enabled: Option<bool>,
    #[serde(default)]
    pub rules: BTreeMap<String, ArgvRuleConfig>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArgvRuleConfig {
    pub enabled: bool,
}

pub type EffectiveConfig = Config;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConfigError {
    #[error("node_name 不能为空")]
    EmptyNodeName,
    #[error("RingBuf 容量必须为 1–256 MiB 范围内的 2 的幂")]
    InvalidRingCapacity,
    #[error("队列容量必须满足 16 MiB <= initial <= max <= 4 GiB")]
    InvalidQueueCapacity,
}

impl Config {
    pub fn merge<'a>(
        mut current: Self,
        layers: impl IntoIterator<Item = &'a ConfigLayer>,
    ) -> Result<Self, ConfigError> {
        for layer in layers {
            if let Some(value) = &layer.node_name {
                current.node_name = Some(value.clone());
            }
            if let Some(value) = &layer.lifecycle_state_file {
                current.lifecycle_state_file = value.clone();
            }
            if let Some(value) = layer.ring_buffer_bytes {
                current.ring_buffer_bytes = value;
            }
            if let Some(value) = layer.queue_initial_bytes {
                current.queue_initial_bytes = value;
            }
            if let Some(value) = layer.queue_max_bytes {
                current.queue_max_bytes = value;
            }
            if let Some(argv) = &layer.argv {
                if let Some(enabled) = argv.enabled {
                    current.argv_enabled = enabled;
                }
                for (key, policy) in &argv.rules {
                    current.argv_rules.insert(key.clone(), policy.enabled);
                }
            }
        }
        current.validate()?;
        Ok(current)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self
            .node_name
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(ConfigError::EmptyNodeName);
        }
        if !self.ring_buffer_bytes.is_power_of_two()
            || !(1024 * 1024..=256 * 1024 * 1024).contains(&self.ring_buffer_bytes)
        {
            return Err(ConfigError::InvalidRingCapacity);
        }
        if self.queue_initial_bytes < 16 * 1024 * 1024
            || self.queue_initial_bytes > self.queue_max_bytes
            || self.queue_max_bytes > 4 * 1024 * 1024 * 1024usize
        {
            return Err(ConfigError::InvalidQueueCapacity);
        }
        Ok(())
    }
}
