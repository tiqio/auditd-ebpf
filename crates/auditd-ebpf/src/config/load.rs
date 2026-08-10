use std::{fs, path::Path};

use anyhow::Context;

use super::model::ConfigLayer;

pub fn load_toml(path: &Path) -> anyhow::Result<ConfigLayer> {
    let content =
        fs::read_to_string(path).with_context(|| format!("无法读取配置 {}", path.display()))?;
    toml::from_str(&content).context("配置 TOML 无效或包含未知键")
}
