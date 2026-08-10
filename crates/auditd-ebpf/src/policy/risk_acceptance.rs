use std::{fs, os::unix::fs::MetadataExt, path::Path};

use anyhow::{Context, bail};

use super::model::RiskAcceptance;

pub fn load_trusted(path: &Path) -> anyhow::Result<RiskAcceptance> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("无法读取 {}", path.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
    {
        bail!("风险接受文件必须为 root 所有、普通文件且 group/other 不可写");
    }
    let bytes = fs::read(path)?;
    if bytes.len() > 64 * 1024 {
        bail!("风险接受文件超过 64 KiB");
    }
    let record: RiskAcceptance = toml::from_slice(&bytes)?;
    if record.record_version != 1 || record.policy_digest_version != 1 {
        bail!("未知风险接受版本");
    }
    Ok(record)
}
