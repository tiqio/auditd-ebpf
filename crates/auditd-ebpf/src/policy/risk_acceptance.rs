use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

use anyhow::{Context, bail};

use super::model::RiskAcceptance;

pub fn load_trusted(path: &Path) -> anyhow::Result<RiskAcceptance> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("无法安全打开 {}", path.display()))?;
    verify(&file.metadata()?)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 64 * 1024 {
        bail!("风险接受文件超过 64 KiB");
    }
    verify(&file.metadata()?)?;
    Ok(toml::from_slice(&bytes)?)
}

fn verify(metadata: &std::fs::Metadata) -> anyhow::Result<()> {
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        bail!("风险接受文件必须为 root 所有、普通文件且 group/other 不可写");
    }
    Ok(())
}
