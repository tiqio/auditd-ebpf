use std::{fs, path::Path};

use anyhow::Context;
use aya::Ebpf;

pub struct LoadedBpf {
    inner: Ebpf,
}

impl LoadedBpf {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let bytes =
            fs::read(path).with_context(|| format!("无法读取 eBPF 对象 {}", path.display()))?;
        Ok(Self {
            inner: Ebpf::load(&bytes).context("Aya 无法加载 eBPF 对象")?,
        })
    }
    pub fn inner_mut(&mut self) -> &mut Ebpf {
        &mut self.inner
    }
}
