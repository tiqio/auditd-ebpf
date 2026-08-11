use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Arch {
    B64,
    B32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleKind {
    Syscall,
    Watch,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ArgvOutput {
    #[default]
    Inherit,
    Enabled,
    Disabled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditRule {
    pub rule_id: u32,
    pub kind: RuleKind,
    pub arch: Option<Arch>,
    pub syscalls: Vec<String>,
    pub path: Option<String>,
    pub dir: Option<String>,
    pub permissions: BTreeSet<char>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub success: Option<bool>,
    pub key: String,
    pub argv_output: ArgvOutput,
}

#[derive(Clone, Debug)]
pub struct RuleSet {
    pub rules: Vec<AuditRule>,
    pub version_hash: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct KernelFilterPlan {
    pub generation: u8,
    pub rules: Vec<AuditRule>,
    pub syscalls_b64: BTreeSet<u32>,
    pub syscalls_b32: BTreeSet<u32>,
    pub exec_capture_enabled: bool,
    pub argv_overrides: BTreeMap<String, ArgvOutput>,
    pub version_hash: [u8; 32],
}

impl KernelFilterPlan {
    /// 输出事件和内核 map 使用 SHA-256 摘要的前 64 位作为紧凑规则版本。
    #[must_use]
    pub fn rule_version(&self) -> u64 {
        u64::from_le_bytes(
            self.version_hash[..8]
                .try_into()
                .expect("SHA-256 前 8 字节长度固定"),
        )
    }
}
