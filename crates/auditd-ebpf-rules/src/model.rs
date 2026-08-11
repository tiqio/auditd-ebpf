use std::collections::{BTreeMap, BTreeSet};

use auditd_ebpf_common::permission::PermissionMask;

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RulePermissionCoverage {
    pub arch: Arch,
    pub requested_permissions: PermissionMask,
    pub effective_syscalls: BTreeSet<u32>,
    pub syscall_permission_masks: BTreeMap<u32, PermissionMask>,
}

#[derive(Clone, Debug)]
pub struct KernelFilterPlan {
    pub generation: u8,
    pub rules: Vec<AuditRule>,
    pub syscalls_b64: BTreeSet<u32>,
    pub syscalls_b32: BTreeSet<u32>,
    pub permission_masks_b64: [u8; 512],
    pub permission_masks_b32: [u8; 512],
    pub maintenance_syscalls_b64: BTreeSet<u32>,
    pub maintenance_syscalls_b32: BTreeSet<u32>,
    pub coverage_by_rule: BTreeMap<u32, BTreeMap<Arch, RulePermissionCoverage>>,
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
