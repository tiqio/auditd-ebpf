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
