use std::{collections::BTreeSet, path::Path};

use auditd_ebpf_rules::{Arch, AuditRule, KernelFilterPlan, RuleKind};

use super::argv_policy::{EffectiveArgvOutput, resolve};

pub struct CandidateEvent<'a> {
    pub arch: Arch,
    pub syscall: &'a str,
    pub path: Option<&'a Path>,
    pub path_confident: bool,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub success: Option<bool>,
    pub permissions: BTreeSet<char>,
}

impl<'a> CandidateEvent<'a> {
    #[must_use]
    pub fn new(arch: Arch, syscall: &'a str) -> Self {
        Self {
            arch,
            syscall,
            path: None,
            path_confident: true,
            uid: None,
            gid: None,
            success: None,
            permissions: BTreeSet::new(),
        }
    }

    #[must_use]
    pub const fn with_identity(mut self, uid: u32, gid: u32) -> Self {
        self.uid = Some(uid);
        self.gid = Some(gid);
        self
    }

    #[must_use]
    pub const fn with_success(mut self, success: bool) -> Self {
        self.success = Some(success);
        self
    }

    #[must_use]
    pub const fn with_path(mut self, path: &'a Path) -> Self {
        self.path = Some(path);
        self
    }

    #[must_use]
    pub fn with_permission(mut self, permission: char) -> Self {
        self.permissions.insert(permission);
        self
    }
}

/// 用户态完成精确求值后的审计事件决策。
///
/// `path` 仅表示进程 root 与 mount namespace 中的词法路径字符串；这里不声明
/// symlink、inode 或 hard-link 等价关系。
pub struct ResolvedAuditEvent<'a> {
    pub rule: &'a AuditRule,
    pub argv_output: EffectiveArgvOutput,
}

pub type MatchResult<'a> = ResolvedAuditEvent<'a>;

pub struct RuleEngine {
    plan: KernelFilterPlan,
    global_argv_enabled: bool,
}

impl RuleEngine {
    pub fn new(plan: KernelFilterPlan, global_argv_enabled: bool) -> Self {
        Self {
            plan,
            global_argv_enabled,
        }
    }
    pub fn evaluate<'a>(&'a self, event: &CandidateEvent<'_>) -> Option<MatchResult<'a>> {
        self.plan
            .rules
            .iter()
            .find(|rule| matches_rule(rule, event))
            .map(|rule| MatchResult {
                rule,
                argv_output: resolve(self.global_argv_enabled, rule.argv_output),
            })
    }

    /// 判断当前 syscall 是否存在必须依赖可靠路径边界的候选规则。
    #[must_use]
    pub fn requires_resolved_path(&self, arch: Arch, syscall: &str) -> bool {
        self.plan.rules.iter().any(|rule| {
            rule.arch.is_none_or(|rule_arch| rule_arch == arch)
                && (rule.path.is_some() || rule.dir.is_some())
                && (rule.kind == RuleKind::Watch
                    || rule.syscalls.iter().any(|name| name == syscall))
        })
    }
}

fn matches_rule(rule: &AuditRule, event: &CandidateEvent<'_>) -> bool {
    if rule.arch.is_some_and(|arch| arch != event.arch) {
        return false;
    }
    if rule.kind == RuleKind::Syscall && !rule.syscalls.iter().any(|name| name == event.syscall) {
        return false;
    }
    if rule.uid.is_some_and(|uid| event.uid != Some(uid)) {
        return false;
    }
    if rule.gid.is_some_and(|gid| event.gid != Some(gid)) {
        return false;
    }
    if rule
        .success
        .is_some_and(|success| event.success != Some(success))
    {
        return false;
    }
    if !rule.permissions.is_empty() && rule.permissions.is_disjoint(&event.permissions) {
        return false;
    }
    if (rule.path.is_some() || rule.dir.is_some()) && !event.path_confident {
        return false;
    }
    if let Some(expected) = rule.path.as_deref()
        && event.path != Some(Path::new(expected))
    {
        return false;
    }
    if let Some(directory) = rule.dir.as_deref()
        && !event.path.is_some_and(|path| path.starts_with(directory))
    {
        return false;
    }
    true
}
