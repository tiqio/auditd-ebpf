use std::path::{Path, PathBuf};

use auditd_ebpf_common::permission::PermissionMask;
use auditd_ebpf_rules::{Arch, AuditRule, KernelFilterPlan, RuleKind, syscall_number};

use super::argv_policy::{EffectiveArgvOutput, resolve};

pub struct CandidateEvent<'a> {
    pub arch: Arch,
    pub syscall: &'a str,
    pub path: Option<&'a Path>,
    pub path_confident: bool,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub success: Option<bool>,
    pub permissions: PermissionMask,
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
            permissions: PermissionMask::EMPTY,
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
    pub const fn with_permissions(mut self, permissions: PermissionMask) -> Self {
        self.permissions = permissions;
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
            .find(|rule| matches_rule(&self.plan, rule, event))
            .map(|rule| MatchResult {
                rule,
                argv_output: resolve(self.global_argv_enabled, rule.argv_output),
            })
    }

    /// 按规则文件顺序优先、候选路径 primary/secondary/fd 次序次之进行求值。
    /// 这样 dual-path syscall 不会因为先遍历路径而让靠后的规则抢先命中。
    pub fn evaluate_paths<'a, 'p>(
        &'a self,
        event: &CandidateEvent<'_>,
        paths: &'p [PathBuf],
    ) -> Option<(MatchResult<'a>, Option<&'p Path>)> {
        self.plan.rules.iter().find_map(|rule| {
            if rule.path.is_none() && rule.dir.is_none() {
                return matches_rule(&self.plan, rule, event).then(|| {
                    (
                        MatchResult {
                            rule,
                            argv_output: resolve(self.global_argv_enabled, rule.argv_output),
                        },
                        None,
                    )
                });
            }
            paths.iter().find_map(|path| {
                let mut with_path = CandidateEvent {
                    arch: event.arch,
                    syscall: event.syscall,
                    path: Some(path),
                    path_confident: event.path_confident,
                    uid: event.uid,
                    gid: event.gid,
                    success: event.success,
                    permissions: event.permissions,
                };
                with_path.path_confident = true;
                matches_rule(&self.plan, rule, &with_path).then(|| {
                    (
                        MatchResult {
                            rule,
                            argv_output: resolve(self.global_argv_enabled, rule.argv_output),
                        },
                        Some(path.as_path()),
                    )
                })
            })
        })
    }

    /// 判断当前 syscall 是否存在必须依赖可靠路径边界的候选规则。
    #[must_use]
    pub fn requires_resolved_path(&self, arch: Arch, syscall: &str) -> bool {
        self.plan.rules.iter().any(|rule| {
            rule.arch.is_none_or(|rule_arch| rule_arch == arch)
                && rule_covers_syscall(&self.plan, rule, arch, syscall)
                && (rule.path.is_some() || rule.dir.is_some())
        })
    }

    #[must_use]
    pub fn requires_permission(&self, arch: Arch, syscall: &str) -> bool {
        self.plan.rules.iter().any(|rule| {
            rule.arch.is_none_or(|rule_arch| rule_arch == arch)
                && rule_covers_syscall(&self.plan, rule, arch, syscall)
                && !rule.permissions.is_empty()
        })
    }
}

fn matches_rule(plan: &KernelFilterPlan, rule: &AuditRule, event: &CandidateEvent<'_>) -> bool {
    if rule.arch.is_some_and(|arch| arch != event.arch) {
        return false;
    }
    if !rule_covers_syscall(plan, rule, event.arch, event.syscall) {
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
    let requested_permissions = permission_mask(&rule.permissions);
    if !requested_permissions.is_empty() && !requested_permissions.intersects(event.permissions) {
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

fn rule_covers_syscall(
    plan: &KernelFilterPlan,
    rule: &AuditRule,
    arch: Arch,
    syscall: &str,
) -> bool {
    if rule.kind == RuleKind::Syscall {
        return rule.syscalls.iter().any(|name| name == syscall);
    }
    let Some(number) = syscall_number(arch, syscall) else {
        return false;
    };
    plan.coverage_by_rule
        .get(&rule.rule_id)
        .and_then(|coverage| coverage.get(&arch))
        .is_some_and(|coverage| coverage.effective_syscalls.contains(&number))
}

fn permission_mask(permissions: &std::collections::BTreeSet<char>) -> PermissionMask {
    permissions
        .iter()
        .fold(PermissionMask::EMPTY, |mask, value| {
            mask | match value {
                'x' => PermissionMask::EXEC,
                'w' => PermissionMask::WRITE,
                'r' => PermissionMask::READ,
                'a' => PermissionMask::ATTR,
                _ => PermissionMask::EMPTY,
            }
        })
}
