use std::collections::BTreeSet;

use auditd_ebpf_common::permission::PermissionMask;

use crate::{
    Arch, AuditRule, COVERAGE_VERSION, KernelFilterPlan, RulePermissionCoverage, syscall_name,
};

#[must_use]
pub fn normalized_line(rule: &AuditRule) -> String {
    normalized_base(rule, &rule.syscalls.join(","))
}

/// 输出包含实际可执行覆盖的规范化规则。
///
/// 基础 `normalized_line` 继续服务编译摘要，避免编译期间反向依赖尚未构造完成的 plan；
/// coverage version、permission tables 和 maintenance 集合已由 compiler 单独写入摘要。
#[must_use]
pub fn normalized_plan_line(plan: &KernelFilterPlan, rule: &AuditRule) -> String {
    let Some(by_arch) = plan.coverage_by_rule.get(&rule.rule_id) else {
        return normalized_line(rule);
    };
    let b64 = by_arch.get(&Arch::B64);
    let b32 = by_arch.get(&Arch::B32);
    let mut names = BTreeSet::new();
    for coverage in by_arch.values() {
        for number in &coverage.effective_syscalls {
            if let Some(name) = syscall_name(coverage.arch, *number) {
                names.insert(name);
            }
        }
    }
    format!(
        "{} coverage_version={} coverage_b64={} coverage_b32={}",
        normalized_base(rule, &names.into_iter().collect::<Vec<_>>().join(",")),
        COVERAGE_VERSION,
        format_coverage(b64),
        format_coverage(b32),
    )
}

fn normalized_base(rule: &AuditRule, syscalls: &str) -> String {
    format!(
        "id={} kind={:?} arch={:?} syscalls={} path={} dir={} perm={} uid={} gid={} success={} key={} argv={:?}",
        rule.rule_id,
        rule.kind,
        rule.arch,
        syscalls,
        rule.path.as_deref().unwrap_or("-"),
        rule.dir.as_deref().unwrap_or("-"),
        rule.permissions.iter().collect::<String>(),
        rule.uid
            .map_or_else(|| "-".to_owned(), |value| value.to_string()),
        rule.gid
            .map_or_else(|| "-".to_owned(), |value| value.to_string()),
        rule.success
            .map_or_else(|| "-".to_owned(), |value| value.to_string()),
        rule.key,
        rule.argv_output,
    )
}

fn format_coverage(coverage: Option<&RulePermissionCoverage>) -> String {
    let Some(coverage) = coverage else {
        return "-".to_owned();
    };
    let mut groups = Vec::new();
    for (permission, symbol) in [
        (PermissionMask::READ, 'r'),
        (PermissionMask::WRITE, 'w'),
        (PermissionMask::EXEC, 'x'),
        (PermissionMask::ATTR, 'a'),
    ] {
        if !coverage.requested_permissions.intersects(permission) {
            continue;
        }
        let names = coverage
            .syscall_permission_masks
            .iter()
            .filter(|(_, mask)| mask.intersects(permission))
            .filter_map(|(number, _)| syscall_name(coverage.arch, *number))
            .collect::<Vec<_>>()
            .join(",");
        groups.push(format!("{symbol}:{names}"));
    }
    groups.join("|")
}
