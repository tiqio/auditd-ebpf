use std::path::Path;

use auditd_ebpf_rules::{Arch, AuditRule, KernelFilterPlan, RuleKind};

use super::argv_policy::{EffectiveArgvOutput, resolve};

pub struct CandidateEvent<'a> {
    pub arch: Arch,
    pub syscall: &'a str,
    pub path: Option<&'a Path>,
    pub success: bool,
}

pub struct MatchResult<'a> {
    pub rule: &'a AuditRule,
    pub argv_output: EffectiveArgvOutput,
}

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
}

fn matches_rule(rule: &AuditRule, event: &CandidateEvent<'_>) -> bool {
    if rule.arch.is_some_and(|arch| arch != event.arch) {
        return false;
    }
    if rule.kind == RuleKind::Syscall && !rule.syscalls.iter().any(|name| name == event.syscall) {
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
