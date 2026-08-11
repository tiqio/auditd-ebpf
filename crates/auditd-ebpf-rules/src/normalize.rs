use crate::AuditRule;

#[must_use]
pub fn normalized_line(rule: &AuditRule) -> String {
    format!(
        "id={} kind={:?} arch={:?} syscalls={} key={}",
        rule.rule_id,
        rule.kind,
        rule.arch,
        rule.syscalls.join(","),
        rule.key
    )
}
