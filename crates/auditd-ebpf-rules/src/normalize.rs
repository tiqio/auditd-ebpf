use crate::AuditRule;

#[must_use]
pub fn normalized_line(rule: &AuditRule) -> String {
    format!(
        "id={} kind={:?} arch={:?} syscalls={} path={} dir={} perm={} uid={} gid={} success={} key={} argv={:?}",
        rule.rule_id,
        rule.kind,
        rule.arch,
        rule.syscalls.join(","),
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
