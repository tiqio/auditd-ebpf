use crate::identity::HostIdentity;

#[must_use]
pub fn unclean_shutdown_gap(
    identity: &HostIdentity,
    msg: &str,
    event_id: &str,
    now_ms: u64,
) -> String {
    format!(
        "type=AUDITD_EBPF_GAP msg={} schema=1 host={} machine_id={} event_id={} reason=unclean_shutdown count=? first_seen={} last_seen={}\n",
        msg,
        super::event_formatter::escape(identity.host.as_bytes()),
        identity.machine_id,
        super::event_formatter::escape(event_id.as_bytes()),
        now_ms,
        now_ms,
    )
}

#[must_use]
pub fn diagnostic(
    identity: &HostIdentity,
    level: &str,
    code: &str,
    component: &str,
    message: &[u8],
) -> String {
    format!(
        "type=AUDITD_EBPF_DIAG host={} machine_id={} level={} code={} component={} message={}\n",
        super::event_formatter::escape(identity.host.as_bytes()),
        identity.machine_id,
        level,
        code,
        component,
        super::event_formatter::escape(message),
    )
}

#[must_use]
pub fn status(
    identity: &HostIdentity,
    state: &str,
    argv_captured: u64,
    argv_suppressed: u64,
    final_record: bool,
) -> String {
    format!(
        "type=AUDITD_EBPF_STATUS host={} machine_id={} state={} argv_captured={} argv_suppressed={} final={}\n",
        super::event_formatter::escape(identity.host.as_bytes()),
        identity.machine_id,
        state,
        argv_captured,
        argv_suppressed,
        if final_record { "yes" } else { "no" },
    )
}
