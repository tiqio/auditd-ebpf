use crate::{health::counters::HealthCounters, identity::HostIdentity};

pub struct StatusRecord<'a> {
    pub state: &'a str,
    pub reason: Option<&'a str>,
    pub uptime_seconds: u64,
    pub rule_version: Option<u64>,
    pub programs_attached: u64,
    pub counters: &'a HealthCounters,
    pub queue_used_bytes: u64,
    pub queue_limit_bytes: u64,
    pub queue_max_bytes: u64,
    pub final_record: bool,
}

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

/// 格式化运行时采集缺口，确保解码失败和 exec 关联失败不会只停留在内存计数中。
///
/// `reason` 会经过与普通审计字段相同的可逆转义，因此错误文本中的空格、引号或控制字符
/// 不会破坏 journald/rsyslog 所依赖的单行记录边界。
#[must_use]
pub fn collector_gap(identity: &HostIdentity, reason: &[u8], sequence: u64, now_ms: u64) -> String {
    format!(
        "type=AUDITD_EBPF_GAP msg=audit(0.000:{sequence}) schema=1 host={} machine_id={} event_id={} reason={} count=1 first_seen={} last_seen={}\n",
        super::event_formatter::escape(identity.host.as_bytes()),
        identity.machine_id,
        super::event_formatter::escape(format!("collector-gap-{sequence}").as_bytes()),
        super::event_formatter::escape(reason),
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

/// 输出结构化 watch 缺口诊断。诊断只包含定位元数据，绝不接收或格式化 argv。
#[must_use]
pub fn watch_diagnostic(
    identity: &HostIdentity,
    reason: crate::health::watch_gap::WatchGapReason,
    rule_version: Option<u64>,
    pid: u32,
    tid: u32,
    syscall: &str,
) -> String {
    let rule_version = rule_version.map_or_else(|| "?".into(), |value| value.to_string());
    format!(
        "type=AUDITD_EBPF_DIAG host={} machine_id={} level=error code=watch_gap component=collector reason={} stage={} rule_version={} pid={} tid={} syscall={} message=\"watch candidate rejected\"\n",
        super::event_formatter::escape(identity.host.as_bytes()),
        identity.machine_id,
        reason.as_str(),
        reason.stage(),
        rule_version,
        pid,
        tid,
        super::event_formatter::escape(syscall.as_bytes()),
    )
}

#[must_use]
pub fn status(identity: &HostIdentity, record: &StatusRecord<'_>) -> String {
    let reason = record.reason.map_or_else(String::new, |reason| {
        format!(
            " reason={}",
            super::event_formatter::escape(reason.as_bytes())
        )
    });
    let rule_version = record
        .rule_version
        .map_or_else(|| "?".to_owned(), |version| version.to_string());
    format!(
        "type=AUDITD_EBPF_STATUS host={} machine_id={} state={}{} uptime_s={} rule_version={} programs_attached={} events_seen={} events_submitted={} events_consumed={} events_matched={} events_unmatched={} events_output={} watch_candidates={} watch_matches={} watch_r={} watch_w={} watch_x={} watch_a={} watch_permission_failures={} watch_fd_failures={} argv_captured={} argv_suppressed={} ring_lost={} kernel_lost={} inflight_lost={} correlation_lost={} argv_lost={} internal_lost={} queue_lost={} path_lost={} unclean_shutdown={} parse_failed={} stdout_failed={} reload_success={} reload_failed={} gaps_generated={} queue_used_bytes={} queue_limit_bytes={} queue_max_bytes={} final={}\n",
        super::event_formatter::escape(identity.host.as_bytes()),
        identity.machine_id,
        record.state,
        reason,
        record.uptime_seconds,
        rule_version,
        record.programs_attached,
        record.counters.events_seen_total,
        record.counters.events_submitted_total,
        record.counters.events_consumed_total,
        record.counters.events_matched_total,
        record.counters.events_unmatched_total,
        record.counters.events_output_total,
        record.counters.watch_candidates_total,
        record.counters.watch_matches_total,
        record.counters.watch_read_matches_total,
        record.counters.watch_write_matches_total,
        record.counters.watch_exec_matches_total,
        record.counters.watch_attr_matches_total,
        record.counters.watch_permission_failures_total,
        record.counters.watch_fd_failures_total,
        record.counters.exec_argv_captured_total,
        record.counters.exec_argv_suppressed_total,
        record.counters.ring_reserve_failed_total,
        record.counters.kernel_lost_total(),
        record.counters.inflight_dropped_total,
        record.counters.correlation_missed_total,
        record.counters.exec_argv_dropped_total,
        record.counters.internal_dropped_total,
        record.counters.queue_dropped_total,
        record.counters.path_resolution_failed_total,
        record.counters.unclean_shutdown_detected_total,
        record.counters.event_parse_failed_total,
        record.counters.stdout_write_failed_total,
        record.counters.rule_reload_success_total,
        record.counters.rule_reload_failed_total,
        record.counters.gap_records_generated_total,
        record.queue_used_bytes,
        record.queue_limit_bytes,
        record.queue_max_bytes,
        if record.final_record { "yes" } else { "no" },
    )
}
