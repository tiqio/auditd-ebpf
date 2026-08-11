use crate::rules::argv_policy::EffectiveArgvOutput;

pub const MAX_EVENT_LINE_BYTES: usize = 16 * 1024;

pub struct AuditEvent<'a> {
    pub unix_seconds: u64,
    pub millis: u16,
    pub sequence: u64,
    pub host: &'a [u8],
    pub machine_id: &'a str,
    pub event_id: &'a [u8],
    pub rule_version: u64,
    pub rule_id: u32,
    pub key: &'a [u8],
    pub arch: u32,
    pub syscall: &'a str,
    pub operation: &'a str,
    pub success: bool,
    pub exit: i64,
    pub pid: u32,
    /// 仅在父进程标识由可信采集源提供时为 `Some`；禁止用零代替未知值。
    pub ppid: Option<u32>,
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub egid: u32,
    pub comm: &'a [u8],
    /// 可执行文件路径尚未可靠关联时为 `None`，格式化为 `exe=?`。
    pub exe: Option<&'a [u8]>,
    pub path: &'a [u8],
    /// 权限语义无法从当前 syscall 事实可靠推导时为 `None`，格式化为 `perm=?`。
    pub perm: Option<&'a str>,
    pub argv_output: EffectiveArgvOutput,
    pub argc: u32,
    pub argv: &'a [Vec<u8>],
    pub argv_truncated: bool,
    pub path_confidence: &'a str,
}

#[must_use]
pub fn format_event(event: &AuditEvent<'_>) -> String {
    let argv_output = match event.argv_output {
        EffectiveArgvOutput::Emitted => "emitted",
        EffectiveArgvOutput::Suppressed => "suppressed",
    };
    let operation_id = operation_id(event)
        .map(|value| format!(" operation_id={value}"))
        .unwrap_or_default();
    let ppid = event
        .ppid
        .map_or_else(|| "?".into(), |value| value.to_string());
    let exe = event.exe.map_or_else(|| "?".into(), escape);
    let perm = event.perm.unwrap_or("?");
    let mut line = format!(
        "type=AUDITD_EBPF msg=audit({}.{:03}:{}) schema=1 host={} machine_id={} event_id={}{} rule_version={} rule_id={} key={} arch={:08x} syscall={} operation={} success={} exit={} pid={} ppid={} uid={} gid={} euid={} egid={} comm={} exe={} path={} perm={} argv_output={} argc={}",
        event.unix_seconds,
        event.millis,
        event.sequence,
        escape(event.host),
        event.machine_id,
        escape(event.event_id),
        operation_id,
        event.rule_version,
        event.rule_id,
        escape(event.key),
        event.arch,
        event.syscall,
        event.operation,
        if event.success { "yes" } else { "no" },
        event.exit,
        event.pid,
        ppid,
        event.uid,
        event.gid,
        event.euid,
        event.egid,
        escape(event.comm),
        exe,
        escape(event.path),
        perm,
        argv_output,
        event.argc,
    );
    let mut truncated = false;
    if event.argv_output == EffectiveArgvOutput::Emitted {
        for (index, argument) in event.argv.iter().take(32).enumerate() {
            let field = format!(" a{index}={}", escape(argument));
            if line.len() + field.len() + 96 > MAX_EVENT_LINE_BYTES {
                truncated = true;
                break;
            }
            line.push_str(&field);
        }
    }
    let argv_truncated = event.argv_truncated || truncated || event.argv.len() > 32;
    line.push_str(&format!(
        " argv_truncated={} path_confidence={} truncated={}\n",
        yes_no(argv_truncated),
        event.path_confidence,
        yes_no(truncated),
    ));
    if line.len() > MAX_EVENT_LINE_BYTES {
        let fallback = format!(
            "type=AUDITD_EBPF msg=audit({}.{:03}:{}) schema=1 host={} machine_id={} event_id={} rule_version={} rule_id={} key={} argv_output={} argc={} argv_truncated=yes path_confidence={} truncated=yes\n",
            event.unix_seconds,
            event.millis,
            event.sequence,
            escape(event.host),
            event.machine_id,
            escape(event.event_id),
            event.rule_version,
            event.rule_id,
            escape(event.key),
            argv_output,
            event.argc,
            event.path_confidence,
        );
        return fallback;
    }
    line
}

fn operation_id<'a>(event: &'a AuditEvent<'a>) -> Option<&'a str> {
    event
        .argv
        .iter()
        .filter_map(|value| std::str::from_utf8(value).ok())
        .chain(std::str::from_utf8(event.comm).ok())
        .chain(std::str::from_utf8(event.path).ok())
        .flat_map(|value| value.split(|character: char| !character.is_ascii_alphanumeric()))
        .find(|part| part.len() == 15 && part.starts_with("op"))
}

#[must_use]
pub fn escape(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() + 2);
    output.push('"');
    for byte in bytes {
        match *byte {
            b'"' => output.push_str("\\\""),
            b'\\' => output.push_str("\\\\"),
            0x20..=0x7e => output.push(char::from(*byte)),
            value => output.push_str(&format!("\\x{value:02X}")),
        }
    }
    output.push('"');
    output
}

const fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}
