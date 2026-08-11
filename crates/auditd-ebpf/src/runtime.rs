use auditd_ebpf_rules::{
    Arch, KernelFilterPlan, RuleCompiler, parse_rules, source::sorted_rule_files, syscall_name,
};
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Write},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use tokio::signal::unix::{SignalKind, signal};

use crate::{
    collector::runtime::{CollectedRecord, CollectorGap, CollectorRuntime, CorrelatedExec},
    identity::{HostIdentity, MachineIdSource},
    lifecycle::{
        model::{LifecycleMarker, LifecycleState},
        state_file::LifecycleStateFile,
    },
    loader::LoadedBpf,
    output::{
        adaptive_queue::{DEFAULT_INITIAL_BYTES, DEFAULT_MAX_BYTES},
        event_formatter::{AuditEvent, format_event},
        status_formatter::{collector_gap, diagnostic, status, unclean_shutdown_gap},
        writer::{OutputPipeline, WriterError},
    },
    rules::{
        argv_policy::EffectiveArgvOutput,
        engine::{CandidateEvent, RuleEngine},
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DrainOutcome {
    Drained,
    TimedOut,
}

impl DrainOutcome {
    #[must_use]
    pub const fn exit_code(self) -> i32 {
        match self {
            Self::Drained => 0,
            Self::TimedOut => 8,
        }
    }
}

#[derive(Default)]
pub struct SignalCoordinator {
    reload_in_progress: bool,
    reload_pending: bool,
    stopping: bool,
}

impl SignalCoordinator {
    pub fn begin_reload(&mut self) {
        if !self.stopping {
            self.reload_in_progress = true;
        }
    }

    pub fn request_reload(&mut self) {
        if self.stopping {
            return;
        }
        self.reload_pending = true;
    }

    pub fn finish_reload(&mut self) -> bool {
        self.reload_in_progress = false;
        std::mem::take(&mut self.reload_pending) && !self.stopping
    }

    pub fn request_stop(&mut self) {
        self.stopping = true;
        self.reload_pending = false;
    }

    #[must_use]
    pub const fn stopping(&self) -> bool {
        self.stopping
    }

    pub fn take_reload(&mut self) -> bool {
        if self.stopping || self.reload_in_progress {
            return false;
        }
        std::mem::take(&mut self.reload_pending)
    }
}

pub fn drain_with_timeout(timeout: Duration, mut is_empty: impl FnMut() -> bool) -> DrainOutcome {
    let deadline = Instant::now() + timeout;
    loop {
        if is_empty() {
            return DrainOutcome::Drained;
        }
        if Instant::now() >= deadline {
            return DrainOutcome::TimedOut;
        }
        thread::sleep(Duration::from_millis(1));
    }
}

pub fn run(
    node_name: Option<&str>,
    lifecycle_path: &Path,
    ebpf_object: Option<&Path>,
    rules_dir: &Path,
) -> i32 {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("type=AUDITD_EBPF_DIAG level=error code=runtime_init message={error}");
            return 7;
        }
    };
    runtime.block_on(run_async(node_name, lifecycle_path, ebpf_object, rules_dir))
}

async fn run_async(
    node_name: Option<&str>,
    lifecycle_path: &Path,
    ebpf_object: Option<&Path>,
    rules_dir: &Path,
) -> i32 {
    // 信号 fd 必须在任何可能耗时的 load/attach 前注册。否则 dirty 已持久化但 attach 尚未完成
    // 的窗口里，SIGTERM 会执行默认动作，绕过排空与最终状态逻辑。
    let mut usr1 = match signal(SignalKind::user_defined1()) {
        Ok(signal) => signal,
        Err(_) => return 7,
    };
    let mut term = match signal(SignalKind::terminate()) {
        Ok(signal) => signal,
        Err(_) => return 7,
    };
    let mut interrupt = match signal(SignalKind::interrupt()) {
        Ok(signal) => signal,
        Err(_) => return 7,
    };
    let mut hangup = match signal(SignalKind::hangup()) {
        Ok(signal) => signal,
        Err(_) => return 7,
    };

    // eBPF 对象可以先完成读取与 Aya 解析，但在 durable dirty 成功前绝不 attach，也不启动
    // RingBuf 消费。这样加载失败不会制造虚假的 dirty，而 attach 后异常一定留下 dirty 证据。
    let mut loaded_bpf = match ebpf_object.map(LoadedBpf::load).transpose() {
        Ok(loaded) => loaded,
        Err(error) => {
            eprintln!(
                "type=AUDITD_EBPF_DIAG level=error code=ebpf_load component=runtime message={error:?}"
            );
            return 6;
        }
    };
    let mut active_plan = None;
    if let Some(loaded) = loaded_bpf.as_mut() {
        let plan = match compile_rules(rules_dir) {
            Ok(plan) => plan,
            Err(error) => {
                eprintln!(
                    "type=AUDITD_EBPF_DIAG level=error code=rule_invalid component=runtime message={error:?}"
                );
                return 3;
            }
        };
        // 规则 bitmap 与版本必须在 attach 前完成 staging；否则程序会以全零 bitmap 启动，
        // 造成静默漏报并使任何性能数据失去正确性前提。
        if let Err(error) = loaded.stage_rules(&plan) {
            eprintln!(
                "type=AUDITD_EBPF_DIAG level=error code=rule_stage component=runtime message={error:?}"
            );
            return 6;
        }
        active_plan = Some(plan);
    }
    let state_file = LifecycleStateFile::new(lifecycle_path);
    let previous = match state_file.read() {
        Ok(marker) => marker,
        Err(error) => {
            eprintln!("type=AUDITD_EBPF_DIAG level=error code=lifecycle_read message={error}");
            return 4;
        }
    };
    let previous_dirty = previous
        .as_ref()
        .is_some_and(|marker| marker.state == LifecycleState::Dirty);
    let dirty = LifecycleMarker::dirty(
        read_trimmed("/proc/sys/kernel/random/boot_id").unwrap_or_else(|| "?".into()),
        read_trimmed("/proc/sys/kernel/random/uuid").unwrap_or_else(fallback_invocation_id),
        std::process::id(),
        now_millis(),
    );
    if let Err(error) = state_file.write(&dirty) {
        eprintln!("type=AUDITD_EBPF_DIAG level=error code=lifecycle_dirty message={error}");
        return 4;
    }

    let identity = resolve_identity(node_name);
    let mut collector = if let Some(loaded) = loaded_bpf.as_mut() {
        if let Err(error) = loaded.attach_collection_programs() {
            eprintln!(
                "type=AUDITD_EBPF_DIAG level=error code=ebpf_attach component=runtime message={error:?}"
            );
            return 6;
        }
        match loaded.take_ring() {
            Ok(ring) => Some(KernelCollector::start(
                ring,
                active_plan.expect("加载 eBPF 时规则计划已编译"),
                identity.clone(),
            )),
            Err(error) => {
                eprintln!(
                    "type=AUDITD_EBPF_DIAG level=error code=ringbuf_open component=runtime message={error:?}"
                );
                return 6;
            }
        }
    } else {
        None
    };

    if previous_dirty {
        let line = unclean_shutdown_gap(
            &identity,
            "audit(0.000:0)",
            "unclean-shutdown",
            now_millis(),
        );
        if io::stdout()
            .write_all(line.as_bytes())
            .and_then(|_| io::stdout().flush())
            .is_err()
        {
            return 7;
        }
        eprint!("{}", status(&identity, "degraded", 0, 0, false));
    } else {
        eprint!("{}", status(&identity, "healthy", 0, 0, false));
    }

    loop {
        tokio::select! {
            _ = usr1.recv() => {
                let collector_degraded = collector.as_ref().is_some_and(KernelCollector::is_degraded);
                eprint!("{}", status(&identity, if previous_dirty || collector_degraded { "degraded" } else { "healthy" }, 0, 0, false));
            }
            _ = hangup.recv() => {
                eprintln!("type=AUDITD_EBPF_DIAG host={} machine_id={} level=info code=reload_requested component=runtime message=\"SIGHUP\"", identity.host, identity.machine_id);
            }
            _ = term.recv() => break,
            _ = interrupt.recv() => break,
        }
    }

    eprint!("{}", status(&identity, "stopping", 0, 0, false));
    let drain = collector
        .as_mut()
        .map_or(DrainOutcome::Drained, |collector| {
            collector.stop(Duration::from_secs(30))
        });
    eprint!("{}", status(&identity, "stopping", 0, 0, true));
    if io::stderr().flush().is_err() {
        return 7;
    }
    let consumed = collector.as_ref().map_or(0, KernelCollector::consumed);
    drop(collector);
    // LoadedBpf 持有所有 Aya links/maps；先 drop 确保 detach 和 map 清理完成，之后才允许 clean。
    drop(loaded_bpf);
    let clean = dirty.into_clean(BTreeMap::from([
        ("events_seen".into(), consumed),
        ("events_submitted".into(), consumed),
        ("events_output".into(), 0),
        ("ring_lost".into(), 0),
        ("queue_lost".into(), 0),
        ("path_lost".into(), 0),
    ]));
    if let Err(error) = state_file.write(&clean) {
        eprintln!("type=AUDITD_EBPF_DIAG level=error code=lifecycle_clean message={error}");
        return 7;
    }
    drain.exit_code()
}

fn compile_rules(rules_dir: &Path) -> anyhow::Result<auditd_ebpf_rules::KernelFilterPlan> {
    let paths = sorted_rule_files(rules_dir).map_err(anyhow::Error::new)?;
    anyhow::ensure!(
        !paths.is_empty(),
        "规则目录 {} 不包含 .rules 文件",
        rules_dir.display()
    );
    let mut rules = Vec::new();
    for path in paths {
        let input = fs::read_to_string(&path)?;
        rules.extend(parse_rules(&path.display().to_string(), &input).map_err(anyhow::Error::new)?);
    }
    for (index, rule) in rules.iter_mut().enumerate() {
        rule.rule_id = index as u32;
    }
    RuleCompiler::compile(rules, 0, Default::default()).map_err(anyhow::Error::new)
}

struct KernelCollector {
    stop: Arc<AtomicBool>,
    counters: Arc<CollectorCounters>,
    thread: Option<thread::JoinHandle<()>>,
}

#[derive(Default)]
struct CollectorCounters {
    consumed: AtomicU64,
    parse_failed: AtomicU64,
    queue_dropped: AtomicU64,
    output_succeeded: AtomicU64,
    stdout_failed: AtomicU64,
    gaps_generated: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct CollectorSnapshot {
    consumed: u64,
    parse_failed: u64,
    queue_dropped: u64,
    output_succeeded: u64,
    stdout_failed: u64,
    gaps_generated: u64,
}

impl CollectorSnapshot {
    #[must_use]
    const fn is_degraded(self) -> bool {
        self.parse_failed != 0
            || self.queue_dropped != 0
            || self.stdout_failed != 0
            || self.gaps_generated != 0
    }
}

impl CollectorCounters {
    fn snapshot(&self) -> CollectorSnapshot {
        CollectorSnapshot {
            consumed: self.consumed.load(Ordering::Relaxed),
            parse_failed: self.parse_failed.load(Ordering::Relaxed),
            queue_dropped: self.queue_dropped.load(Ordering::Relaxed),
            output_succeeded: self.output_succeeded.load(Ordering::Relaxed),
            stdout_failed: self.stdout_failed.load(Ordering::Relaxed),
            gaps_generated: self.gaps_generated.load(Ordering::Relaxed),
        }
    }
}

impl KernelCollector {
    fn start(
        mut ring: aya::maps::RingBuf<aya::maps::MapData>,
        plan: KernelFilterPlan,
        identity: HostIdentity,
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let counters = Arc::new(CollectorCounters::default());
        let thread_stop = Arc::clone(&stop);
        let thread_counters = Arc::clone(&counters);
        let thread = thread::spawn(move || {
            let engine = RuleEngine::new(plan, true);
            let mut collector_runtime = CollectorRuntime::new(65_536, Duration::from_secs(30));
            let mut completed_execs = BTreeMap::<u64, CorrelatedExec>::new();
            let mut output_sequence = 0_u64;
            // collector 是 stdout 的唯一审计事件写入者。统一管线同时持有 stdout/stderr 锁，
            // 既避免逐事件获取全局锁，也保证审计记录先进入有界动态队列再作为完整行写出。
            let stdout = io::stdout();
            let stderr = io::stderr();
            let mut pipeline = OutputPipeline::new(
                stdout.lock(),
                stderr.lock(),
                DEFAULT_INITIAL_BYTES,
                DEFAULT_MAX_BYTES,
            )
            .expect("默认输出队列容量必须有效");
            'collect: loop {
                let mut drained = false;
                while let Some(item) = ring.next() {
                    drained = true;
                    thread_counters.consumed.fetch_add(1, Ordering::Relaxed);
                    if let Err(error) = collector_runtime.accept(&item) {
                        thread_counters.parse_failed.fetch_add(1, Ordering::Relaxed);
                        let reason = format!("decode_error:{error}");
                        if submit_gap(
                            &mut pipeline,
                            &identity,
                            &thread_counters,
                            &reason,
                            output_sequence,
                        ) {
                            break 'collect;
                        }
                        output_sequence = output_sequence.wrapping_add(1);
                        continue;
                    }
                    if process_collected_records(
                        collector_runtime.take_output(),
                        &engine,
                        &identity,
                        &mut completed_execs,
                        &mut pipeline,
                        &thread_counters,
                        &mut output_sequence,
                    ) {
                        break 'collect;
                    }
                }
                collector_runtime.expire(Instant::now());
                if process_collected_records(
                    collector_runtime.take_output(),
                    &engine,
                    &identity,
                    &mut completed_execs,
                    &mut pipeline,
                    &thread_counters,
                    &mut output_sequence,
                ) {
                    break;
                }
                if thread_stop.load(Ordering::Acquire) && !drained {
                    break;
                }
                thread::sleep(Duration::from_millis(1));
            }
            if let Err(error) = pipeline.flush() {
                record_pipeline_failure(&mut pipeline, &identity, &thread_counters, &error);
            }
        });
        Self {
            stop,
            counters,
            thread: Some(thread),
        }
    }

    fn stop(&mut self, timeout: Duration) -> DrainOutcome {
        self.stop.store(true, Ordering::Release);
        let deadline = Instant::now() + timeout;
        while self
            .thread
            .as_ref()
            .is_some_and(|thread| !thread.is_finished())
        {
            if Instant::now() >= deadline {
                return DrainOutcome::TimedOut;
            }
            thread::sleep(Duration::from_millis(1));
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        DrainOutcome::Drained
    }

    fn consumed(&self) -> u64 {
        self.counters.snapshot().consumed
    }

    fn is_degraded(&self) -> bool {
        self.counters.snapshot().is_degraded()
    }
}

fn process_collected_records<StdoutWriter: Write, StderrWriter: Write>(
    records: Vec<CollectedRecord>,
    engine: &RuleEngine,
    identity: &HostIdentity,
    completed_execs: &mut BTreeMap<u64, CorrelatedExec>,
    pipeline: &mut OutputPipeline<StdoutWriter, StderrWriter>,
    counters: &CollectorCounters,
    output_sequence: &mut u64,
) -> bool {
    for record in records {
        match record {
            CollectedRecord::Exec(exec) => {
                completed_execs.insert(exec.process, exec);
            }
            CollectedRecord::Kernel(crate::collector::decode::KernelRecord::Syscall(event)) => {
                let correlated = completed_execs.remove(&event.header.pid_tgid);
                if let Some(line) = format_syscall_record(
                    engine,
                    identity,
                    &event,
                    correlated.as_ref(),
                    *output_sequence,
                ) {
                    let result = pipeline
                        .enqueue_audit(line.as_bytes())
                        .and_then(|_| pipeline.drain_all());
                    *output_sequence = output_sequence.wrapping_add(1);
                    match result {
                        Ok(()) => {
                            counters.output_succeeded.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(error) => {
                            if record_pipeline_failure(pipeline, identity, counters, &error) {
                                return true;
                            }
                        }
                    }
                }
            }
            CollectedRecord::Gap(gap) => {
                let reason = collector_gap_reason(&gap);
                if submit_gap(pipeline, identity, counters, &reason, *output_sequence) {
                    return true;
                }
                *output_sequence = output_sequence.wrapping_add(1);
            }
            CollectedRecord::Kernel(_) => {}
        }
    }
    false
}

fn submit_gap<StdoutWriter: Write, StderrWriter: Write>(
    pipeline: &mut OutputPipeline<StdoutWriter, StderrWriter>,
    identity: &HostIdentity,
    counters: &CollectorCounters,
    reason: &str,
    sequence: u64,
) -> bool {
    counters.gaps_generated.fetch_add(1, Ordering::Relaxed);
    let line = collector_gap(identity, reason.as_bytes(), sequence, now_millis());
    let result = pipeline
        .enqueue_gap(line.as_bytes())
        .and_then(|_| pipeline.drain_all());
    match result {
        Ok(()) => {
            emit_degraded_diagnostic(pipeline, identity, counters, reason.as_bytes());
            false
        }
        Err(error) => record_pipeline_failure(pipeline, identity, counters, &error),
    }
}

fn record_pipeline_failure<StdoutWriter: Write, StderrWriter: Write>(
    pipeline: &mut OutputPipeline<StdoutWriter, StderrWriter>,
    identity: &HostIdentity,
    counters: &CollectorCounters,
    error: &WriterError,
) -> bool {
    match error {
        WriterError::Queue(_) => {
            counters.queue_dropped.fetch_add(1, Ordering::Relaxed);
        }
        WriterError::Stdout(_) => {
            counters.stdout_failed.fetch_add(1, Ordering::Relaxed);
        }
        WriterError::Stderr(_) => {}
    }
    emit_degraded_diagnostic(pipeline, identity, counters, error.to_string().as_bytes());
    error.is_permanent_stdout_failure()
}

fn emit_degraded_diagnostic<StdoutWriter: Write, StderrWriter: Write>(
    pipeline: &mut OutputPipeline<StdoutWriter, StderrWriter>,
    identity: &HostIdentity,
    counters: &CollectorCounters,
    message: &[u8],
) {
    let snapshot = counters.snapshot();
    let detail = format!(
        "{} consumed={} output={} parse_failed={} queue_lost={} stdout_failed={} gaps={}",
        String::from_utf8_lossy(message),
        snapshot.consumed,
        snapshot.output_succeeded,
        snapshot.parse_failed,
        snapshot.queue_dropped,
        snapshot.stdout_failed,
        snapshot.gaps_generated,
    );
    let _ = pipeline.write_operational(
        diagnostic(
            identity,
            "error",
            "collector_degraded",
            "collector",
            detail.as_bytes(),
        )
        .as_bytes(),
    );
    let _ = pipeline.write_operational(status(identity, "degraded", 0, 0, false).as_bytes());
}

fn collector_gap_reason(gap: &CollectorGap) -> String {
    match gap {
        CollectorGap::MissingExecAttempt { process, attempt } => {
            format!("missing_exec_attempt:process={process}:attempt={attempt}")
        }
        CollectorGap::ExecAttemptTimeout { process, attempt } => {
            format!("exec_attempt_timeout:process={process}:attempt={attempt}")
        }
        CollectorGap::PendingCapacity => "exec_pending_capacity".into(),
    }
}

fn format_syscall_record(
    engine: &RuleEngine,
    identity: &HostIdentity,
    event: &auditd_ebpf_common::event::SyscallEvent,
    correlated_exec: Option<&CorrelatedExec>,
    output_sequence: u64,
) -> Option<String> {
    let arch = match event.arch {
        0xc000_003e => Arch::B64,
        0x4000_0003 => Arch::B32,
        _ => return None,
    };
    let syscall = syscall_name(arch, event.syscall_nr)?;
    let path_length = usize::from(event.path_len).min(event.path.len());
    let path_bytes = &event.path[..path_length];
    let path = if path_bytes.is_empty() {
        None
    } else {
        Some(Path::new(std::str::from_utf8(path_bytes).ok()?))
    };
    let mut candidate = CandidateEvent::new(arch, syscall)
        .with_identity(event.uid, event.gid)
        .with_success(event.return_value >= 0);
    if let Some(path) = path {
        candidate = candidate.with_path(path);
    }
    let matched = engine.evaluate(&candidate)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let pid = (event.header.pid_tgid >> 32) as u32;
    let event_id = format!("{}-{output_sequence}", event.header.cpu);
    let comm_length = event
        .comm
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(event.comm.len());
    Some(format_event(&AuditEvent {
        unix_seconds: now.as_secs(),
        millis: now.subsec_millis() as u16,
        sequence: output_sequence,
        host: identity.host.as_bytes(),
        machine_id: &identity.machine_id,
        event_id: event_id.as_bytes(),
        rule_version: event.header.rule_version,
        rule_id: matched.rule.rule_id,
        key: matched.rule.key.as_bytes(),
        arch: event.arch,
        syscall,
        operation: "syscall",
        success: event.return_value >= 0,
        exit: event.return_value,
        pid,
        ppid: event.ppid,
        uid: event.uid,
        gid: event.gid,
        euid: event.euid,
        egid: event.egid,
        comm: &event.comm[..comm_length],
        exe: b"",
        path: path_bytes,
        perm: "",
        argv_output: match matched.argv_output {
            EffectiveArgvOutput::Emitted => EffectiveArgvOutput::Emitted,
            EffectiveArgvOutput::Suppressed => EffectiveArgvOutput::Suppressed,
        },
        argc: correlated_exec.map_or(0, |exec| exec.observed_argc),
        argv: correlated_exec.map_or(&[], |exec| exec.argv.as_slice()),
        argv_truncated: correlated_exec.is_some_and(|exec| exec.argv_flags != 0),
        path_confidence: if path.is_some() { "lexical" } else { "none" },
    }))
}

fn resolve_identity(node_name: Option<&str>) -> HostIdentity {
    struct FileMachineId;
    impl MachineIdSource for FileMachineId {
        fn read_machine_id(&self) -> Result<String, String> {
            fs::read_to_string("/etc/machine-id").map_err(|error| error.to_string())
        }
    }
    let hostname = read_trimmed("/proc/sys/kernel/hostname").unwrap_or_else(|| "?".into());
    HostIdentity::resolve(node_name, &hostname, &FileMachineId)
}

fn read_trimmed(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn fallback_invocation_id() -> String {
    format!("{}-{}", std::process::id(), now_millis())
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor, Write};

    use super::*;

    struct FailingStdout;

    impl Write for FailingStdout {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "测试 EPIPE"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "测试 EPIPE"))
        }
    }

    fn identity() -> HostIdentity {
        HostIdentity {
            host: "test-host".into(),
            machine_id: "test-machine".into(),
            machine_id_diagnostic: None,
        }
    }

    #[test]
    fn 队列硬上限失败会累计丢失并进入degraded() {
        let mut pipeline = OutputPipeline::memory(1, 1).unwrap();
        let counters = CollectorCounters::default();
        let error = pipeline.enqueue_audit(b"too-large").unwrap_err();

        assert!(!record_pipeline_failure(
            &mut pipeline,
            &identity(),
            &counters,
            &error,
        ));
        let snapshot = counters.snapshot();
        assert_eq!(snapshot.queue_dropped, 1);
        assert!(snapshot.is_degraded());
        let operational = String::from_utf8_lossy(pipeline.stderr_bytes());
        assert!(operational.contains("code=collector_degraded"));
        assert!(operational.contains("state=degraded"));
    }

    #[test]
    fn stdout永久失败会累计并要求collector停止() {
        let mut pipeline =
            OutputPipeline::new(FailingStdout, Cursor::new(Vec::new()), 16, 16).unwrap();
        let counters = CollectorCounters::default();
        pipeline.enqueue_audit(b"audit\n").unwrap();
        let error = pipeline.drain_all().unwrap_err();

        assert!(record_pipeline_failure(
            &mut pipeline,
            &identity(),
            &counters,
            &error,
        ));
        let snapshot = counters.snapshot();
        assert_eq!(snapshot.stdout_failed, 1);
        assert!(snapshot.is_degraded());
    }
}
