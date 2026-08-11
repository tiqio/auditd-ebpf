use auditd_ebpf_rules::{
    Arch, ArgvOutput, KernelFilterPlan, RuleCompiler, parse_rules, source::sorted_rule_files,
    syscall_name,
};
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Write},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use tokio::signal::unix::{SignalKind, signal};

use crate::{
    capabilities::drop_runtime_capabilities,
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
    process_cache::{
        ProcessCache, bootstrap,
        lifecycle::on_mount_boundary_change,
        model::{ProcessAbi, ProcessIdentity},
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
    global_argv_enabled: bool,
    argv_rules: &BTreeMap<String, bool>,
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
    runtime.block_on(run_async(
        node_name,
        lifecycle_path,
        ebpf_object,
        rules_dir,
        global_argv_enabled,
        argv_rules,
    ))
}

async fn run_async(
    node_name: Option<&str>,
    lifecycle_path: &Path,
    ebpf_object: Option<&Path>,
    rules_dir: &Path,
    global_argv_enabled: bool,
    argv_rules: &BTreeMap<String, bool>,
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
        let plan = match compile_rules(rules_dir, argv_rules, 0) {
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
    let rule_engines = active_plan.as_ref().map(|plan| {
        Arc::new(RwLock::new(RuleEngineRegistry::new(
            plan.clone(),
            global_argv_enabled,
        )))
    });
    let mut active_generation = active_plan.as_ref().map_or(0, |plan| plan.generation);
    let collector_resources = if let Some(loaded) = loaded_bpf.as_mut() {
        if let Err(error) = loaded.attach_collection_programs() {
            eprintln!(
                "type=AUDITD_EBPF_DIAG level=error code=ebpf_attach component=runtime message={error:?}"
            );
            return 6;
        }
        match loaded.take_ring() {
            Ok(ring) => {
                let process_cache = match bootstrap::scan_proc() {
                    Ok(cache) => cache,
                    Err(error) => {
                        eprintln!(
                            "type=AUDITD_EBPF_DIAG level=error code=process_cache_bootstrap component=runtime message={error:?}"
                        );
                        return 6;
                    }
                };
                Some((ring, process_cache))
            }
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

    // 所有需要特权的 BPF load/attach、map 与 RingBuf fd 获取已经结束。能力降级必须发生在
    // collector 线程创建之前，因为 Linux capability 是线程凭据，新线程只会继承当前集合。
    if let Err(error) = drop_runtime_capabilities() {
        eprintln!(
            "type=AUDITD_EBPF_DIAG level=error code=capability_drop component=runtime message={error:?}"
        );
        return 6;
    }
    // 采集线程会在整个运行期持有 stdout 锁，因此必须先由主线程输出启动阶段的
    // 不洁退出 gap；否则 previous_dirty 路径会永远等待 collector 释放 stdout。
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

    let mut collector = collector_resources.map(|(ring, process_cache)| {
        KernelCollector::start(
            ring,
            Arc::clone(
                rule_engines
                    .as_ref()
                    .expect("加载 eBPF 时用户态规则引擎已创建"),
            ),
            identity.clone(),
            process_cache,
        )
    });

    loop {
        tokio::select! {
            _ = usr1.recv() => {
                let collector_degraded = collector.as_ref().is_some_and(KernelCollector::is_degraded);
                eprint!("{}", status(&identity, if previous_dirty || collector_degraded { "degraded" } else { "healthy" }, 0, 0, false));
            }
            _ = hangup.recv() => {
                let Some(loaded) = loaded_bpf.as_mut() else {
                    eprintln!("type=AUDITD_EBPF_DIAG host={} machine_id={} level=error code=reload_unavailable component=runtime message=\"未加载 eBPF 对象\"", identity.host, identity.machine_id);
                    continue;
                };
                let Some(engines) = rule_engines.as_ref() else {
                    eprintln!("type=AUDITD_EBPF_DIAG host={} machine_id={} level=error code=reload_unavailable component=runtime message=\"用户态规则引擎不存在\"", identity.host, identity.machine_id);
                    continue;
                };
                let generation = 1 - active_generation;
                let candidate = match compile_rules(rules_dir, argv_rules, generation) {
                    Ok(candidate) => candidate,
                    Err(error) => {
                        eprintln!("type=AUDITD_EBPF_DIAG host={} machine_id={} level=error code=reload_rejected component=rules generation={} message={error:?}", identity.host, identity.machine_id, generation);
                        continue;
                    }
                };
                if let Err(error) = loaded.stage_inactive_rules(&candidate) {
                    eprintln!("type=AUDITD_EBPF_DIAG host={} machine_id={} level=error code=reload_stage_failed component=runtime generation={} message={error:?}", identity.host, identity.machine_id, generation);
                    continue;
                }
                let rule_version = candidate.rule_version();
                let previous = match engines.write() {
                    Ok(mut registry) => registry.install(candidate, global_argv_enabled),
                    Err(error) => {
                        eprintln!("type=AUDITD_EBPF_DIAG host={} machine_id={} level=error code=reload_registry_failed component=runtime generation={} message={error:?}", identity.host, identity.machine_id, generation);
                        continue;
                    }
                };
                if let Err(error) = loaded.activate_generation(generation) {
                    if let Ok(mut registry) = engines.write() {
                        registry.restore(generation, previous);
                    }
                    eprintln!("type=AUDITD_EBPF_DIAG host={} machine_id={} level=error code=reload_activate_failed component=runtime generation={} message={error:?}", identity.host, identity.machine_id, generation);
                    continue;
                }
                active_generation = generation;
                eprintln!("type=AUDITD_EBPF_DIAG host={} machine_id={} level=info code=reload_applied component=runtime generation={} rule_version={} message=\"候选规则已完整验证并原子切换\"", identity.host, identity.machine_id, generation, rule_version);
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

fn compile_rules(
    rules_dir: &Path,
    argv_rules: &BTreeMap<String, bool>,
    generation: u8,
) -> anyhow::Result<auditd_ebpf_rules::KernelFilterPlan> {
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
    let overrides = argv_rules
        .iter()
        .map(|(key, enabled)| {
            (
                key.clone(),
                if *enabled {
                    ArgvOutput::Enabled
                } else {
                    ArgvOutput::Disabled
                },
            )
        })
        .collect();
    RuleCompiler::compile(rules, generation, overrides).map_err(anyhow::Error::new)
}

struct VersionedRuleEngine {
    version: u64,
    engine: Arc<RuleEngine>,
}

struct RuleEngineRegistry {
    generations: [Option<VersionedRuleEngine>; 2],
}

impl RuleEngineRegistry {
    fn new(plan: KernelFilterPlan, global_argv_enabled: bool) -> Self {
        let mut registry = Self {
            generations: [None, None],
        };
        registry.install(plan, global_argv_enabled);
        registry
    }

    fn install(
        &mut self,
        plan: KernelFilterPlan,
        global_argv_enabled: bool,
    ) -> Option<VersionedRuleEngine> {
        let generation = usize::from(plan.generation);
        let version = plan.rule_version();
        self.generations[generation].replace(VersionedRuleEngine {
            version,
            engine: Arc::new(RuleEngine::new(plan, global_argv_enabled)),
        })
    }

    fn restore(&mut self, generation: u8, previous: Option<VersionedRuleEngine>) {
        self.generations[usize::from(generation)] = previous;
    }

    fn engine_for_version(&self, version: u64) -> Option<Arc<RuleEngine>> {
        self.generations
            .iter()
            .flatten()
            .find(|entry| entry.version == version)
            .map(|entry| Arc::clone(&entry.engine))
    }
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
    path_resolution_failed: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct CollectorSnapshot {
    consumed: u64,
    parse_failed: u64,
    queue_dropped: u64,
    output_succeeded: u64,
    stdout_failed: u64,
    gaps_generated: u64,
    path_resolution_failed: u64,
}

impl CollectorSnapshot {
    #[must_use]
    const fn is_degraded(self) -> bool {
        self.parse_failed != 0
            || self.queue_dropped != 0
            || self.stdout_failed != 0
            || self.gaps_generated != 0
            || self.path_resolution_failed != 0
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
            path_resolution_failed: self.path_resolution_failed.load(Ordering::Relaxed),
        }
    }
}

impl KernelCollector {
    fn start(
        mut ring: aya::maps::RingBuf<aya::maps::MapData>,
        rule_engines: Arc<RwLock<RuleEngineRegistry>>,
        identity: HostIdentity,
        process_cache: ProcessCache,
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let counters = Arc::new(CollectorCounters::default());
        let thread_stop = Arc::clone(&stop);
        let thread_counters = Arc::clone(&counters);
        let thread = thread::spawn(move || {
            let mut collector_runtime = CollectorRuntime::new(65_536, Duration::from_secs(30));
            let mut state = CollectorProcessingState {
                completed_execs: BTreeMap::new(),
                process_cache,
                output_sequence: 0,
            };
            // collector 是 stdout 的唯一审计事件写入者，因此可以长期持有 stdout 锁；stderr
            // 还要由主线程输出状态与信号诊断，只能在每次写入时短暂获取其内部锁，避免停止死锁。
            let stdout = io::stdout();
            let stderr = io::stderr();
            let mut pipeline = OutputPipeline::new(
                stdout.lock(),
                stderr,
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
                            state.output_sequence,
                        ) {
                            break 'collect;
                        }
                        state.output_sequence = state.output_sequence.wrapping_add(1);
                        continue;
                    }
                    if process_collected_records(
                        collector_runtime.take_output(),
                        &rule_engines,
                        &identity,
                        &mut state,
                        &mut pipeline,
                        &thread_counters,
                    ) {
                        break 'collect;
                    }
                }
                collector_runtime.expire(Instant::now());
                if process_collected_records(
                    collector_runtime.take_output(),
                    &rule_engines,
                    &identity,
                    &mut state,
                    &mut pipeline,
                    &thread_counters,
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

struct CollectorProcessingState {
    completed_execs: BTreeMap<u64, CorrelatedExec>,
    process_cache: ProcessCache,
    output_sequence: u64,
}

fn process_collected_records<StdoutWriter: Write, StderrWriter: Write>(
    records: Vec<CollectedRecord>,
    rule_engines: &RwLock<RuleEngineRegistry>,
    identity: &HostIdentity,
    state: &mut CollectorProcessingState,
    pipeline: &mut OutputPipeline<StdoutWriter, StderrWriter>,
    counters: &CollectorCounters,
) -> bool {
    for record in records {
        match record {
            CollectedRecord::Exec(exec) => {
                state.completed_execs.insert(exec.process, exec);
            }
            CollectedRecord::Kernel(crate::collector::decode::KernelRecord::Syscall(event)) => {
                let correlated = state.completed_execs.remove(&event.header.pid_tgid);
                let engine = match rule_engines
                    .read()
                    .ok()
                    .and_then(|registry| registry.engine_for_version(event.header.rule_version))
                {
                    Some(engine) => engine,
                    None => {
                        let reason = format!(
                            "rule_version_unavailable:version={}",
                            event.header.rule_version
                        );
                        if submit_gap(pipeline, identity, counters, &reason, state.output_sequence)
                        {
                            return true;
                        }
                        state.output_sequence = state.output_sequence.wrapping_add(1);
                        apply_syscall_cache_updates(&mut state.process_cache, &event, None);
                        continue;
                    }
                };
                let resolved_path =
                    match resolve_syscall_path(&mut state.process_cache, &engine, &event) {
                        Ok(path) => path,
                        Err(reason) => {
                            counters
                                .path_resolution_failed
                                .fetch_add(1, Ordering::Relaxed);
                            if submit_gap(
                                pipeline,
                                identity,
                                counters,
                                &reason,
                                state.output_sequence,
                            ) {
                                return true;
                            }
                            state.output_sequence = state.output_sequence.wrapping_add(1);
                            apply_syscall_cache_updates(&mut state.process_cache, &event, None);
                            continue;
                        }
                    };
                if let Some(line) = format_syscall_record(
                    &engine,
                    identity,
                    &event,
                    correlated.as_ref(),
                    resolved_path.as_deref(),
                    state.output_sequence,
                ) {
                    let result = pipeline
                        .enqueue_audit(line.as_bytes())
                        .and_then(|_| pipeline.drain_all());
                    state.output_sequence = state.output_sequence.wrapping_add(1);
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
                apply_syscall_cache_updates(
                    &mut state.process_cache,
                    &event,
                    resolved_path.as_deref(),
                );
            }
            CollectedRecord::Gap(gap) => {
                let reason = collector_gap_reason(&gap);
                if submit_gap(pipeline, identity, counters, &reason, state.output_sequence) {
                    return true;
                }
                state.output_sequence = state.output_sequence.wrapping_add(1);
            }
            CollectedRecord::Kernel(crate::collector::decode::KernelRecord::Process(event)) => {
                apply_process_event(&mut state.process_cache, &event);
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
        "{} consumed={} output={} parse_failed={} queue_lost={} stdout_failed={} path_lost={} gaps={}",
        String::from_utf8_lossy(message),
        snapshot.consumed,
        snapshot.output_succeeded,
        snapshot.parse_failed,
        snapshot.queue_dropped,
        snapshot.stdout_failed,
        snapshot.path_resolution_failed,
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

fn resolve_syscall_path(
    cache: &mut ProcessCache,
    engine: &RuleEngine,
    event: &auditd_ebpf_common::event::SyscallEvent,
) -> Result<Option<PathBuf>, String> {
    let arch = match event.arch {
        0xc000_003e => Arch::B64,
        0x4000_0003 => Arch::B32,
        _ => return Ok(None),
    };
    let Some(syscall) = syscall_name(arch, event.syscall_nr) else {
        return Ok(None);
    };
    let path_length = usize::from(event.path_len).min(event.path.len());
    let path_bytes = &event.path[..path_length];
    if path_bytes.is_empty() {
        return Ok(None);
    }
    let raw = std::str::from_utf8(path_bytes)
        .map_err(|error| format!("path_invalid_utf8:syscall={syscall}:error={error}"))?;
    let (tgid, tid) = process_ids(event.header.pid_tgid);
    let dirfd = (event.dirfd != libc::AT_FDCWD).then_some(event.dirfd);
    let resolve = |cache: &ProcessCache| cache.resolve_path(tid, dirfd, Path::new(raw));

    match resolve(cache) {
        Ok(path) => Ok(Some(path)),
        Err(first_error) => {
            // 缓存缺失或 mount epoch 失效时只从事件进程自己的 /proc 视图刷新；绝不使用
            // collector 进程的 cwd/root 猜测目标路径。
            if let Ok(context) = bootstrap::read_thread(tgid, tid) {
                cache.insert_context(context);
                if let Ok(path) = resolve(cache) {
                    return Ok(Some(path));
                }
            }
            if engine.requires_resolved_path(arch, syscall) {
                Err(format!(
                    "path_resolution_failed:tgid={tgid}:tid={tid}:syscall={syscall}:reason={first_error}"
                ))
            } else {
                Ok(None)
            }
        }
    }
}

fn apply_process_event(cache: &mut ProcessCache, event: &auditd_ebpf_common::event::ProcessEvent) {
    use auditd_ebpf_common::event::{PROCESS_EVENT_EXEC, PROCESS_EVENT_EXIT, PROCESS_EVENT_FORK};

    let (tgid, tid) = process_ids(event.header.pid_tgid);
    match event.event_kind {
        PROCESS_EVENT_FORK => {
            let (child_tgid, child_tid) = process_ids(event.related_pid_tgid);
            if let Ok(context) = bootstrap::read_thread(child_tgid, child_tid) {
                cache.insert_context(context);
            } else {
                let _ = cache.fork_thread(
                    tid,
                    ProcessIdentity {
                        tgid: child_tgid,
                        start_time: event.header.process_start_ns,
                    },
                    child_tid,
                );
            }
        }
        PROCESS_EVENT_EXEC => {
            if let Ok(context) = bootstrap::read_thread(tgid, tid) {
                cache.insert_context(context);
            } else {
                let _ = cache.exec_thread(tid, process_abi(event.abi_arch));
            }
        }
        PROCESS_EVENT_EXIT => cache.exit_thread(tid),
        _ => {}
    }
}

fn apply_syscall_cache_updates(
    cache: &mut ProcessCache,
    event: &auditd_ebpf_common::event::SyscallEvent,
    resolved_path: Option<&Path>,
) {
    let arch = match event.arch {
        0xc000_003e => Arch::B64,
        0x4000_0003 => Arch::B32,
        _ => return,
    };
    let Some(syscall) = syscall_name(arch, event.syscall_nr) else {
        return;
    };
    let success = event.return_value >= 0;
    let (tgid, tid) = process_ids(event.header.pid_tgid);

    if success {
        match syscall {
            "open" | "openat" | "openat2" | "creat" => {
                if let Some(path) = resolved_path {
                    let _ = cache.open_fd(tid, event.return_value as i32, path);
                }
            }
            "close" => {
                let _ = cache.close_fd(tid, event.args[0] as i32);
            }
            "dup" => {
                let _ = cache.duplicate_fd(tid, event.args[0] as i32, event.return_value as i32);
            }
            "dup2" | "dup3" => {
                let _ = cache.duplicate_fd(tid, event.args[0] as i32, event.args[1] as i32);
            }
            "chdir" => {
                if let Some(path) = resolved_path {
                    let _ = cache.change_cwd(tid, path);
                }
            }
            "fchdir" => {
                let _ = cache.fchdir(tid, event.args[0] as i32);
            }
            _ => {}
        }
    }

    if event.path_flags & auditd_ebpf_common::event::PATH_FLAG_MOUNT_BOUNDARY_CHANGED != 0 {
        // 内核位是最终兜底，避免 syscall 名表遗漏新旧 ABI 的边界变更调用。
        cache.invalidate_mounts();
    } else {
        on_mount_boundary_change(cache, syscall, success);
    }
    if cache
        .thread(tid)
        .is_some_and(|context| !context.is_current(cache.mount_epoch()))
        && let Ok(context) = bootstrap::read_thread(tgid, tid)
    {
        cache.insert_context(context);
    }
}

const fn process_ids(pid_tgid: u64) -> (u32, u32) {
    ((pid_tgid >> 32) as u32, pid_tgid as u32)
}

const fn process_abi(arch: u32) -> ProcessAbi {
    match arch {
        0xc000_003e => ProcessAbi::B64,
        0x4000_0003 => ProcessAbi::B32,
        _ => ProcessAbi::Unknown,
    }
}

fn format_syscall_record(
    engine: &RuleEngine,
    identity: &HostIdentity,
    event: &auditd_ebpf_common::event::SyscallEvent,
    correlated_exec: Option<&CorrelatedExec>,
    resolved_path: Option<&Path>,
    output_sequence: u64,
) -> Option<String> {
    let arch = match event.arch {
        0xc000_003e => Arch::B64,
        0x4000_0003 => Arch::B32,
        _ => return None,
    };
    let syscall = syscall_name(arch, event.syscall_nr)?;
    let mut candidate = CandidateEvent::new(arch, syscall)
        .with_identity(event.uid, event.gid)
        .with_success(event.return_value >= 0);
    if let Some(path) = resolved_path {
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
        // 当前 syscall tracepoint 事件中的 ppid 字段由内核程序固定为零，并非可信父进程
        // 标识；在接入进程缓存关联前必须显式输出未知，禁止把零伪装成真实值。
        ppid: None,
        uid: event.uid,
        gid: event.gid,
        euid: event.euid,
        egid: event.egid,
        comm: &event.comm[..comm_length],
        exe: None,
        path: resolved_path.map_or(&[], |path| path.as_os_str().as_bytes()),
        perm: None,
        argv_output: match matched.argv_output {
            EffectiveArgvOutput::Emitted => EffectiveArgvOutput::Emitted,
            EffectiveArgvOutput::Suppressed => EffectiveArgvOutput::Suppressed,
        },
        argc: correlated_exec.map_or(0, |exec| exec.observed_argc),
        argv: correlated_exec.map_or(&[], |exec| exec.argv.as_slice()),
        argv_truncated: correlated_exec.is_some_and(|exec| exec.argv_flags != 0),
        path_confidence: if resolved_path.is_some() {
            "namespace-lexical"
        } else {
            "none"
        },
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
    use std::{
        collections::BTreeMap,
        io::{self, Cursor, Write},
    };

    use auditd_ebpf_common::{
        SCHEMA_VERSION,
        event::{KernelEventHeader, SyscallEvent},
    };
    use auditd_ebpf_rules::{RuleCompiler, parse_rules};

    use super::*;
    use crate::process_cache::model::MountNamespaceId;

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

    #[test]
    fn dirfd相对路径按事件线程边界解析() {
        let mut cache = ProcessCache::default();
        cache.insert_thread(
            ProcessIdentity {
                tgid: 42,
                start_time: 1,
            },
            43,
            "/",
            "/work",
            MountNamespaceId {
                device: 1,
                inode: 2,
            },
        );
        cache.open_fd(43, 5, "/srv/base").unwrap();
        let engine = path_engine("/srv/base/file");
        let event = syscall_event(42, 43, 5, b"file");

        assert_eq!(
            resolve_syscall_path(&mut cache, &engine, &event).unwrap(),
            Some(PathBuf::from("/srv/base/file"))
        );
    }

    #[test]
    fn 路径规则缺少事件线程上下文时返回可关联gap原因() {
        let mut cache = ProcessCache::default();
        let engine = path_engine("/srv/base/file");
        let event = syscall_event(u32::MAX - 1, u32::MAX, 5, b"file");

        let reason = resolve_syscall_path(&mut cache, &engine, &event).unwrap_err();
        assert!(reason.contains("path_resolution_failed"));
        assert!(reason.contains("tid=4294967295"));
        assert!(reason.contains("syscall=openat"));
    }

    #[test]
    fn 双generation规则引擎按事件版本选择() {
        let initial_rules = parse_rules(
            "initial.rules",
            "-a always,exit -F arch=b64 -S execve -k initial\n",
        )
        .unwrap();
        let initial = RuleCompiler::compile(initial_rules, 0, BTreeMap::new()).unwrap();
        let initial_version = initial.rule_version();
        let mut registry = RuleEngineRegistry::new(initial, true);

        let reloaded_rules = parse_rules(
            "reloaded.rules",
            "-a always,exit -F arch=b64 -S execve -k reloaded\n",
        )
        .unwrap();
        let reloaded = RuleCompiler::compile(reloaded_rules, 1, BTreeMap::new()).unwrap();
        let reloaded_version = reloaded.rule_version();
        registry.install(reloaded, true);

        let event = CandidateEvent::new(Arch::B64, "execve");
        assert_eq!(
            registry
                .engine_for_version(initial_version)
                .unwrap()
                .evaluate(&event)
                .unwrap()
                .rule
                .key,
            "initial"
        );
        assert_eq!(
            registry
                .engine_for_version(reloaded_version)
                .unwrap()
                .evaluate(&event)
                .unwrap()
                .rule
                .key,
            "reloaded"
        );
        assert!(registry.engine_for_version(u64::MAX).is_none());
    }

    fn path_engine(path: &str) -> RuleEngine {
        let rules = parse_rules(
            "runtime.rules",
            &format!("-a always,exit -F arch=b64 -S openat -F path={path} -k path\n"),
        )
        .unwrap();
        let plan = RuleCompiler::compile(rules, 0, BTreeMap::new()).unwrap();
        RuleEngine::new(plan, true)
    }

    fn syscall_event(tgid: u32, tid: u32, dirfd: i32, path: &[u8]) -> SyscallEvent {
        let mut event = SyscallEvent {
            header: KernelEventHeader {
                schema_version: SCHEMA_VERSION,
                record_type: 1,
                record_len: std::mem::size_of::<SyscallEvent>() as u32,
                cpu: 0,
                flags: 0,
                ktime_ns: 0,
                sequence: 0,
                rule_version: 1,
                pid_tgid: ((tgid as u64) << 32) | u64::from(tid),
                process_start_ns: 0,
            },
            arch: 0xc000_003e,
            syscall_nr: 257,
            args: [0; 6],
            return_value: 0,
            uid: 0,
            gid: 0,
            euid: 0,
            egid: 0,
            ppid: 0,
            comm: [0; 16],
            dirfd,
            path_flags: auditd_ebpf_common::event::PATH_FLAG_PRIMARY_PRESENT,
            path_len: path.len() as u16,
            path2_len: 0,
            path: [0; auditd_ebpf_common::event::MAX_PATH_ARG_BYTES],
            path2: [0; auditd_ebpf_common::event::MAX_PATH_ARG_BYTES],
        };
        event.path[..path.len()].copy_from_slice(path);
        event
    }
}
