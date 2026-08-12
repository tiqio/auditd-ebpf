use auditd_ebpf_common::{event::permission_from_event_flags, permission::PermissionMask};
use auditd_ebpf_rules::{
    Arch, ArgvOutput, KernelFilterPlan, RuleCompiler, RuleKind, parse_rules,
    source::sorted_rule_files, syscall_name,
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
    health::{
        counters::HealthCounters,
        watch_gap::{WatchGapReason, decide_watch_gap},
    },
    identity::{HostIdentity, MachineIdSource},
    lifecycle::{
        model::{LifecycleMarker, LifecycleState},
        state_file::LifecycleStateFile,
    },
    loader::LoadedBpf,
    output::{
        adaptive_queue::{DEFAULT_INITIAL_BYTES, DEFAULT_MAX_BYTES},
        event_formatter::{AuditEvent, format_event},
        status_formatter::{
            StatusRecord, collector_gap, diagnostic, status, unclean_shutdown_gap, watch_diagnostic,
        },
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
    let started_at = Instant::now();
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
    let mut dirty = LifecycleMarker::dirty(
        read_trimmed("/proc/sys/kernel/random/boot_id").unwrap_or_else(|| "?".into()),
        read_trimmed("/proc/sys/kernel/random/uuid").unwrap_or_else(fallback_invocation_id),
        std::process::id(),
        now_millis(),
    );
    dirty.rule_version = active_plan.as_ref().map(KernelFilterPlan::rule_version);
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
    let mut active_rule_version = active_plan.as_ref().map(KernelFilterPlan::rule_version);
    if emit_runtime_status(
        &identity,
        loaded_bpf.as_mut(),
        collector.as_ref(),
        previous_dirty,
        started_at,
        active_rule_version,
        false,
        None,
    )
    .is_err()
    {
        return 7;
    }
    let mut status_interval = tokio::time::interval(Duration::from_secs(10));
    status_interval.tick().await;

    loop {
        tokio::select! {
            _ = usr1.recv() => {
                if emit_runtime_status(&identity, loaded_bpf.as_mut(), collector.as_ref(), previous_dirty, started_at, active_rule_version, false, None).is_err() {
                    break;
                }
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
                        if let Some(collector) = collector.as_ref() { collector.record_reload_failed(); }
                        eprintln!("type=AUDITD_EBPF_DIAG host={} machine_id={} level=error code=reload_rejected component=rules generation={} message={error:?}", identity.host, identity.machine_id, generation);
                        continue;
                    }
                };
                if let Err(error) = loaded.stage_inactive_rules(&candidate) {
                    if let Some(collector) = collector.as_ref() { collector.record_reload_failed(); }
                    eprintln!("type=AUDITD_EBPF_DIAG host={} machine_id={} level=error code=reload_stage_failed component=runtime generation={} message={error:?}", identity.host, identity.machine_id, generation);
                    continue;
                }
                let rule_version = candidate.rule_version();
                let previous = match engines.write() {
                    Ok(mut registry) => registry.install(candidate, global_argv_enabled),
                    Err(error) => {
                        if let Some(collector) = collector.as_ref() { collector.record_reload_failed(); }
                        eprintln!("type=AUDITD_EBPF_DIAG host={} machine_id={} level=error code=reload_registry_failed component=runtime generation={} message={error:?}", identity.host, identity.machine_id, generation);
                        continue;
                    }
                };
                if let Err(error) = loaded.activate_generation(generation) {
                    if let Some(collector) = collector.as_ref() { collector.record_reload_failed(); }
                    if let Ok(mut registry) = engines.write() {
                        registry.restore(generation, previous);
                    }
                    eprintln!("type=AUDITD_EBPF_DIAG host={} machine_id={} level=error code=reload_activate_failed component=runtime generation={} message={error:?}", identity.host, identity.machine_id, generation);
                    continue;
                }
                active_generation = generation;
                active_rule_version = Some(rule_version);
                if let Some(collector) = collector.as_ref() { collector.record_reload_success(); }
                eprintln!("type=AUDITD_EBPF_DIAG host={} machine_id={} level=info code=reload_applied component=runtime generation={} rule_version={} message=\"候选规则已完整验证并原子切换\"", identity.host, identity.machine_id, generation, rule_version);
            }
            _ = status_interval.tick() => {
                if emit_runtime_status(&identity, loaded_bpf.as_mut(), collector.as_ref(), previous_dirty, started_at, active_rule_version, false, None).is_err() {
                    break;
                }
            }
            _ = term.recv() => break,
            _ = interrupt.recv() => break,
        }
    }

    let _ = emit_runtime_status(
        &identity,
        loaded_bpf.as_mut(),
        collector.as_ref(),
        previous_dirty,
        started_at,
        active_rule_version,
        false,
        Some("stopping"),
    );
    if let Some(loaded) = loaded_bpf.as_mut()
        && let Err(error) = loaded.detach_collection_programs()
    {
        eprintln!(
            "type=AUDITD_EBPF_DIAG level=error code=ebpf_detach component=runtime message={error:?}"
        );
        return 7;
    }
    let drain = collector
        .as_mut()
        .map_or(DrainOutcome::Drained, |collector| {
            collector.stop(Duration::from_secs(30))
        });
    let final_counters = match runtime_health_counters(
        loaded_bpf.as_mut(),
        collector.as_ref(),
        previous_dirty,
    ) {
        Ok(counters) => counters,
        Err(error) => {
            eprintln!(
                "type=AUDITD_EBPF_DIAG level=error code=final_counters component=runtime message={error:?}"
            );
            return 7;
        }
    };
    eprint!(
        "{}",
        status(
            &identity,
            &status_record(
                &final_counters,
                collector.as_ref(),
                started_at,
                active_rule_version,
                true,
                "stopping",
                None,
                loaded_bpf.is_some()
            )
        )
    );
    if io::stderr().flush().is_err() {
        return 7;
    }
    drop(collector);
    // LoadedBpf 持有所有 Aya links/maps；先 drop 确保 detach 和 map 清理完成，之后才允许 clean。
    drop(loaded_bpf);
    let clean = dirty.into_clean(final_lifecycle_counters(&final_counters));
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

fn runtime_health_counters(
    loaded_bpf: Option<&mut LoadedBpf>,
    collector: Option<&KernelCollector>,
    previous_dirty: bool,
) -> anyhow::Result<HealthCounters> {
    let mut counters = HealthCounters::default();
    if let Some(loaded) = loaded_bpf {
        let mut applied = false;
        for _ in 0..16 {
            let sample = loaded.read_kernel_counters()?;
            if counters.apply_kernel_sample(&sample).is_ok() {
                applied = true;
                break;
            }
            // PerCpuArray 的不同槽位无法在一个内核事务中读取；活跃 CPU 恰好在两次
            // map lookup 之间更新时会出现瞬时不变量偏差，短暂重试而不是伪造或忽略。
            thread::sleep(Duration::from_millis(1));
        }
        anyhow::ensure!(applied, "无法取得满足内核计数不变量的一致快照");
    }
    if let Some(collector) = collector {
        let snapshot = collector.snapshot();
        counters.events_consumed_total = snapshot.consumed;
        counters.events_matched_total = snapshot.matched;
        counters.events_unmatched_total = snapshot.unmatched;
        counters.events_output_total = snapshot.output_succeeded;
        counters.exec_argv_suppressed_total = snapshot.argv_suppressed;
        counters.queue_dropped_total = snapshot.queue_dropped;
        counters.path_resolution_failed_total = snapshot.path_resolution_failed;
        counters.event_parse_failed_total = snapshot.parse_failed;
        counters.stdout_write_failed_total = snapshot.stdout_failed;
        counters.rule_reload_success_total = snapshot.reload_success;
        counters.rule_reload_failed_total = snapshot.reload_failed;
        counters.gap_records_generated_total = snapshot.gaps_generated;
        counters.watch_candidates_total = snapshot.watch_candidates;
        counters.watch_matches_total = snapshot.watch_matches;
        counters.watch_read_matches_total = snapshot.watch_read_matches;
        counters.watch_write_matches_total = snapshot.watch_write_matches;
        counters.watch_exec_matches_total = snapshot.watch_exec_matches;
        counters.watch_attr_matches_total = snapshot.watch_attr_matches;
        counters.watch_permission_failures_total = snapshot.watch_permission_failures;
        counters.watch_fd_failures_total = snapshot.watch_fd_failures;
    }
    counters.unclean_shutdown_detected_total = u64::from(previous_dirty);
    anyhow::ensure!(counters.all_invariants_hold(), "运行时计数不变量被破坏");
    Ok(counters)
}

#[allow(clippy::too_many_arguments)]
fn status_record<'a>(
    counters: &'a HealthCounters,
    collector: Option<&KernelCollector>,
    started_at: Instant,
    rule_version: Option<u64>,
    final_record: bool,
    state: &'a str,
    reason: Option<&'a str>,
    programs_attached: bool,
) -> StatusRecord<'a> {
    let collector = collector.map_or_else(CollectorSnapshot::default, KernelCollector::snapshot);
    StatusRecord {
        state,
        reason,
        uptime_seconds: started_at.elapsed().as_secs(),
        rule_version,
        programs_attached: if programs_attached { 5 } else { 0 },
        counters,
        queue_used_bytes: collector.queue_used_bytes,
        queue_limit_bytes: collector.queue_limit_bytes,
        queue_max_bytes: collector.queue_max_bytes,
        final_record,
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_runtime_status(
    identity: &HostIdentity,
    loaded_bpf: Option<&mut LoadedBpf>,
    collector: Option<&KernelCollector>,
    previous_dirty: bool,
    started_at: Instant,
    rule_version: Option<u64>,
    final_record: bool,
    state_override: Option<&str>,
) -> anyhow::Result<HealthCounters> {
    let programs_attached = loaded_bpf.is_some();
    let counters = runtime_health_counters(loaded_bpf, collector, previous_dirty)?;
    let collector_degraded = collector.is_some_and(KernelCollector::is_degraded);
    let (state, reason) = if let Some(state) = state_override {
        (state, None)
    } else if previous_dirty {
        ("degraded", Some("unclean_shutdown"))
    } else if started_at.elapsed() >= Duration::from_secs(10)
        && (counters.kernel_lost_total() != 0
            || counters.watch_permission_failures_total != 0
            || counters.watch_fd_failures_total != 0
            || counters.path_resolution_failed_total != 0
            || counters.queue_dropped_total != 0
            || counters.stdout_write_failed_total != 0)
    {
        ("unhealthy", Some("persistent_audit_gap"))
    } else if counters.kernel_lost_total() != 0 {
        ("degraded", Some("kernel_event_loss"))
    } else if counters.path_resolution_failed_total != 0 {
        ("degraded", Some("path_resolution_failed"))
    } else if collector_degraded {
        ("degraded", Some("collector_gap"))
    } else {
        ("healthy", None)
    };
    eprint!(
        "{}",
        status(
            identity,
            &status_record(
                &counters,
                collector,
                started_at,
                rule_version,
                final_record,
                state,
                reason,
                programs_attached,
            ),
        )
    );
    Ok(counters)
}

fn final_lifecycle_counters(counters: &HealthCounters) -> BTreeMap<String, u64> {
    BTreeMap::from([
        ("events_seen".into(), counters.events_seen_total),
        ("events_submitted".into(), counters.events_submitted_total),
        ("events_consumed".into(), counters.events_consumed_total),
        ("events_matched".into(), counters.events_matched_total),
        ("events_output".into(), counters.events_output_total),
        ("watch_candidates".into(), counters.watch_candidates_total),
        ("watch_matches".into(), counters.watch_matches_total),
        ("watch_r".into(), counters.watch_read_matches_total),
        ("watch_w".into(), counters.watch_write_matches_total),
        ("watch_x".into(), counters.watch_exec_matches_total),
        ("watch_a".into(), counters.watch_attr_matches_total),
        (
            "watch_permission_failures".into(),
            counters.watch_permission_failures_total,
        ),
        ("watch_fd_failures".into(), counters.watch_fd_failures_total),
        ("ring_lost".into(), counters.ring_reserve_failed_total),
        ("kernel_lost".into(), counters.kernel_lost_total()),
        ("queue_lost".into(), counters.queue_dropped_total),
        ("path_lost".into(), counters.path_resolution_failed_total),
        ("parse_failed".into(), counters.event_parse_failed_total),
        ("stdout_failed".into(), counters.stdout_write_failed_total),
        (
            "gaps_generated".into(),
            counters.gap_records_generated_total,
        ),
    ])
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
    matched: AtomicU64,
    unmatched: AtomicU64,
    argv_suppressed: AtomicU64,
    reload_success: AtomicU64,
    reload_failed: AtomicU64,
    watch_candidates: AtomicU64,
    watch_matches: AtomicU64,
    watch_read_matches: AtomicU64,
    watch_write_matches: AtomicU64,
    watch_exec_matches: AtomicU64,
    watch_attr_matches: AtomicU64,
    watch_permission_failures: AtomicU64,
    watch_fd_failures: AtomicU64,
    queue_used_bytes: AtomicU64,
    queue_limit_bytes: AtomicU64,
    queue_max_bytes: AtomicU64,
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
    matched: u64,
    unmatched: u64,
    argv_suppressed: u64,
    reload_success: u64,
    reload_failed: u64,
    watch_candidates: u64,
    watch_matches: u64,
    watch_read_matches: u64,
    watch_write_matches: u64,
    watch_exec_matches: u64,
    watch_attr_matches: u64,
    watch_permission_failures: u64,
    watch_fd_failures: u64,
    queue_used_bytes: u64,
    queue_limit_bytes: u64,
    queue_max_bytes: u64,
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
            matched: self.matched.load(Ordering::Relaxed),
            unmatched: self.unmatched.load(Ordering::Relaxed),
            argv_suppressed: self.argv_suppressed.load(Ordering::Relaxed),
            reload_success: self.reload_success.load(Ordering::Relaxed),
            reload_failed: self.reload_failed.load(Ordering::Relaxed),
            watch_candidates: self.watch_candidates.load(Ordering::Relaxed),
            watch_matches: self.watch_matches.load(Ordering::Relaxed),
            watch_read_matches: self.watch_read_matches.load(Ordering::Relaxed),
            watch_write_matches: self.watch_write_matches.load(Ordering::Relaxed),
            watch_exec_matches: self.watch_exec_matches.load(Ordering::Relaxed),
            watch_attr_matches: self.watch_attr_matches.load(Ordering::Relaxed),
            watch_permission_failures: self.watch_permission_failures.load(Ordering::Relaxed),
            watch_fd_failures: self.watch_fd_failures.load(Ordering::Relaxed),
            queue_used_bytes: self.queue_used_bytes.load(Ordering::Relaxed),
            queue_limit_bytes: self.queue_limit_bytes.load(Ordering::Relaxed),
            queue_max_bytes: self.queue_max_bytes.load(Ordering::Relaxed),
        }
    }

    fn update_queue<StdoutWriter: Write, StderrWriter: Write>(
        &self,
        pipeline: &OutputPipeline<StdoutWriter, StderrWriter>,
    ) {
        self.queue_used_bytes
            .store(pipeline.queue_used_bytes() as u64, Ordering::Relaxed);
        self.queue_limit_bytes
            .store(pipeline.queue_limit_bytes() as u64, Ordering::Relaxed);
        self.queue_max_bytes
            .store(pipeline.queue_max_bytes() as u64, Ordering::Relaxed);
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
            thread_counters.update_queue(&pipeline);
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
                thread_counters.update_queue(&pipeline);
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

    fn is_degraded(&self) -> bool {
        self.counters.snapshot().is_degraded()
    }

    fn snapshot(&self) -> CollectorSnapshot {
        self.counters.snapshot()
    }

    fn record_reload_success(&self) {
        self.counters.reload_success.fetch_add(1, Ordering::Relaxed);
    }

    fn record_reload_failed(&self) {
        self.counters.reload_failed.fetch_add(1, Ordering::Relaxed);
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
                let resolved_paths =
                    match resolve_syscall_paths(&mut state.process_cache, &engine, &event) {
                        Ok(path) => path,
                        Err(reason) => {
                            counters
                                .path_resolution_failed
                                .fetch_add(1, Ordering::Relaxed);
                            let syscall = syscall_name_for_event(&event);
                            let watch_candidate = match event.arch {
                                0xc000_003e => engine.is_watch_candidate(Arch::B64, syscall),
                                0x4000_0003 => engine.is_watch_candidate(Arch::B32, syscall),
                                _ => false,
                            };
                            if watch_candidate && let Some(gap_reason) = classify_watch_gap(&reason)
                            {
                                counters.watch_candidates.fetch_add(1, Ordering::Relaxed);
                                record_watch_gap_counter(counters, gap_reason);
                                if submit_watch_gap(
                                    pipeline,
                                    identity,
                                    counters,
                                    gap_reason,
                                    event.header.rule_version,
                                    event.header.pid_tgid,
                                    syscall,
                                    state.output_sequence,
                                ) {
                                    return true;
                                }
                                state.output_sequence = state.output_sequence.wrapping_add(1);
                            }
                            apply_syscall_cache_updates(&mut state.process_cache, &event, None);
                            continue;
                        }
                    };
                let arch = match event.arch {
                    0xc000_003e => Arch::B64,
                    0x4000_0003 => Arch::B32,
                    _ => {
                        counters.unmatched.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                let syscall = syscall_name(arch, event.syscall_nr).unwrap_or("unknown");
                let watch_candidate = engine.is_watch_candidate(arch, syscall);
                if watch_candidate {
                    counters.watch_candidates.fetch_add(1, Ordering::Relaxed);
                }
                let permission = match permission_from_event_flags(event.header.flags) {
                    Ok(permission) => permission,
                    Err(error) => {
                        if watch_candidate {
                            record_watch_gap_counter(
                                counters,
                                WatchGapReason::PermissionClassificationFailed,
                            );
                            if submit_watch_gap(
                                pipeline,
                                identity,
                                counters,
                                WatchGapReason::PermissionClassificationFailed,
                                event.header.rule_version,
                                event.header.pid_tgid,
                                syscall,
                                state.output_sequence,
                            ) {
                                return true;
                            }
                        } else {
                            let reason = format!(
                                "permission_flags_malformed:syscall={syscall}:flags={:#x}:error={error:?}",
                                event.header.flags
                            );
                            if submit_gap(
                                pipeline,
                                identity,
                                counters,
                                &reason,
                                state.output_sequence,
                            ) {
                                return true;
                            }
                        }
                        state.output_sequence = state.output_sequence.wrapping_add(1);
                        apply_syscall_cache_updates(
                            &mut state.process_cache,
                            &event,
                            resolved_paths.first().map(PathBuf::as_path),
                        );
                        continue;
                    }
                };
                let permission_gap_matches_path = permission.is_none()
                    && engine.requires_permission(arch, syscall)
                    && engine
                        .evaluate_paths(
                            &CandidateEvent::new(arch, syscall)
                                .with_identity(event.uid, event.gid)
                                .with_success(event.return_value >= 0)
                                .with_permissions(PermissionMask::ALL),
                            &resolved_paths,
                        )
                        .is_some();
                if permission_gap_matches_path {
                    record_watch_gap_counter(counters, WatchGapReason::PermissionFlagsMissing);
                    if submit_watch_gap(
                        pipeline,
                        identity,
                        counters,
                        WatchGapReason::PermissionFlagsMissing,
                        event.header.rule_version,
                        event.header.pid_tgid,
                        syscall,
                        state.output_sequence,
                    ) {
                        return true;
                    }
                    state.output_sequence = state.output_sequence.wrapping_add(1);
                    apply_syscall_cache_updates(
                        &mut state.process_cache,
                        &event,
                        resolved_paths.first().map(PathBuf::as_path),
                    );
                    continue;
                }
                if let Some((line, argv_suppressed, watch_permissions)) = format_syscall_record(
                    &engine,
                    identity,
                    &event,
                    correlated.as_ref(),
                    &resolved_paths,
                    permission,
                    state.output_sequence,
                ) {
                    counters.matched.fetch_add(1, Ordering::Relaxed);
                    if let Some(permissions) = watch_permissions {
                        record_watch_match(counters, permissions);
                    }
                    if argv_suppressed {
                        counters.argv_suppressed.fetch_add(1, Ordering::Relaxed);
                    }
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
                } else {
                    counters.unmatched.fetch_add(1, Ordering::Relaxed);
                }
                counters.update_queue(pipeline);
                apply_syscall_cache_updates(
                    &mut state.process_cache,
                    &event,
                    resolved_paths.first().map(PathBuf::as_path),
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

#[allow(clippy::too_many_arguments)]
fn submit_watch_gap<StdoutWriter: Write, StderrWriter: Write>(
    pipeline: &mut OutputPipeline<StdoutWriter, StderrWriter>,
    identity: &HostIdentity,
    counters: &CollectorCounters,
    reason: WatchGapReason,
    rule_version: u64,
    pid_tgid: u64,
    syscall: &str,
    sequence: u64,
) -> bool {
    let decision = decide_watch_gap(reason);
    debug_assert!(!decision.emit_audit_event);
    counters.gaps_generated.fetch_add(1, Ordering::Relaxed);
    let (pid, tid) = process_ids(pid_tgid);
    let line = collector_gap(identity, reason.as_str().as_bytes(), sequence, now_millis());
    let result = pipeline
        .enqueue_gap(line.as_bytes())
        .and_then(|_| pipeline.drain_all());
    if pipeline
        .write_operational(
            watch_diagnostic(identity, reason, Some(rule_version), pid, tid, syscall).as_bytes(),
        )
        .is_err()
    {
        // stderr 失败不能把 stdout 审计事件错误地标成成功；统一交给 writer 错误路径统计。
    }
    match result {
        Ok(()) => false,
        Err(error) => record_pipeline_failure(pipeline, identity, counters, &error),
    }
}

fn classify_watch_gap(reason: &str) -> Option<WatchGapReason> {
    [
        ("path_argument_missing", WatchGapReason::PathArgumentMissing),
        (
            "path_argument_truncated",
            WatchGapReason::PathArgumentTruncated,
        ),
        (
            "thread_context_missing",
            WatchGapReason::ThreadContextMissing,
        ),
        ("mount_context_stale", WatchGapReason::MountContextStale),
        (
            "fd_association_missing",
            WatchGapReason::FdAssociationMissing,
        ),
        ("fd_association_stale", WatchGapReason::FdAssociationStale),
        (
            "path_resolution_failed",
            WatchGapReason::ThreadContextMissing,
        ),
    ]
    .into_iter()
    .find_map(|(prefix, gap)| reason.starts_with(prefix).then_some(gap))
}

fn record_watch_gap_counter(counters: &CollectorCounters, reason: WatchGapReason) {
    match reason {
        WatchGapReason::PermissionFlagsMissing | WatchGapReason::PermissionClassificationFailed => {
            counters
                .watch_permission_failures
                .fetch_add(1, Ordering::Relaxed);
        }
        WatchGapReason::FdAssociationMissing | WatchGapReason::FdAssociationStale => {
            counters.watch_fd_failures.fetch_add(1, Ordering::Relaxed);
        }
        WatchGapReason::PathArgumentMissing
        | WatchGapReason::PathArgumentTruncated
        | WatchGapReason::ThreadContextMissing
        | WatchGapReason::MountContextStale => {}
    }
}

fn record_watch_match(counters: &CollectorCounters, permissions: PermissionMask) {
    counters.watch_matches.fetch_add(1, Ordering::Relaxed);
    for (permission, counter) in [
        (PermissionMask::READ, &counters.watch_read_matches),
        (PermissionMask::WRITE, &counters.watch_write_matches),
        (PermissionMask::EXEC, &counters.watch_exec_matches),
        (PermissionMask::ATTR, &counters.watch_attr_matches),
    ] {
        if permissions.intersects(permission) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn syscall_name_for_event(event: &auditd_ebpf_common::event::SyscallEvent) -> &'static str {
    let arch = match event.arch {
        0xc000_003e => Arch::B64,
        0x4000_0003 => Arch::B32,
        _ => return "unknown",
    };
    syscall_name(arch, event.syscall_nr).unwrap_or("unknown")
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

fn resolve_syscall_paths(
    cache: &mut ProcessCache,
    engine: &RuleEngine,
    event: &auditd_ebpf_common::event::SyscallEvent,
) -> Result<Vec<PathBuf>, String> {
    let arch = match event.arch {
        0xc000_003e => Arch::B64,
        0x4000_0003 => Arch::B32,
        _ => return Ok(Vec::new()),
    };
    let Some(syscall) = syscall_name(arch, event.syscall_nr) else {
        return Ok(Vec::new());
    };
    let (tgid, tid) = process_ids(event.header.pid_tgid);
    if event.path_flags & auditd_ebpf_common::event::PATH_FLAG_TRUNCATED != 0
        && engine.requires_resolved_path(arch, syscall)
    {
        return Err(format!(
            "path_argument_truncated:tgid={tgid}:tid={tid}:syscall={syscall}"
        ));
    }

    let mut requests = Vec::new();
    push_path_request(
        &mut requests,
        &event.path,
        event.path_len,
        primary_dirfd(event),
    );
    push_path_request(
        &mut requests,
        &event.path2,
        event.path2_len,
        secondary_dirfd(arch, syscall, event),
    );
    if requests.is_empty() && is_fd_only_path_syscall(syscall) {
        let fd = event.args[0] as i32;
        let resolve = |cache: &ProcessCache| cache.resolve_fd_path(tid, fd);
        if let Ok(path) = resolve(cache) {
            return Ok(vec![path]);
        }
        if let Ok(snapshot) = bootstrap::read_thread(tgid, tid) {
            cache.insert_context(snapshot);
            if let Ok(path) = resolve(cache) {
                return Ok(vec![path]);
            }
        }
        if engine.requires_resolved_path(arch, syscall) {
            return Err(format!(
                "fd_association_missing:tgid={tgid}:tid={tid}:syscall={syscall}:fd={fd}"
            ));
        }
        return Ok(Vec::new());
    }

    let resolve_all =
        |cache: &ProcessCache| -> Result<Vec<PathBuf>, crate::process_cache::path::PathError> {
            requests
                .iter()
                .map(|(raw, dirfd)| {
                    let raw = Path::new(raw);
                    if raw.is_absolute() {
                        return crate::process_cache::path::normalize_in_boundary(
                            Path::new("/"),
                            Path::new("/"),
                            None,
                            raw,
                        );
                    }
                    cache.resolve_path(tid, *dirfd, raw)
                })
                .collect()
        };
    match resolve_all(cache) {
        Ok(paths) => Ok(paths),
        Err(first_error) => {
            // 仅使用事件进程自己的 /proc 视图刷新，绝不借用 collector 的 cwd/root。
            if let Ok(snapshot) = bootstrap::read_thread(tgid, tid) {
                cache.insert_context(snapshot);
                if let Ok(paths) = resolve_all(cache) {
                    return Ok(paths);
                }
            }
            if engine.requires_resolved_path(arch, syscall) {
                Err(format!(
                    "path_resolution_failed:tgid={tgid}:tid={tid}:syscall={syscall}:reason={first_error}"
                ))
            } else {
                Ok(Vec::new())
            }
        }
    }
}

fn push_path_request(
    requests: &mut Vec<(String, Option<i32>)>,
    bytes: &[u8],
    declared_length: u16,
    dirfd: Option<i32>,
) {
    let length = usize::from(declared_length).min(bytes.len());
    let raw = &bytes[..length];
    let raw = raw.strip_suffix(&[0]).unwrap_or(raw);
    if let Ok(path) = std::str::from_utf8(raw)
        && !path.is_empty()
    {
        requests.push((path.to_owned(), dirfd));
    }
}

fn primary_dirfd(event: &auditd_ebpf_common::event::SyscallEvent) -> Option<i32> {
    (event.dirfd != libc::AT_FDCWD).then_some(event.dirfd)
}

fn secondary_dirfd(
    arch: Arch,
    syscall: &str,
    event: &auditd_ebpf_common::event::SyscallEvent,
) -> Option<i32> {
    let raw = match (arch, syscall) {
        (_, "renameat" | "renameat2" | "linkat") => event.args[2] as i32,
        (_, "symlinkat") => event.args[1] as i32,
        _ => libc::AT_FDCWD,
    };
    (raw != libc::AT_FDCWD).then_some(raw)
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
            "fcntl" if matches!(event.args[1] as i32, libc::F_DUPFD | libc::F_DUPFD_CLOEXEC) => {
                let _ = cache.duplicate_fd(tid, event.args[0] as i32, event.return_value as i32);
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

fn is_fd_only_path_syscall(syscall: &str) -> bool {
    matches!(
        syscall,
        "ftruncate"
            | "fallocate"
            | "fchmod"
            | "fchown"
            | "fgetxattr"
            | "flistxattr"
            | "fsetxattr"
            | "fremovexattr"
    )
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
    resolved_paths: &[PathBuf],
    permissions: Option<PermissionMask>,
    output_sequence: u64,
) -> Option<(String, bool, Option<PermissionMask>)> {
    let arch = match event.arch {
        0xc000_003e => Arch::B64,
        0x4000_0003 => Arch::B32,
        _ => return None,
    };
    let syscall = syscall_name(arch, event.syscall_nr)?;
    let candidate = CandidateEvent::new(arch, syscall)
        .with_identity(event.uid, event.gid)
        .with_success(event.return_value >= 0)
        .with_permissions(permissions.unwrap_or(PermissionMask::EMPTY));
    let (matched, matched_path) = engine.evaluate_paths(&candidate, resolved_paths)?;
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
    let argv_suppressed = matched.argv_output == EffectiveArgvOutput::Suppressed;
    let permission_text = permissions.map(|permission| permission.to_string());
    // `bool::then_some` 会急切求值参数；这里必须显式分支，否则普通 syscall 规则在
    // `permissions=None` 时也会被 `?` 提前丢弃，造成与 watch 无关的静默漏报。
    let watch_permissions = if matched.rule.kind == RuleKind::Watch {
        Some(permissions?)
    } else {
        None
    };
    Some((
        format_event(&AuditEvent {
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
            operation: syscall,
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
            path: matched_path.map_or(&[], |path| path.as_os_str().as_bytes()),
            perm: permission_text.as_deref(),
            argv_output: match matched.argv_output {
                EffectiveArgvOutput::Emitted => EffectiveArgvOutput::Emitted,
                EffectiveArgvOutput::Suppressed => EffectiveArgvOutput::Suppressed,
            },
            argc: correlated_exec.map_or(0, |exec| exec.observed_argc),
            argv: correlated_exec.map_or(&[], |exec| exec.argv.as_slice()),
            argv_truncated: correlated_exec.is_some_and(|exec| exec.argv_flags != 0),
            path_confidence: if matched_path.is_some() {
                "namespace-lexical"
            } else {
                "none"
            },
        }),
        argv_suppressed,
        watch_permissions,
    ))
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
        assert!(operational.contains("queue"));
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
            resolve_syscall_paths(&mut cache, &engine, &event).unwrap(),
            vec![PathBuf::from("/srv/base/file")]
        );
    }

    #[test]
    fn 路径规则缺少事件线程上下文时返回可关联gap原因() {
        let mut cache = ProcessCache::default();
        let engine = path_engine("/srv/base/file");
        let event = syscall_event(u32::MAX - 1, u32::MAX, 5, b"file");

        let reason = resolve_syscall_paths(&mut cache, &engine, &event).unwrap_err();
        assert!(reason.contains("path_resolution_failed"));
        assert!(reason.contains("tid=4294967295"));
        assert!(reason.contains("syscall=openat"));
    }

    #[test]
    fn dual_path分别使用自己的dirfd且截断明确失败() {
        let mut cache = ProcessCache::default();
        cache.insert_thread(
            ProcessIdentity {
                tgid: 44,
                start_time: 2,
            },
            45,
            "/",
            "/work",
            MountNamespaceId {
                device: 1,
                inode: 2,
            },
        );
        cache.open_fd(45, 5, "/old/base").unwrap();
        cache.open_fd(45, 6, "/new/base").unwrap();
        let rules = parse_rules(
            "dual.rules",
            "-a always,exit -F arch=b64 -S renameat -F path=/new/base/new -k dual\n",
        )
        .unwrap();
        let engine = RuleEngine::new(
            RuleCompiler::compile(rules, 0, BTreeMap::new()).unwrap(),
            true,
        );
        let mut event = syscall_event(44, 45, 5, b"old");
        event.syscall_nr = 264;
        event.args[2] = 6;
        event.path2_len = 3;
        event.path2[..3].copy_from_slice(b"new");
        event.path_flags |= auditd_ebpf_common::event::PATH_FLAG_SECONDARY_PRESENT;

        assert_eq!(
            resolve_syscall_paths(&mut cache, &engine, &event).unwrap(),
            vec![
                PathBuf::from("/old/base/old"),
                PathBuf::from("/new/base/new")
            ]
        );

        event.path_flags |= auditd_ebpf_common::event::PATH_FLAG_TRUNCATED;
        assert!(
            resolve_syscall_paths(&mut cache, &engine, &event)
                .unwrap_err()
                .contains("path_argument_truncated")
        );
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
