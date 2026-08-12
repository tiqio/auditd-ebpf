use std::time::Duration;

use auditd_ebpf::health::{
    counters::{HealthCounters, KernelCounterSample},
    reporter::{HealthReporter, ProductionPolicyState},
    state::{HealthState, HealthStateMachine},
};

#[test]
fn ebpf每cpu计数按字段求和且保持内核不变量() {
    let sample = KernelCounterSample {
        events_seen_per_cpu: vec![4, 6],
        events_submitted_per_cpu: vec![3, 6],
        ring_reserve_failed_per_cpu: vec![1, 0],
        inflight_dropped_per_cpu: vec![1, 2],
        correlation_missed_per_cpu: vec![0, 1],
        exec_argv_captured_per_cpu: vec![2, 3],
        exec_argv_dropped_per_cpu: vec![1, 0],
        internal_dropped_per_cpu: vec![0, 2],
        permission_classification_failed_per_cpu: vec![1, 1],
    };
    let mut counters = HealthCounters::default();
    counters.apply_kernel_sample(&sample).unwrap();

    assert_eq!(counters.events_seen_total, 10);
    assert_eq!(counters.events_submitted_total, 9);
    assert_eq!(counters.ring_reserve_failed_total, 1);
    assert_eq!(counters.exec_argv_captured_total, 5);
    assert_eq!(counters.inflight_dropped_total, 3);
    assert_eq!(counters.correlation_missed_total, 1);
    assert_eq!(counters.exec_argv_dropped_total, 1);
    assert_eq!(counters.internal_dropped_total, 2);
    assert_eq!(counters.permission_classification_failed_total, 2);
    assert_eq!(counters.kernel_lost_total(), 10);
    assert!(counters.kernel_invariant_holds());
}

#[test]
fn 所有流水线计数不变量都可检查() {
    let counters = HealthCounters {
        events_seen_total: 10,
        events_submitted_total: 9,
        ring_reserve_failed_total: 1,
        events_consumed_total: 9,
        events_output_total: 7,
        queue_dropped_total: 2,
        gap_records_generated_total: 0,
        exec_argv_captured_total: 4,
        exec_argv_suppressed_total: 2,
        ..HealthCounters::default()
    };

    assert!(counters.all_invariants_hold());
    let mut broken = counters.clone();
    broken.exec_argv_suppressed_total = 5;
    assert!(!broken.all_invariants_hold());
}

#[test]
fn watch候选命中权限和失败计数保持单调不变量() {
    use auditd_ebpf_common::permission::PermissionMask;

    let mut counters = HealthCounters {
        watch_candidates_total: 2,
        ..HealthCounters::default()
    };
    counters.record_watch_match(PermissionMask::READ | PermissionMask::WRITE);
    counters.watch_permission_failures_total += 1;
    counters.watch_fd_failures_total += 1;

    assert_eq!(counters.watch_matches_total, 1);
    assert_eq!(counters.watch_read_matches_total, 1);
    assert_eq!(counters.watch_write_matches_total, 1);
    assert_eq!(counters.watch_exec_matches_total, 0);
    assert!(counters.all_invariants_hold());

    counters.watch_matches_total = 3;
    assert!(!counters.all_invariants_hold());
}

#[test]
fn 连续缺口十秒内从degraded升级为unhealthy() {
    let mut health = HealthStateMachine::new();
    health.ready();
    health.record_gap_at("fd_association_stale", Duration::from_secs(1));
    assert_eq!(health.state(), HealthState::Degraded);
    health.record_gap_at("fd_association_stale", Duration::from_secs(11));
    assert_eq!(health.state(), HealthState::Unhealthy);
}

#[test]
fn 异常关闭计数首版只能从零增加到一() {
    let mut counters = HealthCounters::default();
    assert!(counters.record_unclean_shutdown().is_ok());
    assert_eq!(counters.unclean_shutdown_detected_total, 1);
    assert!(counters.record_unclean_shutdown().is_err());
}

#[test]
fn degraded连续五分钟无新增缺口才恢复() {
    let mut health = HealthStateMachine::new();
    health.ready();
    health.record_gap_at("ring_full", Duration::from_secs(10));

    assert!(!health.recover_if_quiet(Duration::from_secs(309)));
    assert_eq!(health.state(), HealthState::Degraded);
    assert!(health.recover_if_quiet(Duration::from_secs(310)));
    assert_eq!(health.state(), HealthState::Healthy);
}

#[test]
fn 生产策略与final状态进入健康快照() {
    let mut reporter = HealthReporter::new(ProductionPolicyState::Failed);
    reporter.ready();
    let regular = reporter.snapshot(false);
    assert_eq!(regular.production_policy, ProductionPolicyState::Failed);
    assert!(!regular.final_record);

    reporter.fail("counter_invariant");
    let final_snapshot = reporter.snapshot(true);
    assert_eq!(final_snapshot.state, HealthState::Unhealthy);
    assert!(final_snapshot.final_record);
}

#[test]
fn 状态变化立即报告且常态每十秒报告() {
    let mut reporter = HealthReporter::new(ProductionPolicyState::Passed);
    assert!(reporter.poll(Duration::ZERO).is_some());
    assert!(reporter.poll(Duration::from_secs(9)).is_none());
    assert!(reporter.poll(Duration::from_secs(10)).is_some());

    reporter.record_gap("queue_drop", Duration::from_secs(11));
    let changed = reporter.poll(Duration::from_secs(11)).unwrap();
    assert_eq!(changed.state, HealthState::Degraded);
    assert_eq!(changed.reason.as_deref(), Some("queue_drop"));
}

#[test]
fn 历史dirty立即产生degraded告警且计数为一() {
    let mut reporter = HealthReporter::new(ProductionPolicyState::NotRequested);
    reporter
        .record_unclean_shutdown(Duration::from_secs(1))
        .unwrap();
    let snapshot = reporter.poll(Duration::from_secs(1)).unwrap();

    assert_eq!(snapshot.state, HealthState::Degraded);
    assert_eq!(snapshot.reason.as_deref(), Some("unclean_shutdown"));
    assert_eq!(snapshot.counters.unclean_shutdown_detected_total, 1);
}

#[test]
fn 内核计数不变量破坏会进入unhealthy() {
    let mut reporter = HealthReporter::new(ProductionPolicyState::Passed);
    let invalid = KernelCounterSample {
        events_seen_per_cpu: vec![10],
        events_submitted_per_cpu: vec![10],
        ring_reserve_failed_per_cpu: vec![1],
        exec_argv_captured_per_cpu: vec![0],
        ..KernelCounterSample::default()
    };

    assert!(reporter.update_kernel_counters(&invalid).is_err());
    assert_eq!(reporter.snapshot(false).state, HealthState::Unhealthy);
}
