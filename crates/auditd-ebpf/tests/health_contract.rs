use std::time::Duration;

use auditd_ebpf::health::{
    counters::HealthCounters,
    reporter::{HealthReporter, ProductionPolicyState},
    state::{HealthState, HealthStateMachine},
};

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
