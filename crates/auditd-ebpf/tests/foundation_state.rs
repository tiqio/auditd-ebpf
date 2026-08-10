use auditd_ebpf::{
    health::state::{HealthState, HealthStateMachine},
    output::adaptive_queue::AdaptiveQueue,
};

#[test]
fn queue_never_grows_past_hard_limit() {
    let mut queue = AdaptiveQueue::new(16, 32).unwrap();
    assert!(queue.try_push(vec![0; 20]).is_ok());
    assert_eq!(queue.limit_bytes(), 32);
    assert!(queue.try_push(vec![0; 20]).is_err());
}

#[test]
fn loss_degrades_health() {
    let mut health = HealthStateMachine::new();
    health.ready();
    health.record_gap("ring_full");
    assert_eq!(health.state(), HealthState::Degraded);
}
