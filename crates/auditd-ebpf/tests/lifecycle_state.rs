use auditd_ebpf::lifecycle::model::{LifecycleMarker, LifecycleState};

#[test]
fn marker_starts_dirty_and_clean_requires_final_counters() {
    let dirty = LifecycleMarker::dirty("boot", "invocation", 42, 100);
    assert_eq!(dirty.state, LifecycleState::Dirty);
    assert!(dirty.final_counters.is_none());

    let clean = dirty.into_clean([("events_seen".to_string(), 10)].into());
    assert_eq!(clean.state, LifecycleState::Clean);
    assert_eq!(clean.final_counters.unwrap()["events_seen"], 10);
}
