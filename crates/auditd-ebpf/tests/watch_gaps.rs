use auditd_ebpf::health::watch_gap::{WatchGapReason, decide_watch_gap};

#[test]
fn 所有watch不确定原因都拒绝伪事件并进入degraded() {
    for reason in [
        WatchGapReason::PermissionFlagsMissing,
        WatchGapReason::PermissionClassificationFailed,
        WatchGapReason::PathArgumentMissing,
        WatchGapReason::PathArgumentTruncated,
        WatchGapReason::ThreadContextMissing,
        WatchGapReason::MountContextStale,
        WatchGapReason::FdAssociationMissing,
        WatchGapReason::FdAssociationStale,
    ] {
        let decision = decide_watch_gap(reason);
        assert!(!decision.emit_audit_event);
        assert_eq!(decision.state, "degraded");
        assert!(!reason.as_str().is_empty());
        assert!(!reason.stage().is_empty());
    }
}
