//! watch 候选无法可靠归类时的稳定缺口契约。
//!
//! 原因名称会进入 journald、rsyslog、告警和基准正确性判定，因此属于外部契约。这里使用
//! `repr(u8)` 固定枚举而不是自由文本，避免不同分支为同一缺口产生不可聚合的高基数字符串。

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WatchGapReason {
    PermissionFlagsMissing,
    PermissionClassificationFailed,
    PathArgumentMissing,
    PathArgumentTruncated,
    ThreadContextMissing,
    MountContextStale,
    FdAssociationMissing,
    FdAssociationStale,
}

impl WatchGapReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PermissionFlagsMissing => "permission_flags_missing",
            Self::PermissionClassificationFailed => "permission_classification_failed",
            Self::PathArgumentMissing => "path_argument_missing",
            Self::PathArgumentTruncated => "path_argument_truncated",
            Self::ThreadContextMissing => "thread_context_missing",
            Self::MountContextStale => "mount_context_stale",
            Self::FdAssociationMissing => "fd_association_missing",
            Self::FdAssociationStale => "fd_association_stale",
        }
    }

    #[must_use]
    pub const fn stage(self) -> &'static str {
        match self {
            Self::PermissionFlagsMissing | Self::PermissionClassificationFailed => {
                "permission_classification"
            }
            Self::PathArgumentMissing | Self::PathArgumentTruncated => "path_capture",
            Self::ThreadContextMissing | Self::MountContextStale => "namespace_resolution",
            Self::FdAssociationMissing | Self::FdAssociationStale => "fd_resolution",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchGapDecision {
    pub reason: WatchGapReason,
    pub emit_audit_event: bool,
    pub state: &'static str,
}

/// 所有不确定候选都必须被拒绝为普通审计事件，并立即进入 degraded。
///
/// `unhealthy` 留给持续十秒仍在增长的缺口，由健康状态机基于时间窗口升级；决策层不读取
/// 时钟，从而保持测试确定性，也避免把 wall clock 带进采集热路径。
#[must_use]
pub const fn decide_watch_gap(reason: WatchGapReason) -> WatchGapDecision {
    WatchGapDecision {
        reason,
        emit_audit_event: false,
        state: "degraded",
    }
}
