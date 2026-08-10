use aya_ebpf::{macros::raw_tracepoint, programs::RawTracePointContext};

/// Foundational smoke program：不读取上下文，只证明对象可加载、挂载和清理。
#[raw_tracepoint]
pub fn auditd_sys_enter(_context: RawTracePointContext) -> u32 {
    0
}
