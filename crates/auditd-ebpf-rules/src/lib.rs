#![deny(unsafe_code)]

/// 首版规则数量硬上限。
pub const MAX_RULES: usize = 4_096;

/// 返回当前规则契约支持的最大规则数。
#[must_use]
pub const fn max_rules() -> usize {
    MAX_RULES
}
