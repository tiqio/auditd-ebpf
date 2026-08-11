#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod counters;
pub mod event;

/// 共享 ABI 的 schema 主版本。
pub const SCHEMA_VERSION: u16 = 1;

/// 返回共享 ABI 版本，供早期构建和诊断命令使用。
#[must_use]
pub const fn schema_version() -> u16 {
    SCHEMA_VERSION
}
