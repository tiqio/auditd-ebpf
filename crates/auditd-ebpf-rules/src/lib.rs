#![deny(unsafe_code)]

pub mod compiler;
pub mod diagnostic;
pub mod lexer;
pub mod model;
pub mod normalize;
pub mod parser;
pub mod permissions;
pub mod source;
pub mod syscalls;

pub use compiler::RuleCompiler;
pub use diagnostic::{Diagnostic, RuleErrors};
pub use model::{
    Arch, ArgvOutput, AuditRule, KernelFilterPlan, RuleKind, RulePermissionCoverage, RuleSet,
};
pub use parser::parse_rules;
pub use permissions::{COVERAGE_VERSION, PermissionCoverageEntry, permission_coverage};
pub use syscalls::{syscall_name, syscall_number};

pub const MAX_RULES: usize = 4_096;

#[must_use]
pub const fn max_rules() -> usize {
    MAX_RULES
}
