use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};

use crate::normalize::normalized_line;
use crate::{Arch, ArgvOutput, AuditRule, KernelFilterPlan, RuleErrors, syscall_number};

pub struct RuleCompiler;

impl RuleCompiler {
    pub fn compile(
        mut rules: Vec<AuditRule>,
        generation: u8,
        overrides: BTreeMap<String, ArgvOutput>,
    ) -> Result<KernelFilterPlan, RuleErrors> {
        if generation > 1 {
            return Err(RuleErrors::one(
                "<compiled>",
                0,
                "E_GENERATION",
                "generation 只能为 0/1",
            ));
        }
        for (key, output) in &overrides {
            let matches: Vec<_> = rules
                .iter_mut()
                .filter(|rule| {
                    rule.key == *key
                        && rule
                            .syscalls
                            .iter()
                            .any(|name| matches!(name.as_str(), "execve" | "execveat"))
                })
                .collect();
            if matches.len() != 1 {
                return Err(RuleErrors::one(
                    "<compiled>",
                    0,
                    "E_ARGV_KEY",
                    format!("argv 覆盖 key {key} 必须恰好命中一条 exec 规则"),
                ));
            }
            matches.into_iter().next().expect("长度已验证").argv_output = *output;
        }
        let mut b64 = BTreeSet::new();
        let mut b32 = BTreeSet::new();
        let mut hasher = Sha256::new();
        for rule in &rules {
            hasher.update(normalized_line(rule));
            hasher.update(b"\n");
            for name in &rule.syscalls {
                match rule.arch.unwrap_or(Arch::B64) {
                    Arch::B64 => {
                        if let Some(number) = syscall_number(Arch::B64, name) {
                            b64.insert(number);
                        } else {
                            return Err(RuleErrors::one(
                                "<compiled>",
                                0,
                                "E_SYSCALL",
                                format!("未知 syscall {name}"),
                            ));
                        }
                    }
                    Arch::B32 => {
                        if let Some(number) = syscall_number(Arch::B32, name) {
                            b32.insert(number);
                        } else {
                            return Err(RuleErrors::one(
                                "<compiled>",
                                0,
                                "E_SYSCALL",
                                format!("未知 syscall {name}"),
                            ));
                        }
                    }
                }
            }
        }
        let version_hash: [u8; 32] = hasher.finalize().into();
        let exec_capture_enabled = rules.iter().any(|rule| {
            rule.syscalls
                .iter()
                .any(|name| matches!(name.as_str(), "execve" | "execveat"))
        });
        Ok(KernelFilterPlan {
            generation,
            rules,
            syscalls_b64: b64,
            syscalls_b32: b32,
            exec_capture_enabled,
            argv_overrides: overrides,
            version_hash,
        })
    }
}
