use std::collections::{BTreeMap, BTreeSet};

use auditd_ebpf_common::permission::PermissionMask;
use sha2::{Digest, Sha256};

use crate::normalize::normalized_line;
use crate::permissions::{COVERAGE_VERSION, maintenance_syscalls, permission_coverage};
use crate::{
    Arch, ArgvOutput, AuditRule, KernelFilterPlan, RuleErrors, RuleKind, RulePermissionCoverage,
    syscall_number,
};

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
        apply_argv_overrides(&mut rules, &overrides)?;

        let mut b64 = BTreeSet::new();
        let mut b32 = BTreeSet::new();
        let mut permission_masks_b64 = [0_u8; 512];
        let mut permission_masks_b32 = [0_u8; 512];
        let mut maintenance_b64 = BTreeSet::new();
        let mut maintenance_b32 = BTreeSet::new();
        let mut coverage_by_rule = BTreeMap::new();

        for rule in &rules {
            compile_explicit_syscalls(rule, &mut b64, &mut b32)?;
            let requested = permission_mask(rule)?;
            if !requested.is_empty() {
                let arches: &[Arch] = if rule.kind == RuleKind::Watch {
                    &[Arch::B64, Arch::B32]
                } else {
                    &[rule.arch.unwrap_or(Arch::B64)]
                };
                let mut rule_coverages = BTreeMap::new();
                for &arch in arches {
                    let available = permission_coverage(arch, requested);
                    let selected = if rule.kind == RuleKind::Watch {
                        available
                    } else {
                        let mut selected = BTreeMap::new();
                        for name in &rule.syscalls {
                            let number = syscall_number(arch, name).ok_or_else(|| {
                                RuleErrors::one(
                                    "<compiled>",
                                    0,
                                    "E_SYSCALL",
                                    format!("未知 syscall {name}"),
                                )
                            })?;
                            let Some(entry) = available.get(&number).copied() else {
                                return Err(RuleErrors::one(
                                    "<compiled>",
                                    0,
                                    "E_PERMISSION_COVERAGE",
                                    format!("syscall {name} 无法可靠分类为 perm={requested}"),
                                ));
                            };
                            selected.insert(number, entry);
                        }
                        selected
                    };
                    ensure_each_permission_is_covered(requested, arch, &selected)?;
                    let coverage = RulePermissionCoverage {
                        arch,
                        requested_permissions: requested,
                        effective_syscalls: selected.keys().copied().collect(),
                        syscall_permission_masks: selected
                            .iter()
                            .map(|(number, entry)| (*number, entry.permissions))
                            .collect(),
                    };
                    for (number, entry) in selected {
                        let (syscalls, masks) = match arch {
                            Arch::B64 => (&mut b64, &mut permission_masks_b64),
                            Arch::B32 => (&mut b32, &mut permission_masks_b32),
                        };
                        syscalls.insert(number);
                        masks[number as usize] |= entry.permissions.bits();
                    }
                    rule_coverages.insert(arch, coverage);
                }
                coverage_by_rule.insert(rule.rule_id, rule_coverages);
            }

            if rule.kind == RuleKind::Watch || rule.path.is_some() || rule.dir.is_some() {
                maintenance_b64.extend(maintenance_syscalls(Arch::B64));
                maintenance_b32.extend(maintenance_syscalls(Arch::B32));
            }
        }
        b64.extend(maintenance_b64.iter().copied());
        b32.extend(maintenance_b32.iter().copied());

        let version_hash = version_hash(
            &rules,
            &permission_masks_b64,
            &permission_masks_b32,
            &maintenance_b64,
            &maintenance_b32,
        );
        let exec_capture_enabled = [
            (Arch::B64, syscall_number(Arch::B64, "execve")),
            (Arch::B64, syscall_number(Arch::B64, "execveat")),
            (Arch::B32, syscall_number(Arch::B32, "execve")),
            (Arch::B32, syscall_number(Arch::B32, "execveat")),
        ]
        .into_iter()
        .any(|(arch, number)| {
            number.is_some_and(|number| match arch {
                Arch::B64 => b64.contains(&number),
                Arch::B32 => b32.contains(&number),
            })
        });

        Ok(KernelFilterPlan {
            generation,
            rules,
            syscalls_b64: b64,
            syscalls_b32: b32,
            permission_masks_b64,
            permission_masks_b32,
            maintenance_syscalls_b64: maintenance_b64,
            maintenance_syscalls_b32: maintenance_b32,
            coverage_by_rule,
            exec_capture_enabled,
            argv_overrides: overrides,
            version_hash,
        })
    }
}

fn apply_argv_overrides(
    rules: &mut [AuditRule],
    overrides: &BTreeMap<String, ArgvOutput>,
) -> Result<(), RuleErrors> {
    for (key, output) in overrides {
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
    Ok(())
}

fn compile_explicit_syscalls(
    rule: &AuditRule,
    b64: &mut BTreeSet<u32>,
    b32: &mut BTreeSet<u32>,
) -> Result<(), RuleErrors> {
    for name in &rule.syscalls {
        let arch = rule.arch.unwrap_or(Arch::B64);
        let number = syscall_number(arch, name).ok_or_else(|| {
            RuleErrors::one("<compiled>", 0, "E_SYSCALL", format!("未知 syscall {name}"))
        })?;
        if number >= 512 {
            return Err(RuleErrors::one(
                "<compiled>",
                0,
                "E_SYSCALL_RANGE",
                format!("syscall {name} 编号 {number} 超过 511"),
            ));
        }
        match arch {
            Arch::B64 => b64.insert(number),
            Arch::B32 => b32.insert(number),
        };
    }
    Ok(())
}

fn permission_mask(rule: &AuditRule) -> Result<PermissionMask, RuleErrors> {
    let mut mask = PermissionMask::EMPTY;
    for permission in &rule.permissions {
        mask |= match permission {
            'r' => PermissionMask::READ,
            'w' => PermissionMask::WRITE,
            'x' => PermissionMask::EXEC,
            'a' => PermissionMask::ATTR,
            _ => {
                return Err(RuleErrors::one(
                    "<compiled>",
                    0,
                    "E_PERMISSION",
                    format!("未知 permission {permission}"),
                ));
            }
        };
    }
    Ok(mask)
}

fn ensure_each_permission_is_covered(
    requested: PermissionMask,
    arch: Arch,
    coverage: &BTreeMap<u32, crate::PermissionCoverageEntry>,
) -> Result<(), RuleErrors> {
    for permission in [
        PermissionMask::READ,
        PermissionMask::WRITE,
        PermissionMask::EXEC,
        PermissionMask::ATTR,
    ] {
        if requested.intersects(permission)
            && !coverage
                .values()
                .any(|entry| entry.permissions.intersects(permission))
        {
            return Err(RuleErrors::one(
                "<compiled>",
                0,
                "E_PERMISSION_COVERAGE",
                format!("{arch:?} permission {permission} 覆盖为空"),
            ));
        }
    }
    Ok(())
}

fn version_hash(
    rules: &[AuditRule],
    b64_masks: &[u8; 512],
    b32_masks: &[u8; 512],
    maintenance_b64: &BTreeSet<u32>,
    maintenance_b32: &BTreeSet<u32>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for rule in rules {
        hasher.update(normalized_line(rule));
        hasher.update(b"\n");
    }
    hasher.update(COVERAGE_VERSION.to_le_bytes());
    hasher.update(b64_masks);
    hasher.update(b32_masks);
    for number in maintenance_b64 {
        hasher.update(number.to_le_bytes());
    }
    hasher.update(b"|");
    for number in maintenance_b32 {
        hasher.update(number.to_le_bytes());
    }
    hasher.finalize().into()
}
