use std::collections::BTreeSet;

use crate::{
    diagnostic::RuleErrors,
    lexer::tokenize,
    model::{Arch, AuditRule, RuleKind},
};

pub fn parse_rules(file: &str, input: &str) -> Result<Vec<AuditRule>, RuleErrors> {
    let mut rules = Vec::new();
    let mut errors = Vec::new();
    for (index, raw) in input.lines().enumerate() {
        let line_number = index + 1;
        let line = raw.trim_end_matches('\r').trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_line(file, line_number, line, rules.len() as u32) {
            Ok(rule) => rules.push(rule),
            Err(mut error) => errors.append(&mut error.0),
        }
    }
    if errors.is_empty() {
        Ok(rules)
    } else {
        Err(RuleErrors(errors))
    }
}

fn parse_line(
    file: &str,
    line_number: usize,
    line: &str,
    rule_id: u32,
) -> Result<AuditRule, RuleErrors> {
    let tokens = tokenize(file, line_number, line)?;
    let kind = match tokens.first().copied() {
        Some("-a") if tokens.get(1) == Some(&"always,exit") => RuleKind::Syscall,
        Some("-w") => RuleKind::Watch,
        _ => {
            return Err(RuleErrors::one(
                file,
                line_number,
                "E_ACTION",
                "仅支持 -a always,exit 或 -w",
            ));
        }
    };
    let mut rule = AuditRule {
        rule_id,
        kind,
        arch: None,
        syscalls: Vec::new(),
        path: None,
        dir: None,
        permissions: BTreeSet::new(),
        key: String::new(),
        argv_output: Default::default(),
    };
    let mut key_count = 0;
    let mut cursor = if kind == RuleKind::Syscall { 2 } else { 1 };
    if kind == RuleKind::Watch {
        rule.path = Some(validate_path(
            file,
            line_number,
            tokens.get(cursor).copied(),
        )?);
        cursor += 1;
    }
    while cursor < tokens.len() {
        let option = tokens[cursor];
        let value = tokens.get(cursor + 1).copied().ok_or_else(|| {
            RuleErrors::one(file, line_number, "E_VALUE", format!("{option} 缺少值"))
        })?;
        match option {
            "-S" if kind == RuleKind::Syscall => rule.syscalls.extend(
                value
                    .split(',')
                    .filter(|item| !item.is_empty())
                    .map(str::to_string),
            ),
            "-k" => {
                key_count += 1;
                rule.key = value.to_string();
            }
            "-p" if kind == RuleKind::Watch => {
                rule.permissions = parse_permissions(file, line_number, value)?
            }
            "-F" => parse_field(file, line_number, value, &mut rule, &mut key_count)?,
            _ => {
                return Err(RuleErrors::one(
                    file,
                    line_number,
                    "E_OPTION",
                    format!("不支持 {option}"),
                ));
            }
        }
        cursor += 2;
    }
    if key_count != 1 || rule.key.is_empty() || rule.key.len() > 31 {
        return Err(RuleErrors::one(
            file,
            line_number,
            "E_KEY",
            "每条规则必须且只能包含一个 1–31 字节 key",
        ));
    }
    if kind == RuleKind::Syscall && rule.syscalls.is_empty() {
        return Err(RuleErrors::one(
            file,
            line_number,
            "E_SYSCALL",
            "syscall 规则至少需要一个 -S",
        ));
    }
    Ok(rule)
}

fn parse_field(
    file: &str,
    line: usize,
    value: &str,
    rule: &mut AuditRule,
    key_count: &mut usize,
) -> Result<(), RuleErrors> {
    if let Some(arch) = value.strip_prefix("arch=") {
        rule.arch = Some(match arch {
            "b64" => Arch::B64,
            "b32" => Arch::B32,
            _ => return Err(RuleErrors::one(file, line, "E_ARCH", "arch 只能为 b64/b32")),
        });
    } else if let Some(key) = value.strip_prefix("key=") {
        *key_count += 1;
        rule.key = key.to_string();
    } else if let Some(path) = value.strip_prefix("path=") {
        rule.path = Some(validate_path(file, line, Some(path))?);
    } else if let Some(path) = value.strip_prefix("dir=") {
        rule.dir = Some(validate_path(file, line, Some(path))?);
    } else if let Some(perms) = value.strip_prefix("perm=") {
        rule.permissions = parse_permissions(file, line, perms)?;
    } else if ["uid", "euid", "gid", "egid", "success"]
        .iter()
        .any(|name| value.starts_with(name))
    {
        // 首版模型暂不保存这些值，但词法层接受契约字段，精确比较器在 US1 engine 中扩展。
    } else {
        return Err(RuleErrors::one(
            file,
            line,
            "E_FIELD",
            format!("不支持字段 {value}"),
        ));
    }
    Ok(())
}

fn validate_path(file: &str, line: usize, value: Option<&str>) -> Result<String, RuleErrors> {
    let value = value.ok_or_else(|| RuleErrors::one(file, line, "E_PATH", "缺少路径"))?;
    if !value.starts_with('/') || value.split('/').any(|part| part == "." || part == "..") {
        return Err(RuleErrors::one(
            file,
            line,
            "E_PATH",
            "路径必须绝对且不得包含 . 或 ..",
        ));
    }
    Ok(value.to_string())
}

fn parse_permissions(file: &str, line: usize, value: &str) -> Result<BTreeSet<char>, RuleErrors> {
    let permissions: BTreeSet<_> = value.chars().collect();
    if permissions.is_empty()
        || permissions
            .iter()
            .any(|value| !matches!(value, 'r' | 'w' | 'x' | 'a'))
    {
        return Err(RuleErrors::one(file, line, "E_PERM", "perm 只允许 r/w/x/a"));
    }
    Ok(permissions)
}
