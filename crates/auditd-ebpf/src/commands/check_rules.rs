use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, bail};
use auditd_ebpf_rules::{
    RuleCompiler, normalize::normalized_line, parse_rules, source::sorted_rule_files,
};

pub fn run(
    file: Option<&Path>,
    directory: Option<&Path>,
    print_normalized: bool,
) -> anyhow::Result<()> {
    let mut all_rules = Vec::new();
    for path in select_paths(file, directory)? {
        let input =
            fs::read_to_string(&path).with_context(|| format!("无法读取 {}", path.display()))?;
        all_rules
            .extend(parse_rules(&path.display().to_string(), &input).map_err(anyhow::Error::new)?);
    }
    for (index, rule) in all_rules.iter_mut().enumerate() {
        rule.rule_id = index as u32;
    }
    let plan =
        RuleCompiler::compile(all_rules, 0, Default::default()).map_err(anyhow::Error::new)?;
    if print_normalized {
        for rule in &plan.rules {
            println!("{}", normalized_line(rule));
        }
    } else {
        println!(
            "rules={} generation={} version={}",
            plan.rules.len(),
            plan.generation,
            hex::encode(plan.version_hash)
        );
    }
    Ok(())
}

fn select_paths(file: Option<&Path>, directory: Option<&Path>) -> anyhow::Result<Vec<PathBuf>> {
    if let Some(file) = file {
        return Ok(vec![file.to_path_buf()]);
    }
    let directory = directory.unwrap_or(Path::new("/etc/audit/rules.d"));
    if directory.is_dir() {
        let paths = sorted_rule_files(directory).map_err(anyhow::Error::new)?;
        if !paths.is_empty() {
            return Ok(paths);
        }
    }
    let fallback = PathBuf::from("/etc/audit/audit.rules");
    if fallback.is_file() {
        Ok(vec![fallback])
    } else {
        bail!("未找到可用规则文件")
    }
}
