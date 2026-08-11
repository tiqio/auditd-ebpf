use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use crate::RuleErrors;

pub fn sorted_rule_files(directory: &Path) -> Result<Vec<PathBuf>, RuleErrors> {
    let mut paths: Vec<_> = fs::read_dir(directory)
        .map_err(|error| {
            RuleErrors::one(
                &directory.display().to_string(),
                0,
                "E_SOURCE",
                error.to_string(),
            )
        })?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rules"))
        .collect();
    paths.sort_by(|left, right| {
        left.as_os_str()
            .as_encoded_bytes()
            .cmp(right.as_os_str().as_encoded_bytes())
    });
    for path in &paths {
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            RuleErrors::one(
                &path.display().to_string(),
                0,
                "E_SOURCE",
                error.to_string(),
            )
        })?;
        if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(RuleErrors::one(
                &path.display().to_string(),
                0,
                "E_SOURCE_TRUST",
                "规则文件必须 root 所有且 group/other 不可写",
            ));
        }
    }
    Ok(paths)
}
