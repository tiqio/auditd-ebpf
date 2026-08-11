use std::path::{Component, Path, PathBuf};

use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PathError {
    #[error("路径包含禁止的父目录或前缀组件")]
    EscapesBoundary,
}

pub fn normalize_in_boundary(
    _root: &Path,
    cwd: &Path,
    dirfd: Option<&Path>,
    raw: &Path,
) -> Result<PathBuf, PathError> {
    let base = if raw.is_absolute() {
        Path::new("/")
    } else {
        dirfd.unwrap_or(cwd)
    };
    let mut normalized = PathBuf::from(base);
    for component in raw.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(value) => normalized.push(value),
            Component::ParentDir | Component::Prefix(_) => return Err(PathError::EscapesBoundary),
        }
    }
    Ok(normalized)
}
