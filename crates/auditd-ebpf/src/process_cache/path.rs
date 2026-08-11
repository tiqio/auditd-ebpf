use std::path::{Component, Path, PathBuf};

use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PathError {
    #[error("缺少线程路径上下文")]
    MissingThread,
    #[error("mount namespace 状态已失效，必须重新从 /proc 引导")]
    StaleMountEpoch,
    #[error("缺少 root、cwd 或 dirfd 路径")]
    MissingBase,
    #[error("缺少可靠的 fd 路径关联")]
    MissingFdAssociation,
    #[error("fd 路径关联已失效")]
    StaleFdAssociation,
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
