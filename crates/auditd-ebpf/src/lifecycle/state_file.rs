use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use thiserror::Error;

use super::model::{LifecycleMarker, LifecycleState};

const MAX_STATE_BYTES: u64 = 64 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Error)]
pub enum StateFileError {
    #[error("生命周期路径缺少父目录")]
    MissingParent,
    #[error("生命周期父目录必须由 root 所有且 group/other 不可写")]
    UntrustedParent,
    #[error("生命周期文件必须由 root 所有、模式 0600、普通文件且不得为符号链接")]
    UntrustedFile,
    #[error("生命周期文件超过 64 KiB")]
    TooLarge,
    #[error("生命周期 schema 或状态转换无效: {0}")]
    InvalidSchema(String),
    #[error("生命周期文件 I/O 失败: {0}")]
    Io(#[from] std::io::Error),
    #[error("生命周期 TOML 解析失败: {0}")]
    Decode(#[from] toml::de::Error),
    #[error("生命周期 TOML 编码失败: {0}")]
    Encode(#[from] toml::ser::Error),
}

pub struct LifecycleStateFile {
    path: PathBuf,
}

impl LifecycleStateFile {
    #[must_use]
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    pub fn read(&self) -> Result<Option<LifecycleMarker>, StateFileError> {
        let parent = self.path.parent().ok_or(StateFileError::MissingParent)?;
        verify_parent(parent)?;
        if !self.path.try_exists()? {
            return Ok(None);
        }
        let mut file = open_nofollow(&self.path, false)?;
        verify_file(&file.metadata()?)?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(MAX_STATE_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_STATE_BYTES {
            return Err(StateFileError::TooLarge);
        }
        // 读取后再次 fstat，防止检查与使用之间的对象被替换。
        verify_file(&file.metadata()?)?;
        let marker: LifecycleMarker = toml::from_slice(&bytes)?;
        validate_marker(&marker)?;
        Ok(Some(marker))
    }

    pub fn write(&self, marker: &LifecycleMarker) -> Result<(), StateFileError> {
        validate_marker(marker)?;
        let parent = self.path.parent().ok_or(StateFileError::MissingParent)?;
        verify_parent(parent)?;
        if self.path.try_exists()? {
            let existing = open_nofollow(&self.path, false)?;
            verify_file(&existing.metadata()?)?;
        }

        let bytes = toml::to_string(marker)?.into_bytes();
        if bytes.len() as u64 > MAX_STATE_BYTES {
            return Err(StateFileError::TooLarge);
        }
        let temp_path = self.temp_path(parent);
        let result = self.write_replace(parent, &temp_path, &bytes);
        if result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        result
    }

    fn write_replace(
        &self,
        parent: &Path,
        temp_path: &Path,
        bytes: &[u8],
    ) -> Result<(), StateFileError> {
        let mut temporary = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(temp_path)?;
        temporary.write_all(bytes)?;
        temporary.sync_all()?;
        verify_file(&temporary.metadata()?)?;

        fs::rename(temp_path, &self.path)?;
        let persisted = open_nofollow(&self.path, false)?;
        verify_file(&persisted.metadata()?)?;
        File::open(parent)?.sync_all()?;
        verify_parent(parent)?;
        Ok(())
    }

    fn temp_path(&self, parent: &Path) -> PathBuf {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("lifecycle.toml");
        parent.join(format!(".{name}.tmp.{}.{sequence}", std::process::id()))
    }
}

fn open_nofollow(path: &Path, write: bool) -> Result<File, StateFileError> {
    Ok(OpenOptions::new()
        .read(!write)
        .write(write)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?)
}

fn verify_parent(parent: &Path) -> Result<(), StateFileError> {
    let metadata = fs::symlink_metadata(parent)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
    {
        return Err(StateFileError::UntrustedParent);
    }
    Ok(())
}

fn verify_file(metadata: &fs::Metadata) -> Result<(), StateFileError> {
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o777 != 0o600 {
        return Err(StateFileError::UntrustedFile);
    }
    Ok(())
}

fn validate_marker(marker: &LifecycleMarker) -> Result<(), StateFileError> {
    if marker.version != 1 {
        return Err(StateFileError::InvalidSchema("未知 version".into()));
    }
    if marker.boot_id.trim().is_empty()
        || marker.invocation_id.trim().is_empty()
        || marker.updated_at.trim().is_empty()
    {
        return Err(StateFileError::InvalidSchema("必填字符串为空".into()));
    }
    match marker.state {
        LifecycleState::Dirty if marker.final_counters.is_some() => Err(
            StateFileError::InvalidSchema("dirty 不得包含 final_counters".into()),
        ),
        LifecycleState::Clean if marker.final_counters.is_none() => Err(
            StateFileError::InvalidSchema("clean 必须包含 final_counters".into()),
        ),
        _ => Ok(()),
    }
}

#[must_use]
pub fn rfc3339_now() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as libc::time_t;
    let mut broken_down = std::mem::MaybeUninit::<libc::tm>::uninit();
    // SAFETY: broken_down 指向有效可写内存；gmtime_r 仅写入该对象并读取按值传入的 time_t。
    let result = unsafe { libc::gmtime_r(&seconds, broken_down.as_mut_ptr()) };
    if result.is_null() {
        return "1970-01-01T00:00:00Z".into();
    }
    // SAFETY: gmtime_r 返回非空即表示完整初始化了 tm。
    let value = unsafe { broken_down.assume_init() };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        value.tm_year + 1900,
        value.tm_mon + 1,
        value.tm_mday,
        value.tm_hour,
        value.tm_min,
        value.tm_sec,
    )
}
