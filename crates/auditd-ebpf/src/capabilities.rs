#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityReport {
    pub architecture: String,
    pub kernel_release: String,
    pub failures: Vec<String>,
}

impl CapabilityReport {
    #[must_use]
    pub fn supported(&self) -> bool {
        self.failures.is_empty()
    }
}

pub trait ProbeSource {
    fn architecture(&self) -> &str;
    fn kernel_release(&self) -> &str;
    fn has_btf(&self) -> bool;
    fn has_ringbuf(&self) -> bool;
    fn has_raw_tracepoint(&self) -> bool;
    fn has_tracepoint(&self) -> bool;
}

pub struct HostProbe {
    architecture: String,
    kernel_release: String,
}

impl HostProbe {
    pub fn detect() -> Self {
        let kernel_release = std::process::Command::new("uname")
            .arg("-r")
            .output()
            .ok()
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
            .unwrap_or_else(|| "unknown".into());
        Self {
            architecture: std::env::consts::ARCH.into(),
            kernel_release,
        }
    }
}

impl ProbeSource for HostProbe {
    fn architecture(&self) -> &str {
        &self.architecture
    }
    fn kernel_release(&self) -> &str {
        &self.kernel_release
    }
    fn has_btf(&self) -> bool {
        std::path::Path::new("/sys/kernel/btf/vmlinux").is_file()
    }
    fn has_ringbuf(&self) -> bool {
        true
    }
    fn has_raw_tracepoint(&self) -> bool {
        std::path::Path::new("/sys/kernel/tracing/events/raw_syscalls").exists()
            || std::path::Path::new("/sys/kernel/debug/tracing/events/raw_syscalls").exists()
    }
    fn has_tracepoint(&self) -> bool {
        std::path::Path::new("/sys/kernel/tracing/events/sched").exists()
            || std::path::Path::new("/sys/kernel/debug/tracing/events/sched").exists()
    }
}

pub struct CapabilityProbe;

impl CapabilityProbe {
    pub fn inspect(source: &impl ProbeSource) -> CapabilityReport {
        let mut failures = Vec::new();
        if source.architecture() != "x86_64" {
            failures.push("unsupported_arch".into());
        }
        if !kernel_at_least_5_15(source.kernel_release()) {
            failures.push("kernel_too_old".into());
        }
        if !source.has_btf() {
            failures.push("missing_btf".into());
        }
        if !source.has_ringbuf() {
            failures.push("missing_ringbuf".into());
        }
        if !source.has_raw_tracepoint() {
            failures.push("missing_raw_tracepoint".into());
        }
        if !source.has_tracepoint() {
            failures.push("missing_tracepoint".into());
        }
        CapabilityReport {
            architecture: source.architecture().into(),
            kernel_release: source.kernel_release().into(),
            failures,
        }
    }
}

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
const SECBIT_NOROOT: libc::c_ulong = 1 << 0;
const SECBIT_NOROOT_LOCKED: libc::c_ulong = 1 << 1;
const SECBIT_NO_SETUID_FIXUP: libc::c_ulong = 1 << 2;
const SECBIT_NO_SETUID_FIXUP_LOCKED: libc::c_ulong = 1 << 3;

#[repr(C)]
struct CapabilityHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

#[derive(Debug, Error)]
pub enum CapabilityDropError {
    #[error("设置 NoNewPrivs 失败: {0}")]
    NoNewPrivileges(#[source] io::Error),
    #[error("锁定 securebits 失败: {0}")]
    SecureBits(#[source] io::Error),
    #[error("读取 cap_last_cap 失败: {0}")]
    LastCapability(#[source] io::Error),
    #[error("从 bounding set 删除 capability {capability} 失败: {source}")]
    BoundingSet {
        capability: u32,
        #[source]
        source: io::Error,
    },
    #[error("清空 ambient capabilities 失败: {0}")]
    Ambient(#[source] io::Error),
    #[error("清空 effective/permitted/inheritable capabilities 失败: {0}")]
    CapabilitySets(#[source] io::Error),
}

/// 将加载阶段权限收敛到运行期零 capability 集合。
///
/// eBPF program、link、map 与 RingBuf fd 在调用前必须全部打开。调用成功后当前线程不能再
/// 执行需要 capability 的加载或 attach 操作；因此运行时必须在创建 collector 线程之前调用，
/// 使后续线程继承已经收紧的凭据。`NoNewPrivs` 同时阻止通过 exec/setuid 文件重新获得权限。
pub fn drop_runtime_capabilities() -> Result<(), CapabilityDropError> {
    // SAFETY: prctl 参数均为 Linux 定义的整数常量；PR_SET_NO_NEW_PRIVS 的其余参数必须为零。
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(CapabilityDropError::NoNewPrivileges(
            io::Error::last_os_error(),
        ));
    }

    // UID 0 在传统 Linux 语义下可能在后续 exec 时从 bounding set 重新获得能力。先锁定
    // NOROOT/NO_SETUID_FIXUP，再删除 bounding set，确保清零不是临时的表面状态。
    let securebits = SECBIT_NOROOT
        | SECBIT_NOROOT_LOCKED
        | SECBIT_NO_SETUID_FIXUP
        | SECBIT_NO_SETUID_FIXUP_LOCKED;
    // SAFETY: PR_SET_SECUREBITS 接收位掩码整数，其余参数按内核 ABI 为零。
    if unsafe { libc::prctl(libc::PR_SET_SECUREBITS, securebits, 0, 0, 0) } != 0 {
        return Err(CapabilityDropError::SecureBits(io::Error::last_os_error()));
    }

    let last_capability = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .map_err(CapabilityDropError::LastCapability)?
        .trim()
        .parse::<u32>()
        .map_err(|error| {
            CapabilityDropError::LastCapability(io::Error::new(io::ErrorKind::InvalidData, error))
        })?;
    for capability in 0..=last_capability {
        // SAFETY: PR_CAPBSET_DROP 只读取 capability 编号，不涉及任何用户指针。
        if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) } != 0 {
            return Err(CapabilityDropError::BoundingSet {
                capability,
                source: io::Error::last_os_error(),
            });
        }
    }

    // SAFETY: PR_CAP_AMBIENT_CLEAR_ALL 不读取指针，其余参数按内核 ABI 必须为零。
    if unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    } != 0
    {
        return Err(CapabilityDropError::Ambient(io::Error::last_os_error()));
    }

    let header = CapabilityHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [CapabilityData::default(); 2];
    // SAFETY: header/data 使用 Linux capability v3 的 repr(C) 固定布局；pid=0 表示当前线程，
    // 两个 data 元素覆盖 64 个 capability 位。全零只会删除权限，不会授予新权限。
    if unsafe { libc::syscall(libc::SYS_capset, std::ptr::addr_of!(header), data.as_ptr()) } != 0 {
        return Err(CapabilityDropError::CapabilitySets(
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

fn kernel_at_least_5_15(release: &str) -> bool {
    let mut parts = release
        .split(['.', '-'])
        .filter_map(|part| part.parse::<u32>().ok());
    matches!((parts.next(), parts.next()), (Some(major), Some(minor)) if major > 5 || major == 5 && minor >= 15)
}
use std::io;

use thiserror::Error;
