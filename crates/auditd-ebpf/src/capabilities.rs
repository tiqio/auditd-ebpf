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

fn kernel_at_least_5_15(release: &str) -> bool {
    let mut parts = release
        .split(['.', '-'])
        .filter_map(|part| part.parse::<u32>().ok());
    matches!((parts.next(), parts.next()), (Some(major), Some(minor)) if major > 5 || major == 5 && minor >= 15)
}
