use std::{
    collections::BTreeMap,
    fs,
    io::{self, Write},
    path::Path,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use tokio::signal::unix::{SignalKind, signal};

use crate::{
    identity::{HostIdentity, MachineIdSource},
    lifecycle::{
        model::{LifecycleMarker, LifecycleState},
        state_file::LifecycleStateFile,
    },
    output::status_formatter::{status, unclean_shutdown_gap},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DrainOutcome {
    Drained,
    TimedOut,
}

impl DrainOutcome {
    #[must_use]
    pub const fn exit_code(self) -> i32 {
        match self {
            Self::Drained => 0,
            Self::TimedOut => 8,
        }
    }
}

#[derive(Default)]
pub struct SignalCoordinator {
    reload_in_progress: bool,
    reload_pending: bool,
    stopping: bool,
}

impl SignalCoordinator {
    pub fn begin_reload(&mut self) {
        if !self.stopping {
            self.reload_in_progress = true;
        }
    }

    pub fn request_reload(&mut self) {
        if self.stopping {
            return;
        }
        self.reload_pending = true;
    }

    pub fn finish_reload(&mut self) -> bool {
        self.reload_in_progress = false;
        std::mem::take(&mut self.reload_pending) && !self.stopping
    }

    pub fn request_stop(&mut self) {
        self.stopping = true;
        self.reload_pending = false;
    }

    #[must_use]
    pub const fn stopping(&self) -> bool {
        self.stopping
    }

    pub fn take_reload(&mut self) -> bool {
        if self.stopping || self.reload_in_progress {
            return false;
        }
        std::mem::take(&mut self.reload_pending)
    }
}

pub fn drain_with_timeout(timeout: Duration, mut is_empty: impl FnMut() -> bool) -> DrainOutcome {
    let deadline = Instant::now() + timeout;
    loop {
        if is_empty() {
            return DrainOutcome::Drained;
        }
        if Instant::now() >= deadline {
            return DrainOutcome::TimedOut;
        }
        thread::sleep(Duration::from_millis(1));
    }
}

pub fn run(node_name: Option<&str>, lifecycle_path: &Path) -> i32 {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("type=AUDITD_EBPF_DIAG level=error code=runtime_init message={error}");
            return 7;
        }
    };
    runtime.block_on(run_async(node_name, lifecycle_path))
}

async fn run_async(node_name: Option<&str>, lifecycle_path: &Path) -> i32 {
    let state_file = LifecycleStateFile::new(lifecycle_path);
    let previous = match state_file.read() {
        Ok(marker) => marker,
        Err(error) => {
            eprintln!("type=AUDITD_EBPF_DIAG level=error code=lifecycle_read message={error}");
            return 4;
        }
    };
    let previous_dirty = previous
        .as_ref()
        .is_some_and(|marker| marker.state == LifecycleState::Dirty);
    let dirty = LifecycleMarker::dirty(
        read_trimmed("/proc/sys/kernel/random/boot_id").unwrap_or_else(|| "?".into()),
        read_trimmed("/proc/sys/kernel/random/uuid").unwrap_or_else(fallback_invocation_id),
        std::process::id(),
        now_millis(),
    );
    if let Err(error) = state_file.write(&dirty) {
        eprintln!("type=AUDITD_EBPF_DIAG level=error code=lifecycle_dirty message={error}");
        return 4;
    }

    let identity = resolve_identity(node_name);
    if previous_dirty {
        let line = unclean_shutdown_gap(
            &identity,
            "audit(0.000:0)",
            "unclean-shutdown",
            now_millis(),
        );
        if io::stdout()
            .write_all(line.as_bytes())
            .and_then(|_| io::stdout().flush())
            .is_err()
        {
            return 7;
        }
        eprint!("{}", status(&identity, "degraded", 0, 0, false));
    } else {
        eprint!("{}", status(&identity, "healthy", 0, 0, false));
    }

    let mut usr1 = match signal(SignalKind::user_defined1()) {
        Ok(signal) => signal,
        Err(_) => return 7,
    };
    let mut term = match signal(SignalKind::terminate()) {
        Ok(signal) => signal,
        Err(_) => return 7,
    };
    let mut interrupt = match signal(SignalKind::interrupt()) {
        Ok(signal) => signal,
        Err(_) => return 7,
    };
    let mut hangup = match signal(SignalKind::hangup()) {
        Ok(signal) => signal,
        Err(_) => return 7,
    };

    loop {
        tokio::select! {
            _ = usr1.recv() => {
                eprint!("{}", status(&identity, if previous_dirty { "degraded" } else { "healthy" }, 0, 0, false));
            }
            _ = hangup.recv() => {
                eprintln!("type=AUDITD_EBPF_DIAG host={} machine_id={} level=info code=reload_requested component=runtime message=\"SIGHUP\"", identity.host, identity.machine_id);
            }
            _ = term.recv() => break,
            _ = interrupt.recv() => break,
        }
    }

    eprint!("{}", status(&identity, "stopping", 0, 0, false));
    let drain = drain_with_timeout(Duration::from_secs(30), || true);
    eprint!("{}", status(&identity, "stopping", 0, 0, true));
    if io::stderr().flush().is_err() {
        return 7;
    }
    let clean = dirty.into_clean(BTreeMap::from([
        ("events_seen".into(), 0),
        ("events_submitted".into(), 0),
        ("events_output".into(), 0),
        ("ring_lost".into(), 0),
        ("queue_lost".into(), 0),
        ("path_lost".into(), 0),
    ]));
    if let Err(error) = state_file.write(&clean) {
        eprintln!("type=AUDITD_EBPF_DIAG level=error code=lifecycle_clean message={error}");
        return 7;
    }
    drain.exit_code()
}

fn resolve_identity(node_name: Option<&str>) -> HostIdentity {
    struct FileMachineId;
    impl MachineIdSource for FileMachineId {
        fn read_machine_id(&self) -> Result<String, String> {
            fs::read_to_string("/etc/machine-id").map_err(|error| error.to_string())
        }
    }
    let hostname = read_trimmed("/proc/sys/kernel/hostname").unwrap_or_else(|| "?".into());
    HostIdentity::resolve(node_name, &hostname, &FileMachineId)
}

fn read_trimmed(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn fallback_invocation_id() -> String {
    format!("{}-{}", std::process::id(), now_millis())
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
