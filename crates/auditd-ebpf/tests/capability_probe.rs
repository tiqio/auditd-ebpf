use auditd_ebpf::capabilities::{CapabilityProbe, ProbeSource};

struct Supported;

impl ProbeSource for Supported {
    fn architecture(&self) -> &str {
        "x86_64"
    }
    fn kernel_release(&self) -> &str {
        "6.14.0"
    }
    fn has_btf(&self) -> bool {
        true
    }
    fn has_ringbuf(&self) -> bool {
        true
    }
    fn has_raw_tracepoint(&self) -> bool {
        true
    }
    fn has_tracepoint(&self) -> bool {
        true
    }
}

#[test]
fn reports_supported_mock_host() {
    let report = CapabilityProbe::inspect(&Supported);
    assert!(report.supported());
    assert!(report.failures.is_empty());
}
