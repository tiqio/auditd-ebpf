use hmac::{Hmac, Mac};
use sha2::Sha256;

pub trait MachineIdSource {
    fn read_machine_id(&self) -> Result<String, String>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostIdentity {
    pub host: String,
    pub machine_id: String,
    pub machine_id_diagnostic: Option<String>,
}

impl HostIdentity {
    pub fn resolve(
        configured: Option<&str>,
        hostname: &str,
        source: &impl MachineIdSource,
    ) -> Self {
        let host = configured.unwrap_or(hostname).to_string();
        match source.read_machine_id().and_then(|value| normalize(&value)) {
            Ok(value) => Self {
                host,
                machine_id: derive(&value),
                machine_id_diagnostic: None,
            },
            Err(error) => Self {
                host,
                machine_id: "?".into(),
                machine_id_diagnostic: Some(error),
            },
        }
    }
}

fn normalize(value: &str) -> Result<String, String> {
    let value = value.trim().to_ascii_lowercase();
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("machine-id 必须是 32 个十六进制字符".into());
    }
    Ok(value)
}

fn derive(value: &str) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(b"auditd-ebpf.machine-id.v1").expect("固定 HMAC key 有效");
    mac.update(value.as_bytes());
    hex::encode(&mac.finalize().into_bytes()[..16])
}
