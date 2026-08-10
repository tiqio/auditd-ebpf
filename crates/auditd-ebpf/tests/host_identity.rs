use auditd_ebpf::identity::{HostIdentity, MachineIdSource};

struct FixedMachineId;

impl MachineIdSource for FixedMachineId {
    fn read_machine_id(&self) -> Result<String, String> {
        Ok("8de277067b3544d4b65c267d0edab928".into())
    }
}

#[test]
fn configured_node_name_and_digest_are_stable() {
    let identity = HostIdentity::resolve(Some("node-a"), "ignored", &FixedMachineId);
    assert_eq!(identity.host, "node-a");
    assert_eq!(identity.machine_id.len(), 32);
    assert_eq!(identity, identity.clone());
}
