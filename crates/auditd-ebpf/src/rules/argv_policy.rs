use auditd_ebpf_rules::ArgvOutput;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectiveArgvOutput {
    Emitted,
    Suppressed,
}

#[must_use]
pub fn resolve(global_enabled: bool, rule: ArgvOutput) -> EffectiveArgvOutput {
    match rule {
        ArgvOutput::Enabled => EffectiveArgvOutput::Emitted,
        ArgvOutput::Disabled => EffectiveArgvOutput::Suppressed,
        ArgvOutput::Inherit if global_enabled => EffectiveArgvOutput::Emitted,
        ArgvOutput::Inherit => EffectiveArgvOutput::Suppressed,
    }
}
