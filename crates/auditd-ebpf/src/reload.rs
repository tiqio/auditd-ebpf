use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

use auditd_ebpf_rules::{ArgvOutput, KernelFilterPlan, RuleCompiler, RuleErrors, parse_rules};

#[derive(Clone)]
pub struct ReloadService {
    active: Arc<RwLock<KernelFilterPlan>>,
}

impl ReloadService {
    pub fn new(active: KernelFilterPlan) -> Self {
        Self {
            active: Arc::new(RwLock::new(active)),
        }
    }
    pub fn reload(
        &self,
        file: &str,
        input: &str,
        overrides: BTreeMap<String, ArgvOutput>,
    ) -> Result<(), RuleErrors> {
        let generation = 1 - self.active.read().expect("rule lock poisoned").generation;
        let candidate = RuleCompiler::compile(parse_rules(file, input)?, generation, overrides)?;
        *self.active.write().expect("rule lock poisoned") = candidate;
        Ok(())
    }
    pub fn snapshot(&self) -> KernelFilterPlan {
        self.active.read().expect("rule lock poisoned").clone()
    }
}
