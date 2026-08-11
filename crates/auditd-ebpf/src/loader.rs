use std::{fs, path::Path};

use anyhow::Context;
use auditd_ebpf_rules::KernelFilterPlan;
use aya::{
    Ebpf,
    maps::{Array, RingBuf},
    programs::{RawTracePoint, TracePoint},
};

pub struct LoadedBpf {
    inner: Ebpf,
}

impl LoadedBpf {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let bytes =
            fs::read(path).with_context(|| format!("无法读取 eBPF 对象 {}", path.display()))?;
        Ok(Self {
            inner: Ebpf::load(&bytes).context("Aya 无法加载 eBPF 对象")?,
        })
    }
    pub fn inner_mut(&mut self) -> &mut Ebpf {
        &mut self.inner
    }

    pub fn stage_rules(&mut self, plan: &KernelFilterPlan) -> anyhow::Result<()> {
        let generation = u32::from(plan.generation);
        let bitmap_b64 = syscall_bitmap(&plan.syscalls_b64);
        let bitmap_b32 = syscall_bitmap(&plan.syscalls_b32);
        let rule_version = u64::from_le_bytes(
            plan.version_hash[..8]
                .try_into()
                .expect("SHA-256 前 8 字节长度固定"),
        );
        Array::<_, [u64; 8]>::try_from(
            self.inner
                .map_mut("SYSCALL_BITMAPS_B64")
                .context("缺少 SYSCALL_BITMAPS_B64")?,
        )?
        .set(generation, bitmap_b64, 0)?;
        Array::<_, [u64; 8]>::try_from(
            self.inner
                .map_mut("SYSCALL_BITMAPS_B32")
                .context("缺少 SYSCALL_BITMAPS_B32")?,
        )?
        .set(generation, bitmap_b32, 0)?;
        Array::<_, u64>::try_from(
            self.inner
                .map_mut("RULE_VERSIONS")
                .context("缺少 RULE_VERSIONS")?,
        )?
        .set(generation, rule_version, 0)?;
        Array::<_, u32>::try_from(
            self.inner
                .map_mut("ACTIVE_GENERATION")
                .context("缺少 ACTIVE_GENERATION")?,
        )?
        .set(0, generation, 0)?;
        Ok(())
    }

    pub fn attach_collection_programs(&mut self) -> anyhow::Result<()> {
        attach_raw(&mut self.inner, "auditd_sys_enter", "sys_enter")?;
        attach_raw(&mut self.inner, "auditd_sys_exit", "sys_exit")?;
        verify_sched_tracepoint_layout()?;
        attach_tracepoint(
            &mut self.inner,
            "auditd_sched_process_fork",
            "sched",
            "sched_process_fork",
        )?;
        attach_tracepoint(
            &mut self.inner,
            "auditd_sched_process_exec",
            "sched",
            "sched_process_exec",
        )?;
        attach_tracepoint(
            &mut self.inner,
            "auditd_sched_process_exit",
            "sched",
            "sched_process_exit",
        )?;
        Ok(())
    }

    pub fn take_ring(&mut self) -> anyhow::Result<RingBuf<aya::maps::MapData>> {
        let map = self
            .inner
            .take_map("EVENTS")
            .context("缺少 EVENTS RingBuf")?;
        Ok(RingBuf::try_from(map)?)
    }
}

fn syscall_bitmap(syscalls: &std::collections::BTreeSet<u32>) -> [u64; 8] {
    let mut bitmap = [0_u64; 8];
    for syscall in syscalls.iter().copied().filter(|number| *number < 512) {
        bitmap[(syscall / 64) as usize] |= 1_u64 << (syscall % 64);
    }
    bitmap
}

fn attach_raw(bpf: &mut Ebpf, program_name: &str, tracepoint: &str) -> anyhow::Result<()> {
    let program: &mut RawTracePoint = bpf
        .program_mut(program_name)
        .with_context(|| format!("对象缺少 {program_name}"))?
        .try_into()?;
    program
        .load()
        .with_context(|| format!("加载 raw tracepoint 程序 {program_name} 失败"))?;
    program
        .attach(tracepoint)
        .with_context(|| format!("挂载 raw tracepoint {tracepoint} 失败"))?;
    Ok(())
}

fn attach_tracepoint(
    bpf: &mut Ebpf,
    program_name: &str,
    category: &str,
    tracepoint: &str,
) -> anyhow::Result<()> {
    let program: &mut TracePoint = bpf
        .program_mut(program_name)
        .with_context(|| format!("对象缺少 {program_name}"))?
        .try_into()?;
    program
        .load()
        .with_context(|| format!("加载 tracepoint 程序 {program_name} 失败"))?;
    program
        .attach(category, tracepoint)
        .with_context(|| format!("挂载 tracepoint {category}/{tracepoint} 失败"))?;
    Ok(())
}

fn verify_sched_tracepoint_layout() -> anyhow::Result<()> {
    let tracing = ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"]
        .into_iter()
        .find(|root| Path::new(root).exists())
        .context("找不到 tracefs")?;
    verify_format(
        tracing,
        "sched_process_fork",
        &["parent_pid;\toffset:24;", "child_pid;\toffset:44;"],
    )?;
    verify_format(
        tracing,
        "sched_process_exec",
        &["pid;\toffset:12;", "old_pid;\toffset:16;"],
    )?;
    verify_format(tracing, "sched_process_exit", &["pid;\toffset:24;"])?;
    Ok(())
}

fn verify_format(root: &str, event: &str, required: &[&str]) -> anyhow::Result<()> {
    let path = Path::new(root)
        .join("events/sched")
        .join(event)
        .join("format");
    let format = fs::read_to_string(&path)
        .with_context(|| format!("无法读取 tracepoint 格式 {}", path.display()))?;
    for fragment in required {
        anyhow::ensure!(
            format.contains(fragment),
            "tracepoint {event} 布局不兼容，缺少 {fragment}"
        );
    }
    Ok(())
}
