use std::{fs, path::Path};

use anyhow::Context;
use auditd_ebpf_common::counters::{
    COUNTER_CORRELATION_MISSED, COUNTER_EVENTS_SEEN, COUNTER_EVENTS_SUBMITTED,
    COUNTER_EXEC_ARGV_CAPTURED, COUNTER_EXEC_ARGV_DROPPED, COUNTER_INFLIGHT_DROPPED,
    COUNTER_INTERNAL_DROPPED, COUNTER_PERMISSION_CLASSIFICATION_FAILED, COUNTER_RINGBUF_DROPPED,
};
use auditd_ebpf_rules::{KernelFilterPlan, RuleKind};
use aya::{
    Ebpf,
    maps::{Array, PerCpuArray, RingBuf},
    programs::{RawTracePoint, TracePoint},
};

use crate::health::counters::KernelCounterSample;

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
        self.stage_inactive_rules(plan)?;
        self.activate_generation(plan.generation)
    }

    /// 只填充指定 generation 的完整规则数据，不切换当前活动 generation。
    ///
    /// reload 必须先完成此步骤和用户态引擎安装，最后才写 `ACTIVE_GENERATION`，
    /// 从而避免内核看到只写入一半的候选规则。
    pub fn stage_inactive_rules(&mut self, plan: &KernelFilterPlan) -> anyhow::Result<()> {
        let generation = u32::from(plan.generation);
        let bitmap_b64 = syscall_bitmap(&plan.syscalls_b64);
        let bitmap_b32 = syscall_bitmap(&plan.syscalls_b32);
        let maintenance_b64 = syscall_bitmap(&plan.maintenance_syscalls_b64);
        let maintenance_b32 = syscall_bitmap(&plan.maintenance_syscalls_b32);
        let rule_version = plan.rule_version();
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
        stage_permission_table(
            &mut self.inner,
            "PERMISSION_MASKS_B64",
            generation,
            &plan.permission_masks_b64,
        )?;
        stage_permission_table(
            &mut self.inner,
            "PERMISSION_MASKS_B32",
            generation,
            &plan.permission_masks_b32,
        )?;
        Array::<_, [u64; 8]>::try_from(
            self.inner
                .map_mut("MAINTENANCE_BITMAPS_B64")
                .context("缺少 MAINTENANCE_BITMAPS_B64")?,
        )?
        .set(generation, maintenance_b64, 0)?;
        Array::<_, [u64; 8]>::try_from(
            self.inner
                .map_mut("MAINTENANCE_BITMAPS_B32")
                .context("缺少 MAINTENANCE_BITMAPS_B32")?,
        )?
        .set(generation, maintenance_b32, 0)?;
        stage_watch_path_filter(&mut self.inner, plan, generation)?;
        Array::<_, u64>::try_from(
            self.inner
                .map_mut("RULE_VERSIONS")
                .context("缺少 RULE_VERSIONS")?,
        )?
        .set(generation, rule_version, 0)?;
        Ok(())
    }

    /// 原子切换内核读取的活动 generation；此前候选 generation 必须已完整填充。
    pub fn activate_generation(&mut self, generation: u8) -> anyhow::Result<()> {
        anyhow::ensure!(generation <= 1, "generation 只能为 0/1");
        Array::<_, u32>::try_from(
            self.inner
                .map_mut("ACTIVE_GENERATION")
                .context("缺少 ACTIVE_GENERATION")?,
        )?
        .set(0, u32::from(generation), 0)?;
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

    /// 停止所有内核采集入口，但保留 maps 供用户态排空 RingBuf 和读取最终计数。
    ///
    /// 必须先 detach 再等待 collector；否则系统调用持续写入 RingBuf，高负载下消费者
    /// 永远观察不到空队列，优雅退出只能等到超时。
    pub fn detach_collection_programs(&mut self) -> anyhow::Result<()> {
        for name in ["auditd_sys_enter", "auditd_sys_exit"] {
            let program: &mut RawTracePoint = self
                .inner
                .program_mut(name)
                .with_context(|| format!("缺少 {name} 程序"))?
                .try_into()?;
            program
                .unload()
                .with_context(|| format!("无法卸载 {name}"))?;
        }
        for name in [
            "auditd_sched_process_fork",
            "auditd_sched_process_exec",
            "auditd_sched_process_exit",
        ] {
            let program: &mut TracePoint = self
                .inner
                .program_mut(name)
                .with_context(|| format!("缺少 {name} 程序"))?
                .try_into()?;
            program
                .unload()
                .with_context(|| format!("无法卸载 {name}"))?;
        }
        Ok(())
    }

    pub fn take_ring(&mut self) -> anyhow::Result<RingBuf<aya::maps::MapData>> {
        let map = self
            .inner
            .take_map("EVENTS")
            .context("缺少 EVENTS RingBuf")?;
        Ok(RingBuf::try_from(map)?)
    }

    pub fn read_kernel_counters(&mut self) -> anyhow::Result<KernelCounterSample> {
        let counters = PerCpuArray::<_, u64>::try_from(
            self.inner
                .map_mut("EVENT_COUNTERS")
                .context("缺少 EVENT_COUNTERS")?,
        )?;
        Ok(KernelCounterSample {
            events_seen_per_cpu: read_per_cpu(&counters, COUNTER_EVENTS_SEEN)?,
            events_submitted_per_cpu: read_per_cpu(&counters, COUNTER_EVENTS_SUBMITTED)?,
            ring_reserve_failed_per_cpu: read_per_cpu(&counters, COUNTER_RINGBUF_DROPPED)?,
            inflight_dropped_per_cpu: read_per_cpu(&counters, COUNTER_INFLIGHT_DROPPED)?,
            correlation_missed_per_cpu: read_per_cpu(&counters, COUNTER_CORRELATION_MISSED)?,
            exec_argv_captured_per_cpu: read_per_cpu(&counters, COUNTER_EXEC_ARGV_CAPTURED)?,
            exec_argv_dropped_per_cpu: read_per_cpu(&counters, COUNTER_EXEC_ARGV_DROPPED)?,
            internal_dropped_per_cpu: read_per_cpu(&counters, COUNTER_INTERNAL_DROPPED)?,
            permission_classification_failed_per_cpu: read_per_cpu(
                &counters,
                COUNTER_PERMISSION_CLASSIFICATION_FAILED,
            )?,
        })
    }
}

fn stage_watch_path_filter(
    bpf: &mut Ebpf,
    plan: &KernelFilterPlan,
    generation: u32,
) -> anyhow::Result<()> {
    const MAX_KERNEL_WATCH_PATHS: usize = 16;
    let exact_paths: Vec<_> = plan
        .rules
        .iter()
        .filter_map(|rule| rule.path.as_deref())
        .collect();
    let safe_to_filter = !plan.rules.is_empty()
        && plan.rules.iter().all(|rule| {
            rule.kind == RuleKind::Watch
                && rule.dir.is_none()
                && rule
                    .path
                    .as_deref()
                    .is_some_and(|path| path.starts_with('/'))
        })
        && exact_paths.len() <= MAX_KERNEL_WATCH_PATHS;
    let base = generation * MAX_KERNEL_WATCH_PATHS as u32;
    let mut path_values = [0_u64; MAX_KERNEL_WATCH_PATHS];
    let mut basename_values = [0_u64; MAX_KERNEL_WATCH_PATHS];
    for index in 0..MAX_KERNEL_WATCH_PATHS {
        let path = safe_to_filter.then(|| exact_paths.get(index)).flatten();
        path_values[index] = path.map_or(0, |path| fnv1a(path.as_bytes()));
        basename_values[index] = path.map_or(0, |path| {
            let bytes = path.as_bytes();
            bytes
                .iter()
                .rev()
                .take(8)
                .enumerate()
                .fold(0_u64, |signature, (offset, byte)| {
                    signature | (u64::from(*byte) << (offset * 8))
                })
        });
    }
    {
        let mut hashes = Array::<_, u64>::try_from(
            bpf.map_mut("WATCH_PATH_HASHES")
                .context("缺少 WATCH_PATH_HASHES")?,
        )?;
        for (index, hash) in path_values.into_iter().enumerate() {
            hashes.set(base + index as u32, hash, 0)?;
        }
    }
    {
        let mut basename_hashes = Array::<_, u64>::try_from(
            bpf.map_mut("WATCH_BASENAME_HASHES")
                .context("缺少 WATCH_BASENAME_HASHES")?,
        )?;
        for (index, hash) in basename_values.into_iter().enumerate() {
            basename_hashes.set(base + index as u32, hash, 0)?;
        }
    }
    Array::<_, u32>::try_from(
        bpf.map_mut("WATCH_PATH_COUNTS")
            .context("缺少 WATCH_PATH_COUNTS")?,
    )?
    .set(
        generation,
        if safe_to_filter {
            exact_paths.len() as u32
        } else {
            0
        },
        0,
    )?;
    Ok(())
}

fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x100_0000_01b3)
    })
}

fn stage_permission_table(
    bpf: &mut Ebpf,
    map_name: &str,
    generation: u32,
    permissions: &[u8; 512],
) -> anyhow::Result<()> {
    let mut table = Array::<_, u8>::try_from(
        bpf.map_mut(map_name)
            .with_context(|| format!("规则包含 permission 覆盖，但对象缺少 {map_name}"))?,
    )?;
    let base = generation * 512;
    for (syscall_nr, permission) in permissions.iter().copied().enumerate() {
        table.set(base + syscall_nr as u32, permission, 0)?;
    }
    Ok(())
}

fn read_per_cpu<T: std::borrow::Borrow<aya::maps::MapData>>(
    counters: &PerCpuArray<T, u64>,
    index: u32,
) -> anyhow::Result<Vec<u64>> {
    Ok(counters.get(&index, 0)?.iter().copied().collect())
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
