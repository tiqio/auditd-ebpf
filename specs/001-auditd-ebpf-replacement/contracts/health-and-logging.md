# Contract: 健康状态、计数器与日志链路

## Health States

| State | Entry Condition | Exit Condition | Service Exit? |
|---|---|---|---:|
| `starting` | 进程启动 | 全部程序、规则和消费者就绪 | no |
| `healthy` | 无当前缺口 | 新增缺口或致命错误 | no |
| `degraded` | 任意事件丢失、路径解析缺口或可恢复输出错误 | 连续 5 分钟无新增缺口 | no |
| `unhealthy` | 程序脱离、活动规则失效、stdout 永久失败、内部不变量破坏 | 无；准备退出 | yes |
| `stopping` | SIGTERM/SIGINT | 排空完成或超时 | yes |

历史累计计数不因状态恢复而清零。`healthy` 只表示当前窗口无新增缺口。

## Required Counters

所有计数为从进程启动开始的 u64 单调累计值；溢出前进入 unhealthy。

| Name | Source | Meaning |
|---|---|---|
| `events_seen_total` | eBPF per CPU | 粗筛选后尝试处理 |
| `events_submitted_total` | eBPF per CPU | 成功提交 RingBuf |
| `ring_reserve_failed_total` | eBPF per CPU | RingBuf 无空间 |
| `events_consumed_total` | collector | 从 RingBuf 读取 |
| `events_matched_total` | rule engine | first-match 成功 |
| `events_unmatched_total` | rule engine | 粗筛选候选未精确命中 |
| `events_output_total` | writer | stdout 完整写入 |
| `queue_dropped_total` | queue | 用户队列达到硬上限 |
| `path_resolution_failed_total` | process cache | 不能可靠规范化路径 |
| `event_parse_failed_total` | collector | schema/长度/字段无效 |
| `stdout_write_failed_total` | writer | stdout write/flush 错误 |
| `rule_reload_success_total` | reload | 原子切换成功 |
| `rule_reload_failed_total` | reload | 候选规则拒绝 |

必须满足以下可检查不变量：

```text
events_seen_total = events_submitted_total + ring_reserve_failed_total
events_consumed_total <= events_submitted_total
events_output_total + queue_dropped_total <= events_consumed_total + gap_records_generated
```

## Status Record

每 10 秒及 SIGUSR1 时向 stderr 输出 `type=AUDITD_EBPF_STATUS`：

```text
type=AUDITD_EBPF_STATUS state=healthy uptime_s=600 rule_version=184467 programs_attached=5 events_seen=100000 events_submitted=100000 events_consumed=100000 events_matched=82000 events_output=82000 ring_lost=0 queue_lost=0 path_lost=0 parse_failed=0 stdout_failed=0 queue_used_bytes=1048576 queue_limit_bytes=67108864 queue_max_bytes=536870912
```

- 数值字段不可省略；不可用值使用 `?`。
- 状态变化必须立即输出，不等待周期。
- degraded 记录必须包含 `reason` 和首次/最近发生时间。
- 停止前必须输出 final=yes 的最终记录。

## systemd Contract

计划 unit 的关键属性：

```ini
[Service]
Type=simple
ExecStart=/usr/sbin/auditd-ebpf run
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=auditd-ebpf
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN
AmbientCapabilities=CAP_BPF CAP_PERFMON
LimitMEMLOCK=infinity
```

- `CAP_SYS_ADMIN` 仅作为兼容回退；能力探测通过后进程必须从 effective/permitted 集合删除。
- `ProtectSystem=strict` 下只读规则和配置，允许写入的路径仅限运行目录和可选基准输出目录。
- 发行包不得同时自动启动 auditd 与 auditd-ebpf。

## rsyslog Contract

- 使用 `imjournal` 时必须配置持久 `StateFile`，避免重启后游标丢失。
- 按 `$programname == 'auditd-ebpf'` 且 `$msg contains 'type=AUDITD_EBPF '` 分流审计事件。
- `AUDITD_EBPF_STATUS` 与 `AUDITD_EBPF_DIAG` 必须进入独立运维日志或远端 stream。
- 必须显式设置 action queue 和磁盘辅助队列；远端不可用不能反向阻塞服务 stdout。
- journald/rsyslog 的 rate limit、丢弃和队列统计纳入端到端稳定性测试。

## Unredacted argv Production Gate

命中 exec 规则时默认输出不脱敏 argv。生产启用前必须完成并可验证以下门禁：

- 存在已批准的风险接受记录，包含责任人、用途、获准读取主体、日志目的地、传输保护、
  journal 或文件访问策略、保留期和事件响应要求。
- systemd journal 仅允许 root 和获准审计管理员组读取；不得通过宽泛组成员资格或 world-readable
  导出规避该限制。
- 本地事件日志权限不得宽于 `0640`，离线导出或诊断包权限不得宽于 `0600`，所有者和组必须
  与风险接受记录一致。
- rsyslog 远端转发必须使用经认证的加密通道，并验证服务端身份；明文 TCP/UDP 不得作为
  生产审计事件目的地。
- 必须配置并验证 journal、本地文件、rsyslog 队列和远端接收端的保留期与删除流程。
- 风险接受不得豁免访问控制、保留、加密或事件响应要求。

任一检查失败或无法自动验证时，服务必须报告生产策略未通过，不得声明生产就绪；若配置
允许非生产诊断运行，状态必须明确包含 `production_policy=failed`，且不得以 `healthy` 表示
生产安全门禁合格。

## Alert Recommendations

- 任意 `ring_lost`、`queue_lost` 或 `path_lost` 增量：立即告警。
- `state=unhealthy` 或进程退出码 4–8：严重告警。
- 队列持续 60 秒高于 80%：容量/下游告警。
- 连续 5 分钟无状态记录：存活告警。
