# Contract: 健康状态、计数器与日志链路

## Health States

| State | Entry Condition | Exit Condition | Service Exit? |
|---|---|---|---:|
| `starting` | 进程启动 | 全部程序、规则和消费者就绪 | no |
| `healthy` | 无当前缺口 | 新增缺口或致命错误 | no |
| `degraded` | 任意事件丢失、路径解析缺口、历史 dirty 标记或可恢复输出错误 | 连续 5 分钟无新增缺口 | no |
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
| `exec_argv_captured_total` | eBPF per CPU | 成功提交包含 argv 的 ExecAttempt |
| `exec_argv_suppressed_total` | rule engine | first-match 后未输出 argv 的 exec 事件 |
| `queue_dropped_total` | queue | 用户队列达到硬上限 |
| `path_resolution_failed_total` | process cache | 不能可靠规范化路径 |
| `unclean_shutdown_detected_total` | lifecycle | 启动时发现历史 dirty 标记；首版每次启动为 0 或 1 |
| `event_parse_failed_total` | collector | schema/长度/字段无效 |
| `stdout_write_failed_total` | writer | stdout write/flush 错误 |
| `rule_reload_success_total` | reload | 原子切换成功 |
| `rule_reload_failed_total` | reload | 候选规则拒绝 |

必须满足以下可检查不变量：

```text
events_seen_total = events_submitted_total + ring_reserve_failed_total
events_consumed_total <= events_submitted_total
events_output_total + queue_dropped_total <= events_consumed_total + gap_records_generated
exec_argv_suppressed_total <= exec_argv_captured_total
```

## Status Record

每 10 秒及 SIGUSR1 时向 stderr 输出 `type=AUDITD_EBPF_STATUS`：

```text
type=AUDITD_EBPF_STATUS state=healthy production_policy=passed uptime_s=600 rule_version=184467 programs_attached=5 events_seen=100000 events_submitted=100000 events_consumed=100000 events_matched=82000 events_output=82000 argv_captured=12000 argv_suppressed=2000 ring_lost=0 queue_lost=0 path_lost=0 unclean_shutdown=0 parse_failed=0 stdout_failed=0 queue_used_bytes=1048576 queue_limit_bytes=67108864 queue_max_bytes=536870912
```

- 数值字段不可省略；不可用值使用 `?`。
- 状态变化必须立即输出，不等待周期。
- degraded 记录必须包含 `reason` 和首次/最近发生时间。
- 停止前必须输出 final=yes 的最终记录。
- 启动发现历史 dirty 标记时，10 秒内必须同时输出 `reason=unclean_shutdown count=?` gap、
  `state=degraded reason=unclean_shutdown` 状态，并令 `unclean_shutdown=1`。

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
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_SETPCAP
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_SETPCAP
LimitMEMLOCK=infinity
```

- `CAP_SYS_ADMIN` 仅作为兼容回退；`CAP_SETPCAP` 仅用于初始化结束时删除 bounding set。
  所有 eBPF fd 打开且 attach 完成后，进程必须锁定 securebits、清空 bounding/ambient/
  effective/permitted/inheritable 集合，并保持 `NoNewPrivileges`，运行期不得保留 capability。
- `ProtectSystem=strict` 下只读规则和配置，允许写入的路径仅限运行目录、
  `/var/lib/auditd-ebpf` 生命周期目录和可选基准输出目录。
- 发行包允许 auditd 与 auditd-ebpf 在迁移观察期同时运行，不得通过 systemd `Conflicts=`
  隐式停止传统 auditd；两套代理必须使用独立规则目录和可区分的日志来源。性能对比、丢失率
  测量和单代理正确性验收仍必须只运行被测审计代理。

## rsyslog Contract

- 使用 `imjournal` 时必须配置持久 `StateFile`，避免重启后游标丢失。
- 按 `$programname == 'auditd-ebpf'` 且 `$msg contains 'type=AUDITD_EBPF '` 分流审计事件。
- `AUDITD_EBPF_STATUS` 与 `AUDITD_EBPF_DIAG` 必须进入独立运维日志或远端 stream。
- 必须显式设置 action queue 和磁盘辅助队列；远端不可用不能反向阻塞服务 stdout。
- journald/rsyslog 的 rate limit、丢弃和队列统计纳入端到端稳定性测试。
- rsyslog 保存的事件必须与服务完成 argv 输出策略后写入 stdout 的整行逐字节一致；
  `argv_output=suppressed` 记录缺少 `aN` 是预期契约，不得补齐或标记为不完整。

## Unredacted argv Production Gate

命中 exec 规则时默认输出不脱敏 argv。生产启用前必须完成并可验证以下门禁：

- 存在已批准的本地 TOML 风险接受记录，包含审批人、责任人、审批时间、用途、获准读取主体、
  日志目的地、传输保护、journal 或文件访问策略、保留期、事件响应要求和当前有效策略摘要。
- 风险接受文件必须由 root 所有且 group/other 不可写；`policy_digest_version=1`，摘要必须与
  当前 argv 输出策略、读取者、目的地、传输认证和逐目的地保留期完全匹配。
- systemd journal 仅允许 root 和获准审计管理员组读取；不得通过宽泛组成员资格或 world-readable
  导出规避该限制。
- 本地事件日志权限不得宽于 `0640`，离线导出或诊断包权限不得宽于 `0600`，所有者和组必须
  与风险接受记录一致。
- rsyslog 远端转发必须使用经认证的加密通道，并验证服务端身份；明文 TCP/UDP 不得作为
  生产审计事件目的地。
- 必须配置并验证 journal、本地文件、rsyslog 队列和远端接收端的保留期与删除流程。
- 风险接受不得豁免访问控制、保留、加密或事件响应要求。
- 风险接受无固定到期时间；策略摘要不匹配、必填字段缺失或文件可信属性失效时立即失效。

任一检查失败或无法自动验证时，服务必须报告生产策略未通过，不得声明生产就绪；若配置
允许非生产诊断运行，状态必须明确包含 `production_policy=failed`，且不得以 `healthy` 表示
生产安全门禁合格。

## Alert Recommendations

- 任意 `ring_lost`、`queue_lost`、`path_lost` 或 `unclean_shutdown` 增量：立即告警。
- `state=unhealthy` 或进程退出码 4–9：严重告警。
- 队列持续 60 秒高于 80%：容量/下游告警。
- 连续 5 分钟无状态记录：存活告警。
