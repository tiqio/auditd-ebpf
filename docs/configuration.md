# auditd-ebpf 配置参考

## 身份字段

进程启动时冻结 `host` 和 `machine_id`，运行中不会随 hostname 或配置文件变化。`--node-name`
优先于内核 hostname。`machine_id` 是对 `/etc/machine-id` 使用应用专用 HMAC-SHA256 后截取的
128 bit 小写十六进制摘要；读取或格式错误时稳定输出 `?` 并产生诊断，不生成随机身份。

## argv 输出策略

命中受支持 exec 规则时，内核始终按最多 32 个参数、每参数 192 字节捕获 argv。输出默认是
`emitted`，即在单行 16 KiB 上限内原样、可逆转义输出 `a0`–`a31`。这是明确接受的敏感信息
风险，不是脱敏功能。

用户态 first-match 后才应用抑制。`suppressed` 事件保留 `argc` 和
`argv_output=suppressed`，但原始参数在进入 AdaptiveQueue 前被移除，绝不进入 stdout、stderr、
status、diag 或 gap。按规则 key 的覆盖优先于全局默认；存在覆盖时，该 key 必须唯一对应一条
exec 规则，冲突会使候选规则集整体失败。

## 容量

- RingBuf 默认 16 MiB，必须是 1–256 MiB 范围内的二次幂。
- 用户态队列默认 64 MiB，连续三个窗口超过 80% 后倍增，最大 512 MiB。
- 低于 25% 持续十分钟后逐级缩容，但不低于初始容量。
- 达到硬上限采用 drop-new，不阻塞被审计业务；丢失计数并进入 degraded。

## 生命周期文件

默认路径为 `/var/lib/auditd-ebpf/lifecycle.toml`。父目录必须 root 所有且 group/other 不可写，
文件必须是 root 所有的 `0600` 普通文件。实现使用 `O_NOFOLLOW`、读取前后 `fstat`、同目录
临时文件、文件 `fsync`、原子 rename 和父目录 `fsync`。

启动顺序固定为：读取 eBPF 对象但不 attach → durable dirty → attach → RingBuf 消费。停止顺序
固定为：停止接收 → 排空或超时 → final status → drop RingBuf、links 和 maps → durable clean。
SIGKILL、崩溃或断电会保留 dirty；下次启动在十秒内输出
`reason=unclean_shutdown count=?`，不能据此伪造精确丢失数量。

## 生产模式

生产启动必须同时提供：

```console
auditd-ebpf run --deployment-mode production \
  --risk-acceptance-file /etc/auditd-ebpf/risk-acceptance.toml \
  --ebpf-object /usr/lib/auditd-ebpf/auditd-ebpf-ebpf
```

风险记录必须包含审批人、责任人、带时区审批时间、用途、获准读取者、事件响应、所有目的地、
传输保护、访问模式、保留期和当前策略摘要。审批没有固定到期时间；策略摘要、必填字段或文件
可信属性变化时立即失效。风险接受不能豁免访问控制、认证加密、保留或事件响应要求。

使用 `auditd-ebpf print-policy-digest --value-only` 生成待审批摘要，使用
`auditd-ebpf check-production --risk-acceptance-file PATH` 执行与 production `run` 相同门禁。
失败统一返回退出码 9，且在 durable dirty 和 eBPF attach 前终止。

