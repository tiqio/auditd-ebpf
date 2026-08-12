# auditd-ebpf 运维指南

## systemd 与 journal

安装 `packaging/systemd/auditd-ebpf.service`，创建 `auditd-ebpf-auditors` 组，并仅把获准审计
人员加入该组。unit 使用 `ProtectSystem=strict`，只允许写 `/var/lib/auditd-ebpf`，stdout 和
stderr 都进入 journal。审计事件只写 stdout；status、diag 写 stderr，便于 rsyslog 独立分流。

默认 systemd 单元从 `/etc/auditd-ebpf/rules.d` 读取本服务规则；不要与传统 auditd 的
`/etc/audit/rules.d` 混用。单元不再声明 `Conflicts=auditd.service`，允许迁移观察期同时运行
传统 auditd 与 auditd-ebpf；运维方必须按日志来源区分两套记录，并接受同一操作可能重复记录。
进行性能对比、丢失率测量或单代理正确性验收时，必须只运行被测审计代理，避免互相污染结果。

```console
systemctl enable --now auditd-ebpf.service
journalctl -u auditd-ebpf.service -o cat
journalctl -u auditd-ebpf.service -o cat --grep 'type=AUDITD_EBPF '
kill -USR1 "$(systemctl show -p MainPID --value auditd-ebpf.service)"
```

`SIGHUP` 合并执行规则 reload；`SIGUSR1` 立即输出状态；`SIGTERM`/`SIGINT` 优先停止并排空。
排空超时返回 8，永久 stdout 失败返回 7。状态每十秒输出；任意 ring、queue、path 或异常关闭
增量应立即告警，连续五分钟无新缺口才从 degraded 恢复 healthy，累计计数不清零。

规则 reload 使用双 generation：先写完 syscall bitmap、permission tables、maintenance bitmap、
路径候选摘要和 rule version，再安装用户态 RuleEngine，最后切换 `ACTIVE_GENERATION`。日志中的
`reload_applied` 包含 generation/rule_version；`reload_rejected` 包含文件、行号和稳定错误码。
拒绝后必须继续观察到旧 key 与旧 rule version，禁止人工重启掩盖原子性问题。

## rsyslog

安装 `packaging/rsyslog/60-auditd-ebpf.conf`，替换示例 CA、客户端证书、服务端 DNS 身份和目的
地址。配置使用 imjournal 持久游标；事件日志为 root:`auditd-ebpf-auditors` `0640`，离线导出
为 root:root `0600`。远端只允许 TCP+GTLS、`x509/name` 服务端身份验证，禁止明文 UDP/TCP。

rsyslog 使用 `%msg%` 加 LF 保存已经完成 argv 策略的源行，不解析或补齐 suppressed 事件的
`aN`。磁盘辅助 LinkedList 队列在断网时吸收流量并 `saveonshutdown`；恢复后按原顺序继续转发，
不得反向阻塞服务 stdout。部署必须为 journal、本地事件、离线导出、发送队列和远端接收端分别
记录 1–3650 天保留期及删除流程，示例策略为 90 天。

## 验证与故障处理

```console
auditd-ebpf print-capabilities
auditd-ebpf check-rules --rules-file /etc/audit/rules.d/auditd-ebpf.rules --print-normalized
auditd-ebpf check-production --risk-acceptance-file /etc/auditd-ebpf/risk-acceptance.toml
systemd-analyze verify /usr/lib/systemd/system/auditd-ebpf.service
rsyslogd -N1
```

包含 permission 条件的规则要求 eBPF 对象提供双 ABI permission/maintenance maps。旧对象
`flags=0` 仅兼容不依赖权限的普通 syscall 事件；permission watch 会形成明确缺口。任何未知
syscall header flags 都会在解码阶段拒绝，不能静默解释为 `perm=?`。

发现历史 dirty 时，先保存 gap、状态和上次 lifecycle 文件，再调查宿主机重启、OOM、SIGKILL、
stdout/rsyslog 故障。`count=?` 只表示异常清理期间数量未知，不能解释为零。完整 argv 可能包含
口令、token 和个人数据；越权读取、日志错误转发或保留期失控必须按风险记录中的事件响应流程
处置并轮换相关凭据。
