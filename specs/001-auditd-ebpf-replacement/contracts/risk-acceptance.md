# Contract: 生产风险接受记录与策略摘要

## File Trust

- 默认路径为 `/etc/auditd-ebpf/risk-acceptance.toml`。
- 文件必须为普通文件、由 UID 0 所有，且 group/other 均不可写；符号链接、目录、设备或权限
  检查竞争失败时必须拒绝。
- 读取必须使用防符号链接和读取后 `fstat` 复核；文件大小上限 64 KiB，未知键必须拒绝。

## TOML Schema

```toml
record_version = 1
approval_id = "SEC-2026-0042"
approver = "security-team@example.invalid"
owner = "linux-platform@example.invalid"
approved_at = "2026-08-10T09:00:00+08:00"
purpose = "记录受支持 exec 审计规则命中的完整命令行参数"
approved_readers = ["root", "auditd-ebpf-auditors"]
incident_response = "IR-AUDIT-ARGV-01"
policy_digest_version = 1
policy_digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[[destinations]]
id = "service-journal"
kind = "journal"
target = "auditd-ebpf.service"
retention_days = 90
transport_mode = "local-only"
owner = "root"
group = "auditd-ebpf-auditors"
mode = "0640"

[[destinations]]
id = "local-events"
kind = "file"
target = "/var/log/auditd-ebpf/events.log"
retention_days = 90
transport_mode = "local-only"
owner = "root"
group = "auditd-ebpf-auditors"
mode = "0640"
```

- 所有字符串去除首尾空白后不得为空；数组去重并使用 C locale 字节顺序比较。
- `approved_at` 必须是带时区 RFC 3339 时间，但不产生 `expires_at`，审批不因时间自动失效。
- 每个 `destinations` 项的 `id` 必须唯一。`transport_mode=local-only` 只允许本地目的地；远端
  目的地必须记录经认证加密模式、受信 CA/证书指纹和预期服务端身份。
- journal、本地文件和导出目的地必须记录预期 owner、group 和 mode；不适用字段使用空字符串，
  不得省略，以保证摘要输入稳定。
- 记录中的读取者、目的地、传输和保留值必须与有效配置一致，不能仅依赖摘要字符串。

## Policy Digest Version 1

实现必须把有效策略规范化为 UTF-8、单个 LF 结尾的固定顺序 `key=value` 行，再计算 SHA-256。
禁止把审批元数据、文件路径、`approved_at` 或运行时时间放入摘要。

固定顺序如下：

1. `argv.default=emitted|suppressed`
2. 零到多行 `argv.rule.<escaped-key>=emitted|suppressed`，按 key 原始字节升序
3. 零到多行 `reader=<normalized-name>`，去重后升序
4. 零到多组目的地行，按 `(kind, normalized-target)` 升序：
   `destination=<kind>:<target>`、`transport=<mode>:<peer-identity>:<trust-fingerprint>`、
   `access=<owner>:<group>:<octal-mode>`、`retention_days=<u32>`

`escaped-key` 使用事件格式的 `\xHH` 字节转义，不受 locale 或 Unicode 归一化影响。摘要输出为
小写十六进制 `sha256:<64 hex>`。任何规范化规则变化必须提升 `policy_digest_version`。

## Validation Result

`check-production` 和 production `run` 必须执行相同验证：

1. 验证文件可信属性和 TOML schema。
2. 规范化当前有效规则、argv 覆盖和日志链路配置。
3. 重新计算摘要并与记录比较。
4. 独立检查 journal 读取组、本地文件模式、远端身份认证和实际保留配置。
5. 任一失败返回退出码 9，并输出稳定错误码；不得把风险接受当作强制控制豁免。

审批保持有效，直到策略摘要变化、必填字段缺失或文件可信属性失效。
