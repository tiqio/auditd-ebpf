# Contract: Watch Audit Event Format

## Stream

- watch 审计事件写 stdout，进入 journal 后保持单行。
- status 与 diag 写 stderr，不得重复输出事件敏感字段或 exec argv。
- 继续使用现有 `type=AUDITD_EBPF` 事件前缀和转义规则。

## Required Fields

watch 命中事件必须包含现有事件公共字段，并满足：

| Field | Contract |
|-------|----------|
| `key` | 命中 WatchRule 的非空 key |
| `rule_id` | 当前 rule version 中的稳定规则 ID |
| `rule_version` | 事件采集 generation 的规则版本 |
| `syscall` | 规范化 syscall 名 |
| `operation` | 与 syscall 一致的稳定操作名称，不使用泛化 `syscall` 值 |
| `path` | 实际触发匹配的 namespace lexical path |
| `perm` | 非空 `rwxa` 子集，固定按 `rwxa` 输出 |
| `success` | `yes` / `no` |
| `exit` | 原始 syscall 返回值 |
| `path_confidence` | `namespace-lexical` |

## Examples

读取：

```text
type=AUDITD_EBPF ... key="ddtest" syscall="openat" operation="openat" path="/tmp/ddtest" perm="r" success="yes" exit=3 path_confidence="namespace-lexical" ...
```

读写：

```text
type=AUDITD_EBPF ... key="ddtest" syscall="openat" operation="openat" path="/tmp/ddtest" perm="rw" success="yes" exit=3 path_confidence="namespace-lexical" ...
```

失败写入：

```text
type=AUDITD_EBPF ... key="ddtest" syscall="openat" operation="openat" path="/tmp/ddtest" perm="w" success="no" exit=-13 path_confidence="namespace-lexical" ...
```

省略号只用于文档；实际输出不得包含省略号。

## Matching and Duplication

- 一个 syscall 事件可以解析出 primary、secondary 或 fd path。
- 规则按原始顺序、路径按 primary -> secondary -> fd 顺序求值。
- 第一个完整匹配决定 key/path/perm；同一内核事件默认只输出一条记录。
- `perm` 输出当前操作与命中规则请求权限的交集。例如实际 `rw`、规则只请求 `r` 时输出 `r`。

## Gap Behavior

无法可靠确认权限或路径时不得输出伪造 WatchAuditEvent。系统改为：

1. 增加对应 gap 和原因计数；
2. 输出 `type=AUDITD_EBPF_DIAG` 或既定 gap 记录，包含 event_id、rule_version、pid/tid、syscall、
   reason，不包含 argv；
3. 在 10 秒内进入 degraded；
4. 保持 stdout 审计事件中没有 `perm=""` 或 `path=""` 的假匹配。

## Structured Watch Diagnostic

watch gap 诊断固定包含 `reason`、`stage`、`rule_version`、`pid`、`tid`、`syscall`；未知规则版本输出 `?`。诊断构造接口不接受 argv，字段顺序由 golden 测试固定。
