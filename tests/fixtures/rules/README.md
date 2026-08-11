# 规则 Fixture

这里保存受支持、拒绝和边界规则语料。fixture 不得包含真实生产路径、账号或敏感命令行参数。

## Watch 语料

- `watch-supported.rules` 覆盖 `r`、`w`、`rw`、`x`、`a`、b64/b32 syscall 形式和双路径目标。
- `watch-rejected.rules` 的每个非注释行都应独立失败，错误必须包含文件、行号和稳定错误码。
- 受支持 watch 的规范化结果必须包含非空 symbolic syscalls、coverage version 和 b64/b32 覆盖。
- fixture 只使用 `/tmp/auditd-ebpf-watch`，不得替换为生产路径或真实敏感命令参数。
