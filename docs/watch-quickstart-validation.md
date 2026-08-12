# Watch Quickstart 完整验证

日期：2026-08-12；宿主：Linux `6.14.0-37-generic` x86_64。

| 区段 | 结果 | 说明 |
|---|---|---|
| 1–4 构建、规则检查、启动 | PASS | workspace、release eBPF、非空 b64/b32 coverage 均通过。 |
| 5–10 r/w/rw/x/a、失败、双路径、FD、reload | PASS | `cargo xtask test-kernel --kernel host` 内的 `watch_rules.sh`、`rule_reload.sh` 通过。 |
| 11 状态与计数 | PASS | status golden 含 candidates/matches、rwxa、permission/FD/path/ring/queue/stdout。 |
| 12 特权门禁 | PASS | host suite 通过；b32 实际执行因无 32 位 helper SKIP。 |
| 13 性能证据 | BLOCKED | `qualify=false`，VMware、背景负载、governor 和隔离声明不满足，不声明收益。 |
| 14 停止清理 | PASS | host suite 正常 TERM、排空并恢复测试环境。 |

主要命令总耗时约 20 秒（不含首次依赖构建缓存）；未执行的隔离性能测量需要每侧至少 5 × 120 秒，不能在不合格宿主缩短后冒充正式证据。
