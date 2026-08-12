# Watch 发布验证

日期：2026-08-12。

## 发布门禁

- fmt、严格 Clippy、workspace tests：PASS。
- eBPF release build、host 特权套件：PASS。
- watch quickstart、安全审查、需求追踪：PASS。
- host x86_64 b64：PASS；b32 与 5.15/6.1/6.6/6.12：环境不可用，明确 SKIP。
- 性能协议与 invalid 门禁：PASS；隔离性能资格：FAIL-CLOSED，禁止声明定量提升。

## 判定

功能可用于当前已验证的 host b64 环境进行测试和试运行。不得把本次结果表述为完整多内核矩阵或已证明的性能提升；完成隔离机 5 样本对照和目标内核 VM 后方可扩大兼容/性能声明。
