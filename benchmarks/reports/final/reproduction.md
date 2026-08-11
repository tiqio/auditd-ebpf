# 第二维护者复现记录

**状态**：`pending`

当前尚未产生通过隔离主机门禁的完整报告，因此不得签署方向复现结论。

## 复现前提

1. 使用独立主机或明确隔离的专用虚拟机。
2. 设置 `AUDITD_EBPF_BENCH_ISOLATED=1`，并确保 `auditd-ebpf-bench qualify` 返回 0。
3. 使用与主报告相同的 Git commit、内核/BTF、规则 hash、CPU governor、affinity 和日志配置。
4. 完整执行 syscall/path/mixed × capture-only/operational，每种实现至少 5 个有效样本。
5. 保留所有 invalid、contaminated 和 failed 样本。

## 待填写

- 维护者：
- 日期：
- Git commit：
- 环境文件：
- 动态报告目录：
- 与主报告差异：
- CPU 改善方向是否一致：
- 吞吐/延迟方向是否一致：
- 签字结论：
