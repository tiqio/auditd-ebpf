# Watch 性能验证

日期：2026-08-12。

实现了同一二进制 watch-off 与 watch-on（`-w /tmp/ddtest -p rw -k ddtest`）的 capture-only/operational 调度协议；每侧至少 5 个有效样本，记录 CPU、RSS、吞吐、p95、丢失和 path ledger。任何 ledger 不一致、丢失或非有效样本都会禁止性能声明。

当前宿主资格检查为 `qualified=false`，原因包括：缺少 `AUDITD_EBPF_BENCH_ISOLATED=1` 人工隔离声明、`load1=4.28` 超过 16 CPU 的 25% 门限、无法读取 CPU governor、存在 `unattended-upgrades.service` 干扰，且运行于 VMware。原始资格结果位于 `benchmarks/reports/watch/qualification.json`。

因此本次只验证协议与报告门禁，**不声明定量性能提升**。只有隔离主机 `qualify` 通过并完成 watch 关闭/开启每侧至少 5 次有效样本后，才能形成性能收益结论。
