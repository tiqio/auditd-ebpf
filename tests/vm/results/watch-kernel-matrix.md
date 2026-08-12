# Watch 内核矩阵

日期：2026-08-12。

| 内核 | 架构/ABI | 结果 | 原因/证据 |
|---|---|---|---|
| host 6.14.0-37-generic | x86_64 b64 | PASS | build、load、watch、reload、gap/计数、TERM 清理通过。 |
| host 6.14.0-37-generic | x86_64 b32 compat | SKIP | 无可执行 32 位 helper；仅规则矩阵与 ABI 契约测试通过。 |
| 5.15 | x86_64 b64/b32 | SKIP | 当前环境未提供该 VM/内核。 |
| 6.1 | x86_64 b64/b32 | SKIP | 当前环境未提供该 VM/内核。 |
| 6.6 | x86_64 b64/b32 | SKIP | 当前环境未提供该 VM/内核。 |
| 6.12 | x86_64 b64/b32 | SKIP | 当前环境未提供该 VM/内核。 |

SKIP 不计为 PASS。对外声明最低内核兼容前，应在对应 VM 执行同一 `cargo xtask test-kernel` 套件并替换本表。
