# 测试目录

单元测试放在各 crate，跨 crate 集成测试放在 `tests/integration/`，需要 root、BTF 或真实内核的
测试放在 `tests/privileged/` 与 `tests/vm/`。特权环境不可用时必须明确报告跳过，不能伪装通过。

