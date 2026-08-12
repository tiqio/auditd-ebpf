# Watch 需求追踪矩阵

日期：2026-08-12。

| 需求 | 实现/任务 | 测试与证据 |
|---|---|---|
| FR-001–FR-004 | T007–T017、T046–T052 | permission/compile/coverage tests，`docs/watch-foundation-validation.md`、`docs/watch-us2-validation.md` |
| FR-005–FR-009 | T018–T045 | path/process cache、watch engine、golden、`tests/privileged/watch_rules.sh` |
| FR-010–FR-011 | T046–T056 | parser rejected、check-rules、reload tests 与特权 reload |
| FR-012–FR-014 | T057–T065 | health contract、watch gaps、status/diag golden、failure injection |
| FR-015 | T028–T045、T070 | host kernel suite：r/w/rw/x/a、失败、无关路径、FD、reload |
| FR-016 | T061、T066–T069 | watch report/ledger/schedule；不合格宿主禁止性能声明 |
| SR-001 | 既有 capability/lifecycle 门禁 | capability_drop、lifecycle 与 host suite |
| SR-002–SR-003 | 宪章 2.0、argv/output 契约 | argv_suppression、risk_acceptance、journal/rsyslog quickstart |
| SR-004–SR-005 | T046–T065 | invalid rules、gap counters、ABI flags、status/diag tests |
| SC-001–SC-004 | US1/US2 | watch privileged、coverage 与 reload PASS |
| SC-005 | US3 | failure injection PASS；真实 RingBuf 满明确 SKIP |
| SC-006 | T076 | host 6.14 PASS；5.15/6.1/6.6/6.12 与 b32 因环境不可用 SKIP |
| SC-007 | watch report correctness gate | 任一漏报/重复/误报/丢失使报告 invalid |
| SC-008 | watch comparison protocol | 每侧至少 5 样本已强制；当前资格失败，尚无可发布定量结果 |
