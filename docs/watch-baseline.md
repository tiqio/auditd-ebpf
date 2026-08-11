# Watch 运行基线

**日期**：2026-08-11

## 规则

```text
-w /tmp/ddtest -p rw -k ddtest
```

## 当前规范化结果

```text
id=0 kind=Watch arch=None syscalls= path=/tmp/ddtest dir=- perm=rw uid=- gid=- success=- key=ddtest argv=Inherit
```

`syscalls=` 为空。规则 parser 保存了 path、permission 和 key，但编译器只遍历显式 `-S`，因此
不会为 watch 规则生成内核 syscall bitmap。运行时构造 CandidateEvent 时也没有设置 permission，
所以该规则即使收到候选事件也无法通过 permission 求交。

## 修复边界

- 将 `rwxa` 编译成版本化、双 ABI 的非空 syscall 覆盖。
- 自动加入 close/dup/chdir/mount 等缓存维护调用，但没有规则命中时不输出。
- 内核以固定 flags 传递本次操作权限，用户态完成 namespace lexical 路径和 FD 关联。
- 无法可靠分类时输出 gap、累计计数并进入 degraded，禁止空字段假匹配。
- 首版不声明 inode、hard-link 或 symlink 身份与传统 audit watch 完全等价。

## 基线命令

```bash
target/debug/auditd-ebpf check-rules --rules-dir RULES_DIR --print-normalized
cargo test -p auditd-ebpf-rules -p auditd-ebpf-common -p auditd-ebpf --tests
git diff --check
```

2026-08-11 执行结果：规则检查返回 0 但 `syscalls=` 为空；现有规则、共享 ABI 和用户态测试全部
通过。这一结果证明缺口是未实现的 watch 运行语义，不是 parser 语法错误或既有测试失败。
