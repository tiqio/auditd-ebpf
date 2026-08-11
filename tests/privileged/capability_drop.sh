#!/usr/bin/env bash
set -euo pipefail

# 测试在独立子进程中永久清空 capability 集合，避免污染 cargo test 主进程。
cargo test -p auditd-ebpf --test capability_drop -- --exact 初始化后清空运行期capabilities并设置no_new_privs
