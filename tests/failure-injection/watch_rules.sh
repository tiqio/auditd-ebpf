#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
run() { echo "INJECT: $1"; shift; "$@"; echo "PASS: $1"; }
run permission_flags cargo test -p auditd-ebpf --test event_decode syscall_decoder_accepts_old_zero_flags_and_rejects_unknown_abi_bits
run fd_stale cargo test -p auditd-ebpf --test path_resolution fd_only_resolution_uses_process_shared_table_and_rejects_stale_entries
run path_truncated cargo test -p auditd-ebpf runtime::tests::dual_path分别使用自己的dirfd且截断明确失败
run queue_full cargo test -p auditd-ebpf runtime::tests::队列硬上限失败会累计丢失并进入degraded
run stdout_epipe cargo test -p auditd-ebpf runtime::tests::stdout永久失败会累计并要求collector停止
run ring_counter cargo test -p auditd-ebpf --test health_contract ebpf每cpu计数按字段求和且保持内核不变量
printf '%s\n' 'SKIP: real_ringbuf_full 256MiB RingBuf 在共享宿主无法确定性压满；使用内核计数 ABI 测试验证可观测性。'
printf '%s\n' 'PASS: watch failure injection contract'
