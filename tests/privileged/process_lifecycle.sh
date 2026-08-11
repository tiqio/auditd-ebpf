#!/usr/bin/env bash
set -euo pipefail
cargo test -p auditd-ebpf --test process_cache
cargo xtask test-kernel --kernel host
