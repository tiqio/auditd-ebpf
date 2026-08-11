#!/usr/bin/env bash
set -euo pipefail
cargo test -p auditd-ebpf --test collector_runtime
cargo xtask test-kernel --kernel host
