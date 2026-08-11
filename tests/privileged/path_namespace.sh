#!/usr/bin/env bash
set -euo pipefail
command -v unshare >/dev/null
cargo test -p auditd-ebpf --test process_cache

