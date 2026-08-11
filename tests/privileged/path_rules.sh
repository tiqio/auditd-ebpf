#!/usr/bin/env bash
set -euo pipefail
cargo test -p auditd-ebpf --test path_resolution
cargo xtask test-kernel --kernel host
