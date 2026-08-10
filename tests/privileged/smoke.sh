#!/usr/bin/env bash
set -euo pipefail
test "$(uname -m)" = x86_64
test -r /sys/kernel/btf/vmlinux
cargo xtask test-kernel --kernel host
