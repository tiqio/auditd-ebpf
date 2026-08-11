#!/usr/bin/env bash
set -euo pipefail
reload_requested=0
trap 'reload_requested=1' HUP
kill -HUP $$
test "$reload_requested" -eq 1

cargo test -p auditd-ebpf --test reload
cargo test -p auditd-ebpf-rules --test compile_rules
cargo xtask test-kernel --kernel host
