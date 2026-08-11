#!/usr/bin/env bash
set -euo pipefail
cargo test -p auditd-ebpf-rules --test compile_rules

