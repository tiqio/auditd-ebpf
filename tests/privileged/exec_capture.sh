#!/usr/bin/env bash
set -euo pipefail
cargo test -p auditd-ebpf --test event_decode

