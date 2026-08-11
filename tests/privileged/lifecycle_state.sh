#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "SKIP: lifecycle_state 需要 root"
  exit 0
fi

cargo test -p auditd-ebpf --test lifecycle_state_file

