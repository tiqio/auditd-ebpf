#!/usr/bin/env bash
set -euo pipefail

unit=${1:-packaging/systemd/auditd-ebpf.service}
grep -Fxq 'StandardOutput=journal' "${unit}"
grep -Fxq 'StandardError=journal' "${unit}"
grep -Fxq 'NoNewPrivileges=yes' "${unit}"
grep -Fxq 'ProtectSystem=strict' "${unit}"
grep -Fxq 'ProtectHome=yes' "${unit}"
grep -Fxq 'CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN' "${unit}"
grep -Fxq 'AmbientCapabilities=CAP_BPF CAP_PERFMON' "${unit}"
grep -Fxq 'ReadWritePaths=/var/lib/auditd-ebpf' "${unit}"
grep -Fxq 'SupplementaryGroups=auditd-ebpf-auditors' "${unit}"
grep -Fxq 'ExecReload=/bin/kill -HUP $MAINPID' "${unit}"
! grep -Eq '^ReadWritePaths=.*(/etc|/usr|/var/log)' "${unit}"

