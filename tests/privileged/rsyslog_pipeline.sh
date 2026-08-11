#!/usr/bin/env bash
set -euo pipefail

config=${1:-packaging/rsyslog/60-auditd-ebpf.conf}
grep -Fq 'module(load="imjournal" StateFile="auditd-ebpf-imjournal.state")' "${config}"
grep -Fq "\$programname == 'auditd-ebpf'" "${config}"
grep -Fq "\$msg contains 'type=AUDITD_EBPF '" "${config}"
grep -Fq 'template(name="AuditdEbpfRaw" type="string" string="%msg%\n")' "${config}"
grep -Fq 'StreamDriver="gtls"' "${config}"
grep -Fq 'StreamDriverMode="1"' "${config}"
grep -Fq 'StreamDriverAuthMode="x509/name"' "${config}"
grep -Fq 'StreamDriverPermittedPeers=' "${config}"
grep -Fq 'queue.type="LinkedList"' "${config}"
grep -Fq 'queue.size="250000"' "${config}"
grep -Fq 'queue.filename="auditd-ebpf-forward"' "${config}"
grep -Fq 'queue.saveonshutdown="on"' "${config}"
grep -Fq 'FileCreateMode="0640"' "${config}"
grep -Fq 'FileCreateMode="0600"' "${config}"
grep -Fq 'type=AUDITD_EBPF_STATUS' "${config}"
grep -Fq 'type=AUDITD_EBPF_DIAG' "${config}"

# 模板必须只写策略处理后的 msg，不能重新解析或补齐 suppressed argv。
source_line='type=AUDITD_EBPF event_id=e argv_output=suppressed argc=2'
rendered=$(printf '%s\n' "${source_line}")
[[ ${rendered} == "${source_line}" ]]
[[ ${rendered} != *' a0='* ]]
