#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "SKIP: production_policy 需要 root"
  exit 0
fi

binary=${1:?用法: production_policy.sh /path/to/auditd-ebpf}
workdir=$(mktemp -d /tmp/auditd-ebpf-policy.XXXXXX)
chmod 0700 "${workdir}"
record=${workdir}/risk.toml
trap 'rm -rf "${workdir}"' EXIT

digest=$("${binary}" print-policy-digest --value-only)
cat >"${record}" <<EOF
record_version = 1
approval_id = "SEC-TEST"
approver = "security@example.invalid"
owner = "platform@example.invalid"
approved_at = "2026-08-10T09:00:00+08:00"
purpose = "test production policy"
approved_readers = ["root", "auditd-ebpf-auditors"]
incident_response = "IR-TEST"
policy_digest_version = 1
policy_digest = "${digest}"
[[destinations]]
id = "service-journal"
kind = "journal"
target = "auditd-ebpf.service"
retention_days = 90
transport_mode = "local-only"
peer_identity = ""
trust_fingerprint = ""
owner = "root"
group = "auditd-ebpf-auditors"
mode = "0640"
EOF
chmod 0600 "${record}"
"${binary}" check-production --risk-acceptance-file "${record}" | grep -q 'production_policy=passed'
sed -i 's/^policy_digest = .*/policy_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"/' "${record}"
set +e
"${binary}" check-production --risk-acceptance-file "${record}" >/dev/null 2>"${workdir}/error"
status=$?
set -e
[[ ${status} -eq 9 ]]
grep -q 'code=policy_digest_mismatch' "${workdir}/error"

