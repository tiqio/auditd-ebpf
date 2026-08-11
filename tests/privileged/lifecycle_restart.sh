#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "SKIP: lifecycle_restart 需要 root"
  exit 0
fi

binary=${1:?用法: lifecycle_restart.sh /path/to/auditd-ebpf}
ebpf_object=${2:-}
workdir=$(mktemp -d /tmp/auditd-ebpf-lifecycle.XXXXXX)
chmod 0700 "${workdir}"
state=${workdir}/lifecycle.toml
rules_dir=${workdir}/rules.d
first_out=${workdir}/first.out
first_err=${workdir}/first.err
second_out=${workdir}/second.out
second_err=${workdir}/second.err
trap 'rm -rf "${workdir}"' EXIT
mkdir -m 0750 "${rules_dir}"
cat >"${rules_dir}/10-lifecycle.rules" <<'EOF'
-a always,exit -F arch=b64 -S execve -k lifecycle-test
EOF
chown root:root "${rules_dir}/10-lifecycle.rules"
chmod 0640 "${rules_dir}/10-lifecycle.rules"
run_args=(run)
if [[ -n ${ebpf_object} ]]; then
  run_args+=(--ebpf-object "${ebpf_object}")
fi
run_args+=(--rules-dir "${rules_dir}")
run_args+=(--lifecycle-state-file "${state}")

"${binary}" "${run_args[@]}" >"${first_out}" 2>"${first_err}" &
first_pid=$!
for _ in $(seq 1 100); do
  [[ -f ${state} ]] && grep -q 'state = "dirty"' "${state}" && break
  sleep 0.05
done
grep -q 'state = "dirty"' "${state}"
kill -KILL "${first_pid}"
wait "${first_pid}" 2>/dev/null || true
grep -q 'state = "dirty"' "${state}"

start=$(date +%s)
"${binary}" "${run_args[@]}" >"${second_out}" 2>"${second_err}" &
second_pid=$!
for _ in $(seq 1 200); do
  grep -q 'reason=unclean_shutdown count=?' "${second_out}" && break
  sleep 0.05
done
grep -q 'reason=unclean_shutdown count=?' "${second_out}"
(( $(date +%s) - start <= 10 ))
kill -TERM "${second_pid}"
wait "${second_pid}"
grep -q 'state = "clean"' "${state}"
grep -q 'final=yes' "${second_err}"
