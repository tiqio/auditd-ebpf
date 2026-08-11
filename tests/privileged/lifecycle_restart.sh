#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "SKIP: lifecycle_restart 需要 root"
  exit 0
fi

binary=${1:?用法: lifecycle_restart.sh /path/to/auditd-ebpf}
workdir=$(mktemp -d /tmp/auditd-ebpf-lifecycle.XXXXXX)
chmod 0700 "${workdir}"
state=${workdir}/lifecycle.toml
first_out=${workdir}/first.out
first_err=${workdir}/first.err
second_out=${workdir}/second.out
second_err=${workdir}/second.err
trap 'rm -rf "${workdir}"' EXIT

"${binary}" run --lifecycle-state-file "${state}" >"${first_out}" 2>"${first_err}" &
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
"${binary}" run --lifecycle-state-file "${state}" >"${second_out}" 2>"${second_err}" &
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

