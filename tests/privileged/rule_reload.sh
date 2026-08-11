#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "SKIP: rule_reload 需要 root"
  exit 0
fi

binary=${1:?用法: rule_reload.sh /path/to/auditd-ebpf /path/to/ebpf-object}
ebpf_object=${2:?用法: rule_reload.sh /path/to/auditd-ebpf /path/to/ebpf-object}
workdir=$(mktemp -d /tmp/auditd-ebpf-reload.XXXXXX)
chmod 0700 "${workdir}"
rules_dir=${workdir}/rules.d
state=${workdir}/lifecycle.toml
stdout_file=${workdir}/stdout.log
stderr_file=${workdir}/stderr.log
mkdir -m 0750 "${rules_dir}"
pid=

cleanup() {
  if [[ -n ${pid} ]] && kill -0 "${pid}" 2>/dev/null; then
    kill -TERM "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
  fi
  rm -rf "${workdir}"
}
trap cleanup EXIT

write_rule() {
  local key=$1
  cat >"${rules_dir}/10-reload.rules" <<EOF
-a always,exit -F arch=b64 -S execve -k ${key}
EOF
  chown root:root "${rules_dir}/10-reload.rules"
  chmod 0640 "${rules_dir}/10-reload.rules"
}

wait_for() {
  local pattern=$1
  local file=$2
  for _ in $(seq 1 200); do
    grep -q -- "${pattern}" "${file}" 2>/dev/null && return 0
    sleep 0.05
  done
  echo "未观察到 ${pattern}" >&2
  tail -n 40 "${file}" >&2 || true
  return 1
}

initial_key="reload-initial-${$}"
active_key="reload-active-${$}"
write_rule "${initial_key}"
"${binary}" run \
  --ebpf-object "${ebpf_object}" \
  --rules-dir "${rules_dir}" \
  --lifecycle-state-file "${state}" \
  >"${stdout_file}" 2>"${stderr_file}" &
pid=$!
wait_for 'state = "dirty"' "${state}"
/bin/true
wait_for "key=\"${initial_key}\"" "${stdout_file}"
initial_version=$(grep -m1 "key=\"${initial_key}\"" "${stdout_file}" | sed -n 's/.* rule_version=\([0-9][0-9]*\) .*/\1/p')
test -n "${initial_version}"

write_rule "${active_key}"
kill -HUP "${pid}"
wait_for 'code=reload_applied' "${stderr_file}"
/bin/true
wait_for "key=\"${active_key}\"" "${stdout_file}"
active_version=$(grep -m1 "key=\"${active_key}\"" "${stdout_file}" | sed -n 's/.* rule_version=\([0-9][0-9]*\) .*/\1/p')
test -n "${active_version}"
test "${initial_version}" != "${active_version}"

cat >"${rules_dir}/10-reload.rules" <<'EOF'
-a always,exit -F arch=b64 -S execve
EOF
chown root:root "${rules_dir}/10-reload.rules"
chmod 0640 "${rules_dir}/10-reload.rules"
applied_before=$(grep -c "key=\"${active_key}\"" "${stdout_file}" || true)
kill -HUP "${pid}"
wait_for 'code=reload_rejected' "${stderr_file}"
/bin/true
applied_after=${applied_before}
for _ in $(seq 1 200); do
  applied_after=$(grep -c "key=\"${active_key}\"" "${stdout_file}" || true)
  (( applied_after > applied_before )) && break
  sleep 0.05
done
(( applied_after > applied_before ))

kill -TERM "${pid}"
wait "${pid}"
pid=
grep -q 'state = "clean"' "${state}"
grep -q 'final=yes' "${stderr_file}"
echo "US1 runtime reload PASS initial_version=${initial_version} active_version=${active_version}"
