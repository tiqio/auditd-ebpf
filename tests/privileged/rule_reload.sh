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
watch_file=${workdir}/ddtest
mkdir -m 0750 "${rules_dir}"
printf 'initial\n' >"${watch_file}"
pid=

cleanup() {
  local status=$?
  if [[ -n ${pid} ]] && kill -0 "${pid}" 2>/dev/null; then
    kill -TERM "${pid}" 2>/dev/null || true
    for _ in $(seq 1 100); do
      kill -0 "${pid}" 2>/dev/null || break
      sleep 0.05
    done
    kill -KILL "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
  fi
  if (( status != 0 )); then
    echo "rule_reload 失败现场保留在 ${workdir}" >&2
    tail -n 80 "${stdout_file}" >&2 || true
    tail -n 80 "${stderr_file}" >&2 || true
    return
  fi
  rm -rf "${workdir}"
}
trap cleanup EXIT

write_rule() {
  local key=$1
  local permissions=$2
  cat >"${rules_dir}/10-reload.rules" <<RULES
-w ${watch_file} -p ${permissions} -k ${key}
RULES
  chown root:root "${rules_dir}/10-reload.rules"
  chmod 0640 "${rules_dir}/10-reload.rules"
}

wait_for() {
  local pattern=$1
  local file=$2
  for _ in $(seq 1 200); do
    grep -qE -- "${pattern}" "${file}" 2>/dev/null && return 0
    sleep 0.05
  done
  echo "未观察到 ${pattern}" >&2
  tail -n 40 "${file}" >&2 || true
  return 1
}

initial_key="reload-initial-${$}"
active_key="reload-active-${$}"
write_rule "${initial_key}" r
"${binary}" run \
  --ebpf-object "${ebpf_object}" \
  --rules-dir "${rules_dir}" \
  --lifecycle-state-file "${state}" \
  >"${stdout_file}" 2>"${stderr_file}" &
pid=$!
wait_for 'state = "dirty"' "${state}"
wait_for 'programs_attached=5' "${stderr_file}"
cat "${watch_file}" >/dev/null

# 有效候选同时改变 key 与 permission；只有 bitmap、permission table、rule version 和
# 用户态 RuleEngine 全部 staging 成功后才允许 generation 切换。
write_rule "${active_key}" w
kill -HUP "${pid}"
wait_for 'code=reload_applied.*generation=1' "${stderr_file}"
printf 'active\n' >"${watch_file}"

# 无效 watch 候选不得切换 active generation；随后写操作必须继续使用旧 key/version。
cat >"${rules_dir}/10-reload.rules" <<RULES
-w ${watch_file} -k rejected
RULES
chown root:root "${rules_dir}/10-reload.rules"
chmod 0640 "${rules_dir}/10-reload.rules"
kill -HUP "${pid}"
wait_for 'code=reload_rejected.*E_PERMISSION' "${stderr_file}"
printf 'still-active\n' >"${watch_file}"

kill -TERM "${pid}"
wait "${pid}"
pid=

wait_for "key=\"${initial_key}\".*perm=r" "${stdout_file}"
initial_version=$(grep -m1 "key=\"${initial_key}\"" "${stdout_file}" | sed -n 's/.* rule_version=\([0-9][0-9]*\) .*/\1/p')
test -n "${initial_version}"
wait_for "key=\"${active_key}\".*perm=w" "${stdout_file}"
active_version=$(grep -m1 "key=\"${active_key}\"" "${stdout_file}" | sed -n 's/.* rule_version=\([0-9][0-9]*\) .*/\1/p')
test -n "${active_version}"
test "${initial_version}" != "${active_version}"
test "$(grep -c "rule_version=${active_version}.*key=\"${active_key}\".*perm=w" "${stdout_file}")" -ge 2
! grep -q 'key="rejected"' "${stdout_file}"
grep -q 'state = "clean"' "${state}"
grep -q 'final=yes' "${stderr_file}"
final_status=$(grep 'type=AUDITD_EBPF_STATUS.*final=yes' "${stderr_file}" | tail -n 1)
status_value() {
  local name=$1
  sed -n "s/.* ${name}=\([0-9][0-9]*\) .*/\1/p" <<<"${final_status}"
}
reload_success=$(status_value reload_success)
reload_failed=$(status_value reload_failed)
test "${reload_success}" -eq 1
test "${reload_failed}" -eq 1
echo "US2 watch reload PASS initial_version=${initial_version} active_version=${active_version}"
