#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "SKIP: watch_rules 需要 root"
  exit 0
fi

binary=${1:?用法: watch_rules.sh /path/to/auditd-ebpf /path/to/ebpf-object}
ebpf_object=${2:?用法: watch_rules.sh /path/to/auditd-ebpf /path/to/ebpf-object}
workdir=$(mktemp -d /tmp/auditd-ebpf-watch.XXXXXX)
chmod 0700 "${workdir}"
rules_dir=${workdir}/rules.d
state=${workdir}/lifecycle.toml
stdout_file=${workdir}/stdout.log
stderr_file=${workdir}/stderr.log
watch_file=${workdir}/ddtest
pid=

cleanup() {
  if [[ -n ${pid} ]] && kill -0 "${pid}" 2>/dev/null; then
    kill -TERM "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
  fi
  rm -rf "${workdir}"
}
trap cleanup EXIT

mkdir -m 0750 "${rules_dir}"
cat >"${rules_dir}/10-watch.rules" <<EOF
-w ${watch_file} -p rw -k ddtest
EOF
chown root:root "${rules_dir}/10-watch.rules"
chmod 0640 "${rules_dir}/10-watch.rules"

"${binary}" run \
  --ebpf-object "${ebpf_object}" \
  --rules-dir "${rules_dir}" \
  --lifecycle-state-file "${state}" \
  >"${stdout_file}" 2>"${stderr_file}" &
pid=$!

for _ in $(seq 1 200); do
  [[ -f ${state} ]] && grep -q 'state = "dirty"' "${state}" && break
  sleep 0.05
done
grep -q 'state = "dirty"' "${state}"

printf 'write' >"${watch_file}"
cat "${watch_file}" >/dev/null
python3 - "${watch_file}" <<'PY'
import os
import sys

fd = os.open(sys.argv[1], os.O_RDWR)
os.close(fd)
PY

# T023 先固定真实内核场景；T039–T042 完成用户态权限消费后，本脚本必须在十秒内
# 分别观察到 r/w/rw。当前内核 flags smoke 由 `cargo xtask test-kernel --kernel host`
# 独立验证，避免把尚未实现的用户态匹配误标为内核采集失败。
for _ in $(seq 1 200); do
  grep -q 'key="ddtest".*perm="r"' "${stdout_file}" 2>/dev/null \
    && grep -q 'key="ddtest".*perm="w"' "${stdout_file}" 2>/dev/null \
    && grep -q 'key="ddtest".*perm="rw"' "${stdout_file}" 2>/dev/null \
    && break
  sleep 0.05
done

grep -q 'key="ddtest".*perm="r"' "${stdout_file}"
grep -q 'key="ddtest".*perm="w"' "${stdout_file}"
grep -q 'key="ddtest".*perm="rw"' "${stdout_file}"

kill -TERM "${pid}"
wait "${pid}"
pid=
