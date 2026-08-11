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
other_file=${workdir}/ddtest-other
moved_file=${workdir}/ddtest-moved
pid=

wait_for() {
  local pattern=$1
  for _ in $(seq 1 200); do
    grep -qE "${pattern}" "${stdout_file}" 2>/dev/null && return 0
    sleep 0.05
  done
  return 1
}

reload_rules() {
  local permissions=$1
  cat >"${rules_dir}/10-watch.rules" <<EOF
-w ${watch_file} -p ${permissions} -k ddtest
EOF
  chown root:root "${rules_dir}/10-watch.rules"
  chmod 0640 "${rules_dir}/10-watch.rules"
  local before
  before=$(grep -c 'code=reload_applied' "${stderr_file}" 2>/dev/null || true)
  kill -HUP "${pid}"
  for _ in $(seq 1 200); do
    local after
    after=$(grep -c 'code=reload_applied' "${stderr_file}" 2>/dev/null || true)
    (( after > before )) && return 0
    sleep 0.05
  done
  return 1
}

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
    echo "watch_rules 失败现场保留在 ${workdir}" >&2
    grep 'key="ddtest"' "${stdout_file}" >&2 || true
    tail -n 80 "${stderr_file}" >&2 || true
    return
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
for _ in $(seq 1 200); do
  grep -q 'programs_attached=5' "${stderr_file}" 2>/dev/null && break
  sleep 0.05
done
grep -q 'programs_attached=5' "${stderr_file}"

printf 'write' >"${watch_file}"
printf 'other' >"${other_file}"
cat "${watch_file}" >/dev/null
cat "${other_file}" >/dev/null
python3 - "${watch_file}" <<'PY'
import os
import sys

fd = os.open(sys.argv[1], os.O_RDWR)
os.close(fd)
PY

# 失败访问仍应保留目标路径、写权限、失败结果和负 errno。工作目录 0700 可确保
# nobody 无法穿越父目录，避免依赖 root 对文件 mode 的绕过行为。
if command -v setpriv >/dev/null && id nobody >/dev/null 2>&1; then
  setpriv --reuid="$(id -u nobody)" --regid="$(id -g nobody)" --clear-groups \
    sh -c "printf denied > '${watch_file}'" 2>/dev/null || true
else
  echo "SKIP: 缺少 setpriv 或 nobody，跳过失败访问场景" >&2
fi

reload_rules rwxa
chmod 0755 "${watch_file}"

cat >"${watch_file}" <<'SCRIPT'
#!/bin/sh
exit 0
SCRIPT
chmod 0755 "${watch_file}"
"${watch_file}"

# rename 的源/目标路径独立采集；两次移动分别覆盖 primary 与 secondary 命中。
mv "${watch_file}" "${moved_file}"
mv "${moved_file}" "${watch_file}"

fd_ready=${workdir}/fd-ready
python3 - "${watch_file}" "${other_file}" "${fd_ready}" <<'PY' &
import os
import sys
import time

target, other, ready = sys.argv[1:]
fd = os.open(target, os.O_RDWR)
duplicate = os.dup(fd)
os.ftruncate(duplicate, 0)
open(ready, "w").close()
time.sleep(10)
os.close(fd)
os.close(duplicate)
PY
fd_workload_pid=$!
for _ in $(seq 1 200); do
  [[ -f ${fd_ready} ]] && break
  sleep 0.05
done
[[ -f ${fd_ready} ]]

# 独立进程关闭目标 fd 后立即复用到无关文件，禁止沿用旧关联。
python3 - "${watch_file}" "${other_file}" <<'PY'
import os
import sys

target, other = sys.argv[1:]
fd = os.open(target, os.O_RDWR)
os.close(fd)
other_fd = os.open(other, os.O_RDWR)
os.ftruncate(other_fd, 0)
os.close(other_fd)
PY

if [[ $(getconf LONG_BIT) == 64 ]]; then
  echo "SKIP: 当前主机未提供可执行 b32 测试二进制" >&2
fi

kill -TERM "${pid}"
wait "${pid}"
pid=
wait "${fd_workload_pid}"

for pattern in \
  'key="ddtest".*perm=r' \
  'key="ddtest".*perm=w' \
  'key="ddtest".*perm=rw' \
  'key="ddtest".*success=no.*path="'"${watch_file}"'".*perm=w' \
  'key="ddtest".*syscall=(chmod|fchmodat).*path="'"${watch_file}"'".*perm=a' \
  'key="ddtest".*syscall=execve.*operation=execve.*path="'"${watch_file}"'".*perm=x' \
  'key="ddtest".*syscall=rename(at|at2)?.*path="'"${watch_file}"'"'
do
  if ! grep -qE "${pattern}" "${stdout_file}"; then
    echo "缺少 watch 场景: ${pattern}" >&2
    exit 1
  fi
done
if grep -q 'key="ddtest".*path="'"${other_file}"'"' "${stdout_file}"; then
  echo "无关路径或 fd 复用产生误报" >&2
  exit 1
fi
