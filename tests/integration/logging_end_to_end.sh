#!/usr/bin/env bash
set -euo pipefail

binary=${1:?用法: logging_end_to_end.sh /path/to/auditd-ebpf /path/to/ebpf-object}
ebpf_object=${2:?用法: logging_end_to_end.sh /path/to/auditd-ebpf /path/to/ebpf-object}

# 无特权契约：稳定身份、格式、argv 泄露负例、stdout/stderr 分流和自适应背压。
cargo test -p auditd-ebpf \
  --test host_identity \
  --test event_format_golden \
  --test event_escape \
  --test argv_suppression \
  --test output_streams \
  --test adaptive_queue \
  --test health_contract

first_digest=$("${binary}" print-policy-digest --value-only)
second_digest=$("${binary}" print-policy-digest --value-only)
[[ ${first_digest} == "${second_digest}" ]]
[[ ${first_digest} =~ ^sha256:[0-9a-f]{64}$ ]]

if [[ ${EUID} -ne 0 ]]; then
  echo "SKIP: journal、rsyslog、production 和生命周期 quickstart 需要 root"
  exit 0
fi

tests/privileged/production_policy.sh "${binary}"
tests/privileged/systemd_journal.sh
tests/privileged/rsyslog_pipeline.sh

# journalctl 在十秒内取回完成 argv 策略后的整行；suppressed 行不得出现参数字段。
if command -v systemd-cat >/dev/null && command -v journalctl >/dev/null; then
  event_id="quickstart-$(date +%s)-$$"
  journal_line="type=AUDITD_EBPF event_id=${event_id} argv_output=suppressed argc=2"
  started=$(date +%s)
  printf '%s\n' "${journal_line}" | systemd-cat -t auditd-ebpf --level-prefix=false
  journalctl --sync
  found=""
  for _ in $(seq 1 200); do
    found=$(journalctl -t auditd-ebpf --since "@${started}" -o cat --no-pager 2>/dev/null \
      | grep -Fx "${journal_line}" | tail -1 || true)
    [[ -n ${found} ]] && break
    sleep 0.05
  done
  [[ ${found} == "${journal_line}" ]]
  [[ ${found} != *' a0='* ]]
  (( $(date +%s) - started <= 10 ))
else
  echo "SKIP: 当前环境没有 systemd-cat/journalctl"
fi

# 真实 eBPF attach 下验证 SIGKILL dirty、十秒内 unknown-count gap 和 SIGTERM clean。
tests/privileged/lifecycle_restart.sh "${binary}" "${ebpf_object}"

echo "US2 logging quickstart PASS"

