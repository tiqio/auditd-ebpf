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

if [[ ${EUID} -ne 0 ]] || ! command -v rsyslogd >/dev/null || ! command -v logger >/dev/null; then
  echo "SKIP: 动态 rsyslog 队列测试需要 root、rsyslogd 和 logger"
  exit 0
fi

identifier="auditd-ebpf-$RANDOM-$$"
source_port=$((20000 + RANDOM % 10000))
dest_port=$((30000 + RANDOM % 10000))
spool="/var/spool/rsyslog/${identifier}"
output="/var/log/${identifier}.log"
sender_conf="/etc/rsyslog.d/${identifier}-sender.conf"
receiver_conf="/etc/rsyslog.d/${identifier}-receiver.conf"
sender_log="/var/log/${identifier}-sender.stderr"
receiver_log="/var/log/${identifier}-receiver.stderr"
sender_process=""
receiver_process=""

cleanup() {
  [[ -z ${sender_process} ]] || kill "${sender_process}" 2>/dev/null || true
  [[ -z ${receiver_process} ]] || kill "${receiver_process}" 2>/dev/null || true
  [[ -z ${sender_process} ]] || wait "${sender_process}" 2>/dev/null || true
  [[ -z ${receiver_process} ]] || wait "${receiver_process}" 2>/dev/null || true
  rm -rf "${spool}" "${output}" "${sender_conf}" "${receiver_conf}" \
    "${sender_log}" "${receiver_log}"
}
finish() {
  status=$?
  if [[ ${status} -ne 0 ]]; then
    echo "--- sender stderr ---" >&2
    cat "${sender_log}" 2>/dev/null >&2 || true
    echo "--- receiver stderr ---" >&2
    cat "${receiver_log}" 2>/dev/null >&2 || true
  fi
  cleanup
  exit "${status}"
}
trap finish EXIT

install -d -m 0700 -o root -g root "${spool}"
sed -e "s|@SPOOL@|${spool}|g" \
    -e "s|@SOURCE_PORT@|${source_port}|g" \
    -e "s|@DEST_PORT@|${dest_port}|g" \
    tests/fixtures/rsyslog/sender.conf.in >"${sender_conf}"
sed -e "s|@OUTPUT@|${output}|g" \
    -e "s|@DEST_PORT@|${dest_port}|g" \
    tests/fixtures/rsyslog/receiver.conf.in >"${receiver_conf}"
chmod 0644 "${sender_conf}" "${receiver_conf}"
rsyslogd -N1 -f "${sender_conf}" >/dev/null
rsyslogd -N1 -f "${receiver_conf}" >/dev/null

rsyslogd -n -iNONE -f "${sender_conf}" 2>"${sender_log}" &
sender_process=$!
for _ in $(seq 1 100); do
  logger --tcp --server 127.0.0.1 --port "${source_port}" --tag auditd-ebpf \
    'type=AUDITD_EBPF event_id=queued argv_output=suppressed argc=2' 2>/dev/null && break
  sleep 0.05
done
# 下游尚未启动时 logger 必须快速返回。优雅停止 sender 后，saveonshutdown 必须把内存队列
# 持久化；这同时模拟宿主机维护重启期间的断网积压。
sleep 0.2
kill -TERM "${sender_process}"
wait "${sender_process}"
sender_process=""
for _ in $(seq 1 100); do
  find "${spool}" -type f -size +0c | grep -q . && break
  sleep 0.05
done
find "${spool}" -type f -size +0c | grep -q .

rsyslogd -n -iNONE -f "${receiver_conf}" 2>"${receiver_log}" &
receiver_process=$!
rsyslogd -n -iNONE -f "${sender_conf}" 2>>"${sender_log}" &
sender_process=$!
for _ in $(seq 1 200); do
  grep -q 'event_id=queued argv_output=suppressed argc=2' "${output}" 2>/dev/null && break
  sleep 0.05
done
grep -q 'event_id=queued argv_output=suppressed argc=2' "${output}"
! grep -q ' a0=' "${output}"
[[ $(stat -c '%a' "${output}") == 600 ]]

# 生成临时 CA 和服务端证书，证明配置中的 x509/name 身份可通过预期 DNS，错误 DNS 必须失败。
certdir="${spool}/certs"
mkdir -m 0700 "${certdir}"
openssl req -x509 -newkey rsa:2048 -nodes -subj '/CN=audit-test-ca' \
  -keyout "${certdir}/ca.key" -out "${certdir}/ca.crt" -days 1 >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj '/CN=audit-logs.example.invalid' \
  -addext 'subjectAltName=DNS:audit-logs.example.invalid' \
  -keyout "${certdir}/server.key" -out "${certdir}/server.csr" >/dev/null 2>&1
openssl x509 -req -in "${certdir}/server.csr" -CA "${certdir}/ca.crt" \
  -CAkey "${certdir}/ca.key" -CAcreateserial -days 1 -copy_extensions copy \
  -out "${certdir}/server.crt" >/dev/null 2>&1
openssl verify -CAfile "${certdir}/ca.crt" -verify_hostname audit-logs.example.invalid \
  "${certdir}/server.crt" >/dev/null
! openssl verify -CAfile "${certdir}/ca.crt" -verify_hostname attacker.example.invalid \
  "${certdir}/server.crt" >/dev/null 2>&1
