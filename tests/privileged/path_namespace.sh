#!/usr/bin/env bash
set -euo pipefail

command -v unshare >/dev/null
command -v mount >/dev/null
command -v pivot_root >/dev/null

parent_ns=$(stat -Lc '%d:%i' /proc/self/ns/mnt)
work=$(mktemp -d /tmp/auditd-ebpf-ns.XXXXXX)
trap 'rm -rf "$work"' EXIT
export AUDITD_EBPF_PARENT_NS="$parent_ns"
export AUDITD_EBPF_NS_WORK="$work"

unshare --mount --fork bash -euo pipefail <<'INNER'
child_ns=$(stat -Lc '%d:%i' /proc/self/ns/mnt)
test "$child_ns" != "$AUDITD_EBPF_PARENT_NS"
mount --make-rprivate /
mkdir -p "$AUDITD_EBPF_NS_WORK/source" "$AUDITD_EBPF_NS_WORK/target"
printf namespace >"$AUDITD_EBPF_NS_WORK/source/file"
mount --bind "$AUDITD_EBPF_NS_WORK/source" "$AUDITD_EBPF_NS_WORK/target"
test "$(cat "$AUDITD_EBPF_NS_WORK/target/file")" = namespace
mount -o remount,bind,ro "$AUDITD_EBPF_NS_WORK/target"
if printf fail >"$AUDITD_EBPF_NS_WORK/target/blocked" 2>/dev/null; then
  echo "只读 remount 未生效" >&2
  exit 1
fi
umount "$AUDITD_EBPF_NS_WORK/target"

mkdir -p "$AUDITD_EBPF_NS_WORK/newroot/oldroot" \
  "$AUDITD_EBPF_NS_WORK/newroot/bin" \
  "$AUDITD_EBPF_NS_WORK/newroot/lib" \
  "$AUDITD_EBPF_NS_WORK/newroot/lib64"
mount --rbind /bin "$AUDITD_EBPF_NS_WORK/newroot/bin"
mount --rbind /lib "$AUDITD_EBPF_NS_WORK/newroot/lib"
mount --rbind /lib64 "$AUDITD_EBPF_NS_WORK/newroot/lib64"
chroot "$AUDITD_EBPF_NS_WORK/newroot" /bin/true
nsenter --mount=/proc/1/ns/mnt /bin/true
mount --bind "$AUDITD_EBPF_NS_WORK/newroot" "$AUDITD_EBPF_NS_WORK/newroot"
cd "$AUDITD_EBPF_NS_WORK/newroot"
pivot_root . oldroot
cd /
INNER

cargo test -p auditd-ebpf --test path_resolution --test process_cache
