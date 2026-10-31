#!/bin/bash
# CI: boot a disk image of the appliance in QEMU (KVM, UEFI) and run the checks over SSH, including a roll back.
# Usage: boot-test.sh <disk.raw> <ssh private key>
set -euo pipefail
RAW=$1 KEY=$2
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${OUT:-/tmp/appliance-test}
mkdir -p "$OUT"
qemu-img convert -O qcow2 "$RAW" "$OUT/disk.qcow2"
qemu-img resize "$OUT/disk.qcow2" 96G
cp /usr/share/OVMF/OVMF_VARS_4M.fd "$OUT/vars.fd"
# size the VM to the runner: all CPUs, and the free memory less 1 GiB for the host (SQL Server needs 2 GiB)
CPUS=$(nproc)
MEM=$(awk '/MemAvailable/ {m = int($2 / 1024) - 1024; print (m > 11264 ? 11264 : m)}' /proc/meminfo)
[ "$MEM" -ge 4096 ] || { echo "only ${MEM} MiB free for the VM" >&2; exit 1; }
echo "VM: $CPUS CPUs, $MEM MiB"
start_vm() {
  qemu-system-x86_64 -enable-kvm -cpu host -smp "$CPUS" -m "$MEM" -machine q35 \
    -drive if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
    -drive if=pflash,format=raw,unit=1,file="$OUT/vars.fd" \
    -drive file="$OUT/disk.qcow2",if=virtio,format=qcow2 \
    -netdev user,id=n0,hostfwd=tcp:127.0.0.1:2222-:22,hostfwd=tcp:127.0.0.1:8443-:443 \
    -device virtio-net-pci,netdev=n0 -serial "file:$OUT/serial-$1.log" -display none \
    -daemonize -pidfile "$OUT/qemu.pid"
}
SSH=(ssh -i "$KEY" -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10
     -o ServerAliveInterval=15 -o LogLevel=ERROR root@127.0.0.1)
wait_ssh() {  # seconds
  local end=$((SECONDS + $1))
  until "${SSH[@]}" true 2>/dev/null; do
    [ $SECONDS -lt $end ] || { echo "no SSH after $1 s" >&2; tail -100 "$OUT"/serial-*.log >&2; return 1; }
    sleep 10
  done
}
wait_active() {  # seconds: SSH answers in the active system (not the recovery system that deploys it)
  local end=$((SECONDS + $1))
  until "${SSH[@]}" test -f /run/elemental/active_mode 2>/dev/null; do
    [ $SECONDS -lt $end ] || { echo "not in the active system after $1 s" >&2; tail -100 "$OUT"/serial-*.log >&2; return 1; }
    sleep 10
  done
}
wait_reboot() {  # the VM restarts on its own: wait for SSH to go away, then to come back
  local end=$((SECONDS + 300))
  while "${SSH[@]}" true 2>/dev/null; do [ $SECONDS -lt $end ] || break; sleep 5; done
  wait_ssh 1200
}
diag() {
  echo "--- diagnostics"
  "${SSH[@]}" 'systemctl --failed --no-pager; journalctl -b --no-pager -p warning | tail -200;
    for u in elemental-setup-initramfs elemental-setup-rootfs elemental-setup-network elemental-setup-boot \
      containerizer-firstboot containerizer-firewall containerizer-dns containerizer-mssql containerizer-db-init \
      containerizer-web containerizer-worker containerizer-registry caddy k3s containerizer-sysagent; do
      echo "--- $u"; journalctl -b -u $u --no-pager | tail -40; done' > "$OUT/diagnostics.txt" 2>&1 || true
  tail -c 20000 "$OUT/diagnostics.txt" || true
}
trap 'diag; kill "$(cat "$OUT/qemu.pid" 2>/dev/null)" 2>/dev/null || true' EXIT

start_vm 1
# an expandable image boots the recovery system first, which deploys the active system to the whole disk
# (elemental reset) and restarts; SSH already answers in the recovery system, so wait for the active one
wait_active 1800
"${SSH[@]}" 'bash -s' < "$HERE/vm-checks.sh"

echo "=== from outside: only HTTPS and SSH are forwarded; HTTPS answers"
curl -fsSk https://127.0.0.1:8443/healthz

echo "=== roll back"
"${SSH[@]}" 'bash -s prepare' < "$HERE/rollback-checks.sh"
"${SSH[@]}" 'systemctl reboot' || true
wait_reboot
"${SSH[@]}" 'bash -s rollback' < "$HERE/rollback-checks.sh"
wait_reboot
"${SSH[@]}" 'for i in $(seq 60); do test -s /run/containerizer/system/status.json && break; sleep 5; done; bash -s verify' \
  < "$HERE/rollback-checks.sh"
trap - EXIT
diag >/dev/null
kill "$(cat "$OUT/qemu.pid")" || true
echo "BOOT TEST PASSED"
