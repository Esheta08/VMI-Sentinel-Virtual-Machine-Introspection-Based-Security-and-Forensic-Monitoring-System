#!/usr/bin/env bash
# Start the monitored guest VM with the KVMI-enabled QEMU. Its console runs in
# this terminal: log in as ubuntu. Shut it down from inside with: sudo poweroff
set -euo pipefail
cd "$HOME/vmi-guest"
exec sudo "$HOME/kvm-vmi/qemu/x86_64-softmmu/qemu-system-x86_64" \
  -enable-kvm -cpu host -m 2048 -smp 2 \
  -drive file=guest.qcow2,if=virtio -drive file=seed.img,if=virtio,format=raw \
  -nographic \
  -chardev socket,path=/tmp/kvmi.sock,id=chardev0,reconnect=10 \
  -object introspection,id=kvmi,chardev=chardev0
