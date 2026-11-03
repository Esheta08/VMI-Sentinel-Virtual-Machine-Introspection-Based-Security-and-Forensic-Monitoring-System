#!/usr/bin/env bash
# Start the monitored guest VM (KVMI-enabled QEMU). The VM console runs in THIS
# terminal: log in as "ubuntu". Keep the terminal open - closing it stops the VM.
set -u
if pgrep -f '[q]emu-system-x86_64.*guest.qcow2' > /dev/null; then
  echo "The VM is already running."; exit 0
fi
cd ~/vmi-guest || { echo "~/vmi-guest not found"; exit 1; }
echo "Starting the VM (sudo password may be asked) ..."
exec sudo ~/kvm-vmi/qemu/x86_64-softmmu/qemu-system-x86_64 -enable-kvm -cpu host \
  -m 2048 -smp 2 \
  -drive file=guest.qcow2,if=virtio -drive file=seed.img,if=virtio,format=raw \
  -nographic \
  -chardev socket,path=/tmp/kvmi.sock,id=chardev0,reconnect=1 \
  -object introspection,id=kvmi,chardev=chardev0
