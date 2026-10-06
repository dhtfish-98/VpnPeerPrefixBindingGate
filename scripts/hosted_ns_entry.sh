#!/bin/sh
# Copyright (c) 2026 dhtfish98. MIT License.
# Entered only after sudo unshare --mount --net --pid --fork --mount-proc.
set -eu
umask 077

test "$(id -u)" -eq 0
test "$(readlink /proc/self/ns/net)" != "${LAB_HOST_NETNS:?}"
mount -t tmpfs -o mode=0700,nosuid,nodev,size=16m tmpfs /tmp
if [ ! -c /dev/net/tun ]; then
    echo 'TUN_DEVICE=ABSENT'
    exit 78
fi
echo 'KERNEL_NAMESPACE_ENTERED=PASS'
exec /bin/sh "${LAB_EXPERIMENT_SCRIPT:?}"
