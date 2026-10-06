# Copyright (c) 2026 dhtfish98. MIT License.
"""Run the disposable Apple Virtualization VM and fail closed on missing gates."""

import argparse
import os
import pty
import select
import subprocess
import sys
import time
from pathlib import Path


REQUIRED = (
    "NETNS_DISTINCT=PASS",
    "WG_CONFIG=PASS",
    "PEER1_PING=PASS",
    "PEER2_PING=PASS",
    "DELIVERY_MATRIX=PASS",
    "REPLAY_IDENTICAL=PASS",
    "WEAK_UNBOUND_FORWARD=PASS",
    "WEAK_DELIVERY=PASS",
    "GUARD_MATRIX=PASS",
    "GUARD_DELIVERY=PASS",
    "EXPERIMENT_DONE",
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("build_dir", type=Path, help="prepared Build-only VM directory")
    args = parser.parse_args()
    root = args.build_dir.resolve()
    master, slave = pty.openpty()
    process = subprocess.Popen(
        [str(root / "probe_vm"), str(root / "Image-6.18.52-0-virt"), str(root / "initramfs-experiment.gz")],
        stdin=slave,
        stdout=slave,
        stderr=slave,
    )
    os.close(slave)
    output = bytearray()
    sent = False
    deadline = time.monotonic() + 180
    try:
        while time.monotonic() < deadline:
            readable, _, _ = select.select([master], [], [], 0.2)
            if readable:
                try:
                    chunk = os.read(master, 32768)
                except OSError:
                    break
                if not chunk:
                    break
                output.extend(chunk)
                if not sent and b"~ #" in output:
                    os.write(master, b"/bin/sh /usr/bin/experiment_guest.sh\n/bin/busybox poweroff -f\n")
                    sent = True
            if process.poll() is not None and not readable:
                break
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=5)
    finally:
        os.close(master)
        (root / "experiment-serial.log").write_bytes(output)
    text = output.decode(errors="replace").replace("\r", "")
    missing = [marker for marker in REQUIRED if marker not in text]
    print(f"host_exit={process.returncode} command_sent={sent} serial_bytes={len(output)}")
    for line in text.splitlines():
        if any(marker in line for marker in REQUIRED) or "GUARD_DECISION" in line or "DELIVERY source=" in line:
            print(line)
    if process.returncode != 0 or not sent or missing:
        print("VM_RESULT=FAIL missing=" + ",".join(missing))
        return 1
    print("VM_RESULT=PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
