# Copyright (c) 2026 dhtfish98. MIT License.
"""Fail-closed hosted Linux run with a small, allow-listed machine receipt."""

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MARKERS = (
    "KERNEL_NAMESPACE_ENTERED=PASS",
    "NETNS_DISTINCT=PASS",
    "WG_CONFIG=PASS",
    "PEER1_PING=PASS",
    "PEER2_PING=PASS",
    "REPLAY_EXIT=PASS",
    "RECEIVER_EXIT=PASS",
    "DELIVERY_MATRIX=PASS",
    "REPLAY_IDENTICAL=PASS",
    "WEAK_TUN_RPF_DISABLED=PASS",
    "WEAK_RECEIVER_EXIT=PASS",
    "WEAK_GATEWAY_EXIT=PASS",
    "WEAK_DELIVERY=PASS",
    "WEAK_UNBOUND_FORWARD=PASS",
    "GUARD_TUN_RPF_DISABLED=PASS",
    "GUARD_RECEIVER_EXIT=PASS",
    "GUARD_GATEWAY_EXIT=PASS",
    "GUARD_DELIVERY=PASS",
    "GUARD_MATRIX=PASS",
    "EXPERIMENT_DONE",
)
DELIVERIES = (
    ("10.0.1.2", "P1_ALLOWED"),
    ("10.0.2.2", "P2_ALLOWED"),
    ("10.0.1.2", "P1_AFTER"),
    ("10.0.2.2", "P2_AFTER"),
    ("10.0.2.2", "WEAK_SPOOF"),
    ("10.0.1.2", "G1_ALLOWED"),
    ("10.0.2.2", "G2_ALLOWED"),
    ("10.0.1.2", "G1_AFTER"),
    ("10.0.2.2", "G2_AFTER"),
)
DECISIONS = (
    ("1", "1", "10.0.1.2", "allowed", "192.0.2.2"),
    ("2", "1", "10.0.2.2", "allowed", "198.51.100.2"),
    ("1", "2", "10.0.2.2", "source_prefix", "192.0.2.2"),
    ("1", "1", "10.0.1.2", "replay", "192.0.2.2"),
    ("1", "2", "10.0.1.2", "allowed", "192.0.2.2"),
    ("2", "2", "10.0.2.2", "allowed", "198.51.100.2"),
)
DELIVERY_RE = re.compile(r"^DELIVERY source=(\S+) payload=(\S+) count=(\d+)$")
DECISION_RE = re.compile(
    r"^GUARD_DECISION peer=(\d+) counter=(\d+) claimed_source=(\S+) reason=(\S+) underlay=(\S+)$"
)
REPLAY_RE = re.compile(
    r"^REPLAY_IDENTICAL=PASS sha256=[0-9a-f]{64} counter=1 frame_bytes=[1-9][0-9]*$"
)
WEAK_FORWARD_RE = re.compile(
    r"^WEAK_UNBOUND_FORWARD=PASS underlay_peer=192\.0\.2\.2 "
    r"claimed_inner_source=10\.0\.2\.2 bytes=[1-9][0-9]*$"
)


def safe_number(name: str) -> str:
    value = os.environ.get(name, "")
    return value if re.fullmatch(r"[0-9]{1,20}", value) else ""


def package_versions() -> dict[str, str]:
    if not shutil.which("dpkg-query"):
        return {}
    result = {}
    for package in ("busybox", "wireguard-tools", "iproute2", "kmod", "util-linux"):
        query = subprocess.run(["dpkg-query", "-W", "-f=${Version}", package],
                               capture_output=True, text=True, check=False)
        value = query.stdout.strip()
        if query.returncode == 0 and re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,80}", value):
            result[package] = value
    return result


def metadata() -> dict:
    event_sha = os.environ.get("GITHUB_SHA", "")
    checkout = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                              capture_output=True, text=True, check=False)
    commit = checkout.stdout.strip()
    image = os.environ.get("ImageOS", "")
    version = os.environ.get("ImageVersion", "")
    return {
        "checkout_commit": commit if checkout.returncode == 0 and re.fullmatch(r"[0-9a-fA-F]{40}", commit) else "unavailable",
        "event_sha": event_sha if re.fullmatch(r"[0-9a-fA-F]{40}", event_sha) else "",
        "run_id": safe_number("GITHUB_RUN_ID"),
        "run_attempt": safe_number("GITHUB_RUN_ATTEMPT"),
        "image": image if re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", image) else "",
        "image_version": version if re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", version) else "",
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "ubuntu_packages": package_versions(),
    }


def verify(log: bytes, exit_code: int, stage: str = "namespace_run",
           evidence_kind: str = "offline_log_check") -> dict:
    lines = [line.strip() for line in log.decode("utf-8", "replace").replace("\r", "").splitlines()]
    present = {}
    for marker in MARKERS:
        present[marker] = sum(line == marker or (marker == "REPLAY_IDENTICAL=PASS" and line.startswith(marker + " "))
                             or (marker == "WEAK_UNBOUND_FORWARD=PASS" and line.startswith(marker + " "))
                             for line in lines)
    deliveries = [match.groups() for line in lines if (match := DELIVERY_RE.fullmatch(line))]
    decisions = [match.groups() for line in lines if (match := DECISION_RE.fullmatch(line))]
    expected_deliveries = [(src, payload, "1") for src, payload in DELIVERIES]
    replay_ok = sum(bool(REPLAY_RE.fullmatch(line)) for line in lines) == 1
    weak_forward_ok = sum(bool(WEAK_FORWARD_RE.fullmatch(line)) for line in lines) == 1
    checks = {
        "markers_unique": all(value == 1 for value in present.values()),
        "delivery_matrix_exact": deliveries == expected_deliveries,
        "guard_decisions_exact": decisions == list(DECISIONS),
        "encrypted_replay_exact": replay_ok,
        "weak_forward_exact": weak_forward_ok,
        "process_exit_zero": exit_code == 0,
    }
    passed = all(checks.values())
    if passed:
        status = "PASS"
    elif stage != "namespace_run":
        status = "INFRA_ERROR"
    elif not all(present.get(marker, 0) == 1 for marker in MARKERS[:3]):
        status = "OPEN_HOSTED_RUNTIME"
    else:
        status = "TEST_FAIL"
    return {
        "schema": "vpn-peer-prefix-binding-gate/hosted-linux-receipt/v1",
        "evidence_kind": evidence_kind,
        "status": status,
        "stage": stage,
        "exit_code": exit_code,
        "checks": checks,
        "marker_counts": present,
        "delivery_lines": len(deliveries),
        "decision_lines": len(decisions),
        "raw_log_sha256": hashlib.sha256(log).hexdigest(),
        "raw_log_bytes": len(log),
        "environment": metadata(),
        "boundary": "No hosted result is inferred from a local VM. Private keys and raw logs are not uploaded.",
    }


def write_receipt(path: Path, receipt: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_stage(stage: str, argv: list[str], log_path: Path, env: dict | None = None,
              timeout_s: int = 300) -> int:
    with log_path.open("ab") as output:
        output.write(("STAGE=" + stage + "\n").encode())
        output.flush()
        process = subprocess.Popen(argv, cwd=ROOT, env=env, stdout=output,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            return process.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            output.write(b"STAGE_TIMEOUT\n")
            return 124


def hosted_run(build: Path) -> int:
    if "Build" not in build.parts:
        raise ValueError("output directory must be under Build")
    build.mkdir(parents=True, exist_ok=True)
    os.chmod(build, 0o700)
    receipt_path = build / "machine-receipt.json"
    setup_log = build / "setup.log"
    runtime_log = build / "runtime.log"
    stage = "setup"
    code = 99
    try:
        if os.environ.get("GITHUB_EVENT_NAME") == "pull_request":
            stage = "event_guard"
            code = 78
            return code
        for stage, command in (
            ("apt_update", ["sudo", "-n", "apt-get", "update", "-qq"]),
            ("apt_install", ["sudo", "-n", "apt-get", "install", "-y", "-qq", "busybox", "wireguard-tools", "iproute2", "kmod", "util-linux"]),
        ):
            code = run_stage(stage, command, setup_log)
            if code:
                return code
        tool_names = ("busybox", "wg", "ip", "unshare", "nsenter", "sudo", "go")
        tools = {name: shutil.which(name) for name in tool_names}
        if any(path is None for path in tools.values()):
            stage = "tool_lookup"
            code = 78
            return code
        binary = build / "wirelab"
        env = os.environ.copy()
        for name in ("go-cache", "go-tmp", "go-mod-cache"):
            (build / name).mkdir(exist_ok=True)
        env.update(GOCACHE=str(build / "go-cache"), GOTMPDIR=str(build / "go-tmp"),
                   GOMODCACHE=str(build / "go-mod-cache"), CGO_ENABLED="0", GOOS="linux", GOARCH="amd64")
        stage = "go_build"
        code = run_stage(stage, [tools["go"], "build", "-trimpath", "-buildvcs=false", "-o", str(binary), "./cmd/wirelab"], setup_log, env, 180)
        if code:
            return code
        host_netns = os.readlink("/proc/self/ns/net")
        entry = ROOT / "scripts/hosted_ns_entry.sh"
        guest = ROOT / "scripts/experiment_guest.sh"
        clean_env = [
            "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
            "LAB_HOST_NETNS=" + host_netns,
            "LAB_EXPERIMENT_SCRIPT=" + str(guest),
            "LAB_BUSYBOX=" + str(tools["busybox"]),
            "LAB_WG=" + str(tools["wg"]),
            "LAB_IP=" + str(tools["ip"]),
            "LAB_NSENTER=" + str(tools["nsenter"]),
            "LAB_UNSHARE=" + str(tools["unshare"]),
            "LAB_WIRELAB=" + str(binary),
        ]
        command = [tools["sudo"], "-n", tools["unshare"], "--mount", "--net", "--pid", "--fork",
                   "--mount-proc", "--propagation", "private", "/usr/bin/env", "-i", *clean_env, "/bin/sh", str(entry)]
        stage = "namespace_run"
        code = run_stage(stage, command, runtime_log, timeout_s=150)
        return 0 if verify(runtime_log.read_bytes(), code, stage, "hosted_execution")["status"] == "PASS" else 1
    except (OSError, ValueError, subprocess.SubprocessError):
        stage = "launcher_exception"
        code = 99
        return code
    finally:
        raw = runtime_log.read_bytes() if runtime_log.exists() else b""
        receipt = verify(raw, code, stage, "hosted_execution")
        write_receipt(receipt_path, receipt)
        print(f"HOSTED_RESULT={receipt['status']} stage={stage} receipt={receipt_path}")


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    run_cmd = sub.add_parser("run")
    run_cmd.add_argument("build_dir", type=Path)
    check_cmd = sub.add_parser("verify")
    check_cmd.add_argument("--log", type=Path, required=True)
    check_cmd.add_argument("--exit-code", type=int, required=True)
    check_cmd.add_argument("--receipt", type=Path, required=True)
    init_cmd = sub.add_parser("init")
    init_cmd.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "run":
        return hosted_run(args.build_dir.resolve())
    if args.command == "init":
        receipt = verify(b"", 98, "workflow_initialization", "hosted_execution_pending")
        write_receipt(args.receipt, receipt)
        print("HOSTED_RESULT=INFRA_ERROR stage=workflow_initialization")
        return 0
    receipt = verify(args.log.read_bytes(), args.exit_code)
    write_receipt(args.receipt, receipt)
    print(f"LOG_CHECK_RESULT={receipt['status']}")
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
