# Copyright (c) 2026 dhtfish98. MIT License.
"""Fetch pinned third-party VM inputs and build only inside a supplied Build dir."""

import argparse
import gzip
import hashlib
import os
import platform
import shutil
import subprocess
import sys
import urllib.request
import zlib
from pathlib import Path


NETBOOT = "https://dl-cdn.alpinelinux.org/alpine/v3.23/releases/aarch64/netboot/"
APKS = "https://dl-cdn.alpinelinux.org/alpine/v3.23/main/aarch64/"
PINNED = {
    "vmlinuz-virt": (NETBOOT, "06196d2cf51e9a2bac421564bb64c63a8b7146c9a22755dd22a713e337023013"),
    "initramfs-virt": (NETBOOT, "b0be51c9de43d582da897df3583114192933872a7e219218752b18082d75b6cb"),
    "modloop-virt": (NETBOOT, "e96d6f26f7bc7ce64946deb60dae5e3728d73ecd4f37bc59d974a2027cba825b"),
    "wireguard-tools-wg-1.0.20250521-r1.apk": (APKS, "d7e93f18c08915958fc3f2b14cce71f05ea786aa0ef7482a6d4bf2ac8e16c32c"),
    "iproute2-minimal-6.17.0-r0.apk": (APKS, "cb59fda34bb6683b09cf510985d0d00aebfb78e00c5fd872fa4cd7095175a4a9"),
    "libcap2-2.78-r0.apk": (APKS, "b92145d3ceaf2ba81106241e2939eafc7aacb9c32590e4b1be37171fd2f61112"),
    "libelf-0.194-r0.apk": (APKS, "a92cb7309a0096234fbdd4e19a499e56337d9bb1fe18eb9d5ef6a89a4b46dbc6"),
    "libmnl-1.0.5-r2.apk": (APKS, "e4d193a3cb4a44defd722292edde361e941b891ed93fcea94bbcf13b0972c5bb"),
    "zlib-1.3.2-r0.apk": (APKS, "ecda4cc94fd18f90182f1d3a615889df5e0db9cf78926d11627dd23e06d2e6e8"),
    "zstd-libs-1.5.7-r2.apk": (APKS, "50a998e56e4bf31504996e49c1b4a23eed5e0cd4e24b8a1356a54daf1a6eabbe"),
}
KERNEL_IMAGE_SHA256 = "8dfe2ce7e5bfe4d0efcf2fed0a01a692b5a5d5217e9a55587a17d92203ab7b0d"


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(part)
    return h.hexdigest()


def run(*args: str, cwd: Path | None = None, env: dict | None = None) -> None:
    subprocess.run(args, cwd=cwd, env=env, check=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("build_dir", type=Path, help="directory beneath Build for every output")
    args = parser.parse_args()
    root = args.build_dir.resolve()
    if "Build" not in root.parts:
        parser.error("build_dir must be beneath Build")
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        parser.error("this runner needs macOS arm64 and Apple Virtualization")
    source = Path(__file__).resolve().parents[1]
    root.mkdir(parents=True, exist_ok=True)
    for name, (base, expected) in PINNED.items():
        path = root / name
        if not path.exists():
            urllib.request.urlretrieve(base + name, path)
        actual = digest(path)
        if actual != expected:
            raise RuntimeError(f"pinned input mismatch: {name}: {actual}")
        print(f"PINNED_OK {name} {actual}")

    vmlinuz = (root / "vmlinuz-virt").read_bytes()
    offset = vmlinuz.find(b"\x1f\x8b\x08")
    if offset < 0:
        raise RuntimeError("no embedded kernel gzip stream")
    unpacker = zlib.decompressobj(31)
    image = unpacker.decompress(vmlinuz[offset:]) + unpacker.flush()
    if not unpacker.eof or hashlib.sha256(image).hexdigest() != KERNEL_IMAGE_SHA256:
        raise RuntimeError("extracted kernel Image digest mismatch")
    (root / "Image-6.18.52-0-virt").write_bytes(image)

    extracted = root / "modloop-extracted"
    if not (extracted / "modules/6.18.52-0-virt/kernel/drivers/net/wireguard/wireguard.ko").is_file():
        extracted.mkdir(exist_ok=True)
        run("7z", "x", "-y", str(root / "modloop-virt"), f"-o{extracted}")
    overlay = root / "overlay"
    bin_dir = overlay / "usr/bin"
    lib_dir = overlay / "usr/lib"
    bin_dir.mkdir(parents=True, exist_ok=True)
    lib_dir.mkdir(parents=True, exist_ok=True)
    shutil.copytree(extracted / "modules/6.18.52-0-virt", lib_dir / "modules/6.18.52-0-virt", symlinks=True, ignore=shutil.ignore_patterns("vmlinuz"), dirs_exist_ok=True)
    run("tar", "xzf", str(root / "wireguard-tools-wg-1.0.20250521-r1.apk"), "-C", str(overlay), "usr/bin/wg")
    ip_extract = root / "ip-extract"
    ip_extract.mkdir(exist_ok=True)
    run("tar", "xzf", str(root / "iproute2-minimal-6.17.0-r0.apk"), "-C", str(ip_extract), "sbin/ip")
    shutil.copy2(ip_extract / "sbin/ip", bin_dir / "ip")
    for name in ("libcap2-2.78-r0.apk", "libelf-0.194-r0.apk", "libmnl-1.0.5-r2.apk", "zlib-1.3.2-r0.apk", "zstd-libs-1.5.7-r2.apk"):
        run("tar", "xzf", str(root / name), "-C", str(overlay), "usr/lib")
    shutil.copy2(source / "scripts/experiment_guest.sh", bin_dir / "experiment_guest.sh")

    cache = root / "go-cache"
    temp = root / "go-tmp"
    cache.mkdir(exist_ok=True)
    temp.mkdir(exist_ok=True)
    env = os.environ.copy()
    env.update(GOCACHE=str(cache), GOTMPDIR=str(temp), CGO_ENABLED="0", GOOS="linux", GOARCH="arm64")
    run("go", "build", "-trimpath", "-buildvcs=false", "-o", str(bin_dir / "wirelab"), "./cmd/wirelab", cwd=source, env=env)

    paths = ["."] + sorted("./" + str(p.relative_to(overlay)) for p in overlay.rglob("*"))
    archive = subprocess.run(["cpio", "-o", "-H", "newc"], cwd=overlay, input=("\n".join(paths) + "\n").encode(), capture_output=True, check=True).stdout
    compressed = gzip.compress(archive, compresslevel=9, mtime=0)
    (root / "initramfs-experiment.gz").write_bytes((root / "initramfs-virt").read_bytes() + compressed)

    swift_cache = root / "swift-cache"
    swift_cache.mkdir(exist_ok=True)
    run("swiftc", "-parse-as-library", "-O", "-module-cache-path", str(swift_cache), "-framework", "Virtualization", "-o", str(root / "probe_vm"), str(source / "scripts/probe_vm.swift"))
    run("codesign", "--force", "--sign", "-", "--entitlements", str(source / "scripts/virtualization.entitlements"), str(root / "probe_vm"))
    for name in ("Image-6.18.52-0-virt", "initramfs-experiment.gz", "probe_vm", "usr/bin/wirelab"):
        path = root / name if not name.startswith("usr/") else overlay / name
        print(f"BUILT {path} {digest(path)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
