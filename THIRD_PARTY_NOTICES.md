# Third-party boundary

The versioned source candidate contains no vendored third-party code, Linux module, `wg` binary, or Alpine package. New project files are licensed under this project's MIT license. The test preparation downloads the following runtime inputs into `Build` only and verifies each pinned SHA-256 in `scripts/prepare_macos_vm.py`:

| Runtime input | Source and rights |
| --- | --- |
| Alpine 3.23 aarch64 `vmlinuz-virt`, `initramfs-virt`, `modloop-virt` | [Official Alpine netboot directory](https://dl-cdn.alpinelinux.org/alpine/v3.23/releases/aarch64/netboot/). This includes Linux kernel and module material governed by their own upstream/package notices; none is relicensed by this project. |
| `wireguard-tools-wg` 1.0.20250521-r1 | [Alpine aarch64 package](https://pkgs.alpinelinux.org/package/v3.23/main/aarch64/wireguard-tools-wg), GPL-2.0-only; used as a VM configuration tool. |
| `iproute2-minimal` 6.17.0-r0 | [Alpine aarch64 package](https://pkgs.alpinelinux.org/package/v3.23/main/aarch64/iproute2-minimal), GPL-2.0-or-later; used in the VM to configure namespaces and links. |
| `libcap2`, `libelf`, `libmnl`, `zlib`, `zstd-libs` | [Alpine main aarch64 package index](https://dl-cdn.alpinelinux.org/alpine/v3.23/main/aarch64/). Runtime dependencies carry their own package notices; see their package metadata and the exact downloaded APKs under `Build`. |
| Apple Virtualization framework | Operating-system framework used by the host VM runner; no framework code is bundled. |

The optional hosted Linux job obtains Ubuntu `busybox`, `wireguard-tools`, `iproute2`, `kmod`, and `util-linux` through the runner's distribution package repository at run time. These tools and the runner's Linux kernel retain their own package and upstream rights; they are not included in this source candidate or relicensed by its MIT license. Runner image and package contents can change, so the public job and its receipt—not the local Alpine pin set—must be checked for the exact hosted run.

The workflow calls pinned `actions/checkout`, `actions/setup-go`, and `actions/upload-artifact` revisions as external GitHub Actions. Their implementations and rights remain with their owners; no action source is vendored into this candidate.

The research reference [WireGuard/wireguard-go at the fixed commit](https://github.com/WireGuard/wireguard-go/commit/ecfc5a8d54462e18e13c72173e2623d16d8e25a0) has its own [MIT license](https://github.com/WireGuard/wireguard-go/blob/ecfc5a8d54462e18e13c72173e2623d16d8e25a0/LICENSE). It was read as a reference; its source and binaries are not in the candidate. The VM uses the Linux kernel WireGuard implementation, not `wireguard-go` at that commit.
