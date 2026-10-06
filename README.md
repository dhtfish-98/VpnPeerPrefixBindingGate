# VpnPeerPrefixBindingGate v0.1.0

This is a defensive **reference gateway for a synthetic authenticated UDP/TUN tunnel**. Its independent gate authenticates a peer-specific HMAC, validates the IPv4 source against that peer's configured prefix, and checks a 64-counter replay window **before writing the packet to TUN**. The repository also contains an intentionally weak unbound forwarding control and an isolated, real-kernel WireGuard comparison.

The gateway does not implement WireGuard, modify `wireguard-go`, or fix a WireGuard vulnerability. WireGuard already enforces its own authenticated peer/source binding and replay protection. The real WireGuard run validates the expected data-plane behavior; the new gate protects only the separate synthetic tunnel. Do not use the lab tunnel as a production VPN: it has no key agreement, key rotation, persistence, or operational hardening.

## Code and evidence

- `guard/guard.go`: independent HMAC, canonical prefix, IPv4 integrity, and replay-window decisions. Authenticated peer identity selects exactly one prefix policy; overlapping prefixes are refused at configuration time.
- `cmd/wirelab`: isolated packet sender, TUN gateways, receiver, and Linux encrypted-frame replay helper. The weak gateway deliberately omits the source binding for the negative control.
- `scripts/experiment_guest.sh`: two network namespaces, two actual WireGuard peers, weak control, and five-packet guarded control in one disposable Linux VM.
- `scripts/prepare_macos_vm.py` and `scripts/run_macos_vm.py`: pinned Alpine inputs, Build-only binaries/serial log, and fail-closed required markers on macOS arm64.

The received-packet matrix is: peer 1 `10.0.1.2` once, peer 2 `10.0.2.2` once and again for liveness; peer 1's authenticated claim to peer 2's `10.0.2.2` is absent. An identical encrypted WireGuard frame is reinjected from peer 1's veth; its first payload is delivered once, not twice. In the weak control, a peer 1 underlay packet claiming the peer 2 inner source is actually delivered. The separate guarded TUN control shows an authenticated prefix rejection and a counter replay rejection before TUN injection.

## Reproduce locally

From this source tree, direct every generated file to a path under the workspace `Build` directory:

```sh
export LAB_BUILD=/absolute/workspace/Build/验证/WireGuardPeerPrefixBinding-20261006/environment
mkdir -p "$LAB_BUILD/go-cache" "$LAB_BUILD/go-tmp"
GOCACHE="$LAB_BUILD/go-cache" GOTMPDIR="$LAB_BUILD/go-tmp" go test ./...
python3 scripts/prepare_macos_vm.py "$LAB_BUILD"
python3 scripts/run_macos_vm.py "$LAB_BUILD"
```

The VM route needs macOS arm64 with Apple Virtualization, `swiftc`, `codesign`, `go`, `7z`, `tar`, and `cpio`. The preparation script downloads pinned Alpine aarch64 kernel/initramfs/modules and runtime packages into `Build` and verifies SHA-256 before use. It refuses a changed upstream asset. The VM has no network adapter; all peer traffic stays inside its kernel namespaces. See `VALIDATION.md` for the exact frozen receipt and `THIRD_PARTY_NOTICES.md` for rights.
