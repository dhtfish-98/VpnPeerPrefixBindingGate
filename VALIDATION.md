# v0.1.0 local validation receipt (2026-10-06)

All generated artifacts and raw VM output are under `Build/验证/WireGuardPeerPrefixBinding-20261006/environment/`; that directory keeps the original fixed-topic name so the experiment history remains traceable. This receipt is tied to the final source scripts and rebuilt binary, not to an earlier capability probe.

| Check | Observed result |
| --- | --- |
| Host Go tests | `go test ./...`: `guard` PASS; command package compiles. `go vet ./...`: exit 0, empty diagnostics. |
| VM input checks | Pinned Alpine 3.23 aarch64 kernel, initramfs, modloop, `wg`, `ip`, and shared libraries each matched their SHA-256 before preparation. Kernel `Image` extraction matched `8dfe2ce7e5bfe4d0efcf2fed0a01a692b5a5d5217e9a55587a17d92203ab7b0d`. |
| Real Linux context | Alpine Linux `6.18.52-0-virt`, separate root/peer1/peer2 network namespace inodes; `NETNS_DISTINCT=PASS`. Linux WireGuard/veth/tun modules loaded and two WireGuard peers configured. |
| Real WireGuard allowed peers | Peer 1 `10.0.1.2` and peer 2 `10.0.2.2` each pinged through the tunnel. Inner UDP markers `P1_ALLOWED` and `P2_ALLOWED` each delivered once; `P1_AFTER` and `P2_AFTER` each delivered once after negatives. |
| Real WireGuard spoof and replay | Peer 1 sent an inner UDP packet with the peer 2 source `10.0.2.2`; `P1_SPOOF` had zero deliveries. A peer 1 veth AF_PACKET probe captured a genuine outgoing encrypted type-4 WireGuard frame and reinjected identical bytes with counter 1; `P1_ALLOWED` still had one delivery. The serial log recorded one `wg0` RX error. |
| Intentionally weak control | Peer 1 underlay `192.0.2.2` supplied an IPv4 packet claiming inner source `10.0.2.2`; the unbound UDP/TUN gateway wrote it to TUN and the server application received `WEAK_SPOOF` once from that source. |
| Independent guarded control | Separate lab HMAC keys identified two peers. Four authorized packets were written to `guard0` TUN and delivered once each, including fresh peer 1 and peer 2 packets after negatives. Peer 1's authenticated `10.0.2.2` claim was rejected as `source_prefix` and its repeated counter 1 as `replay`, before TUN write; corresponding receiver counts remained zero/additional zero. |

The final runner printed `VM_RESULT=PASS` after checking all required markers. Exact local artifact hashes:

| Artifact | SHA-256 |
| --- | --- |
| `experiment-serial.log` (raw serial, 5,810 bytes) | `f5f99a14ec9a520b4b3ac9d2f96860c0cc750e8cdefb83e43d0e9a50cfad88ab` |
| `vm-final-receipt.log` | `ff0679da47dfd00eeb04acf051908a0df6f58d3b7616e0b3cd86eace9a425446` |
| `go-test-final.log` | `dae584360b33398b91f6fdfe4e2d30d2ed35aea338258f40466c7a52ab97f5e1` |
| `go-vet-final.log` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| rebuilt `initramfs-experiment.gz` | `ef09f1ef25adca37e03d41552a87e485a782054354dd5f9a95d69633d3bf537b` |
| rebuilt `overlay/usr/bin/wirelab` | `14f171d1eb9e4754cad625039d40934bd0b86db0d95d3a1b4ee211b4be4afb96` |

This proves only the isolated Linux kernel and synthetic-gateway behavior in this run. It does not prove a flaw or patch in `wireguard-go`, production tunnel safety, hosted CI, a published release, or CVP eligibility. The package and Git freeze are recorded separately in the Build receipt so these VM bytes remain tied to the exact candidate files.
