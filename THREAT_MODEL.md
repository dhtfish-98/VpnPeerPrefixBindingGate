# Threat model and enforcement boundary

The protected ingress is the synthetic gateway's authenticated UDP frame receiver. `guard.Gate.Check` rejects unknown peers, wrong HMACs, malformed IPv4, noncanonical/overlapping prefix policy, a source outside the authenticated peer's prefix, and repeated or out-of-window counters. `guard-gateway` calls it before writing an accepted IPv4 packet to `guard0` TUN. The receiving UDP application verifies actual kernel delivery, rather than inferring delivery from the return value alone.

The weak gateway intentionally writes a peer-provided IPv4 packet into `weak0` TUN without binding the claimed inner source to the underlay peer. It is an isolated control demonstrating the missing policy, not a recommended tunnel. The real WireGuard comparator uses the Linux kernel's existing data-plane checks and never routes through this new guard.

Lab trust assumptions: the server holds separate 32-byte HMAC keys for two peers; keys are generated inside the disposable VM and shared with its test processes through root-only files. A valid tag authenticates a synthetic peer identity for this experiment. The protocol has no handshake, encryption, key derivation, key rotation, persistent replay state, destination authorization, fragmentation support, or resistance to compromise of a peer key. A restarted gateway resets replay state. These are explicit limits, so the code is suitable as a defensive reference and test harness, not as a production VPN.

The two peer processes have distinct **network** namespaces only; they run as root in a shared mount namespace. Mode 0600 does not keep one peer process from reading the other's key if that process is malicious. Neither the local VM nor hosted workflow proves cross-peer key isolation. The hosted job adds an outer private mount/PID/network namespace to contain the experiment from the runner, not separate mount identities for the two peers.

The probe uses only documentation-reserved underlay ranges `192.0.2.0/24` and `198.51.100.0/24`, isolated inner `10.0.0.0/8` addresses, and a VM without an external NIC. It does not target a public service.
