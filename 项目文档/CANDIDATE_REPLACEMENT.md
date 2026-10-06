# Candidate naming and fixed-topic relationship

The fixed third-batch index entry is `WireGuardPeerPrefixBinding`, based on `WireGuard/wireguard-go@ecfc5a8d54462e18e13c72173e2623d16d8e25a0`. It asks for peer-prefix and replay data-plane evidence. This candidate supplies that comparison in a real WireGuard kernel tunnel, but its **new enforcement code** runs in a separate HMAC/UDP/TUN gateway. Calling that code a WireGuard rewrite would overstate its relationship to the upstream protocol.

The proposed independent product name is therefore `VpnPeerPrefixBindingGate`. Treat it as a **replacement or narrowed continuation** of the fixed topic, never as an additional completed item alongside `WireGuardPeerPrefixBinding`. The fixed index record is preserved as the historical research selection; changing any portfolio count requires a separate, explicit review. No upstream vulnerability or CVP eligibility is inferred from the local VM result.
