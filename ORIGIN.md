# Origin and authorship

The source in `guard/`, `cmd/wirelab/`, `scripts/`, and `.github/workflows/` was newly written for this candidate. The public project attribution is `dhtfish98 <109978225+dhtfish-98@users.noreply.github.com>` and the new project material carries the MIT notice. Attribution and Git metadata do not establish unaided authorship.

No `wireguard-go` source was copied, translated, or patched. The fixed reference `WireGuard/wireguard-go@ecfc5a8d54462e18e13c72173e2623d16d8e25a0` is MIT-licensed and remains separately owned. The experiment uses Alpine's Linux WireGuard kernel module and the `wg` configuration tool as unmodified third-party runtime inputs only; their respective rights remain with their owners. See `THIRD_PARTY_NOTICES.md`.

The synthetic HMAC/UDP/TUN gateway is intentionally distinct from WireGuard. It provides a limited, reviewable implementation of the peer-to-inner-source and replay checks at its own ingress, plus actual data-plane controls. It is neither a WireGuard implementation nor evidence of a defect in WireGuard.
