# v0.1.0 local candidate

- Added an independent authenticated peer/source-prefix and 64-counter replay gate for a synthetic UDP/TUN tunnel.
- Added a deliberately unbound tunnel control that delivers a peer-forged inner source, and a guarded data-plane control that rejects that source and a repeated counter before TUN injection.
- Added a two-peer, real Linux WireGuard comparison including an identical encrypted-frame reinjection and receiver delivery counts.
- Added pinned Build-only VM preparation and a fail-closed serial receipt validator.

This version does not implement or change WireGuard. Its experiment is not a finding against the referenced upstream project. Publication and program eligibility are tracked separately from versioned functionality.
