# v0.1.0

This version includes a GitHub hosted Linux verification workflow. Pull requests run source checks; main/tag pushes attempt the full real-kernel WireGuard and synthetic-gateway matrix and retain a no-secret machine receipt. The hosted result must be assessed from the exact public run.

- Added an independent authenticated peer/source-prefix and 64-counter replay gate for a synthetic UDP/TUN tunnel.
- Added a deliberately unbound tunnel control that delivers a peer-forged inner source, and a guarded data-plane control that rejects that source and a repeated counter before TUN injection.
- Added a two-peer, real Linux WireGuard comparison including an identical encrypted-frame reinjection and receiver delivery counts.
- Added pinned Build-only VM preparation and a fail-closed serial receipt validator.
- Made the synthetic TUN test's reverse-path-filter setting explicit inside its isolated network namespace, with checked receipt markers. The earlier hosted failure and the current verification boundary are documented in `HOSTED_FAILURE_37407758390.md`.

This version does not implement or change WireGuard. Its experiment is not a finding against the referenced upstream project. Publication and program eligibility are tracked separately from versioned functionality.
