# ADR-002: Central deny-by-default scope guard
**Status:** Accepted
**Decision:** One module (`core/scope.py`) authorizes every assessment action. It requires verified ownership, permanently blocks loopback, link-local/cloud-metadata and multicast, and allows private ranges only inside the lab allowlist.
**Why:** One choke point is easy to test exhaustively and hard to bypass by accident in new scanners.
**Trade-off:** Friction for legitimate private-network users; solved later with explicit, audited allowlists.
