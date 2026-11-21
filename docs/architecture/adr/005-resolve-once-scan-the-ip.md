# ADR-005: Re-check scope at execution time and scan the vetted IP
**Status:** Accepted (closes the DNS-rebinding item in ADR-003)
**Decision:** At run time the worker resolves a domain target, requires every resulting IP to pass `scope.authorize`, then scans the first vetted IP, never the hostname.
**Why:** A name that was safe at creation can later resolve to 169.254.169.254 or an internal host (rebinding), and re-resolving inside nmap would be a time-of-check/time-of-use gap.
**Trade-offs:** Scans use IPs, so virtual-host-based targets need a later explicit "Host header" feature; multi-IP domains scan only the first address for now.
