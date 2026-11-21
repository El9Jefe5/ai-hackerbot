# ADR-004: Redis job queue and isolated worker
**Status:** Accepted
**Decision:** The API enqueues only an `assessment_id` on a Redis list. A separate worker container dequeues it, loads the row from Postgres, runs the scan and writes results. The worker is the only service on both the `core` and `lab` networks, runs as non-root with all Linux capabilities dropped (`cap_drop: ALL`, `no-new-privileges`), and uses TCP connect scans (`-sT`), which need no raw sockets.
**Why:** The web tier must never hold network reach into the lab. Jobs that carry ids instead of hosts or commands mean a compromised queue cannot widen scope. The DB row is the source of truth, so the job is idempotent (status must be `queued`).
**Trade-offs:** A plain list with BRPOP loses a job if the worker dies mid-pop; the DB status makes this recoverable (a stale-`running` sweeper is planned). RQ/Celery would add retries but hide the mechanics, and this is a clear, small design.
