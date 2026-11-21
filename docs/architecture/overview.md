# Architecture

```mermaid
flowchart TB
  UI[Next.js dashboard] --> API[FastAPI: auth, targets, assessments]
  API --> DB[(PostgreSQL)]
  API --> Q[(Redis queue)]
  Q --> W[Isolated workers]
  W -->|only after scope.authorize| LAB[Lab network: internal, no egress]
  W --> AG[LangGraph agent: plan + analyze]
  AG -.->|fixed tool registry, no shell| W
  API --> AUD[(audit_log)]
```

## Trust boundaries
1. **Browser -> API**: JWT bearer, role checks, per-owner resource isolation.
2. **API -> workers**: jobs reference a `target_id`, never a raw host string.
3. **Workers -> targets**: every action passes `core/scope.py` (deny by default).
4. **Agent -> tools**: closed registry of typed actions; no arbitrary commands, no scope expansion.

## Schema (M1)
`users(id, email, password_hash, role)` · `targets(id, owner_id, value, kind, verified, challenge_token)` · `audit_log(id, user_id, action, detail, ts)`
