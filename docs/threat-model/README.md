# Threat model (M1)
| Threat | Mitigation |
|---|---|
| Scanning third-party assets | Verified ownership + scope guard + audit log |
| SSRF / cloud metadata via target field | Permanent block list |
| Prompt injection from scanned content | Agent has typed tools only (ADR-001) |
| Cross-tenant data access | Owner-scoped queries, 404 on foreign IDs |
| Credential theft | scrypt hashes, constant-time compare, short-lived JWT, env secrets |
| Lab breakout | `internal: true` network, non-root workers (M2) |
