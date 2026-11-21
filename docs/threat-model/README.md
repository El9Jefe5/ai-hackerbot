# Threat model (M1-M3)
| Threat | Mitigation |
|---|---|
| Scanning third-party assets | Verified ownership + scope guard + audit log |
| SSRF / cloud metadata via target field | Permanent block list |
| DNS rebinding after approval | Resolve at run time, re-check every IP, scan the vetted IP (ADR-005) |
| Argument injection into nmap | Profile names only, fixed argv, no shell, strict target validation |
| Prompt injection from scanned content | No tools, deterministic severity, validated output (ADR-006) |
| Markdown/HTML injection via banners | Escaped in reports |
| LLM key theft via compromised scanner | Key lives only in the analyst, which has no lab access (ADR-007) |
| Cross-tenant data access | Owner-scoped queries, 404 on foreign IDs |
| Credential theft | scrypt hashes, constant-time compare, short-lived JWT, env secrets |
| Lab breakout | `internal: true` network, non-root workers, `cap_drop: ALL` |
