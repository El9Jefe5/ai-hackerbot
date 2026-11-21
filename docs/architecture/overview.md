# Architecture

```mermaid
flowchart TB
  UI[Next.js dashboard - M4] --> API[FastAPI: auth, targets, assessments, reports]
  API --> DB[(PostgreSQL)]
  API --> Q1[(Redis: scan queue)]
  Q1 --> W[Scanner worker: core + lab, no LLM key]
  W -->|scope.authorize at run time| LAB[Lab network: internal, no egress]
  W --> DB
  W --> Q2[(Redis: analysis queue)]
  Q2 --> AN[Analyst: core only, holds LLM key]
  AN --> G[LangGraph: score - analyze - report]
  G -.->|no tools, validated output| LLM[(LLM API)]
  AN --> DB
  API --> AUD[(audit_log)]
```

## Trust boundaries
1. **Browser -> API**: JWT bearer, role checks, per-owner isolation.
2. **API -> workers**: jobs carry an id, never a host or command.
3. **Worker -> targets**: scope check at run time; scans the vetted IP.
4. **Scan data -> LLM**: untrusted; sanitized, tool-less, output validated (ADR-006).
5. **Scanner vs analyst**: separate containers and networks (ADR-007).

## Schema
`users` · `targets` · `audit_log` · `assessments` · `scan_results` · `findings` · `reports(assessment_id unique, source, markdown, analysis_json)`
