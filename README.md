# AI HackerBot
AI-assisted security assessment platform. The AI orchestrates and analyzes; it never attacks freely.
**Status:** Milestone 1 (auth, targets, scope guard, lab, CI). Live demo and screenshots: _coming with M4._

## Run it
```bash
cp .env.example .env      # set JWT_SECRET
docker compose up --build # API on :8000, docs at /docs
cd backend && pip install -r requirements.txt && PYTHONPATH=. pytest -q
```
## Verified behavior (M1)
- Unverified targets are denied; verified lab targets are allowed ([walkthrough](docs/evidence/scope-walkthrough.md))
- Cloud-metadata and loopback addresses can never be scanned ([tests](backend/tests/test_scope.py))
- Every action is recorded in an audit log ([sample](docs/evidence/audit-log.txt))
- Unauthenticated requests return 401; users cannot see each other's targets
  
## Read this first
- [Architecture](docs/architecture/overview.md) · [ADRs](docs/architecture/adr) · [Threat model](docs/threat-model/README.md)
- Core safety logic: [`backend/app/core/scope.py`](backend/app/core/scope.py)

## Roadmap
M1 foundation ✅ · M2 recon + scanners · M3 LangGraph + reporting · M4 dashboard, hardening, deploy
