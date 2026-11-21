# AI HackerBot
AI-assisted security assessment platform. The AI orchestrates and analyzes; it never attacks freely.
**Status:** Milestone 1 (auth, targets, scope guard, lab, CI). Live demo and screenshots: _coming with M4._

## Run it
```bash
cp .env.example .env      # set JWT_SECRET
docker compose up --build # API on :8000, docs at /docs
cd backend && pip install -r requirements.txt && PYTHONPATH=. pytest -q
```
## Read this first
- [Architecture](docs/architecture/overview.md) · [ADRs](docs/architecture/adr) · [Threat model](docs/threat-model/README.md)
- Core safety logic: [`backend/app/core/scope.py`](backend/app/core/scope.py)

## Roadmap
M1 foundation ✅ · M2 recon + scanners · M3 LangGraph + reporting · M4 dashboard, hardening, deploy
