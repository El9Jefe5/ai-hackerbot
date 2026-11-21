# ADR-001: The AI is an orchestrator and analyst, not an attacker
**Status:** Accepted
**Decision:** The LangGraph agent chooses among a closed set of typed tools (nmap profile, ZAP baseline, CVE lookup) and analyzes output. It cannot run shell commands or add targets.
**Why:** An LLM with a shell plus prompt injection from scanned content equals remote code execution and scope escape. A typed registry keeps the blast radius auditable.
**Trade-off:** Less flexible than a free-form agent; far safer and easier to test.
