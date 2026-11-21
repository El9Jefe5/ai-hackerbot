# ADR-007: Analysis runs in its own service
**Status:** Accepted
**Decision:** The scanner worker (lab network, nmap) and the analyst (LLM key, internet) are separate containers connected by a second Redis queue. The analyst is on `core` only; the worker never sees the API key.
**Why:** The component that touches hostile targets should not hold credentials or an outbound path to a third party, and the component that talks to the LLM should have no route to the lab. Compromising either does not give both.
**Trade-offs:** One more container and queue. Benefits: independent scaling/failure (an LLM outage never fails a scan) and a clear threat boundary.
