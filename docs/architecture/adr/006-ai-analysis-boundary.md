# ADR-006: AI analysis behind a hard boundary
**Status:** Accepted
**Context:** Scan output (service banners, versions) comes from hosts we do not control, so it is a prompt-injection channel into the LLM.
**Decision:**
1. **Severity is deterministic** (`analyzers/risk.py`). The LLM writes narrative only and cannot raise or lower severity.
2. **No tools.** The model is called with no tool definitions; LangGraph nodes are a fixed set (score, rules/LLM analysis, report).
3. **Untrusted input handling.** Fields are control-char stripped, length-limited, JSON-encoded (with `<` escaped so a banner cannot close the `<findings>` block), and the system prompt marks them as data.
4. **Strict output validation.** Output must be JSON of an exact shape. Unknown/duplicate finding ids are dropped, text is length-limited, and `CVE-…` strings are redacted because they are unverified model claims.
5. **Graceful degradation.** Any failure (API error, bad JSON, schema violation) falls back to rules-based narrative; the report is always produced and records its `source`.
**Trade-offs:** The AI adds readability, not detection, and we say so in every report. A real CVE feed (verifiable correlation) is a separate milestone.
