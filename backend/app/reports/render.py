import re

from app.analyzers.risk import SEV_ORDER, overall

_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def esc(value, limit: int = 120) -> str:
    """Untrusted text in markdown: no control chars, tables, code spans or raw HTML."""
    s = _CTRL.sub(" ", str(value))[:limit]
    return s.replace("|", "\\|").replace("`", "'").replace("<", "&lt;").replace(">", "&gt;")


def render(assessment_id: int, target: str, findings: list[dict], analysis: dict, source: str) -> str:
    items = {i["id"]: i for i in analysis.get("items", [])}
    ordered = sorted(findings, key=lambda f: (-SEV_ORDER.index(f["severity"]), f.get("port") or 0))
    lines = [f"# Assessment report #{assessment_id}", "",
             f"**Target:** {esc(target)}  ", f"**Overall risk:** {overall(findings)}  ",
             f"**Narrative source:** {'AI-assisted (validated)' if source == 'llm' else 'deterministic rules'}", "",
             "## Executive summary", "", esc(analysis.get("summary", ""), 1200), "", "## Findings", ""]
    if ordered:
        lines += ["| Severity | Port | Service | Detail |", "|---|---|---|---|"]
        lines += [f"| {f['severity']} | {f.get('port')}/{esc(f.get('protocol', ''), 8)} | "
                  f"{esc(f.get('service', ''))} | {esc(f.get('detail', '')) or '-'} |" for f in ordered]
        lines += ["", "## Remediation", ""]
        for f in ordered:
            it = items.get(f["id"], {})
            lines += [f"### {f['severity'].upper()}: {esc(f['title'])}", "",
                      esc(it.get("explanation") or f["why"], 400), "",
                      f"**Fix:** {esc(it.get('remediation') or f['remediation'], 400)}", ""]
    else:
        lines += ["No open ports were found.", ""]
    lines += ["## Method and limits", "",
              "- Scan: nmap TCP connect, top 100 ports, against a scope-verified address.",
              "- Severity is assigned by deterministic rules; AI text cannot change it.",
              "- No CVE correlation yet: absence of a CVE here does not mean a service is patched.",
              "- AI-written text is validated, length-limited and has CVE identifiers removed."]
    return "\n".join(lines) + "\n"
