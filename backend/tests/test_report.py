from app.reports.render import esc, render

F = [{"id": 1, "title": "Open port 23/tcp (telnet)", "severity": "high", "port": 23, "protocol": "tcp",
      "service": "telnet", "detail": "evil|`x`<script>", "why": "w", "remediation": "r"}]


def test_untrusted_text_is_escaped():
    assert "|" not in esc("a|b").replace("\\|", "") and "`" not in esc("`x`") and "<" not in esc("<b>")


def test_report_contains_key_sections_and_no_raw_html():
    md = render(7, "juice-shop", F, {"summary": "sum", "items": []}, "rules")
    for s in ("# Assessment report #7", "Overall risk:** high", "## Remediation", "## Method and limits"):
        assert s in md
    assert "<script>" not in md


def test_empty_report():
    assert "No open ports" in render(1, "t", [], {"summary": "none"}, "rules")
