from app.analyzers.risk import overall, score_findings


def _f(service, i=1):
    return {"id": i, "service": service, "severity": "info"}


def test_known_services_scored():
    out = {f["service"]: f["severity"] for f in score_findings([_f("telnet"), _f("ftp", 2), _f("http", 3)])}
    assert out == {"telnet": "high", "ftp": "medium", "http": "info"}


def test_unknown_service_defaults_to_info():
    assert score_findings([_f("weird-thing")])[0]["severity"] == "info"


def test_overall_is_highest():
    assert overall(score_findings([_f("http"), _f("telnet", 2)])) == "high"
    assert overall([]) == "none"
