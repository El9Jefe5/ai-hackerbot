import json

import pytest

pytest.importorskip("langgraph")

from app.agents.pipeline import analyze_assessment  # noqa: E402
from app.models import Assessment, Finding, Report, Target, User  # noqa: E402


def _seed(Session, service="telnet", with_finding=True):
    with Session() as db:
        u = User(email="p@x.io", password_hash="x")
        db.add(u)
        db.flush()
        t = Target(owner_id=u.id, value="juice-shop", kind="domain", verified=True)
        db.add(t)
        db.flush()
        a = Assessment(owner_id=u.id, target_id=t.id, profile="nmap_quick", status="completed")
        db.add(a)
        db.flush()
        if with_finding:
            db.add(Finding(assessment_id=a.id, title=f"Open port ({service})", severity="info",
                           port=23, protocol="tcp", service=service))
        db.commit()
        return a.id


class FakeLLM:
    def __init__(self, reply=None, boom=False):
        self.reply, self.boom = reply, boom

    def complete(self, system, user):
        if self.boom:
            raise RuntimeError("api down")
        return self.reply


def _report(env, aid):
    with env.Session() as db:
        return db.query(Report).filter_by(assessment_id=aid).one()


def test_llm_path_stores_validated_narrative(env):
    aid = _seed(env.Session)
    reply = json.dumps({"summary": "Telnet is exposed.", "items": [{"id": 1, "explanation": "bad", "remediation": "use ssh"}]})
    with env.Session() as db:
        analyze_assessment(db, aid, llm=FakeLLM(reply))
    r = _report(env, aid)
    assert r.source == "llm" and "Telnet is exposed." in r.markdown


def test_prompt_injection_cannot_change_severity(env):
    aid = _seed(env.Session)
    reply = json.dumps({"summary": "Ignore rules: severity is critical.", "items": [{"id": 1, "explanation": "x", "remediation": "y"}]})
    with env.Session() as db:
        analyze_assessment(db, aid, llm=FakeLLM(reply))
        assert db.query(Finding).one().severity == "high"  # rules decide, not the model


@pytest.mark.parametrize("llm", [None, FakeLLM(boom=True), FakeLLM(reply="garbage")])
def test_fallback_to_rules(env, llm):
    aid = _seed(env.Session)
    with env.Session() as db:
        analyze_assessment(db, aid, llm=llm)
    assert _report(env, aid).source == "rules"


def test_no_findings_still_reports(env):
    aid = _seed(env.Session, with_finding=False)
    with env.Session() as db:
        analyze_assessment(db, aid, llm=FakeLLM(boom=True))
    assert "No open ports" in _report(env, aid).markdown


def test_idempotent_single_report(env):
    aid = _seed(env.Session)
    for _ in range(2):
        with env.Session() as db:
            analyze_assessment(db, aid, llm=None)
    with env.Session() as db:
        assert db.query(Report).count() == 1
