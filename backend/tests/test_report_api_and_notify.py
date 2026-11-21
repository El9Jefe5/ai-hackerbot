from app.models import Report
from app.worker import run_assessment
from tests.conftest import login
from tests.test_nmap import SAMPLE
from tests.test_worker import _seed


def _assessment(env, h):
    tid = env.client.post("/targets", json={"value": "juice-shop"}, headers=h).json()["id"]
    env.client.post(f"/targets/{tid}/verify", headers=h)
    return env.client.post("/assessments", json={"target_id": tid}, headers=h).json()["id"]


def test_report_not_ready_then_available(env):
    h = login(env.client, "a@x.io")
    aid = _assessment(env, h)
    assert env.client.get(f"/assessments/{aid}/report", headers=h).status_code == 404
    with env.Session() as db:
        db.add(Report(assessment_id=aid, source="rules", markdown="# hi"))
        db.commit()
    r = env.client.get(f"/assessments/{aid}/report", headers=h).json()
    assert r["markdown"] == "# hi" and r["source"] == "rules"


def test_report_is_owner_only(env):
    a, b = login(env.client, "a@x.io"), login(env.client, "b@x.io")
    aid = _assessment(env, a)
    assert env.client.get(f"/assessments/{aid}/report", headers=b).status_code == 404


def test_worker_notifies_analyst_only_on_success(env):
    ok, sent = _seed(env.Session), []
    with env.Session() as db:
        run_assessment(db, ok, runner=lambda p, t: SAMPLE, resolver=lambda h: ["172.28.0.10"], notify=sent.append)
    assert sent == [ok]


def test_worker_does_not_notify_when_blocked(env):
    bad, sent = _seed(env.Session), []
    with env.Session() as db:
        run_assessment(db, bad, runner=lambda p, t: SAMPLE, resolver=lambda h: ["169.254.169.254"], notify=sent.append)
    assert sent == []
