from app.models import Assessment, AuditLog, Finding, Target, User
from app.worker import run_assessment
from tests.test_nmap import SAMPLE


def _seed(Session, value="juice-shop", kind="domain", verified=True):
    with Session() as db:
        u = User(email="w@x.io", password_hash="x")
        db.add(u)
        db.flush()
        t = Target(owner_id=u.id, value=value, kind=kind, verified=verified)
        db.add(t)
        db.flush()
        a = Assessment(owner_id=u.id, target_id=t.id, profile="nmap_quick")
        db.add(a)
        db.commit()
        return a.id


def _run(env, aid, runner, resolver):
    with env.Session() as db:
        run_assessment(db, aid, runner=runner, resolver=resolver)
    return env.Session()


def test_success_scans_vetted_ip_and_stores_findings(env):
    aid, calls = _seed(env.Session), []
    db = _run(env, aid, lambda p, t: calls.append(t) or SAMPLE, lambda h: ["172.28.0.10"])
    a = db.get(Assessment, aid)
    assert a.status == "completed" and calls == ["172.28.0.10"]  # IP, not hostname
    assert db.query(Finding).filter_by(assessment_id=aid).count() == 1


def test_dns_rebinding_to_metadata_is_blocked(env):
    aid, calls = _seed(env.Session), []
    db = _run(env, aid, lambda p, t: calls.append(t) or SAMPLE, lambda h: ["169.254.169.254"])
    assert db.get(Assessment, aid).status == "blocked" and calls == []
    assert db.query(AuditLog).filter_by(action="scope.deny.runtime").count() == 1


def test_resolution_to_private_outside_lab_is_blocked(env):
    aid = _seed(env.Session)
    db = _run(env, aid, lambda p, t: SAMPLE, lambda h: ["10.0.0.5"])
    assert db.get(Assessment, aid).status == "blocked"


def test_unverified_target_never_runs(env):
    aid, calls = _seed(env.Session, verified=False), []
    db = _run(env, aid, lambda p, t: calls.append(t) or SAMPLE, lambda h: ["172.28.0.10"])
    assert db.get(Assessment, aid).status == "blocked" and calls == []


def test_tool_failure_marks_failed(env):
    aid = _seed(env.Session)

    def boom(p, t):
        raise RuntimeError("nmap exploded")

    db = _run(env, aid, boom, lambda h: ["172.28.0.10"])
    a = db.get(Assessment, aid)
    assert a.status == "failed" and "nmap exploded" in a.error


def test_idempotent_second_run_is_noop(env):
    aid, calls = _seed(env.Session), []
    _run(env, aid, lambda p, t: calls.append(t) or SAMPLE, lambda h: ["172.28.0.10"])
    _run(env, aid, lambda p, t: calls.append(t) or SAMPLE, lambda h: ["172.28.0.10"])
    assert len(calls) == 1
