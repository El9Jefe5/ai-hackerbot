"""
Assessment worker. Runs in an isolated container on BOTH the core and lab networks.
Defense in depth: the API already checked scope, the worker checks again at
execution time and scans only the addresses it just vetted.
"""
import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.core import scope
from app.core.config import settings
from app.core.db import Base, SessionLocal, engine
from app.core.queue import get_analysis_queue, get_queue
from app.models import Assessment, AuditLog, Finding, ScanResult, Target
from app.scanners import nmap

log = logging.getLogger("worker")


def _now():
    return datetime.now(timezone.utc)


def run_assessment(db: Session, assessment_id: int, runner=nmap.run, resolver=scope.default_resolver, notify=None) -> None:
    a = db.get(Assessment, assessment_id)
    if not a or a.status != "queued":
        return  # unknown or already handled: idempotent
    a.status, a.started_at = "running", _now()
    db.commit()
    owner_id = a.owner_id
    status, error = "completed", ""
    try:
        t = db.get(Target, a.target_id)
        ips = scope.authorize_resolved(t.value, t.kind, t.verified, settings.lab_targets, resolver)
        db.add(AuditLog(user_id=owner_id, action="assessment.start", detail=f"{t.value} -> {ips[0]}"))
        xml = runner(a.profile, ips[0])  # the vetted IP, never the name (ADR-005)
        ports = nmap.parse_xml(xml)
        db.add(ScanResult(assessment_id=a.id, tool="nmap", raw=xml))
        for p in ports:
            detail = " ".join(x for x in (p["product"], p["version"]) if x)
            if p["method"] == "inferred":
                detail = (detail + " identified from HTTP response").strip()
            elif not p["confirmed"]:
                detail = (detail + " [service guessed from port number, unconfirmed]").strip()
            db.add(Finding(
                assessment_id=a.id, severity="info", host=p["host"], port=p["port"],
                protocol=p["protocol"], service=p["service"], detail=detail,
                title=f"Open port {p['port']}/{p['protocol']} ({p['service']})",
            ))
        db.add(AuditLog(user_id=owner_id, action="assessment.complete", detail=f"id={a.id} findings={len(ports)}"))
        db.commit()
    except scope.ScopeViolation as e:
        db.rollback()
        status, error = "blocked", str(e)
        db.add(AuditLog(user_id=owner_id, action="scope.deny.runtime", detail=f"assessment={assessment_id} {e}"))
    except Exception as e:  # tool missing, timeout, bad XML...
        db.rollback()
        status, error = "failed", f"{type(e).__name__}: {e}"[:500]
        log.exception("assessment %s failed", assessment_id)
    a = db.get(Assessment, assessment_id)
    a.status, a.error, a.finished_at = status, error, _now()
    db.commit()
    if status == "completed" and notify:
        try:
            notify(assessment_id)  # hand off to the analyst service
        except Exception:
            log.exception("could not enqueue analysis for %s", assessment_id)


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    Base.metadata.create_all(engine)
    q, notify = get_queue(), get_analysis_queue().enqueue
    log.info("worker ready; lab allowlist=%s", settings.lab_targets)
    while True:
        aid = q.dequeue(timeout=5)
        if aid is None:
            continue
        with SessionLocal() as db:
            run_assessment(db, aid, notify=notify)


if __name__ == "__main__":
    main()
