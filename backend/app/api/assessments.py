from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import scope
from app.core.config import settings
from app.core.db import get_db
from app.core.queue import get_queue
from app.core.security import current_user
from app.models import Assessment, AuditLog, Finding, Target, User
from app.scanners.nmap import PROFILES

router = APIRouter(prefix="/assessments", tags=["assessments"])


class AssessmentIn(BaseModel):
    target_id: int
    profile: str = "nmap_quick"


def _out(a: Assessment, findings: list[Finding] | None = None) -> dict:
    d = {"id": a.id, "target_id": a.target_id, "profile": a.profile, "status": a.status,
         "error": a.error, "created_at": a.created_at, "finished_at": a.finished_at}
    if findings is not None:
        d["findings"] = [{"title": f.title, "severity": f.severity, "host": f.host, "port": f.port,
                          "protocol": f.protocol, "service": f.service, "detail": f.detail} for f in findings]
    return d


@router.post("", status_code=202)
def create_assessment(body: AssessmentIn, user: User = Depends(current_user),
                      db: Session = Depends(get_db), queue=Depends(get_queue)):
    if body.profile not in PROFILES:
        raise HTTPException(422, f"Unknown profile. Allowed: {sorted(PROFILES)}")
    t = db.get(Target, body.target_id)
    if not t or t.owner_id != user.id:
        raise HTTPException(404, "Target not found")
    try:
        scope.authorize(t.value, t.kind, t.verified, settings.lab_targets)
    except scope.ScopeViolation as e:
        db.add(AuditLog(user_id=user.id, action="scope.deny", detail=f"assessment {t.value}: {e}"))
        db.commit()
        raise HTTPException(403, str(e))
    a = Assessment(owner_id=user.id, target_id=t.id, profile=body.profile)
    db.add(a)
    db.flush()
    db.add(AuditLog(user_id=user.id, action="assessment.create", detail=f"id={a.id} target={t.value}"))
    db.commit()
    try:
        queue.enqueue(a.id)
    except Exception:
        a.status, a.error = "failed", "Queue unavailable"
        db.commit()
        raise HTTPException(503, "Queue unavailable")
    return _out(a)


@router.get("")
def list_assessments(user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(Assessment).where(Assessment.owner_id == user.id).order_by(Assessment.id.desc())).all()
    return [_out(a) for a in rows]


@router.get("/{assessment_id}")
def get_assessment(assessment_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    a = db.get(Assessment, assessment_id)
    if not a or a.owner_id != user.id:
        raise HTTPException(404, "Assessment not found")
    fs = db.scalars(select(Finding).where(Finding.assessment_id == a.id).order_by(Finding.port)).all()
    return _out(a, fs)
