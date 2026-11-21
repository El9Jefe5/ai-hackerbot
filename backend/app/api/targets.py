from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import scope
from app.core.config import settings
from app.core.db import get_db
from app.core.security import current_user
from app.models import AuditLog, Target, User

router = APIRouter(prefix="/targets", tags=["targets"])


class TargetIn(BaseModel):
    value: str = Field(min_length=1, max_length=255)


def _out(t: Target) -> dict:
    return {"id": t.id, "value": t.value, "kind": t.kind, "verified": t.verified,
            "challenge_token": None if t.verified else t.challenge_token}


def _owned(db: Session, user: User, target_id: int) -> Target:
    t = db.get(Target, target_id)
    if not t or t.owner_id != user.id:  # 404, not 403: don't leak existence
        raise HTTPException(404, "Target not found")
    return t


@router.post("", status_code=201)
def create_target(body: TargetIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    try:
        kind = scope.classify(body.value)
    except scope.ScopeViolation as e:
        raise HTTPException(422, str(e))
    t = Target(owner_id=user.id, value=body.value.strip().lower(), kind=kind)
    db.add(t)
    db.flush()
    db.add(AuditLog(user_id=user.id, action="target.create", detail=t.value))
    db.commit()
    return _out(t)


@router.get("")
def list_targets(user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(Target).where(Target.owner_id == user.id)).all()
    return [_out(t) for t in rows]


@router.post("/{target_id}/verify")
def verify_target(target_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    t = _owned(db, user, target_id)
    if scope._in_lab(t.value, t.kind, settings.lab_targets):
        t.verified = True  # we own the lab, so it is pre-authorized
        db.add(AuditLog(user_id=user.id, action="target.verify.lab", detail=t.value))
        db.commit()
        return _out(t)
    # DNS-TXT / HTTP-file challenge for external assets: next milestone (ADR-003).
    raise HTTPException(501, "External ownership challenge not implemented yet")


@router.get("/{target_id}/scope-check")
def scope_check(target_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    t = _owned(db, user, target_id)
    try:
        scope.authorize(t.value, t.kind, t.verified, settings.lab_targets)
        decision, reason = "allow", ""
    except scope.ScopeViolation as e:
        decision, reason = "deny", str(e)
    db.add(AuditLog(user_id=user.id, action=f"scope.{decision}", detail=f"{t.value} {reason}"))
    db.commit()
    return {"decision": decision, "reason": reason}
