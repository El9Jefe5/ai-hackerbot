import json

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.agents.graph import build_graph
from app.models import Assessment, AuditLog, Finding, Report, Target


def analyze_assessment(db: Session, assessment_id: int, llm=None) -> None:
    """Idempotent. `llm` is passed in explicitly so tests and callers never read env or hit a network by accident."""
    a = db.get(Assessment, assessment_id)
    if not a or a.status != "completed":
        return
    t = db.get(Target, a.target_id)
    rows = db.scalars(select(Finding).where(Finding.assessment_id == a.id)).all()
    state = {"assessment_id": a.id, "target": t.value, "findings": [
        {"id": f.id, "title": f.title, "severity": f.severity, "host": f.host, "port": f.port,
         "protocol": f.protocol, "service": f.service, "detail": f.detail} for f in rows]}
    out = build_graph(llm).invoke(state)
    by_id = {f["id"]: f for f in out["findings"]}
    for row in rows:
        row.severity = by_id[row.id]["severity"]  # deterministic severity persisted
    db.execute(delete(Report).where(Report.assessment_id == a.id))
    db.add(Report(assessment_id=a.id, source=out["source"], markdown=out["markdown"],
                  analysis_json=json.dumps(out["analysis"])))
    db.add(AuditLog(user_id=a.owner_id, action="report.generate", detail=f"id={a.id} source={out['source']}"))
    db.commit()
