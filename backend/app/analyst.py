"""
Analyst service: consumes completed assessments, runs the LangGraph pipeline.
It sits on the `core` network ONLY. It holds the LLM key but has no route to the lab,
and the scanner worker (which does touch the lab) never sees the key (ADR-007).
"""
import logging

from app.agents.pipeline import analyze_assessment
from app.analyzers.llm import get_llm
from app.core.db import Base, SessionLocal, engine
from app.core.queue import get_analysis_queue

log = logging.getLogger("analyst")


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    Base.metadata.create_all(engine)
    llm, q = get_llm(), get_analysis_queue()
    log.info("analyst ready; mode=%s", "llm" if llm else "rules-only")
    while True:
        aid = q.dequeue(timeout=5)
        if aid is None:
            continue
        try:
            with SessionLocal() as db:
                analyze_assessment(db, aid, llm=llm)
        except Exception:
            log.exception("analysis failed for assessment %s", aid)


if __name__ == "__main__":
    main()
