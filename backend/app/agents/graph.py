"""
LangGraph orchestration. The graph can only run these fixed nodes: it has no shell, no
network tools and no way to touch targets or scope (ADR-001, ADR-006).

  score -> (no findings) ---------------------> report
        -> (no LLM) -> rules_analysis ---------> report
        -> (LLM) -> llm_analysis --(failure falls back to rules)--> report
"""
import logging
from typing import TypedDict

from app.analyzers import analysis, risk
from app.reports.render import render

log = logging.getLogger("graph")


class State(TypedDict, total=False):
    assessment_id: int
    target: str
    findings: list
    analysis: dict
    source: str
    markdown: str


def build_graph(llm):
    from langgraph.graph import END, START, StateGraph  # imported lazily so pure modules stay testable

    def score(s: State):
        return {"findings": risk.score_findings(s["findings"])}

    def route(s: State):
        if not s["findings"]:
            return "report"
        return "llm_analysis" if llm else "rules_analysis"

    def rules_analysis(s: State):
        return {"analysis": analysis.rules_analysis(s["findings"]), "source": "rules"}

    def llm_analysis(s: State):
        try:
            return {"analysis": analysis.analyze_with_llm(llm, s["findings"]), "source": "llm"}
        except Exception as e:  # API error, bad JSON, schema violation: degrade, never fail the report
            log.warning("LLM analysis rejected (%s); using rules", type(e).__name__)
            return rules_analysis(s)

    def report(s: State):
        a = s.get("analysis") or analysis.rules_analysis(s["findings"])
        src = s.get("source", "rules")
        return {"analysis": a, "source": src,
                "markdown": render(s["assessment_id"], s["target"], s["findings"], a, src)}

    g = StateGraph(State)
    for name, fn in (("score", score), ("rules_analysis", rules_analysis),
                     ("llm_analysis", llm_analysis), ("report", report)):
        g.add_node(name, fn)
    g.add_edge(START, "score")
    g.add_conditional_edges("score", route, {"llm_analysis": "llm_analysis",
                                             "rules_analysis": "rules_analysis", "report": "report"})
    g.add_edge("llm_analysis", "report")
    g.add_edge("rules_analysis", "report")
    g.add_edge("report", END)
    return g.compile()
