"""AI risk register (Clauses 6.1.2 / 8.2 / 8.3) and impact assessments (6.1.4 / 8.4, A.5).

Scores are explainable: score = likelihood x impact, and every point above a threat's
base value is traced to a named attribute of the system (public exposure, free-text
input, tool access, decision criticality). That is how the same threat family scores
12 on the internal fraud model and 20 on the public chatbot.
"""
from __future__ import annotations

from .core import Config, Store, new_id, now, record_evidence


def level_for(score: int, levels: dict) -> str:
    for name in ("critical", "high", "medium", "low"):
        if score >= levels[name]:
            return name
    return "low"


def score_threat(threat: dict, system: dict) -> dict:
    def apply(base: int, mods: dict) -> tuple[int, list[str]]:
        total, why = base, []
        for cond, pts in (mods or {}).items():
            attr, val = cond.split("=")
            if str(system.get(attr)).lower() == val.lower():
                total += pts
                why.append(f"{cond} (+{pts})")
        return max(1, min(5, total)), why

    lik, lwhy = apply(threat["base_likelihood"], threat.get("likelihood_modifiers"))
    imp, iwhy = apply(threat["base_impact"], threat.get("impact_modifiers"))
    rationale = (f"L {threat['base_likelihood']} base" + (" + " + ", ".join(lwhy) if lwhy else "")
                 + f" = {lik}; I {threat['base_impact']} base" + (" + " + ", ".join(iwhy) if iwhy else "")
                 + f" = {imp}")
    return {"likelihood": lik, "impact": imp, "score": lik * imp, "rationale": rationale}


def seed_register(store: Store, cfg: Config) -> list[dict]:
    """Assess every catalogued threat against every AI system it applies to."""
    created = []
    for system in cfg.platform["ai_systems"]:
        for t in cfg.threats:
            if system["type"] not in t["applies_to"]:
                continue
            s = score_threat(t, system)
            rid = f"R-{system['id']}-{t['id']}"
            row = {"id": rid, "system_id": system["id"], "threat_id": t["id"], "name": t["name"],
                   "owasp": ",".join(t["owasp"]), "likelihood": s["likelihood"], "impact": s["impact"],
                   "score": s["score"], "level": level_for(s["score"], cfg.platform["risk_levels"]),
                   "rationale": s["rationale"], "controls": ",".join(t["controls"]),
                   "treatment": t["treatment"], "residual_score": None, "status": "assessed",
                   "source": "threat-catalog", "created_at": now(), "updated_at": now()}
            existing = store.one("SELECT id FROM risks WHERE id=?", [rid])
            if not existing:
                store.insert("risks", row)
                created.append(row)
    record_evidence(store, "risk_register", f"risk register assessed: {len(created)} new risks",
                    {"risks": store.rows("SELECT * FROM risks")})
    return created


def set_treatment(store: Store, risk_id: str, residual_score: int, status: str = "treated") -> None:
    store.update("risks", "id", risk_id, residual_score=residual_score, status=status, updated_at=now())


def record_treatment_plan(store: Store) -> None:
    rows = store.rows("SELECT id, name, system_id, score, treatment, residual_score, status FROM risks")
    record_evidence(store, "risk_treatment", f"risk treatment plan covers {len(rows)} risks",
                    {"treatments": rows})


def raise_from_finding(store: Store, cfg: Config, system_id: str, threat_id: str, note: str) -> None:
    """A confirmed finding means the risk materialised: raise likelihood to 5 and re-score."""
    rid = f"R-{system_id}-{threat_id}"
    r = store.one("SELECT * FROM risks WHERE id=?", [rid])
    if not r:
        return
    lik = 5
    score = lik * r["impact"]
    store.update("risks", "id", rid, likelihood=lik, score=score,
                 level=level_for(score, cfg.platform["risk_levels"]), status="materialised",
                 rationale=r["rationale"] + f"; raised to L5 after finding: {note}", updated_at=now())


def add_conformance_gap_risk(store: Store, cfg: Config, ref: str, title: str) -> None:
    """Close the loop: a conformance gap on the dashboard becomes a tracked risk."""
    rid = f"R-AIMS-GAP-{ref}"
    if store.one("SELECT id FROM risks WHERE id=?", [rid]):
        return
    store.insert("risks", {"id": rid, "system_id": "AIMS", "threat_id": "GAP", "name": f"Conformance gap: {ref} {title}",
                           "owasp": "", "likelihood": 3, "impact": 3, "score": 9,
                           "level": level_for(9, cfg.platform["risk_levels"]),
                           "rationale": "No evidence held for this requirement; audit nonconformity likely",
                           "controls": ref, "treatment": "Assign owner, produce evidence, re-run internal audit",
                           "residual_score": None, "status": "open", "source": "conformance-dashboard",
                           "created_at": now(), "updated_at": now()})


# ------------------------------------------------------------------ impact assessment
def impact_assessment(store: Store, cfg: Config, system_id: str, fairness: dict | None = None) -> str:
    """Structured pre-deployment assessment of impacts on individuals, groups and society."""
    s = cfg.system(system_id)
    risks = store.rows("SELECT name, score, level FROM risks WHERE system_id=? ORDER BY score DESC", [system_id])
    content = {
        "system": s["name"],
        "intended_use": {"fraud-scoring": "Score card transactions for fraud; high scores go to analyst review, not automatic account closure.",
                         "support-llm": "Answer customer questions and look up the requesting customer's own orders."}.get(system_id, ""),
        "foreseeable_misuse": {"fraud-scoring": "Using the score to deny credit or profile customers; evasion by fraudsters.",
                               "support-llm": "Prompt injection to reach other customers' data; social engineering."}.get(system_id, ""),
        "individuals": {"affected": "Cardholders", "harm": "Blocked legitimate payments, unequal false-alarm burden",
                        "fairness_test": fairness or "pending"},
        "groups": "Customer segments compared with the four-fifths rule on legitimate-payment pass rates",
        "societal": "Financial exclusion if false alarms concentrate in one group; trust in digital payments",
        "safety": "No physical safety impact; financial harm bounded by analyst review",
        "security": [f"{r['name']} ({r['score']}, {r['level']})" for r in risks[:5]],
        "human_oversight": "Analysts review every high score; customers can contest a block through support",
        "personal_data": s["personal_data"],
    }
    aid = new_id("IA")
    store.insert("impact_assessments", {"id": aid, "system_id": system_id, "status": "draft",
                                        "content": content, "ts": now(), "approver": None})
    record_evidence(store, "impact_assessment", f"impact assessment {aid} drafted for {system_id}",
                    content, system_id=system_id)
    return aid


def approve_impact_assessment(store: Store, aid: str, approver: str) -> None:
    store.update("impact_assessments", "id", aid, status="approved", approver=approver)
    ia = store.one("SELECT system_id FROM impact_assessments WHERE id=?", [aid])
    record_evidence(store, "impact_assessment", f"impact assessment {aid} approved by {approver}",
                    {"id": aid, "approver": approver}, system_id=ia["system_id"], result="approved")


def latest_impact_assessment(store: Store, system_id: str) -> dict | None:
    return store.one("SELECT * FROM impact_assessments WHERE system_id=? ORDER BY ts DESC, rowid DESC LIMIT 1",
                     [system_id])
