"""Continuous conformance (Clauses 4-10, Annex A), Statement of Applicability, reports.

Nothing on the dashboard is typed in by hand. A requirement counts as met only when
the evidence ledger holds every evidence type the catalog asks for. Missing evidence
shows as a gap and is pushed back into the risk register as a tracked risk.
"""
from __future__ import annotations

import csv
import json
import re
import zipfile
from collections import Counter

import networkx as nx

from .core import PROJECT_ROOT, Config, Store, home, now, record_evidence, verify_chain
from .risk import add_conformance_gap_risk

GOV_DIR = PROJECT_ROOT / "governance"


# ------------------------------------------------------------------ governance documents
def register_documents(store: Store) -> list[dict]:
    """Register approved governance documents (front matter lists the evidence they provide)."""
    found = []
    for path in sorted(GOV_DIR.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        m = re.match(r"---\n(.*?)\n---", text, re.S)
        if not m:
            continue
        meta = dict(line.split(": ", 1) for line in m.group(1).splitlines() if ": " in line)
        if meta.get("status") != "approved":
            continue
        for etype in [e.strip() for e in meta.get("evidence", "").split(",") if e.strip()]:
            record_evidence(store, etype, f"{meta.get('title')} ({path.name}) approved by "
                            f"{meta.get('approved_by')} on {meta.get('approved_on')}",
                            {"document": path.name, **meta}, result="approved")
        found.append({"file": path.name, **meta})
    return found


def register_context(store: Store, cfg: Config) -> None:
    org = cfg.platform["organization"]
    record_evidence(store, "scope_doc", "AIMS scope and interested parties defined",
                    {"scope": org["aims_scope"], "interested_parties": org["interested_parties"]})
    record_evidence(store, "system_inventory", f"{len(cfg.platform['ai_systems'])} AI systems inventoried",
                    {"systems": cfg.platform["ai_systems"]})
    record_evidence(store, "resource_doc", "compute, tooling and storage resources documented",
                    org["resources"])
    record_evidence(store, "roles_raci", "RACI matrix and escalation policy loaded", cfg.raci)


# ------------------------------------------------------------------ conformance
def evidence_types(store: Store) -> Counter:
    return Counter(r["type"] for r in store.rows("SELECT type FROM evidence"))


def _status(required: list[str], have: Counter) -> str:
    n = sum(1 for e in required if have.get(e))
    return "implemented" if n == len(required) else "partial" if n else "gap"


def conformance(store: Store, cfg: Config) -> dict:
    have = evidence_types(store)
    clauses = []
    for c in cfg.iso["clauses"]:
        reqs = [{**r, "status": _status(r["evidence"], have),
                 "missing": [e for e in r["evidence"] if not have.get(e)]} for r in c["requirements"]]
        pts = sum(1 if r["status"] == "implemented" else 0.5 if r["status"] == "partial" else 0 for r in reqs)
        clauses.append({"id": c["id"], "title": c["title"], "pdca": c["pdca"],
                        "score": round(100 * pts / len(reqs)), "requirements": reqs})
    controls = []
    for c in cfg.annex_controls():
        controls.append({**c, "status": _status(c["evidence"], have),
                         "missing": [e for e in c["evidence"] if not have.get(e)],
                         "evidence_count": sum(have.get(e, 0) for e in c["evidence"])})
    counts = Counter(c["status"] for c in controls)
    return {"generated": now(), "clauses": clauses, "controls": controls,
            "annex_summary": {"total": len(controls), "implemented": counts["implemented"],
                              "partial": counts["partial"], "gap": counts["gap"]},
            "evidence_total": sum(have.values())}


def push_gaps_to_register(store: Store, cfg: Config, conf: dict) -> int:
    n = 0
    for c in conf["clauses"]:
        for r in c["requirements"]:
            if r["status"] != "implemented":
                add_conformance_gap_risk(store, cfg, f"Clause {r['id']}", r["title"])
                n += 1
    for c in conf["controls"]:
        if c["status"] != "implemented":
            add_conformance_gap_risk(store, cfg, c["id"], c["title"])
            n += 1
    return n


def statement_of_applicability(store: Store, cfg: Config, conf: dict) -> str:
    risks = store.rows("SELECT id, controls FROM risks")
    path = home() / "reports" / "statement-of-applicability.csv"
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Control", "Title", "Applicable", "Justification", "Status", "Evidence held",
                    "Missing evidence", "Linked risks"])
        for c in conf["controls"]:
            linked = [r["id"] for r in risks if c["id"] in (r["controls"] or "").split(",")]
            w.writerow([c["id"], c["title"], "Yes",
                        "Applicable to all in-scope AI systems" if not linked
                        else f"Treats {len(linked)} assessed risk(s)",
                        c["status"], c["evidence_count"], "; ".join(c["missing"]), "; ".join(linked)])
    record_evidence(store, "soa", f"Statement of Applicability generated ({conf['annex_summary']['implemented']}"
                    f"/{conf['annex_summary']['total']} implemented)", conf["annex_summary"])
    return str(path)


def internal_audit(store: Store, cfg: Config) -> dict:
    """Automated internal audit (Clause 9.2): chain integrity + requirement-by-requirement check."""
    chain = verify_chain(store)
    record_evidence(store, "evidence_chain_verified",
                    f"evidence chain {'intact' if chain['intact'] else 'BROKEN'} ({chain['entries']} entries)",
                    chain, result="pass" if chain["intact"] else "fail")
    conf = conformance(store, cfg)
    nonconf = [f"Clause {r['id']} {r['title']}: missing {', '.join(r['missing'])}"
               for c in conf["clauses"] for r in c["requirements"]
               if r["status"] != "implemented" and r["id"] != "9.2"]  # this audit is the 9.2 evidence
    nonconf += [f"{c['id']} {c['title']}: missing {', '.join(c['missing'])}"
                for c in conf["controls"] if c["status"] != "implemented"]
    result = {"chain": chain, "nonconformities": nonconf, "annex_summary": conf["annex_summary"]}
    record_evidence(store, "internal_audit", f"internal audit: {len(nonconf)} nonconformities, chain "
                    f"{'intact' if chain['intact'] else 'broken'}", result,
                    result="pass" if not nonconf else "findings")
    return result


# ------------------------------------------------------------------ graph
def control_graph(store: Store, cfg: Config) -> nx.DiGraph:
    """System -> risk -> control -> clause dependency graph (exportable to Neo4j)."""
    g = nx.DiGraph()
    for c in cfg.annex_controls():
        g.add_node(c["id"], kind="Control", title=c["title"])
    for s in cfg.platform["ai_systems"]:
        g.add_node(s["id"], kind="AISystem", title=s["name"])
    for r in store.rows("SELECT * FROM risks WHERE system_id != 'AIMS'"):
        g.add_node(r["id"], kind="Risk", title=r["name"], score=r["score"], level=r["level"])
        g.add_edge(r["system_id"], r["id"], rel="HAS_RISK")
        for ctl in (r["controls"] or "").split(","):
            if ctl:
                g.add_edge(r["id"], ctl, rel="TREATED_BY")
    for f in store.rows("SELECT * FROM findings"):
        g.add_node(f["id"], kind="Finding", title=f["title"], severity=f["severity"])
        for ctl in (f["controls"] or "").split(","):
            if ctl:
                g.add_edge(f["id"], ctl, rel="AFFECTS")
    return g


def export_cypher(g: nx.DiGraph) -> str:
    def esc(s):
        return str(s).replace("\\", "\\\\").replace("'", "\\'")
    lines = []
    for n, d in g.nodes(data=True):
        lines.append(f"MERGE (n:{d['kind']} {{id:'{esc(n)}'}}) SET n.title='{esc(d.get('title', ''))}'"
                     + (f", n.score={d['score']}" if "score" in d else "") + ";")
    for a, b, d in g.edges(data=True):
        lines.append(f"MATCH (a {{id:'{esc(a)}'}}), (b {{id:'{esc(b)}'}}) MERGE (a)-[:{d['rel']}]->(b);")
    path = home() / "reports" / "control-graph.cypher"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(path)


def blast_radius(g: nx.DiGraph, control_id: str) -> dict:
    """If this control fails, which risks lose treatment and which systems are exposed?"""
    risks = [n for n in g.predecessors(control_id) if g.nodes[n]["kind"] == "Risk"]
    systems = sorted({s for r in risks for s in g.predecessors(r)})
    return {"control": control_id, "risks": risks, "systems": systems}


# ------------------------------------------------------------------ reports
def board_report(store: Store, cfg: Config, conf: dict) -> str:
    have = evidence_types(store)
    risks = store.rows("SELECT * FROM risks WHERE system_id!='AIMS' ORDER BY score DESC LIMIT 6")
    incidents = store.rows("SELECT * FROM incidents ORDER BY opened_at DESC")
    runs = store.rows("SELECT id, label, status FROM pipeline_runs ORDER BY started")
    s = conf["annex_summary"]
    lines = [f"# AI governance board report", f"Generated {now()} for {cfg.platform['organization']['name']}", "",
             "## Position in one paragraph",
             f"{s['implemented']} of {s['total']} ISO/IEC 42001 Annex A controls are implemented with evidence, "
             f"{s['partial']} are partial and {s['gap']} are gaps. {len(incidents)} AI incidents were recorded "
             f"this period; {sum(1 for i in incidents if i['state'] != 'closed')} remain open. "
             f"The evidence ledger holds {conf['evidence_total']} entries.", "",
             "## Clause conformance", "| Clause | Title | Score |", "|---|---|---|"]
    lines += [f"| {c['id']} | {c['title']} | {c['score']}% |" for c in conf["clauses"]]
    lines += ["", "## Top risks", "| Risk | System | Score | Level | Status |", "|---|---|---|---|---|"]
    lines += [f"| {r['name']} | {r['system_id']} | {r['score']} | {r['level']} | {r['status']} |" for r in risks]
    lines += ["", "## Incidents", "| Incident | Severity | State | Title |", "|---|---|---|---|"]
    lines += [f"| {i['id']} | {i['severity']} | {i['state']} | {i['title']} |" for i in incidents]
    lines += ["", "## Model releases", "| Run | Change | Outcome |", "|---|---|---|"]
    lines += [f"| {r['id']} | {r['label'] or '-'} | {r['status']} |" for r in runs]
    lines += ["", "## NIST AI RMF 1.0 alignment", "| Function | Evidence held |", "|---|---|"]
    lines += [f"| {fn} | {', '.join(f'{e} ({have[e]})' for e in ev if have.get(e)) or 'none'} |"
              for fn, ev in cfg.iso["nist_ai_rmf"].items()]
    lines += ["", "## ISO/IEC 23894 risk process alignment", "| Process step | Evidence held |", "|---|---|"]
    lines += [f"| {st} | {', '.join(f'{e} ({have[e]})' for e in ev if have.get(e)) or 'none'} |"
              for st, ev in cfg.iso["iso_23894"].items()]
    path = home() / "reports" / "board-report.md"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    record_evidence(store, "board_report", "board and regulator report generated", {"path": path.name})
    return str(path)


def audit_pack(store: Store) -> str:
    """Zip every evidence payload with the ledger and its verification result."""
    chain = verify_chain(store)
    path = home() / "reports" / "audit-evidence-pack.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("ledger.json", json.dumps(store.rows("SELECT * FROM evidence ORDER BY seq"), indent=2))
        z.writestr("chain-verification.json", json.dumps(chain, indent=2))
        for p in (home() / "evidence").glob("*.json"):
            z.write(p, f"evidence/{p.name}")
        for p in (home() / "reports").glob("*"):
            if p.suffix in (".md", ".csv", ".cypher"):
                z.write(p, f"reports/{p.name}")
    return str(path)


def management_review(store: Store, chair: str, decisions: list[str]) -> str:
    """Record a management review (Clause 9.3) with its decisions."""
    return record_evidence(store, "management_review", f"management review chaired by {chair}: "
                           f"{len(decisions)} decisions", {"chair": chair, "decisions": decisions},
                           result="recorded")
