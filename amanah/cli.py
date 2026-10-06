"""Amanah command-line interface.

    python -m amanah demo                 run the full end-to-end story (fresh workspace)
    python -m amanah init                 create workspace, keys, datasets, risk register
    python -m amanah pipeline run [--hardened] [--dataset NAME] [--change ID] [--label TEXT]
    python -m amanah gate recheck RUN_ID
    python -m amanah signoff CHANGE_ID SYSTEM ROLE "Name"
    python -m amanah ia approve IA_ID "Name"
    python -m amanah simulate traffic|chatbot|access|tamper
    python -m amanah correlate
    python -m amanah incident advance INC_ID STATE "note"
    python -m amanah audit | report | dashboard | verify | status
    python -m amanah graph impact CONTROL_ID
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import time

from . import __version__, compliance, pipeline, risk, scenarios
from .core import Config, Store, home, verify_chain
from .correlation import correlate
from .governance import Incident, signoff


def say(msg: str = "", indent: int = 0) -> None:
    print("  " * indent + msg, flush=True)


def banner(title: str) -> None:
    say()
    say(f"=== {title} " + "=" * max(3, 72 - len(title)))


def init(store: Store, cfg: Config, quiet: bool = False) -> dict:
    compliance.register_context(store, cfg)
    docs = compliance.register_documents(store)
    ds = scenarios.setup_datasets()
    new = risk.seed_register(store, cfg)
    ia_fraud = risk.impact_assessment(store, cfg, "fraud-scoring")
    ia_llm = risk.impact_assessment(store, cfg, "support-llm")
    if not quiet:
        say(f"Workspace: {home()}")
        say(f"Governance documents approved: {len(docs)}  (drafts are left out on purpose)")
        say(f"Datasets signed: {', '.join(ds)}")
        say(f"Risks assessed: {len(new)}  Impact assessments drafted: {ia_fraud}, {ia_llm}")
    return {"ia_fraud": ia_fraud, "ia_llm": ia_llm}


def print_run(r: dict) -> None:
    for s in r["stages"]:
        extra = ""
        if s["stage"] == "data":
            extra = f"provenance={s['provenance']} suspect_rate={s['suspect_rate']:.2%}"
        elif s["stage"] == "test":
            extra = (f"acc={s['clean_accuracy']:.3f} recall={s['clean_fraud_recall']:.3f} "
                     f"robust_recall={s['robust_fraud_recall']:.3f} evasion={s['evasion_success_rate']:.3f} "
                     f"FPR={s['false_positive_rate']:.3f} DI={s['disparate_impact']:.3f}")
        elif s["stage"] == "sign":
            extra = f"v{s['version']} sha256={s['sha256']}..."
        elif s["stage"] == "gate":
            extra = f"engine={s['engine']}"
        say(f"[{s['status'].upper():5}] {s['stage']:6} {extra}", 1)
    say(f"Outcome: {r['status'].upper()}", 1)
    for d in r["decision"]["deny"]:
        say(f"- {d}", 2)


def demo(args) -> None:
    ws = home()
    if not args.keep:
        shutil.rmtree(ws, ignore_errors=True)
        ws = home()
    store, cfg = Store(), Config()
    t0 = time.time()
    banner("1. Set up the AI management system")
    ids = init(store, cfg)

    banner("2. Quarterly retrain, standard training (change CHG-Q4)")
    r1 = pipeline.run(store, cfg, hardened=False, change_id="CHG-Q4", label="Q4 retrain, standard")
    print_run(r1)

    banner("3. Mitigation: retrain with ART adversarial training (same change)")
    r2 = pipeline.run(store, cfg, hardened=True, change_id="CHG-Q4", label="Q4 retrain, adversarially hardened")
    print_run(r2)

    banner("4. Humans review and sign off, gate re-checked")
    risk.approve_impact_assessment(store, ids["ia_fraud"], "A. Rahman, AI Risk Officer")
    for role, name in [("ai_risk_officer", "A. Rahman"), ("model_owner", "J. Patel"),
                       ("data_protection_officer", "M. Okafor")]:
        signoff(store, cfg, "CHG-Q4", "fraud-scoring", role, name, note="Reviewed v2 robustness and FPR trade-off")
        say(f"signed: {role} ({name})", 1)
    rc = pipeline.recheck_gate(store, cfg, r2["run"])
    say(f"Gate re-check: {'ALLOW' if rc['decision']['allow'] else 'DENY'} -> {rc['status'].upper()}", 1)
    risk.set_treatment(store, "R-fraud-scoring-T-EVA", 6)

    banner("5. Attack: poisoned labels through the chargeback channel")
    r3 = pipeline.run(store, cfg, dataset="partner-batch", change_id="CHG-PARTNER", label="Partner feedback batch")
    print_run(r3)
    import numpy as np
    from .data import load_dataset
    from .poisoning import scan
    Xp, yp, _ = load_dataset("partner-batch")
    Xr, yr, _ = load_dataset("reference")
    truth = np.load(home() / "data" / "partner-batch.truth.npy")
    q = scan(Xp, yp, Xr, yr, truth_mask=truth)["detector_quality"]
    say(f"Detector caught {q['caught']}/{q['injected_rows']} poisoned rows (recall {q['recall']}, "
        f"precision {q['precision']})", 1)

    banner("6. Attack: training data altered after signing")
    r4 = pipeline.run(store, cfg, dataset="tampered-batch", change_id="CHG-TAMPER", label="Tampered batch")
    print_run(r4)

    banner("7. Attack: model file tampering and a privilege bypass attempt")
    tc = scenarios.tamper_check(store)
    say(f"Altered model artifact signature valid? {tc['tampered']['signature_valid']}  "
        f"(restored: {tc['restored']['signature_valid']})", 1)
    say(f"ML engineer promoting directly to production: {scenarios.access_violation(store, cfg)}", 1)

    banner("8. Live traffic: customers, a busy partner, and a model-extraction attacker")
    rt = scenarios.runtime_traffic(store, cfg)
    say(f"Predictions: {rt['stats']['predictions']}  OOD flagged: {rt['stats']['ood']}  "
        f"extraction alerts: {rt['stats']['extraction_alerts']}", 1)
    for cid, p in rt["client_profiles"].items():
        say(f"{cid:20} queries={p['queries']:4} boundary_ratio={p['boundary_ratio']:.2f} "
            f"coverage_entropy={p['coverage_entropy']:.2f}", 1)

    banner("9. Support assistant: customers, a blatant attack, a subtle coordinated attack")
    cb = scenarios.chatbot_traffic(store, cfg)
    say(f"Messages: {cb['stats']['messages']}  blocked: {cb['stats']['blocked']}  "
        f"flagged (allowed): {cb['stats']['flagged']}", 1)
    say(f"Subtle message score {cb['flagged_example']['score']} -> {cb['flagged_example']['action']} "
        f"({', '.join(cb['flagged_example']['techniques'])})", 1)
    say(f"Same session then read {cb['session_rows']['S-7777']} customer rows", 1)

    banner("10. Cross-model correlation")
    fired = correlate(store, cfg)
    for f in fired:
        say(f"{f['rule']} fired on {f['key']} across {', '.join(f['systems'])} -> finding {f['finding']}", 1)

    banner("11. Incident response")
    playbook = {
        "CR-001": [("contained", "Session S-7777 terminated, source IP blocked, tool token revoked"),
                   ("notified", "CISO, DPO, model owner and executive leadership notified per RACI"),
                   ("root_cause", "Guard scored the message 0.75, under the 0.80 block line; lookup tool had "
                                  "no per-call row cap", {"root_cause": "Borderline injection allowed; tool lacked row cap"}),
                   ("reported", "DPO assessed exposure; customer notification decision recorded"),
                   ("closed", "Tool capped at 25 rows per call; privilege-claim plus bulk-request now blocks",
                    {"corrective_action": "Row cap and combined-technique block rule deployed"})],
        "CR-002": [("contained", "API key api-key-7731 revoked, partner notified"),
                   ("notified", "SOC and CISO notified"),
                   ("root_cause", "Partner API allowed unlimited scoring calls", {"root_cause": "No per-key quota"}),
                   ("closed", "Per-key quota of 200 calls/hour deployed", {"corrective_action": "Quota deployed"})],
        "tamper": [("contained", "Batch quarantined; storage access logs pulled"),
                   ("root_cause", "Training bucket allowed writes after the manifest was signed",
                    {"root_cause": "Mutable storage after signing"}),
                   ("closed", "Bucket made write-once; hashes verified on every read",
                    {"corrective_action": "Immutable storage plus hash-on-read"})],
        None: [("contained", "Batch quarantined; chargeback channel paused"),
               ("root_cause", "Chargeback labels accepted without dispute verification",
                {"root_cause": "Unverified feedback labels"}),
               ("closed", "Labels now require analyst-verified disputes", {"corrective_action": "Label verification"})],
    }
    for inc in store.rows("SELECT * FROM incidents ORDER BY opened_at"):
        key = inc["rule_id"] or ("tamper" if "tampered" in inc["title"] else None)
        steps = playbook.get(key, playbook[None]) if inc["severity"] in ("critical", "high") else []
        for step in steps:
            state, note, fields = step[0], step[1], (step[2] if len(step) > 2 else {})
            Incident.advance(store, inc["id"], state, note, **fields)
        final = store.one("SELECT state FROM incidents WHERE id=?", [inc["id"]])["state"]
        say(f"{inc['id']} [{inc['severity']}] {inc['title'][:60]} -> {final}", 1)
    risk.set_treatment(store, "R-support-llm-T-INJ", 12)
    risk.set_treatment(store, "R-support-llm-T-EXF", 10)
    risk.set_treatment(store, "R-fraud-scoring-T-EXT", 4)
    risk.set_treatment(store, "R-fraud-scoring-T-POI", 5)
    risk.record_treatment_plan(store)

    banner("12. Conformance, audit and reporting")
    finish_reporting(store, cfg)
    say(f"Demo finished in {time.time() - t0:.0f}s. Open {home() / 'reports' / 'dashboard.html'}", 1)


def finish_reporting(store: Store, cfg: Config) -> None:
    conf = compliance.conformance(store, cfg)
    compliance.statement_of_applicability(store, cfg, conf)
    compliance.board_report(store, cfg, conf)
    compliance.management_review(store, "Chief Executive Officer", [
        "Accept fraud model v2 robustness/FPR trade-off for two quarters",
        "Fund LMS integration to close competence evidence gap (Clause 7.2)",
        "Legal to approve customer AI terms by month end (A.10.4)"])
    audit = compliance.internal_audit(store, cfg)
    conf = compliance.conformance(store, cfg)
    gaps = compliance.push_gaps_to_register(store, cfg, conf)
    compliance.statement_of_applicability(store, cfg, conf)
    g = compliance.control_graph(store, cfg)
    compliance.export_cypher(g)
    compliance.board_report(store, cfg, conf)
    from .dashboard import build
    path = build(store, cfg)
    s = conf["annex_summary"]
    say(f"Annex A: {s['implemented']}/{s['total']} implemented, {s['partial']} partial, {s['gap']} gap", 1)
    say("Clauses: " + "  ".join(f"{c['id']}:{c['score']}%" for c in conf["clauses"]), 1)
    say(f"Internal audit: {len(audit['nonconformities'])} nonconformities; evidence chain "
        f"{'intact' if audit['chain']['intact'] else 'BROKEN'} ({audit['chain']['entries']} entries)", 1)
    say(f"Gaps pushed back into the risk register: {gaps}", 1)
    say(f"Audit pack: {compliance.audit_pack(store)}", 1)
    say(f"Dashboard: {path}", 1)


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="amanah", description=f"Amanah AI assurance platform {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo")
    d.add_argument("--keep", action="store_true", help="keep the existing workspace")
    sub.add_parser("init")
    p = sub.add_parser("pipeline")
    p.add_argument("action", choices=["run"])
    p.add_argument("--hardened", action="store_true")
    p.add_argument("--dataset", default="train-batch")
    p.add_argument("--change")
    p.add_argument("--label", default="")
    g = sub.add_parser("gate")
    g.add_argument("action", choices=["recheck"])
    g.add_argument("run_id")
    so = sub.add_parser("signoff")
    so.add_argument("change_id"), so.add_argument("system"), so.add_argument("role"), so.add_argument("name")
    ia = sub.add_parser("ia")
    ia.add_argument("action", choices=["approve"]), ia.add_argument("ia_id"), ia.add_argument("name")
    sim = sub.add_parser("simulate")
    sim.add_argument("what", choices=["traffic", "chatbot", "access", "tamper"])
    sub.add_parser("correlate")
    inc = sub.add_parser("incident")
    inc.add_argument("action", choices=["advance"]), inc.add_argument("incident_id")
    inc.add_argument("state", choices=Incident.STATES), inc.add_argument("note")
    for c in ("audit", "report", "dashboard", "verify", "status"):
        sub.add_parser(c)
    gr = sub.add_parser("graph")
    gr.add_argument("action", choices=["impact"]), gr.add_argument("control")
    a = ap.parse_args(argv)

    if a.cmd == "demo":
        return demo(a)
    store, cfg = Store(), Config()
    if a.cmd == "init":
        init(store, cfg)
    elif a.cmd == "pipeline":
        print_run(pipeline.run(store, cfg, hardened=a.hardened, dataset=a.dataset, change_id=a.change,
                               label=a.label))
    elif a.cmd == "gate":
        print(json.dumps(pipeline.recheck_gate(store, cfg, a.run_id), indent=2))
    elif a.cmd == "signoff":
        print(signoff(store, cfg, a.change_id, a.system, a.role, a.name))
    elif a.cmd == "ia":
        risk.approve_impact_assessment(store, a.ia_id, a.name)
    elif a.cmd == "simulate":
        fn = {"traffic": scenarios.runtime_traffic, "chatbot": scenarios.chatbot_traffic,
              "access": scenarios.access_violation, "tamper": lambda s, c: scenarios.tamper_check(s)}[a.what]
        print(json.dumps(fn(store, cfg), indent=2, default=str))
    elif a.cmd == "correlate":
        print(json.dumps(correlate(store, cfg), indent=2))
    elif a.cmd == "incident":
        Incident.advance(store, a.incident_id, a.state, a.note)
    elif a.cmd in ("audit", "report", "dashboard"):
        finish_reporting(store, cfg)
    elif a.cmd == "verify":
        v = verify_chain(store)
        print(json.dumps(v, indent=2))
        sys.exit(0 if v["intact"] else 1)
    elif a.cmd == "graph":
        print(json.dumps(compliance.blast_radius(compliance.control_graph(store, cfg), a.control), indent=2))
    elif a.cmd == "status":
        for r in store.rows("SELECT system_id, version, stage, sha256 FROM models ORDER BY system_id, version"):
            print(f"{r['system_id']} v{r['version']} {r['stage']} {r['sha256'][:12]}")
        for r in store.rows("SELECT id, severity, state, title FROM incidents"):
            print(f"{r['id']} {r['severity']} {r['state']} {r['title']}")


if __name__ == "__main__":
    main()
