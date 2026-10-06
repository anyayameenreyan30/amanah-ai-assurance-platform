"""Secure MLOps pipeline (A.6.1.3, A.6.2.4, A.6.2.5, Clause 8.1).

    data checks -> train -> sign -> test -> gate (OPA) -> deploy

Every retrain runs every stage; nothing can be skipped, and every stage writes to the
evidence ledger. A poisoned batch stops the run before training. A model that fails
the gate stays a signed but unreleased candidate, and its findings are routed by RACI.
A run that passes every technical check but still lacks human sign-off waits at the
gate; `recheck_gate` re-evaluates it once the named approvers have signed.
"""
from __future__ import annotations

import json

import numpy as np

from . import adversarial, poisoning, registry
from .core import Config, Store, new_id, now, record_evidence
from .data import load_dataset, verify_provenance
from .governance import Incident, raise_finding, required_signoffs, signoffs_for
from .policy import evaluate
from .risk import latest_impact_assessment


def _stage(stages: list, name: str, status: str, **info) -> None:
    stages.append({"stage": name, "status": status, "ts": now(), **info})


def run(store: Store, cfg: Config, *, system_id: str = "fraud-scoring", dataset: str = "train-batch",
        reference: str = "reference", holdout: str = "holdout", hardened: bool = False,
        change_id: str | None = None, label: str = "") -> dict:
    run_id = new_id("RUN")
    change_id = change_id or new_id("CHG")
    stages: list = []
    t = cfg.thresholds
    store.insert("pipeline_runs", {"id": run_id, "system_id": system_id, "started": now(), "finished": None,
                                   "status": "running", "stages": [], "gate": None, "model_id": None,
                                   "label": label})

    # 1. Data: provenance + poisoning scan, before any training.
    prov = verify_provenance(dataset)
    record_evidence(store, "data_provenance", f"{dataset}: provenance "
                    f"{'verified' if prov['verified'] else 'FAILED'}", prov, system_id,
                    result="pass" if prov["verified"] else "fail")
    X, y, seg = load_dataset(dataset)
    Xr, yr, _ = load_dataset(reference)
    scan = poisoning.scan(X, y, Xr, yr)
    scan_summary = {k: v for k, v in scan.items() if k != "suspect_indices"}
    data_ok = prov["verified"] and scan["suspect_rate"] <= t["max_poisoning_suspect_rate"]
    record_evidence(store, "poisoning_scan", f"{dataset}: {scan['suspect_rows']} suspect rows "
                    f"({scan['suspect_rate']:.2%}), coordinated={scan['coordinated_campaign']}",
                    scan_summary, system_id, result="pass" if data_ok else "fail")
    record_evidence(store, "data_quality", f"{dataset}: {len(X)} rows, fraud rate {y.mean():.3f}, "
                    f"drifted features {scan['drifted_features'] or 'none'}",
                    {"rows": int(len(X)), "fraud_rate": float(y.mean()),
                     "label_rate_test": scan["label_rate"], "drift": scan["feature_drift"]}, system_id)
    _stage(stages, "data", "pass" if data_ok else "fail", provenance=prov["verified"],
           suspect_rate=scan["suspect_rate"], coordinated=scan["coordinated_campaign"])

    if not data_ok:
        reasons = prov["reasons"] + ([f"{scan['suspect_rows']} suspicious rows; coordinated cluster "
                                      f"of {scan['clusters'][0]['size'] if scan['clusters'] else 0}"]
                                     if scan["suspect_rate"] > t["max_poisoning_suspect_rate"] else [])
        raise_finding(store, cfg, system_id, "data_poisoning", "high",
                      f"Training batch '{dataset}' quarantined before training",
                      {"reasons": reasons, "clusters": scan["clusters"]}, ["A.7.4", "A.7.5", "A.6.2.4"],
                      ["ML02"])
        from .risk import raise_from_finding
        raise_from_finding(store, cfg, system_id, "T-POI", f"batch {dataset} quarantined")
        return _finish(store, run_id, stages, "blocked_at_data", None, {"allow": False, "deny": reasons,
                                                                       "engine": "data-stage"})

    record_evidence(store, "data_preparation", f"{dataset}: features scaled to fixed ranges, "
                    "holdout kept separate", {"scaling": "fixed physical ranges -> [0,1]",
                                              "holdout": holdout}, system_id)

    # 2. Train.
    Xtrain = np.vstack([Xr, X])
    ytrain = np.concatenate([yr, y])
    model = (adversarial.train_hardened(Xtrain, ytrain, eps=t["gate_epsilon"]) if hardened
             else adversarial.train_standard(Xtrain, ytrain))
    training = {"architecture": f"8-{adversarial.ARCH[0]}-{adversarial.ARCH[1]}-2", "rows": int(len(Xtrain)),
                "mode": "ART adversarial training (PGD, ratio 0.5)" if hardened else "standard",
                "epochs": 16 if hardened else 15}
    record_evidence(store, "training_record", f"{system_id} trained ({training['mode']})", training, system_id)
    _stage(stages, "train", "pass", **training)

    # 3. Test on the untouched holdout set.
    Xh, yh, sh = load_dataset(holdout)
    metrics = adversarial.clean_metrics(model, Xh, yh, sh)
    rob = adversarial.robustness(model, Xh, yh, gate_eps=t["gate_epsilon"])
    metrics.update({"robust_fraud_recall": rob["robust_fraud_recall"],
                    "evasion_success_rate": rob["evasion_success_rate"]})

    # 4. Sign and register the candidate.
    reg = registry.register(store, cfg, system_id, model, metrics, change_id=change_id)
    ver = registry.verify(store, reg["id"])
    _stage(stages, "sign", "pass" if ver["signature_valid"] else "fail", model=reg["id"],
           version=reg["version"], sha256=reg["sha256"][:16])

    rob_ok = (rob["robust_fraud_recall"] >= t["min_robust_fraud_recall"]
              and rob["evasion_success_rate"] <= t["max_evasion_success_rate"])
    record_evidence(store, "robustness_test", f"v{reg['version']}: PGD eps {t['gate_epsilon']} robust recall "
                    f"{rob['robust_fraud_recall']:.3f}, evasion {rob['evasion_success_rate']:.3f}", rob,
                    system_id, result="pass" if rob_ok else "fail")
    fair_ok = metrics["disparate_impact"] >= t["min_disparate_impact"]
    record_evidence(store, "fairness_test", f"v{reg['version']}: disparate impact {metrics['disparate_impact']:.3f}",
                    {"disparate_impact": metrics["disparate_impact"],
                     "pass_rate_by_segment": metrics["pass_rate_by_segment"], "rule": "four-fifths"},
                    system_id, result="pass" if fair_ok else "fail")
    _stage(stages, "test", "pass" if rob_ok and fair_ok else "fail", **{k: v for k, v in metrics.items()
                                                                       if k != "pass_rate_by_segment"})
    if not rob_ok:
        raise_finding(store, cfg, system_id, "robustness_failure", "high",
                      f"{system_id} v{reg['version']} fails adversarial robustness (PGD)",
                      {"robust_fraud_recall": rob["robust_fraud_recall"],
                       "evasion_success_rate": rob["evasion_success_rate"], "curve": rob["curve"]},
                      ["A.6.2.4"], ["ML01"])
    if not fair_ok:
        raise_finding(store, cfg, system_id, "fairness_issue", "high", f"{system_id} v{reg['version']} fairness",
                      {"disparate_impact": metrics["disparate_impact"]}, ["A.5.4"])
    registry.write_model_card(store, cfg, system_id, reg["id"], {k: v for k, v in metrics.items()
                                                                 if k != "pass_rate_by_segment"}, training)

    # 5. Gate.
    gate_input = build_gate_input(store, cfg, system_id, change_id, metrics, ver, prov, scan)
    decision = evaluate(gate_input)
    store.update("pipeline_runs", "id", run_id, gate={"input": gate_input, "decision": decision,
                                                      "change_id": change_id})
    record_evidence(store, "deployment_gate", f"{run_id}: gate {'ALLOW' if decision['allow'] else 'DENY'} "
                    f"({decision['engine']})", {"input": gate_input, "decision": decision}, system_id,
                    result="allow" if decision["allow"] else "deny")
    _stage(stages, "gate", "pass" if decision["allow"] else "fail", deny=decision["deny"],
           engine=decision["engine"])

    # 6. Deploy.
    if decision["allow"]:
        registry.promote(store, cfg, reg["id"])
        _stage(stages, "deploy", "pass", version=reg["version"])
        status = "deployed"
    else:
        only_humans = all("sign-off" in d or "impact assessment" in d for d in decision["deny"])
        status = "awaiting_approval" if only_humans else "rejected"
        store.update("models", "id", reg["id"], stage="awaiting_approval" if only_humans else "rejected")
        _stage(stages, "deploy", "held" if only_humans else "fail")
    return _finish(store, run_id, stages, status, reg["id"], decision, change_id)


def build_gate_input(store: Store, cfg: Config, system_id: str, change_id: str, metrics: dict,
                     ver: dict, prov: dict, scan: dict) -> dict:
    ia = latest_impact_assessment(store, system_id)
    return {"thresholds": cfg.thresholds,
            "artifact": {"signature_valid": ver["signature_valid"]},
            "metrics": {k: v for k, v in metrics.items() if k != "pass_rate_by_segment"},
            "data": {"provenance_verified": prov["verified"], "poisoning_suspect_rate": scan["suspect_rate"]},
            "impact_assessment": {"status": ia["status"] if ia else "missing"},
            "required_signoffs": required_signoffs(cfg, system_id),
            "signoffs": signoffs_for(store, change_id),
            "open_critical_incidents": Incident.open_critical(store, system_id)}


def recheck_gate(store: Store, cfg: Config, run_id: str) -> dict:
    """Re-evaluate a held run after humans have signed; promote it if the gate now allows."""
    r = store.one("SELECT * FROM pipeline_runs WHERE id=?", [run_id])
    gate = json.loads(r["gate"])
    gi = gate["input"]
    ia = latest_impact_assessment(store, r["system_id"])
    gi["impact_assessment"] = {"status": ia["status"] if ia else "missing"}
    gi["signoffs"] = signoffs_for(store, gate["change_id"])
    gi["open_critical_incidents"] = Incident.open_critical(store, r["system_id"])
    gi["artifact"] = {"signature_valid": registry.verify(store, r["model_id"])["signature_valid"]}
    decision = evaluate(gi)
    stages = json.loads(r["stages"])
    record_evidence(store, "deployment_gate", f"{run_id}: gate re-check {'ALLOW' if decision['allow'] else 'DENY'}",
                    {"input": gi, "decision": decision}, r["system_id"],
                    result="allow" if decision["allow"] else "deny")
    _stage(stages, "gate-recheck", "pass" if decision["allow"] else "fail", deny=decision["deny"])
    if decision["allow"]:
        registry.promote(store, cfg, r["model_id"])
        _stage(stages, "deploy", "pass")
        status = "deployed"
    else:
        status = r["status"]
    store.update("pipeline_runs", "id", run_id, stages=stages, status=status, finished=now(),
                 gate={"input": gi, "decision": decision, "change_id": gate["change_id"]})
    return {"run": run_id, "status": status, "decision": decision}


def _finish(store, run_id, stages, status, model_id, decision, change_id=None) -> dict:
    store.update("pipeline_runs", "id", run_id, finished=now(), status=status, stages=stages,
                 model_id=model_id)
    record_evidence(store, "pipeline_run", f"{run_id}: {status}", {"stages": stages, "decision": decision},
                    result=status)
    return {"run": run_id, "status": status, "model": model_id, "change_id": change_id,
            "decision": decision, "stages": stages}
