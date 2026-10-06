"""Deployment gate evaluation (policy-as-code).

The source of truth is policies/deployment_gate.rego, evaluated by Open Policy Agent.
If the `opa` binary is not installed, a built-in evaluator applies the same rules so
the platform still works offline; tests/test_policy_parity.py proves both agree.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from .core import POLICY_DIR, PROJECT_ROOT


def opa_path() -> str | None:
    for cand in (os.environ.get("AMANAH_OPA"), str(PROJECT_ROOT / "bin" / "opa"), shutil.which("opa")):
        if cand and Path(cand).exists():
            return cand
    return None


def evaluate_with_opa(gate_input: dict, opa: str) -> dict:
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(gate_input, f)
        path = f.name
    try:
        out = subprocess.run([opa, "eval", "--format", "json", "-d", str(POLICY_DIR / "deployment_gate.rego"),
                              "-i", path, "data.amanah.deployment"],
                             capture_output=True, text=True, timeout=60, check=True)
    finally:
        os.unlink(path)
    value = json.loads(out.stdout)["result"][0]["expressions"][0]["value"]
    return {"allow": value["allow"], "deny": sorted(value.get("deny", [])), "engine": "opa"}


def evaluate_builtin(i: dict) -> dict:
    t, m, d = i["thresholds"], i["metrics"], i["data"]
    deny = []
    if not i["artifact"].get("signature_valid"):
        deny.append("artifact signature missing or invalid (A.6.2.5)")
    if m["clean_accuracy"] < t["min_clean_accuracy"]:
        deny.append(f"clean accuracy {m['clean_accuracy']:.3f} below {t['min_clean_accuracy']:.2f} (A.6.2.4)")
    if m["clean_fraud_recall"] < t["min_clean_fraud_recall"]:
        deny.append(f"fraud recall {m['clean_fraud_recall']:.3f} below {t['min_clean_fraud_recall']:.2f} (A.6.2.4)")
    if m["robust_fraud_recall"] < t["min_robust_fraud_recall"]:
        deny.append(f"robust fraud recall {m['robust_fraud_recall']:.3f} under PGD below "
                    f"{t['min_robust_fraud_recall']:.2f} (A.6.2.4, OWASP ML01)")
    if m["evasion_success_rate"] > t["max_evasion_success_rate"]:
        deny.append(f"evasion success rate {m['evasion_success_rate']:.3f} above "
                    f"{t['max_evasion_success_rate']:.2f} (A.6.2.4, OWASP ML01)")
    if m["false_positive_rate"] > t["max_false_positive_rate"]:
        deny.append(f"false-positive rate {m['false_positive_rate']:.3f} above "
                    f"{t['max_false_positive_rate']:.2f} (A.5.4 customer impact)")
    if not d.get("provenance_verified"):
        deny.append("training data provenance not verified (A.7.5)")
    if d["poisoning_suspect_rate"] > t["max_poisoning_suspect_rate"]:
        deny.append(f"poisoning scan flagged {d['poisoning_suspect_rate']:.4f} of the batch, limit "
                    f"{t['max_poisoning_suspect_rate']:.2f} (A.7.4, OWASP ML02)")
    if m["disparate_impact"] < t["min_disparate_impact"]:
        deny.append(f"disparate impact {m['disparate_impact']:.3f} below {t['min_disparate_impact']:.2f} (A.5.4)")
    if i["impact_assessment"].get("status") != "approved":
        deny.append("impact assessment not approved (Clause 8.4, A.5.2)")
    for role in i["required_signoffs"]:
        if role not in i["signoffs"]:
            deny.append(f"missing sign-off from {role} (Clause 6.3)")
    for inc in i["open_critical_incidents"]:
        deny.append(f"open critical incident {inc} on this system (Clause 10.2)")
    return {"allow": not deny, "deny": sorted(deny), "engine": "builtin"}


def evaluate(gate_input: dict) -> dict:
    opa = opa_path()
    if opa:
        try:
            return evaluate_with_opa(gate_input, opa)
        except (subprocess.SubprocessError, KeyError, json.JSONDecodeError):
            pass
    return evaluate_builtin(gate_input)
