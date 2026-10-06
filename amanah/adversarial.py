"""Adversarial robustness testing and mitigation with IBM ART (A.6.2.4, OWASP ML01).

Threat model: a fraudster who knows how the model works (white-box, the worst case)
alters only what they control when placing a transaction: amount, time, distance,
velocity, merchant and whether it looks foreign. Account age and physical card
presence are masked out of the attack, because a real attacker cannot change them.

Metrics reported per epsilon (perturbation budget on the 0-1 scaled features):
* robust_fraud_recall   - share of all fraud still caught after the attack
* evasion_success_rate  - share of fraud the clean model caught that the attack flips
"""
from __future__ import annotations

import contextlib
import io

import numpy as np
from art.attacks.evasion import FastGradientMethod, ProjectedGradientDescent
from art.defences.trainer import AdversarialTrainer

from .data import ATTACKER_CONTROLLED
from .model import ARTFraudClassifier, FraudMLP

ARCH = (64, 32)


def train_standard(X, y, seed: int = 0) -> FraudMLP:
    return FraudMLP(hidden=ARCH, fraud_weight=3.0, seed=seed).fit(X, y, epochs=15)


def train_hardened(X, y, eps: float = 0.10, seed: int = 1) -> FraudMLP:
    """Mitigation: ART AdversarialTrainer mixes PGD examples into every batch (ratio 0.5)."""
    m = FraudMLP(hidden=ARCH, fraud_weight=6.0, seed=seed)
    m.fit(X, y, epochs=4)                                  # warm start on clean data
    clf = ARTFraudClassifier(m)
    pgd = ProjectedGradientDescent(clf, eps=eps, eps_step=eps / 3, max_iter=7, verbose=False)
    with contextlib.redirect_stderr(io.StringIO()):
        AdversarialTrainer(clf, attacks=pgd, ratio=0.5).fit(
            X.astype(np.float32), np.eye(2)[y], nb_epochs=12, batch_size=256)
    return m


def clean_metrics(model: FraudMLP, X, y, seg) -> dict:
    p = model.predict_proba(X).argmax(1)
    legit = y == 0
    pass_rates = [float(1 - p[legit & (seg == g)].mean()) for g in (0, 1)]
    return {"clean_accuracy": round(float((p == y).mean()), 4),
            "clean_fraud_recall": round(float(p[y == 1].mean()), 4),
            "false_positive_rate": round(float(p[legit].mean()), 4),
            "precision": round(float(y[p == 1].mean()) if p.sum() else 0.0, 4),
            "disparate_impact": round(min(pass_rates) / max(pass_rates), 4),
            "pass_rate_by_segment": {"segment_0": round(pass_rates[0], 4), "segment_1": round(pass_rates[1], 4)}}


def robustness(model: FraudMLP, X, y, epsilons=(0.05, 0.10, 0.15), gate_eps: float = 0.10) -> dict:
    clf = ARTFraudClassifier(model)
    fraud = X[y == 1].astype(np.float32)
    target = np.eye(2)[np.ones(len(fraud), int)]
    mask = np.tile(ATTACKER_CONTROLLED, (len(fraud), 1)).astype(np.float32)
    caught = clf.predict(fraud).argmax(1) == 1
    curve = []
    for eps in sorted(set(epsilons) | {gate_eps}):
        row = {"epsilon": eps}
        for name, attack in (
            ("fgsm", FastGradientMethod(clf, eps=eps)),
            ("pgd", ProjectedGradientDescent(clf, eps=eps, eps_step=eps / 4, max_iter=20,
                                             num_random_init=1, verbose=False)),
        ):
            adv = attack.generate(fraud, y=target, mask=mask)
            pa = clf.predict(adv).argmax(1)
            row[f"{name}_robust_fraud_recall"] = round(float(pa.mean()), 4)
            row[f"{name}_evasion_success_rate"] = round(float(((pa == 0) & caught).sum() / max(caught.sum(), 1)), 4)
            if name == "pgd" and eps == gate_eps:
                delta = np.abs(adv - fraud)[(pa == 0) & caught]
                row["example_changes"] = {
                    "mean_abs_change_per_feature": [round(float(v), 4) for v in delta.mean(0)]} if len(delta) else {}
        curve.append(row)
    gate = next(r for r in curve if r["epsilon"] == gate_eps)
    return {"attack_library": "IBM Adversarial Robustness Toolbox",
            "attacks": ["FastGradientMethod (FGSM)", "ProjectedGradientDescent (PGD, 20 iterations, random start)"],
            "threat_model": "white-box, attacker-controlled features only (account age, card presence masked)",
            "fraud_samples": int(len(fraud)), "curve": curve,
            "gate_epsilon": gate_eps,
            "robust_fraud_recall": gate["pgd_robust_fraud_recall"],
            "evasion_success_rate": gate["pgd_evasion_success_rate"]}
