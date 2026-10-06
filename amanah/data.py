"""Training data for the fraud-scoring reference system, plus data provenance.

The reference deployment uses synthetic card transactions so the platform runs
anywhere without real customer data. To plug in real data, write a loader that
returns the same (X, y, segment) arrays and sign it with `sign_dataset`.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import numpy as np

from .core import home, now
from .crypto import load_or_create_key, sign_bytes, verify_bytes

FEATURES = ["amount", "hour", "distance_km", "txn_count_24h", "merchant_risk",
            "account_age_days", "foreign", "card_present"]
# Fixed physical ranges used to scale every feature to 0-1 (also the attack clip range).
RANGES = np.array([[0, 5000], [0, 23], [0, 3000], [0, 40], [0, 1], [0, 3650], [0, 1], [0, 1]], float)
# Threat model: features a fraudster can influence when placing a transaction.
# Account age and physical card presence are outside the attacker's control.
ATTACKER_CONTROLLED = np.array([1, 1, 1, 1, 1, 0, 1, 0], float)
APPROVED_SOURCES = {"core-banking-ledger", "chargeback-feedback"}


def scale(raw: np.ndarray) -> np.ndarray:
    return np.clip((raw - RANGES[:, 0]) / (RANGES[:, 1] - RANGES[:, 0]), 0, 1)


def generate(n: int = 20000, fraud_rate: float = 0.10, seed: int = 7):
    """Return scaled features X, labels y (1 = fraud) and a customer segment (0/1)."""
    rng = np.random.default_rng(seed)
    n_f = int(n * fraud_rate)
    n_l = n - n_f
    seg = rng.random(n) < 0.35                      # segment 1 = customers under 25
    seg_l, seg_f = seg[:n_l], seg[n_l:]

    def legit(m, s):
        return np.column_stack([
            rng.lognormal(3.8, 0.9, m),                                   # amount
            np.clip(rng.normal(14, 4, m), 0, 23),                         # hour
            rng.exponential(25 + 15 * s, m),                              # distance
            rng.poisson(3 + s, m),                                        # txn count
            rng.beta(2, 8, m),                                            # merchant risk
            np.where(s, rng.uniform(30, 2500, m), rng.uniform(200, 3650, m)),  # account age
            (rng.random(m) < 0.05 + 0.03 * s).astype(float),              # foreign
            (rng.random(m) < 0.7).astype(float)])                         # card present

    def fraud(m, s):
        return np.column_stack([
            rng.lognormal(4.7, 1.1, m),
            np.where(rng.random(m) < 0.45, rng.uniform(0, 6, m), rng.uniform(0, 23, m)),
            rng.exponential(220, m),
            rng.poisson(7, m),
            rng.beta(4, 4, m),
            rng.uniform(10, 2000, m),
            (rng.random(m) < 0.35).astype(float),
            (rng.random(m) < 0.30).astype(float)])

    X = np.vstack([legit(n_l, seg_l), fraud(n_f, seg_f)])
    y = np.concatenate([np.zeros(n_l, int), np.ones(n_f, int)])
    idx = rng.permutation(n)
    return scale(X[idx]), y[idx], seg[idx].astype(int)


def inject_poison(X, y, seg, rate: float = 0.03, seed: int = 11):
    """Simulate a label-poisoning attack through the chargeback-feedback channel.

    The attacker submits fraud-shaped transactions (night, foreign, card-not-present,
    risky merchant) labelled as legitimate, to teach the model to wave that pattern
    through. Returns the poisoned arrays and a mask of injected rows (ground truth
    used only to score the detector).
    """
    rng = np.random.default_rng(seed)
    k = int(len(X) * rate)
    raw = np.column_stack([
        rng.uniform(800, 2500, k), rng.uniform(1, 4, k), rng.uniform(800, 2000, k),
        rng.poisson(9, k), rng.uniform(0.7, 0.95, k), rng.uniform(30, 900, k),
        np.ones(k), np.zeros(k)])
    Xp = np.vstack([X, scale(raw)])
    yp = np.concatenate([y, np.zeros(k, int)])          # mislabelled as legitimate
    sp = np.concatenate([seg, (rng.random(k) < 0.35).astype(int)])
    mask = np.concatenate([np.zeros(len(X), bool), np.ones(k, bool)])
    perm = rng.permutation(len(Xp))
    return Xp[perm], yp[perm], sp[perm], mask[perm]


# ------------------------------------------------------------------ provenance
def dataset_bytes(X, y, seg) -> bytes:
    return np.ascontiguousarray(X).tobytes() + np.ascontiguousarray(y).tobytes() + \
        np.ascontiguousarray(seg).tobytes()


def save_dataset(name: str, X, y, seg, source: str, signer: str = "data_owner") -> dict:
    """Save a dataset with a signed provenance manifest (A.7.3 acquisition, A.7.5 provenance)."""
    folder = home() / "data"
    np.savez_compressed(folder / f"{name}.npz", X=X, y=y, seg=seg)
    digest = hashlib.sha256(dataset_bytes(X, y, seg)).hexdigest()
    manifest = {"dataset": name, "sha256": digest, "rows": int(len(X)), "features": FEATURES,
                "fraud_rate": round(float(y.mean()), 4), "source": source,
                "collected_at": now(), "signed_by": signer}
    key = load_or_create_key(signer)
    manifest["signature"] = sign_bytes(key, json.dumps(manifest, sort_keys=True).encode())
    (folder / f"{name}.manifest.json").write_text(json.dumps(manifest, indent=2))
    return manifest


def load_dataset(name: str):
    d = np.load(home() / "data" / f"{name}.npz")
    return d["X"], d["y"], d["seg"]


def verify_provenance(name: str) -> dict:
    """Check the manifest signature, the content hash and that the source is approved."""
    folder: Path = home() / "data"
    mpath = folder / f"{name}.manifest.json"
    if not mpath.exists():
        return {"verified": False, "reasons": ["no provenance manifest"]}
    manifest = json.loads(mpath.read_text())
    reasons = []
    sig = manifest.pop("signature", "")
    key = load_or_create_key(manifest.get("signed_by", "data_owner"))
    if not verify_bytes(key.public_key(), sig, json.dumps(manifest, sort_keys=True).encode()):
        reasons.append("manifest signature invalid")
    X, y, seg = load_dataset(name)
    if hashlib.sha256(dataset_bytes(X, y, seg)).hexdigest() != manifest["sha256"]:
        reasons.append("dataset content does not match the signed hash (tampered)")
    if manifest.get("source") not in APPROVED_SOURCES:
        reasons.append(f"source '{manifest.get('source')}' is not an approved data source")
    return {"verified": not reasons, "reasons": reasons, "manifest": manifest}
