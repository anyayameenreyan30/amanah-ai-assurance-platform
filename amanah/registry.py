"""Access-controlled model registry with signed artifacts (A.6.2.5 deployment, OWASP ML06/LLM03).

Every model version is stored with its SHA-256 and an Ed25519 signature made by the
pipeline's own key. Production loading re-verifies the signature, so a weights file
swapped on disk (supply-chain tampering) is refused at load time.
"""
from __future__ import annotations

import hashlib
import json

from .core import Config, Store, home, new_id, now, record_evidence
from .crypto import load_or_create_key, sign_bytes, verify_bytes
from .governance import authorize
from .model import FraudMLP

SIGNER = "pipeline_service"


def _signed_payload(sha256: str, system_id: str, version: int) -> bytes:
    return json.dumps({"sha256": sha256, "system": system_id, "version": version}, sort_keys=True).encode()


def register(store: Store, cfg: Config, system_id: str, model: FraudMLP, metrics: dict,
             actor: str = SIGNER, change_id: str | None = None) -> dict:
    authorize(store, cfg, actor, "model_weights", "write")
    last = store.one("SELECT MAX(version) v FROM models WHERE system_id=?", [system_id])
    version = (last["v"] or 0) + 1
    blob = model.to_bytes()
    sha = hashlib.sha256(blob).hexdigest()
    path = home() / "registry" / f"{system_id}-v{version}.npz"
    path.write_bytes(blob)
    sig = sign_bytes(load_or_create_key(SIGNER), _signed_payload(sha, system_id, version))
    mid = new_id("MDL")
    store.insert("models", {"id": mid, "system_id": system_id, "version": version,
                            "path": str(path.relative_to(home())), "sha256": sha, "signature": sig,
                            "stage": "candidate", "metrics": metrics, "created_at": now(),
                            "promoted_at": None, "change_id": change_id})
    record_evidence(store, "model_signature", f"{system_id} v{version} signed (sha256 {sha[:12]})",
                    {"model": mid, "sha256": sha, "signer": SIGNER, "algorithm": "Ed25519"},
                    system_id=system_id)
    return {"id": mid, "version": version, "sha256": sha}


def verify(store: Store, model_id: str) -> dict:
    m = store.one("SELECT * FROM models WHERE id=?", [model_id])
    blob = (home() / m["path"]).read_bytes()
    sha = hashlib.sha256(blob).hexdigest()
    pub = load_or_create_key(SIGNER).public_key()
    sig_ok = verify_bytes(pub, m["signature"], _signed_payload(m["sha256"], m["system_id"], m["version"]))
    return {"hash_matches": sha == m["sha256"], "signature_valid": sig_ok and sha == m["sha256"]}


def promote(store: Store, cfg: Config, model_id: str, actor: str = SIGNER) -> None:
    authorize(store, cfg, actor, "production_promotion", "write")
    m = store.one("SELECT * FROM models WHERE id=?", [model_id])
    store.conn.execute("UPDATE models SET stage='archived' WHERE system_id=? AND stage='production'",
                       [m["system_id"]])
    store.update("models", "id", model_id, stage="production", promoted_at=now())
    record_evidence(store, "deployment_record", f"{m['system_id']} v{m['version']} promoted to production",
                    {"model": model_id}, system_id=m["system_id"], result="deployed")


def load_production(store: Store, cfg: Config, system_id: str, actor: str = SIGNER) -> tuple[FraudMLP, dict]:
    authorize(store, cfg, actor, "model_weights", "read")
    m = store.one("SELECT * FROM models WHERE system_id=? AND stage='production'", [system_id])
    if not m:
        raise LookupError(f"no production model for {system_id}")
    v = verify(store, m["id"])
    if not v["signature_valid"]:
        raise PermissionError(f"refusing to load {system_id} v{m['version']}: signature check failed")
    return FraudMLP.from_bytes((home() / m["path"]).read_bytes()), m


def write_model_card(store: Store, cfg: Config, system_id: str, model_id: str, metrics: dict,
                     training: dict) -> str:
    """Model card: requirements, intended use, limits and test results (A.6.2.2/3/7, A.8.2, A.9.4)."""
    m = store.one("SELECT * FROM models WHERE id=?", [model_id])
    s = cfg.system(system_id)
    card = f"""# Model card: {s['name']} v{m['version']}

**Model ID:** {model_id}  |  **SHA-256:** `{m['sha256']}`  |  **Signed by:** {SIGNER} (Ed25519)

## Intended use
Scores card transactions for fraud risk. Scores above the operating threshold route the
transaction to an analyst; the model never closes accounts or denies credit on its own.

## Out of scope and foreseeable misuse
Credit decisions, customer profiling, or use on transaction types outside the training
distribution. Fraudsters will try to craft transactions that evade the model (tested below).

## Requirements
Clean accuracy >= {cfg.thresholds['min_clean_accuracy']}, fraud recall >= {cfg.thresholds['min_clean_fraud_recall']},
robust fraud recall >= {cfg.thresholds['min_robust_fraud_recall']} under PGD (epsilon {cfg.thresholds['gate_epsilon']}),
false-positive rate <= {cfg.thresholds['max_false_positive_rate']}, disparate impact >= {cfg.thresholds['min_disparate_impact']}.

## Design
Multilayer perceptron {training.get('architecture')}; training mode: {training.get('mode')};
training rows: {training.get('rows')}; epochs: {training.get('epochs')}.

## Results
| Metric | Value |
|---|---|
""" + "\n".join(f"| {k} | {v} |" for k, v in metrics.items()) + """

## Limitations
Trained on synthetic reference data; recalibrate on production data before go-live.
Adversarial training raises the false-alarm rate; analysts absorb that cost by design.
"""
    path = home() / "reports" / f"model-card-{system_id}-v{m['version']}.md"
    path.write_text(card, encoding="utf-8")
    record_evidence(store, "model_card", f"model card written for {system_id} v{m['version']}",
                    {"path": str(path.name), "metrics": metrics}, system_id=system_id)
    return str(path)
