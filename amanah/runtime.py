"""Runtime monitoring for deployed models (A.6.2.6 operation and monitoring).

Every prediction goes through the InferenceGateway, which watches three things:

* Out-of-distribution inputs  - Mahalanobis distance from the training data. Inputs
  further out than the 99.5th percentile of training data are flagged.
* Confidence drift            - the rolling mean confidence is compared with the
  confidence seen at validation time; a sustained drop signals drift or attack.
* Extraction attempts         - per client: query volume, the share of queries that
  land right on the decision boundary, and how evenly the client covers the feature
  space. Customers send a few realistic transactions; an extractor sweeps the space.
"""
from __future__ import annotations

from collections import defaultdict, deque

import numpy as np

from .core import emit_event


class InferenceGateway:
    def __init__(self, model, X_train, cfg_runtime: dict, system_id: str = "fraud-scoring") -> None:
        self.model = model
        self.cfg = cfg_runtime
        self.system_id = system_id
        self.mu = X_train.mean(0)
        cov = np.cov(X_train, rowvar=False) + np.eye(X_train.shape[1]) * 1e-6
        self.cov_inv = np.linalg.inv(cov)
        d = self._mahalanobis(X_train)
        self.ood_threshold = float(np.percentile(d, cfg_runtime["ood_percentile"]))
        self.baseline_conf = float(model.predict_proba(X_train).max(1).mean())
        self.recent_conf: deque = deque(maxlen=cfg_runtime["confidence_drift_window"])
        self.clients: dict = defaultdict(list)
        self.stats = {"predictions": 0, "ood": 0, "drift_alerts": 0, "extraction_alerts": 0}
        self._flagged_clients: set = set()
        self._drift_alerted = False

    def _mahalanobis(self, X):
        diff = X - self.mu
        return np.sqrt(np.einsum("ij,jk,ik->i", diff, self.cov_inv, diff))

    def predict(self, X, client_id: str, source_ip: str | None = None) -> np.ndarray:
        X = np.atleast_2d(X)
        proba = self.model.predict_proba(X)
        dist = self._mahalanobis(X)
        self.stats["predictions"] += len(X)
        for x, p, d in zip(X, proba, dist):
            self.recent_conf.append(float(p.max()))
            self.clients[client_id].append((x, float(p[1])))
            if d > self.ood_threshold:
                self.stats["ood"] += 1
                emit_event(self.system_id, "out_of_distribution_input", "low", client_id=client_id,
                           source_ip=source_ip, owasp=["ML01"],
                           detail={"mahalanobis": round(float(d), 2),
                                   "threshold": round(self.ood_threshold, 2)})
        self._check_drift()
        self._check_extraction(client_id, source_ip)
        return proba

    def _check_drift(self) -> None:
        if len(self.recent_conf) < self.recent_conf.maxlen or self._drift_alerted:
            return
        mean = float(np.mean(self.recent_conf))
        if self.baseline_conf - mean > self.cfg["confidence_drift_drop"]:
            self._drift_alerted = True
            self.stats["drift_alerts"] += 1
            emit_event(self.system_id, "confidence_drift", "medium",
                       detail={"baseline": round(self.baseline_conf, 3), "rolling": round(mean, 3)})

    def client_profile(self, client_id: str) -> dict:
        q = self.clients[client_id]
        if not q:
            return {}
        X = np.array([a for a, _ in q])
        p = np.array([b for _, b in q])
        boundary = float(((p > 0.3) & (p < 0.7)).mean())
        ent = []
        for j in range(X.shape[1]):
            h, _ = np.histogram(X[:, j], bins=10, range=(0, 1))
            pr = h[h > 0] / h.sum()
            ent.append(float(-(pr * np.log(pr)).sum() / np.log(10)))
        return {"queries": len(q), "boundary_ratio": round(boundary, 3),
                "coverage_entropy": round(float(np.mean(ent)), 3)}

    def _check_extraction(self, client_id: str, source_ip: str | None) -> None:
        if client_id in self._flagged_clients:
            return
        q = self.clients[client_id]
        if len(q) < self.cfg["extraction_window_queries"]:
            return
        prof = self.client_profile(client_id)
        if (prof["boundary_ratio"] >= self.cfg["extraction_boundary_ratio"]
                or prof["coverage_entropy"] >= self.cfg["extraction_coverage_entropy"]):
            self._flagged_clients.add(client_id)
            self.stats["extraction_alerts"] += 1
            emit_event(self.system_id, "extraction_suspected", "high", client_id=client_id,
                       source_ip=source_ip, owasp=["ML05"], detail=prof)
