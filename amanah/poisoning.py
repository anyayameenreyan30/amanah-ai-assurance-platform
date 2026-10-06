"""Pre-training data-poisoning scan (A.7.4 data quality, OWASP ML02).

Runs on every new training batch before the model ever sees it. Four independent
checks, so an attacker has to beat all of them at once:

1. Label consistency  - each new row is compared with its nearest neighbours in a
   trusted, previously verified reference set. A "legitimate" label sitting in a
   neighbourhood that is overwhelmingly fraud (or the reverse) is suspicious.
2. Label-rate shift   - the batch's fraud rate is tested against the reference rate.
3. Feature drift      - a two-sample Kolmogorov-Smirnov test per feature.
4. Coordination       - suspicious rows that sit tightly together (DBSCAN) indicate a
   deliberate campaign rather than random labelling noise.
"""
from __future__ import annotations

import numpy as np
from scipy import stats
from sklearn.cluster import DBSCAN
from sklearn.neighbors import NearestNeighbors

from .data import FEATURES


def scan(X_new, y_new, X_ref, y_ref, k: int = 15, disagreement: float = 0.85,
         truth_mask=None) -> dict:
    nn = NearestNeighbors(n_neighbors=k).fit(X_ref)
    _, idx = nn.kneighbors(X_new)
    neigh_fraud = y_ref[idx].mean(1)
    # Share of neighbours whose label disagrees with the row's own label.
    disagree = np.where(y_new == 1, 1 - neigh_fraud, neigh_fraud)
    suspect = disagree >= disagreement

    # Label-rate shift (two-sided binomial test).
    ref_rate = float(y_ref.mean())
    btest = stats.binomtest(int(y_new.sum()), len(y_new), ref_rate)

    drift = {}
    for j, name in enumerate(FEATURES):
        ks = stats.ks_2samp(X_new[:, j], X_ref[:, j])
        drift[name] = {"ks": round(float(ks.statistic), 4), "p": float(ks.pvalue)}
    drifted = [f for f, d in drift.items() if d["p"] < 0.001 and d["ks"] > 0.05]

    clusters = []
    if suspect.sum() >= 10:
        lab = DBSCAN(eps=0.12, min_samples=8).fit_predict(X_new[suspect])
        for c in sorted(set(lab) - {-1}):
            members = np.where(suspect)[0][lab == c]
            centre = X_new[members].mean(0)
            clusters.append({"size": int(len(members)),
                             "label_claimed": "legitimate" if y_new[members].mean() < 0.5 else "fraud",
                             "centre": {f: round(float(v), 3) for f, v in zip(FEATURES, centre)}})
    coordinated = any(c["size"] >= 20 for c in clusters)

    result = {
        "rows": int(len(X_new)),
        "suspect_rows": int(suspect.sum()),
        "suspect_rate": round(float(suspect.mean()), 4),
        "suspect_indices": np.where(suspect)[0].tolist(),
        "label_rate": {"batch": round(float(y_new.mean()), 4), "reference": round(ref_rate, 4),
                       "p_value": float(btest.pvalue)},
        "drifted_features": drifted,
        "feature_drift": drift,
        "clusters": clusters,
        "coordinated_campaign": coordinated,
    }
    if truth_mask is not None:            # only available in simulations
        tp = int((suspect & truth_mask).sum())
        result["detector_quality"] = {
            "injected_rows": int(truth_mask.sum()),
            "caught": tp,
            "recall": round(tp / max(truth_mask.sum(), 1), 3),
            "precision": round(tp / max(suspect.sum(), 1), 3)}
    return result
