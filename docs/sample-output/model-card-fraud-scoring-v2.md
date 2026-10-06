# Model card: Card fraud scoring model v2

**Model ID:** MDL-1C461C70  |  **SHA-256:** `339a6bb7443687a8edeaa2fcf010d44dbf329b6ee044aef5c066155d51512321`  |  **Signed by:** pipeline_service (Ed25519)

## Intended use
Scores card transactions for fraud risk. Scores above the operating threshold route the
transaction to an analyst; the model never closes accounts or denies credit on its own.

## Out of scope and foreseeable misuse
Credit decisions, customer profiling, or use on transaction types outside the training
distribution. Fraudsters will try to craft transactions that evade the model (tested below).

## Requirements
Clean accuracy >= 0.9, fraud recall >= 0.8,
robust fraud recall >= 0.7 under PGD (epsilon 0.1),
false-positive rate <= 0.05, disparate impact >= 0.8.

## Design
Multilayer perceptron 8-64-32-2; training mode: ART adversarial training (PGD, ratio 0.5);
training rows: 30000; epochs: 16.

## Results
| Metric | Value |
|---|---|
| clean_accuracy | 0.958 |
| clean_fraud_recall | 0.86 |
| false_positive_rate | 0.0311 |
| precision | 0.7544 |
| disparate_impact | 0.9858 |
| robust_fraud_recall | 0.734 |
| evasion_success_rate | 0.1465 |

## Limitations
Trained on synthetic reference data; recalibrate on production data before go-live.
Adversarial training raises the false-alarm rate; analysts absorb that cost by design.
