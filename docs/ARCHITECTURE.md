# Amanah architecture

The exam guide (section 2.2) asks for six kinds of diagram. All six are below, written in
Mermaid, so they render on GitHub, in VS Code, and on mermaid.live, and can be edited live.

## 1. System architecture

Four layers. Each AI system sits behind a guard that writes to one event log. The governance
core reads that log and the evidence ledger, and never talks to customers directly.

```mermaid
flowchart TB
  subgraph Z1["Untrusted zone: internet and partners"]
    C[Customers] ; P[Partner merchants] ; A[Attackers]
  end
  subgraph Z2["Edge zone: guards"]
    G1[LLM guard<br/>injection + output scan]
    G2[Inference gateway<br/>OOD, drift, extraction]
  end
  subgraph Z3["Application zone: AI systems"]
    LLM[Support assistant<br/>external LLM API]
    FM[Fraud-scoring model v2<br/>signed, production]
    DS[(Customer data store<br/>row baselines)]
  end
  subgraph Z4["Restricted zone: Amanah governance core"]
    SIEM[(Unified event log)]
    COR[Correlation engine]
    GOV[Governance: RACI routing,<br/>sign-off, incidents]
    PIPE[Secure MLOps pipeline<br/>+ OPA gate]
    REG[(Signed model registry)]
    LED[(Hash-chained evidence ledger)]
    CMP[Conformance engine<br/>Clauses 4-10, Annex A]
    DASH[Dashboard, SoA,<br/>board report, audit pack]
  end
  C --> G1 --> LLM --> DS
  P --> G2 --> FM
  A -.-> G1 & G2
  G1 & G2 & DS --> SIEM --> COR --> GOV
  PIPE --> REG --> FM
  GOV & PIPE & COR --> LED --> CMP --> DASH
  CMP -- gaps become risks --> GOV
```

## 2. Network and deployment (cloud, hybrid or on-premises)

```mermaid
flowchart LR
  subgraph Internet
    U[Users / partners]
  end
  subgraph DMZ["DMZ (public subnet)"]
    WAF[WAF + API gateway<br/>TLS, rate limits, API keys]
  end
  subgraph App["Private subnet: application"]
    GW[Amanah guards<br/>container]
    MS[Model serving<br/>container]
  end
  subgraph Data["Private subnet: data"]
    DB[(PostgreSQL:<br/>register, findings)]
    OBJ[(Object storage:<br/>models, datasets,<br/>write-once)]
  end
  subgraph Mgmt["Management subnet (no inbound internet)"]
    CI[CI runner:<br/>pipeline + OPA]
    KMS[KMS / HSM:<br/>signing keys]
    SIEMX[SIEM: Elastic / Splunk / Sentinel]
  end
  LLMAPI[External LLM API<br/>supplier-assessed A.10.3]
  U -->|443| WAF --> GW --> MS
  GW -->|egress allow-list| LLMAPI
  MS --> OBJ
  GW --> DB
  CI --> OBJ & KMS & DB
  GW & MS & CI -->|log shipping| SIEMX
```

Cloud: each zone is a VPC subnet with security groups. On-premises: VLANs and firewalls.
Hybrid: the governance core and keys stay on-premises; serving runs in the cloud.

## 3. Data flow (DFD level 1) with trust boundaries

```mermaid
flowchart LR
  E1([Data owner]) -->|"1 dataset + signed manifest"| P1[1.0 Verify provenance]
  P1 -->|verified| P2[2.0 Poisoning scan]
  REF[(D1 Trusted reference data)] --> P2
  P2 -->|clean batch| P3[3.0 Train and harden]
  P2 -->|suspect rows| Q[(D2 Quarantine)]
  P3 --> P4[4.0 Sign and register]
  P4 --> D3[(D3 Model registry)]
  D3 --> P5[5.0 Test: ART, fairness]
  P5 --> P6[6.0 OPA gate]
  E2([Approvers]) -->|sign-offs| P6
  P6 -->|allow| P7[7.0 Serve]
  E3([Customer]) -->|transaction| P7
  P7 -->|score + telemetry| D4[(D4 Event log)]
  P1 & P2 & P5 & P6 -->|evidence| D5[(D5 Evidence ledger)]
```

Trust boundaries are crossed at steps 1 (external data in), 7 (customer input in) and at the
external LLM API. Every crossing is verified (signature, guard) and logged.

## 4. Process flow: model release

```mermaid
flowchart TD
  A[Change request CHG] --> B{Provenance OK?}
  B -- no --> X1[Block + finding A.7.5]
  B -- yes --> C{Poisoning scan under 1.5%?}
  C -- no --> X2[Quarantine + incident A.7.4]
  C -- yes --> D[Train standard or hardened]
  D --> E[Sign Ed25519 + register candidate]
  E --> F[Test: accuracy, recall, PGD robustness, FPR, fairness]
  F --> G{OPA gate}
  G -- technical deny --> X3[Reject + route finding by RACI]
  G -- only human approvals missing --> H[Hold: awaiting approval]
  H --> I[Impact assessment approved + sign-offs]
  I --> G
  G -- allow --> J[Promote to production]
  J --> K[Runtime monitoring]
```

## 5. Security architecture: controls against each threat

```mermaid
flowchart LR
  T1[Evasion ML01] --> C1[ART PGD gate test] & C2[Adversarial training] & C3[OOD detection]
  T2[Poisoning ML02] --> C4[Signed manifests] & C5[kNN label scan + clustering]
  T3[Extraction ML05] --> C6[Per-client query analytics] & C7[Rate limits]
  T4[Injection LLM01] --> C8[Injection scoring] & C9[Correlation CR-001]
  T5[Exfiltration LLM02/06] --> C10[Row baselines] & C9
  T6[Supply chain ML06/LLM03] --> C11[Artifact signatures] & C12[Supplier assessment]
  T7[Insider bypass] --> C13[Least-privilege RBAC] & C14[OPA gate + sign-off]
  C1 & C2 & C5 & C11 --> A1[A.6.2.4 / A.6.2.5]
  C3 & C6 & C8 & C10 --> A2[A.6.2.6 / A.6.2.8]
  C4 --> A3[A.7.3 / A.7.5]
  C9 --> A4[A.8.4 incident communication]
```

Defence in depth: each threat meets at least two independent controls, so one failure is not
a breach. Example from the demo: the injection guard let a 0.75-score message through by design,
and correlation with the data-store baseline caught it.

## 6. Incident workflow (RACI)

```mermaid
sequenceDiagram
  participant M as Monitors
  participant C as Correlation
  participant S as SOC (R)
  participant K as CISO (A)
  participant D as DPO (C)
  participant X as Executives (I)
  M->>C: injection flag (S-7777), bulk read (S-7777)
  C->>S: CR-001 critical incident
  C->>K: notify within 15 min
  C->>D: consult (personal data)
  C->>X: inform
  S->>S: contain: kill session, block IP, revoke token
  S->>K: root cause: guard threshold, no row cap
  K->>K: corrective action approved, incident closed
  Note over C,K: every step written to the evidence ledger (A.8.4, Clause 10.2)
```

## Design decisions and trade-offs (RQF Level 6)

| Decision | Alternative | Why this choice | Cost accepted |
|---|---|---|---|
| Adversarial training for the fraud model | Input sanitisation only | Cuts evasion from 60.3% to 14.6% at the gate strength | False alarms rise from 0.9% to 3.1%; analysts absorb it; the gate caps it at 5% |
| Flag, not block, borderline injections (0.35-0.80) | Block everything suspicious | Real customers write messy messages; over-blocking hurts service | A borderline attack gets through once; correlation catches it within the window |
| Policy-as-code (OPA/Rego) | Gate rules in Python | Rules are auditable, versioned, unit-tested, owned by risk not engineering | One more component; mitigated by a parity-tested built-in fallback |
| Hash-chained evidence ledger | Plain database table | Auditor can verify nothing was edited after the fact | Corrections must be new entries, never edits |
| NumPy model wrapped as an ART estimator | PyTorch | Runs on any CPU laptop; ART attacks are unchanged | Swap the adapter for PyTorchClassifier in production |
| SQLite + file keys | PostgreSQL + KMS | Zero-setup single node for v1 | Must migrate for multi-node and key custody |
| Graph export (Cypher) | Live Neo4j dependency | Works offline; Neo4j optional | Blast-radius queries run in NetworkX until Neo4j is connected |

## Failure and recovery

| Failure | Detection | Recovery |
|---|---|---|
| OPA binary missing or crashes | Policy engine falls back | Built-in evaluator applies the same rules (parity tested) |
| Model file corrupted or swapped | Signature check on every load | Load refused; previous signed production version keeps serving |
| Evidence row edited | `amanah verify` recomputes the chain | Exact entry reported; restore from backup; incident raised |
| Monitor floods with false positives | Alert counts on dashboard | Thresholds live in config/platform.yaml, change goes through sign-off |
| Critical incident open | Gate rule (Clause 10.2) | New releases for that system blocked until incident closed |
| Poisoned batch reaches storage | Scan before training | Batch quarantined; model never trained on it |

## Scalability

Guards are stateless per request except per-client counters, which move to Redis when scaled
horizontally. The event log ships to a SIEM that already scales. Pipeline runs are independent
jobs in CI. Robustness tests are the heaviest step (a few seconds here) and parallelise per epsilon.
