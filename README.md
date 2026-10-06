# Amanah: AI governance and security assurance platform (v1.0)

*Amanah* (Arabic: a trust placed in your care) is an ISO/IEC 42001:2023-aligned AI management
platform. It defends deployed machine-learning and LLM systems against adversarial, data-integrity
and misuse threats, and it proves conformance continuously from evidence it collects itself.

Built for EduQual Level 6, Diploma in Artificial Intelligence Operations (Topic 231), by Anya Yameen.

## What it does

| Capability | How | Standard mapping |
|---|---|---|
| AI risk register with explainable scoring | Likelihood x impact, with each point traced to a system attribute (public, free text, tool access, criticality) | Clauses 6.1.2, 8.2, 8.3; ISO/IEC 23894 |
| Impact assessments | Structured pre-deployment assessment, human approval required | Clauses 6.1.4, 8.4; A.5.2-A.5.5 |
| Adversarial robustness testing | IBM ART FGSM and PGD against the real model, attacker-controlled features only | A.6.2.4; OWASP ML01 |
| Mitigation | ART AdversarialTrainer (PGD examples mixed into training) | A.6.2.4 |
| Data-poisoning detection | Signed provenance manifests plus a 4-check statistical scan before training | A.7.3, A.7.4, A.7.5; OWASP ML02 |
| Runtime monitoring | Out-of-distribution, confidence drift and model-extraction detection per client | A.6.2.6; OWASP ML05 |
| LLM guardrails | Prompt-injection scoring, output leak scanning, per-session data-access baselines | OWASP LLM01, LLM02, LLM06, LLM07 |
| Cross-model correlation | Rules join events across systems by session or client inside a time window | A.6.2.8; OWASP mapping on every event |
| Governance routing | RACI matrix, severity-based escalation deadlines, named sign-off | Clauses 5.3, 6.3; A.3.2 |
| Incident workflow | Detect, contain, notify, root cause, report, close; each step evidenced | A.8.4; Clause 10.2 |
| Secure MLOps | Ed25519-signed artifacts, least-privilege access control, Open Policy Agent deployment gate | A.6.2.5; OWASP ML06 |
| Continuous conformance | Clauses 4-10 and all 38 Annex A controls scored from evidence; gaps fed back into the risk register | Clauses 9.1, 9.2, 10.1 |
| Audit readiness | Hash-chained evidence ledger, Statement of Applicability, board report with NIST AI RMF and ISO/IEC 23894 crosswalks, audit pack zip, Neo4j export | Clause 7.5; A.8.3 |

## Quick start

```bash
pip install -r requirements.txt
make opa                      # downloads the Open Policy Agent binary to bin/opa (optional)
python -m amanah demo         # full end-to-end story, about 20 seconds on a laptop CPU
open var/reports/dashboard.html
```

Without OPA installed, the gate runs on a built-in evaluator that applies the same rules
(`tests/test_policy_parity.py` proves both engines agree).

Docker: `docker compose up --build` runs the demo and serves the dashboard on http://localhost:8080.

## What the demo shows (real results from `docs/sample-output/demo-run.txt`)

| Step | What happens | Result |
|---|---|---|
| Standard retrain | ART PGD flips 60% of caught fraud to "legitimate" | Gate **denies** (OWASP ML01, A.6.2.4) |
| Hardened retrain | ART adversarial training; evasion drops to 14.6%, fraud recall 86.0% | Gate **holds** for human sign-off |
| Sign-off | AI Risk Officer, Model Owner, DPO approve | Gate **allows**, v2 deployed |
| Poisoned batch | 300 mislabelled rows via the chargeback channel | All 300 caught; batch **quarantined** before training |
| Tampered batch | Labels edited after signing | Hash mismatch; **blocked** |
| Tampered model file | One byte flipped | Signature check **fails** |
| Privilege bypass | ML engineer tries to promote directly | **Denied**, logged, finding raised |
| Model extraction | 900 sweeping and boundary-probing queries | Flagged; correlated into an incident |
| Chatbot attack | Borderline injection (allowed) plus 1,200-row data pull | Correlated as one **critical** attack |
| Conformance | 36/38 Annex A controls implemented; 2 honest gaps | Gaps pushed into the risk register |

## Commands

```
python -m amanah init | demo | status | verify | audit | report | dashboard
python -m amanah pipeline run [--hardened] [--dataset NAME] [--change ID] [--label TEXT]
python -m amanah gate recheck RUN_ID
python -m amanah signoff CHANGE_ID SYSTEM ROLE "Name"
python -m amanah ia approve IA_ID "Name"
python -m amanah simulate traffic|chatbot|access|tamper
python -m amanah correlate
python -m amanah incident advance INC_ID contained|notified|root_cause|reported|closed "note"
python -m amanah graph impact A.6.2.4        # which risks and systems depend on this control
```

## Layout

```
amanah/        platform code (one module per capability)
config/        ISO 42001 catalog, AI system inventory, thresholds, threats, RACI, correlation rules
policies/      Rego deployment gate and its OPA unit tests
governance/    AI policy, acceptable use, risk methodology, incident procedure, supplier assessment
tests/         pytest suite
docs/          architecture, demo script, sample output
var/           runtime workspace (database, keys, registry, SIEM log, reports) - created on first run
```

## Production notes and honest limits

* The reference model is a NumPy neural network exposed to IBM ART as a genuine ART estimator, so the
  platform runs on any CPU. For PyTorch models, use `art.estimators.classification.PyTorchClassifier`.
* Data is synthetic so the platform runs without customer data; plug real loaders into `amanah/data.py`.
* The chatbot is simulated behind a real guard; connect `SupportAssistantGateway` to your LLM API.
* SQLite and file keys are for a single node. Use PostgreSQL and a KMS or HSM signer in production.
* The event log is ECS-style JSON lines; ship it to Elastic, Splunk, Wazuh or Sentinel with their
  file forwarders. Notifications land in `var/outbox`; wire `governance.deliver()` to email or Slack.
* Control titles are paraphrased; consult the licensed ISO/IEC 42001 text for normative wording.
