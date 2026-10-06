---
title: AI Policy
doc_id: AIMS-POL-001
status: approved
owner: AI Risk Officer
approved_by: Chief Executive Officer
approved_on: 2026-09-15
next_review: 2027-09-15
evidence: ai_policy_doc, concern_channel, policy_review
---
# AI Policy (AIMS-POL-001)

## 1. Purpose
Meridian Financial uses AI to protect customers from fraud and to answer their questions.
This policy sets the rules every AI system in the AIMS scope must follow so that it stays
safe, fair, secure and accountable across its whole life cycle. (ISO/IEC 42001 Clause 5.2, A.2.2)

## 2. Commitments by top management (Clause 5.1)
1. AI risk is managed like any enterprise risk: identified, scored, treated, monitored.
2. No AI system reaches production without passing the automated deployment gate and,
   for high-risk changes, named human sign-off.
3. Resources for the AIMS (people, tooling, compute) are funded each budget cycle.

## 3. AI objectives (Clause 6.2, A.6.1.2)
| Objective | Measure | Target |
|---|---|---|
| Catch fraud reliably | Fraud recall on holdout data | >= 80% |
| Resist evasion | Fraud recall under PGD attack (epsilon 0.10) | >= 70% |
| Treat customers fairly | Disparate impact on legitimate-payment pass rates | >= 0.80 |
| Limit customer friction | False-positive rate | <= 5% |
| Respond to AI incidents fast | Critical incidents reaching the CISO | within 15 minutes |

## 4. Alignment with other policies (A.2.3)
This policy works alongside the Information Security Policy (ISO/IEC 27001 ISMS), the
Data Protection Policy and the Model Risk Management Standard. Where they overlap, the
stricter requirement applies.

## 5. Roles
Roles and accountabilities are defined in the RACI matrix (config/raci.yaml). The AI
Risk Officer owns this policy; the AI Governance Board approves it.

## 6. Reporting concerns (A.3.3)
Anyone (staff, contractors, customers) can raise a concern about bias, safety or misuse
of an AI system at ai-concerns@meridian.example or through the anonymous ethics line.
Concerns are logged as findings and routed through the RACI matrix. Retaliation against
anyone raising a concern in good faith is prohibited.

## 7. Review (A.2.4)
Reviewed every 12 months, and after any critical AI incident or material change to an
in-scope AI system.
