---
title: AI Risk Assessment Methodology
doc_id: AIMS-PRO-003
status: approved
owner: AI Risk Officer
approved_by: AI Governance Board
approved_on: 2026-09-15
next_review: 2027-03-15
evidence: risk_methodology_doc
---
# AI risk assessment methodology (Clause 6.1.2, aligned with ISO/IEC 23894)

## Scale
Risk score = Likelihood (1-5) x Impact (1-5).
| Score | Level | Response |
|---|---|---|
| 20-25 | Critical | Treat before deployment; executive visibility |
| 12-19 | High | Treat before deployment; AI Risk Officer sign-off |
| 6-11 | Medium | Treat within the quarter |
| 1-5 | Low | Accept and monitor |

## Scenario-based scoring
Each threat has a base likelihood and impact. Points are added only for named system
attributes, so every score can be explained:
- Public exposure raises likelihood (anyone can attack it).
- Free-text input raises likelihood for manipulation threats (more room to hide an attack).
- Tool access raises impact for injection threats (the model can act, not just talk).
- High decision criticality raises impact (decisions affect customers' money).

## Triggers for reassessment
Every retrain, every material change, every confirmed incident (likelihood is raised to 5
when a risk materialises), and every conformance gap found by the dashboard.
