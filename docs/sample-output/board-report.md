# AI governance board report
Generated 2026-10-04T22:17:33+00:00 for Meridian Financial (reference deployment)

## Position in one paragraph
36 of 38 ISO/IEC 42001 Annex A controls are implemented with evidence, 0 are partial and 2 are gaps. 4 AI incidents were recorded this period; 0 remain open. The evidence ledger holds 85 entries.

## Clause conformance
| Clause | Title | Score |
|---|---|---|
| 4 | Context of the organization | 100% |
| 5 | Leadership | 100% |
| 6 | Planning | 100% |
| 7 | Support | 60% |
| 8 | Operation | 100% |
| 9 | Performance evaluation | 100% |
| 10 | Improvement | 100% |

## Top risks
| Risk | System | Score | Level | Status |
|---|---|---|---|---|
| Data poisoning | fraud-scoring | 25 | critical | treated |
| Prompt injection | support-llm | 20 | critical | treated |
| Data exfiltration through AI tools | support-llm | 20 | critical | treated |
| Adversarial evasion | fraud-scoring | 12 | high | treated |
| Unfair outcomes across customer groups | fraud-scoring | 12 | high | assessed |
| Data poisoning | support-llm | 12 | high | assessed |

## Incidents
| Incident | Severity | State | Title |
|---|---|---|---|
| INC-0FC5E8AA | high | closed | Training batch 'tampered-batch' quarantined before training |
| INC-B8BF3FE6 | critical | closed | CR-001 Prompt injection followed by bulk data access (session_id=S-7777) |
| INC-C3B81FBD | high | closed | CR-002 Model extraction campaign (client_id=api-key-7731) |
| INC-1F1316E8 | high | closed | Training batch 'partner-batch' quarantined before training |

## Model releases
| Run | Change | Outcome |
|---|---|---|
| RUN-C74F4C77 | Q4 retrain, standard | rejected |
| RUN-BAFBB075 | Q4 retrain, adversarially hardened | deployed |
| RUN-C8AA9958 | Partner feedback batch | blocked_at_data |
| RUN-47E41D6A | Tampered batch | blocked_at_data |

## NIST AI RMF 1.0 alignment
| Function | Evidence held |
|---|---|
| GOVERN | ai_policy_doc (1), roles_raci (1), signoff_record (3), management_review (1) |
| MAP | system_inventory (1), risk_register (1), impact_assessment (3) |
| MEASURE | robustness_test (2), poisoning_scan (4), fairness_test (2), runtime_monitoring (2) |
| MANAGE | risk_treatment (1), deployment_gate (3), incident_record (11), corrective_action (8) |

## ISO/IEC 23894 risk process alignment
| Process step | Evidence held |
|---|---|
| Risk identification | risk_register (1) |
| Risk analysis | risk_register (1), robustness_test (2) |
| Risk evaluation | risk_register (1), deployment_gate (3) |
| Risk treatment | risk_treatment (1), corrective_action (8) |
| Monitoring and review | runtime_monitoring (2), internal_audit (1) |
| Recording and reporting | event_log (1), board_report (1) |
