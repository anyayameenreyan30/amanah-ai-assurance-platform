---
title: AI Incident Response Procedure
doc_id: AIMS-PRO-004
status: approved
owner: CISO
approved_by: AI Governance Board
approved_on: 2026-09-15
next_review: 2027-03-15
evidence: incident_procedure_doc
---
# AI incident response procedure (A.8.4, Clause 10.2)

| Step | Who (RACI) | What | Platform evidence |
|---|---|---|---|
| 1. Detect | Platform | Monitors and correlation rules raise a finding | incident_record |
| 2. Contain | Security Operations | Block the session or client, rate-limit the API, roll back the model if needed | incident_record |
| 3. Notify | Platform via RACI | Accountable owner, DPO and leadership within the severity deadline | stakeholder_notification |
| 4. Root cause | Model Owner + SOC | Which control failed or was bypassed, and why | corrective_action |
| 5. Report | DPO / AI Risk Officer | Internal report; regulator or customer notice where required | incident_record |
| 6. Close | CISO | Corrective action verified, risk register updated | corrective_action |

Critical incidents block any new deployment of the affected system until closed.
