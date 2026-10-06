# Amanah deployment gate (policy-as-code).
# Every model version must satisfy every rule below before it can be promoted to
# production. The pipeline sends the evidence it gathered as `input`; OPA answers
# with `allow` and the list of reasons in `deny`.
package amanah.deployment

import rego.v1

default allow := false

allow if count(deny) == 0

t := input.thresholds

# A.6.2.5 deployment: only signed, untampered artifacts ship.
deny contains "artifact signature missing or invalid (A.6.2.5)" if {
	not input.artifact.signature_valid
}

# A.6.2.4 verification and validation: baseline quality.
deny contains sprintf("clean accuracy %.3f below %.2f (A.6.2.4)", [input.metrics.clean_accuracy, t.min_clean_accuracy]) if {
	input.metrics.clean_accuracy < t.min_clean_accuracy
}

deny contains sprintf("fraud recall %.3f below %.2f (A.6.2.4)", [input.metrics.clean_fraud_recall, t.min_clean_fraud_recall]) if {
	input.metrics.clean_fraud_recall < t.min_clean_fraud_recall
}

# A.6.2.4: adversarial robustness (ART PGD at the gate epsilon).
deny contains sprintf("robust fraud recall %.3f under PGD below %.2f (A.6.2.4, OWASP ML01)", [input.metrics.robust_fraud_recall, t.min_robust_fraud_recall]) if {
	input.metrics.robust_fraud_recall < t.min_robust_fraud_recall
}

deny contains sprintf("evasion success rate %.3f above %.2f (A.6.2.4, OWASP ML01)", [input.metrics.evasion_success_rate, t.max_evasion_success_rate]) if {
	input.metrics.evasion_success_rate > t.max_evasion_success_rate
}

deny contains sprintf("false-positive rate %.3f above %.2f (A.5.4 customer impact)", [input.metrics.false_positive_rate, t.max_false_positive_rate]) if {
	input.metrics.false_positive_rate > t.max_false_positive_rate
}

# A.7.4 / A.7.5: training data must pass provenance and poisoning checks.
deny contains "training data provenance not verified (A.7.5)" if {
	not input.data.provenance_verified
}

deny contains sprintf("poisoning scan flagged %.4f of the batch, limit %.2f (A.7.4, OWASP ML02)", [input.data.poisoning_suspect_rate, t.max_poisoning_suspect_rate]) if {
	input.data.poisoning_suspect_rate > t.max_poisoning_suspect_rate
}

# A.5.4: fairness across customer segments (four-fifths rule).
deny contains sprintf("disparate impact %.3f below %.2f (A.5.4)", [input.metrics.disparate_impact, t.min_disparate_impact]) if {
	input.metrics.disparate_impact < t.min_disparate_impact
}

# Clause 8.4 / A.5.2: an approved impact assessment must exist.
deny contains "impact assessment not approved (Clause 8.4, A.5.2)" if {
	input.impact_assessment.status != "approved"
}

# Clause 6.3: high-risk changes need named human sign-off.
deny contains sprintf("missing sign-off from %s (Clause 6.3)", [role]) if {
	some role in input.required_signoffs
	not role in input.signoffs
}

# Clause 10.2: no promotion while a critical incident is open on this system.
deny contains sprintf("open critical incident %s on this system (Clause 10.2)", [inc]) if {
	some inc in input.open_critical_incidents
}
