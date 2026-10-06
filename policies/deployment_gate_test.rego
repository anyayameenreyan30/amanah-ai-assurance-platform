package amanah.deployment_test

import rego.v1

import data.amanah.deployment

good := {
	"thresholds": {
		"min_clean_accuracy": 0.9, "min_clean_fraud_recall": 0.8, "min_robust_fraud_recall": 0.7,
		"max_evasion_success_rate": 0.25, "max_false_positive_rate": 0.05, "min_disparate_impact": 0.8, "max_poisoning_suspect_rate": 0.01,
	},
	"artifact": {"signature_valid": true},
	"metrics": {
		"clean_accuracy": 0.97, "clean_fraud_recall": 0.9, "robust_fraud_recall": 0.8,
		"evasion_success_rate": 0.1, "disparate_impact": 0.95, "false_positive_rate": 0.02,
	},
	"data": {"provenance_verified": true, "poisoning_suspect_rate": 0.0},
	"impact_assessment": {"status": "approved"},
	"required_signoffs": ["ai_risk_officer"],
	"signoffs": ["ai_risk_officer"],
	"open_critical_incidents": [],
}

test_good_model_allowed if deployment.allow with input as good

test_unsigned_model_denied if {
	not deployment.allow with input as object.union(good, {"artifact": {"signature_valid": false}})
}

test_weak_robustness_denied if {
	bad := object.union(good, {"metrics": object.union(good.metrics, {"robust_fraud_recall": 0.2})})
	not deployment.allow with input as bad
}

test_missing_signoff_denied if {
	not deployment.allow with input as object.union(good, {"signoffs": []})
}

test_open_incident_denied if {
	not deployment.allow with input as object.union(good, {"open_critical_incidents": ["INC-1"]})
}

test_false_alarm_burden_denied if {
	bad := object.union(good, {"metrics": object.union(good.metrics, {"false_positive_rate": 0.2})})
	not deployment.allow with input as bad
}
