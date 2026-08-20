package cis_kms_test

import rego.v1

meta := {"account_id": "111122223333", "scanned_at": "2026-08-20T00:00:00Z", "collected_types": []}

denials(doc) := d if {
	all_denies := data.cis_kms.deny with input as doc
	d := [e | some e in all_denies; e.control == "KMS.4"]
}

applicables(doc) := a if {
	all_apps := data.cis_kms.applicable with input as doc
	a := [e | some e in all_apps; e.control == "KMS.4"]
}

test_kms_4_fails_without_rotation if {
	doc := {"meta": meta, "resources": [{"_type": "aws_kms_key", "_name": "app-key", "enable_key_rotation": false}]}
	count(denials(doc)) == 1
}

test_kms_4_passes_with_rotation if {
	doc := {"meta": meta, "resources": [{"_type": "aws_kms_key", "_name": "app-key", "enable_key_rotation": true}]}
	count(denials(doc)) == 0
}

test_kms_4_skips_asymmetric_keys if {
	doc := {"meta": meta, "resources": [{"_type": "aws_kms_key", "_name": "signing-key", "customer_master_key_spec": "RSA_2048", "key_usage": "SIGN_VERIFY", "enable_key_rotation": false}]}
	count(denials(doc)) == 0
	count(applicables(doc)) == 0
}
