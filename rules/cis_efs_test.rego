package cis_efs_test

import rego.v1

meta := {"account_id": "111122223333", "scanned_at": "2026-08-20T00:00:00Z", "collected_types": []}

denials(doc, control) := d if {
	all_denies := data.cis_efs.deny with input as doc
	d := [e | some e in all_denies; e.control == control]
}

test_efs_fails_when_unencrypted if {
	doc := {"meta": meta, "resources": [{"_type": "aws_efs_file_system", "_name": "shared", "encrypted": false}]}
	count(denials(doc, "EFS.1")) == 1
	count(denials(doc, "EFS.8")) == 1
}

test_efs_passes_when_encrypted if {
	doc := {"meta": meta, "resources": [{"_type": "aws_efs_file_system", "_name": "shared", "encrypted": true}]}
	count(denials(doc, "EFS.1")) == 0
	count(denials(doc, "EFS.8")) == 0
}
