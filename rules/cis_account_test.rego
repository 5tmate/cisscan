package cis_account_test

import rego.v1

meta := {
	"account_id": "111122223333",
	"scanned_at": "2026-08-20T00:00:00Z",
	"collected_types": ["aws_account_alternate_contact"],
}

denials(doc, control) := d if {
	all_denies := data.cis_account.deny with input as doc
	d := [e | some e in all_denies; e.control == control]
}

applicables(doc, control) := a if {
	all_apps := data.cis_account.applicable with input as doc
	a := [e | some e in all_apps; e.control == control]
}

test_account_1_fails_without_security_contact if {
	doc := {"meta": meta, "resources": []}
	count(denials(doc, "Account.1")) == 1
}

test_account_1_passes_with_security_contact if {
	doc := {"meta": meta, "resources": [{
		"_type": "aws_account_alternate_contact",
		"_name": "security-contact",
		"alternate_contact_type": "SECURITY",
	}]}
	count(denials(doc, "Account.1")) == 0
	count(applicables(doc, "Account.1")) == 1
}

test_account_1_billing_contact_does_not_count if {
	doc := {"meta": meta, "resources": [{
		"_type": "aws_account_alternate_contact",
		"_name": "billing-contact",
		"alternate_contact_type": "BILLING",
	}]}
	count(denials(doc, "Account.1")) == 1
}

test_account_1_not_applicable_when_not_collected if {
	doc := {"meta": {"account_id": "1", "scanned_at": "2026-08-20T00:00:00Z", "collected_types": []}, "resources": []}
	count(denials(doc, "Account.1")) == 0
	count(applicables(doc, "Account.1")) == 0
}
