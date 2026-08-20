package cis_account

import data.cislib
import rego.v1

title := "CIS AWS Foundations Benchmark v5.0.0 — Account"

titles := {"Account.1": "Security contact information should be provided for an AWS account"}

cis_requirements := {"Account.1": "1.2"}

severities := {"Account.1": "Medium"}

enforced := {"Account.1"}

applicable contains entry if {
	cislib.collected("aws_account_alternate_contact")
	entry := {"control": "Account.1", "resource": "account"}
}

security_contact_registered if {
	r := input.resources[_]
	r._type == "aws_account_alternate_contact"
	object.get(r, "alternate_contact_type", "") == "SECURITY"
}

deny contains entry if {
	cislib.collected("aws_account_alternate_contact")
	not security_contact_registered
	entry := {"control": "Account.1", "message": "the account has no SECURITY alternate contact: register one so AWS can reach you about security issues"}
}
