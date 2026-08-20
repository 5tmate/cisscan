package cis_kms

import data.cislib
import rego.v1

title := "CIS AWS Foundations Benchmark v5.0.0 — KMS"

titles := {"KMS.4": "AWS KMS key rotation should be enabled"}

cis_requirements := {"KMS.4": "3.6"}

severities := {"KMS.4": "Medium"}

enforced := {"KMS.4"}

finding(control, message) := {"control": control, "message": message}

rotatable_keys contains k if {
	k := input.resources[_]
	k._type == "aws_kms_key"
	object.get(k, "customer_master_key_spec", "SYMMETRIC_DEFAULT") == "SYMMETRIC_DEFAULT"
	object.get(k, "key_usage", "ENCRYPT_DECRYPT") == "ENCRYPT_DECRYPT"
}

applicable contains entry if {
	k := rotatable_keys[_]
	entry := {"control": "KMS.4", "resource": cislib.name(k)}
}

deny contains entry if {
	k := rotatable_keys[_]
	object.get(k, "enable_key_rotation", false) != true
	entry := finding("KMS.4", sprintf("KMS key '%s' has automatic rotation disabled: set enable_key_rotation=true", [cislib.name(k)]))
}
