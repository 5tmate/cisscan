package cis_config_test

import rego.v1

meta := {
	"account_id": "111122223333",
	"scanned_at": "2026-08-20T00:00:00Z",
	"collected_types": ["aws_config_configuration_recorder", "aws_config_configuration_recorder_status"],
}

recorder(extra) := object.union(
	{
		"_type": "aws_config_configuration_recorder",
		"_name": "default",
		"name": "default",
		"role_arn": "arn:aws:iam::111122223333:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig",
		"recording_group": [{"all_supported": true}],
	},
	extra,
)

denials(doc) := d if {
	all_denies := data.cis_config.deny with input as doc
	d := [e | some e in all_denies; e.control == "Config.1"]
}

applicables(doc) := a if {
	all_apps := data.cis_config.applicable with input as doc
	a := [e | some e in all_apps; e.control == "Config.1"]
}

test_config1_fails_with_no_recorder if {
	doc := {"meta": meta, "resources": []}
	count(denials(doc)) == 1
}

test_config1_passes_with_service_linked_recorder if {
	doc := {"meta": meta, "resources": [recorder({})]}
	count(denials(doc)) == 0
	count(applicables(doc)) == 1
}

test_config1_fails_with_custom_role if {
	doc := {"meta": meta, "resources": [recorder({"role_arn": "arn:aws:iam::111122223333:role/my-config-role"})]}
	count(denials(doc)) == 1
}

test_config1_fails_when_not_recording_all if {
	doc := {"meta": meta, "resources": [recorder({"recording_group": [{"all_supported": false}]})]}
	count(denials(doc)) == 1
}

test_config1_fails_when_recorder_disabled if {
	doc := {"meta": meta, "resources": [
		recorder({}),
		{"_type": "aws_config_configuration_recorder_status", "name": "default", "is_enabled": false},
	]}
	count(denials(doc)) == 1
}

test_config1_passes_when_recorder_enabled if {
	doc := {"meta": meta, "resources": [
		recorder({}),
		{"_type": "aws_config_configuration_recorder_status", "name": "default", "is_enabled": true},
	]}
	count(denials(doc)) == 0
}

test_config1_not_applicable_when_not_collected if {
	doc := {"meta": {"account_id": "1", "scanned_at": "2026-08-20T00:00:00Z", "collected_types": []}, "resources": []}
	count(denials(doc)) == 0
	count(applicables(doc)) == 0
}
