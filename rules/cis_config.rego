package cis_config

import data.cislib
import rego.v1

title := "CIS AWS Foundations Benchmark v5.0.0 — AWS Config"

titles := {"Config.1": "AWS Config should be enabled and use the service-linked role for resource recording"}

cis_requirements := {"Config.1": "3.3"}

severities := {"Config.1": "Critical"}

enforced := {"Config.1"}

finding(control, message) := {"control": control, "message": message}

recorders contains r if {
	r := input.resources[_]
	r._type == "aws_config_configuration_recorder"
}

applicable contains entry if {
	cislib.collected("aws_config_configuration_recorder")
	entry := {"control": "Config.1", "resource": "account"}
}

deny contains entry if {
	cislib.collected("aws_config_configuration_recorder")
	count(recorders) == 0
	entry := finding("Config.1", "AWS Config has no configuration recorder: enable Config resource recording")
}

deny contains entry if {
	r := recorders[_]
	not contains(object.get(r, "role_arn", ""), "AWSServiceRoleForConfig")
	entry := finding("Config.1", sprintf("Config recorder '%s' does not use the AWSServiceRoleForConfig service-linked role", [cislib.name(r)]))
}

deny contains entry if {
	r := recorders[_]
	g := object.get(r, "recording_group", [])[_]
	object.get(g, "all_supported", true) == false
	entry := finding("Config.1", sprintf("Config recorder '%s' does not record all supported resource types", [cislib.name(r)]))
}

deny contains entry if {
	r := recorders[_]
	s := input.resources[_]
	s._type == "aws_config_configuration_recorder_status"
	object.get(s, "name", "") == object.get(r, "name", "")
	object.get(s, "is_enabled", true) == false
	entry := finding("Config.1", sprintf("Config recorder '%s' is disabled", [cislib.name(r)]))
}
