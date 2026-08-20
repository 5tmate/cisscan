package cis_cloudtrail

import data.cislib
import rego.v1

title := "CIS AWS Foundations Benchmark v5.0.0 — CloudTrail"

titles := {
	"CloudTrail.1": "CloudTrail should be enabled and configured with at least one multi-Region trail that includes read and write management events",
	"CloudTrail.2": "CloudTrail should have encryption at-rest enabled",
	"CloudTrail.4": "CloudTrail log file validation should be enabled",
	"CloudTrail.7": "Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket",
}

cis_requirements := {
	"CloudTrail.1": "3.1",
	"CloudTrail.2": "3.5",
	"CloudTrail.4": "3.2",
	"CloudTrail.7": "3.4",
}

severities := {
	"CloudTrail.1": "High",
	"CloudTrail.2": "Medium",
	"CloudTrail.4": "Low",
	"CloudTrail.7": "Low",
}

enforced := {"CloudTrail.1", "CloudTrail.2", "CloudTrail.4", "CloudTrail.7"}

finding(control, message) := {"control": control, "message": message}

trails contains t if {
	t := input.resources[_]
	t._type == "aws_cloudtrail"
}

applicable contains entry if {
	cislib.collected("aws_cloudtrail")
	entry := {"control": "CloudTrail.1", "resource": "account"}
}

applicable contains entry if {
	t := trails[_]
	some control in ["CloudTrail.2", "CloudTrail.4"]
	entry := {"control": control, "resource": cislib.name(t)}
}

applicable contains entry if {
	b := trail_buckets[_]
	entry := {"control": "CloudTrail.7", "resource": cislib.name(b)}
}

deny contains entry if {
	cislib.collected("aws_cloudtrail")
	not multi_region_management_trail
	entry := finding("CloudTrail.1", "no enabled multi-Region trail records read and write management events: create one or fix the existing trail")
}

multi_region_management_trail if {
	t := trails[_]
	t.is_multi_region_trail == true
	object.get(t, "enable_logging", true) == true
	management_all(t)
}

management_all(t) if {
	count(object.get(t, "event_selector", [])) == 0
	count(object.get(t, "advanced_event_selector", [])) == 0
}

management_all(t) if {
	s := object.get(t, "event_selector", [])[_]
	object.get(s, "include_management_events", true) == true
	object.get(s, "read_write_type", "All") == "All"
}

management_all(t) if {
	s := object.get(t, "advanced_event_selector", [])[_]
	fs := object.get(s, "field_selector", [])[_]
	object.get(fs, "field", "") == "eventCategory"
	"Management" in object.get(fs, "equals", [])
	not readonly_restricted(s)
}

readonly_restricted(s) if {
	fs := object.get(s, "field_selector", [])[_]
	object.get(fs, "field", "") == "readOnly"
}

deny contains entry if {
	t := trails[_]
	object.get(t, "kms_key_id", "") == ""
	entry := finding("CloudTrail.2", sprintf("trail '%s' does not encrypt log files with a KMS key: set kms_key_id", [cislib.name(t)]))
}

deny contains entry if {
	t := trails[_]
	object.get(t, "enable_log_file_validation", false) != true
	entry := finding("CloudTrail.4", sprintf("trail '%s' has log file validation disabled: set enable_log_file_validation=true", [cislib.name(t)]))
}

trail_buckets contains b if {
	t := trails[_]
	target := object.get(t, "s3_bucket_name", "")
	target != ""
	b := input.resources[_]
	b._type == "aws_s3_bucket"
	object.get(b, "bucket", "") == target
}

deny contains entry if {
	b := trail_buckets[_]
	not access_logged(b)
	entry := finding("CloudTrail.7", sprintf("S3 bucket '%s' stores CloudTrail logs but has no server access logging", [cislib.name(b)]))
}

access_logged(b) if count(object.get(b, "logging", [])) > 0

access_logged(b) if {
	cfg := input.resources[_]
	cfg._type == "aws_s3_bucket_logging"
	object.get(cfg, "bucket", "") == object.get(b, "bucket", "")
}
