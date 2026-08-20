package cis_cloudtrail_test

import rego.v1

meta := {
	"account_id": "111122223333",
	"scanned_at": "2026-08-20T00:00:00Z",
	"collected_types": ["aws_cloudtrail", "aws_s3_bucket", "aws_s3_bucket_logging"],
}

trail(extra) := object.union(
	{
		"_type": "aws_cloudtrail",
		"_name": "main-trail",
		"is_multi_region_trail": true,
		"enable_logging": true,
		"s3_bucket_name": "trail-logs",
	},
	extra,
)

denials(doc, control) := d if {
	all_denies := data.cis_cloudtrail.deny with input as doc
	d := [e | some e in all_denies; e.control == control]
}

applicables(doc, control) := a if {
	all_apps := data.cis_cloudtrail.applicable with input as doc
	a := [e | some e in all_apps; e.control == control]
}

test_ct1_fails_with_no_trails if {
	doc := {"meta": meta, "resources": []}
	count(denials(doc, "CloudTrail.1")) == 1
}

test_ct1_passes_with_default_selectors if {
	doc := {"meta": meta, "resources": [trail({})]}
	count(denials(doc, "CloudTrail.1")) == 0
}

test_ct1_fails_when_single_region if {
	doc := {"meta": meta, "resources": [trail({"is_multi_region_trail": false})]}
	count(denials(doc, "CloudTrail.1")) == 1
}

test_ct1_fails_when_logging_disabled if {
	doc := {"meta": meta, "resources": [trail({"enable_logging": false})]}
	count(denials(doc, "CloudTrail.1")) == 1
}

test_ct1_fails_when_selector_write_only if {
	doc := {"meta": meta, "resources": [trail({"event_selector": [{
		"include_management_events": true,
		"read_write_type": "WriteOnly",
	}]})]}
	count(denials(doc, "CloudTrail.1")) == 1
}

test_ct1_passes_with_all_management_selector if {
	doc := {"meta": meta, "resources": [trail({"event_selector": [{
		"include_management_events": true,
		"read_write_type": "All",
	}]})]}
	count(denials(doc, "CloudTrail.1")) == 0
}

test_ct1_not_applicable_when_not_collected if {
	doc := {"meta": {"account_id": "1", "scanned_at": "2026-08-20T00:00:00Z", "collected_types": []}, "resources": []}
	count(denials(doc, "CloudTrail.1")) == 0
	count(applicables(doc, "CloudTrail.1")) == 0
}

test_ct2_fails_without_kms if {
	doc := {"meta": meta, "resources": [trail({})]}
	count(denials(doc, "CloudTrail.2")) == 1
}

test_ct2_passes_with_kms if {
	doc := {"meta": meta, "resources": [trail({"kms_key_id": "arn:aws:kms:ap-northeast-1:111122223333:key/abc"})]}
	count(denials(doc, "CloudTrail.2")) == 0
}

test_ct4_fails_without_log_validation if {
	doc := {"meta": meta, "resources": [trail({})]}
	count(denials(doc, "CloudTrail.4")) == 1
}

test_ct4_passes_with_log_validation if {
	doc := {"meta": meta, "resources": [trail({"enable_log_file_validation": true})]}
	count(denials(doc, "CloudTrail.4")) == 0
}

test_ct7_fails_when_trail_bucket_unlogged if {
	doc := {"meta": meta, "resources": [
		trail({}),
		{"_type": "aws_s3_bucket", "_name": "trail-logs", "bucket": "trail-logs", "logging": []},
	]}
	count(denials(doc, "CloudTrail.7")) == 1
}

test_ct7_passes_with_inline_logging if {
	doc := {"meta": meta, "resources": [
		trail({}),
		{"_type": "aws_s3_bucket", "_name": "trail-logs", "bucket": "trail-logs", "logging": [{"target_bucket": "access-logs"}]},
	]}
	count(denials(doc, "CloudTrail.7")) == 0
}

test_ct7_passes_with_logging_resource if {
	doc := {"meta": meta, "resources": [
		trail({}),
		{"_type": "aws_s3_bucket", "_name": "trail-logs", "bucket": "trail-logs"},
		{"_type": "aws_s3_bucket_logging", "bucket": "trail-logs", "target_bucket": "access-logs"},
	]}
	count(denials(doc, "CloudTrail.7")) == 0
}

test_ct7_not_applicable_when_bucket_absent if {
	doc := {"meta": meta, "resources": [trail({})]}
	count(denials(doc, "CloudTrail.7")) == 0
	count(applicables(doc, "CloudTrail.7")) == 0
}
