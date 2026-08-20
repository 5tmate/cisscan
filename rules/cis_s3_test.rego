package cis_s3_test

import rego.v1

meta := {
	"account_id": "111122223333",
	"scanned_at": "2026-08-20T00:00:00Z",
	"collected_types": [
		"aws_s3_bucket",
		"aws_s3_bucket_policy",
		"aws_s3_bucket_public_access_block",
		"aws_s3_account_public_access_block",
		"aws_cloudtrail",
	],
}

bucket(extra) := object.union({"_type": "aws_s3_bucket", "_name": "data", "bucket": "data"}, extra)

pab(extra) := object.union(
	{
		"_type": "aws_s3_bucket_public_access_block",
		"bucket": "data",
		"block_public_acls": true,
		"block_public_policy": true,
		"ignore_public_acls": true,
		"restrict_public_buckets": true,
	},
	extra,
)

account_pab(extra) := object.union(
	{
		"_type": "aws_s3_account_public_access_block",
		"_name": "account",
		"block_public_acls": true,
		"block_public_policy": true,
		"ignore_public_acls": true,
		"restrict_public_buckets": true,
	},
	extra,
)

ssl_policy := json.marshal({
	"Version": "2012-10-17",
	"Statement": [{
		"Sid": "AllowSSLRequestsOnly",
		"Effect": "Deny",
		"Principal": "*",
		"Action": "s3:*",
		"Resource": ["arn:aws:s3:::data", "arn:aws:s3:::data/*"],
		"Condition": {"Bool": {"aws:SecureTransport": "false"}},
	}],
})

denials(doc, control) := d if {
	all_denies := data.cis_s3.deny with input as doc
	d := [e | some e in all_denies; e.control == control]
}

applicables(doc, control) := a if {
	all_apps := data.cis_s3.applicable with input as doc
	a := [e | some e in all_apps; e.control == control]
}

test_s3_1_fails_without_account_pab if {
	doc := {"meta": meta, "resources": []}
	count(denials(doc, "S3.1")) == 1
}

test_s3_1_fails_with_partial_account_pab if {
	doc := {"meta": meta, "resources": [account_pab({"restrict_public_buckets": false})]}
	count(denials(doc, "S3.1")) == 1
}

test_s3_1_passes_with_full_account_pab if {
	doc := {"meta": meta, "resources": [account_pab({})]}
	count(denials(doc, "S3.1")) == 0
}

test_s3_5_fails_without_policy if {
	doc := {"meta": meta, "resources": [bucket({})]}
	count(denials(doc, "S3.5")) == 1
}

test_s3_5_passes_with_ssl_deny_policy_resource if {
	doc := {"meta": meta, "resources": [
		bucket({}),
		{"_type": "aws_s3_bucket_policy", "bucket": "data", "policy": ssl_policy},
	]}
	count(denials(doc, "S3.5")) == 0
}

test_s3_5_passes_with_inline_policy_attribute if {
	doc := {"meta": meta, "resources": [bucket({"policy": ssl_policy})]}
	count(denials(doc, "S3.5")) == 0
}

test_s3_5_fails_without_secure_transport_condition if {
	other := json.marshal({"Version": "2012-10-17", "Statement": [{
		"Effect": "Deny",
		"Principal": "*",
		"Action": "s3:*",
		"Resource": "arn:aws:s3:::data/*",
		"Condition": {"StringNotEquals": {"aws:PrincipalOrgID": "o-abc"}},
	}]})
	doc := {"meta": meta, "resources": [bucket({"policy": other})]}
	count(denials(doc, "S3.5")) == 1
}

test_s3_8_fails_without_bucket_pab if {
	doc := {"meta": meta, "resources": [bucket({})]}
	count(denials(doc, "S3.8")) == 1
}

test_s3_8_fails_with_partial_bucket_pab if {
	doc := {"meta": meta, "resources": [bucket({}), pab({"block_public_policy": false})]}
	count(denials(doc, "S3.8")) == 1
}

test_s3_8_passes_with_full_bucket_pab if {
	doc := {"meta": meta, "resources": [bucket({}), pab({})]}
	count(denials(doc, "S3.8")) == 0
}

test_s3_8_not_judged_when_pab_not_collected if {
	doc := {"meta": {"account_id": "1", "scanned_at": "2026-08-20T00:00:00Z", "collected_types": ["aws_s3_bucket"]}, "resources": [bucket({})]}
	count(denials(doc, "S3.8")) == 0
}

test_s3_20_fails_without_mfa_delete if {
	doc := {"meta": meta, "resources": [bucket({"versioning": [{"enabled": true, "mfa_delete": false}]})]}
	count(denials(doc, "S3.20")) == 1
}

test_s3_20_passes_with_mfa_delete if {
	doc := {"meta": meta, "resources": [bucket({"versioning": [{"enabled": true, "mfa_delete": true}]})]}
	count(denials(doc, "S3.20")) == 0
}

test_s3_20_passes_with_versioning_resource if {
	doc := {"meta": meta, "resources": [
		bucket({}),
		{"_type": "aws_s3_bucket_versioning", "bucket": "data", "versioning_configuration": [{"status": "Enabled", "mfa_delete": "Enabled"}]},
	]}
	count(denials(doc, "S3.20")) == 0
}

test_s3_20_skips_buckets_with_lifecycle if {
	doc := {"meta": meta, "resources": [bucket({"lifecycle_rule": [{"id": "expire"}]})]}
	count(denials(doc, "S3.20")) == 0
	count(applicables(doc, "S3.20")) == 0
}

data_trail(rw) := {
	"_type": "aws_cloudtrail",
	"_name": "main-trail",
	"is_multi_region_trail": true,
	"enable_logging": true,
	"event_selector": [{
		"read_write_type": rw,
		"include_management_events": true,
		"data_resource": [{"type": "AWS::S3::Object", "values": ["arn:aws:s3"]}],
	}],
}

test_s3_22_23_pass_with_all_data_events if {
	doc := {"meta": meta, "resources": [data_trail("All")]}
	count(denials(doc, "S3.22")) == 0
	count(denials(doc, "S3.23")) == 0
}

test_s3_22_passes_23_fails_with_write_only if {
	doc := {"meta": meta, "resources": [data_trail("WriteOnly")]}
	count(denials(doc, "S3.22")) == 0
	count(denials(doc, "S3.23")) == 1
}

test_s3_22_23_fail_without_data_events if {
	doc := {"meta": meta, "resources": [{
		"_type": "aws_cloudtrail",
		"_name": "main-trail",
		"is_multi_region_trail": true,
		"enable_logging": true,
	}]}
	count(denials(doc, "S3.22")) == 1
	count(denials(doc, "S3.23")) == 1
}

test_s3_22_single_bucket_selector_does_not_count if {
	doc := {"meta": meta, "resources": [{
		"_type": "aws_cloudtrail",
		"_name": "main-trail",
		"is_multi_region_trail": true,
		"enable_logging": true,
		"event_selector": [{
			"read_write_type": "All",
			"include_management_events": true,
			"data_resource": [{"type": "AWS::S3::Object", "values": ["arn:aws:s3:::onebucket/"]}],
		}],
	}]}
	count(denials(doc, "S3.22")) == 1
}
