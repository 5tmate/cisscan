package cis_s3

import data.cislib
import rego.v1

title := "CIS AWS Foundations Benchmark v5.0.0 — S3"

titles := {
	"S3.1": "S3 general purpose buckets should have block public access settings enabled",
	"S3.5": "S3 general purpose buckets should require requests to use SSL",
	"S3.8": "S3 general purpose buckets should block public access",
	"S3.20": "S3 general purpose buckets should have MFA delete enabled",
	"S3.22": "S3 general purpose buckets should log object-level write events",
	"S3.23": "S3 general purpose buckets should log object-level read events",
}

cis_requirements := {
	"S3.1": "2.1.4",
	"S3.5": "2.1.1",
	"S3.8": "2.1.4",
	"S3.20": "2.1.2",
	"S3.22": "3.8",
	"S3.23": "3.9",
}

severities := {
	"S3.1": "Medium",
	"S3.5": "Medium",
	"S3.8": "High",
	"S3.20": "Low",
	"S3.22": "Medium",
	"S3.23": "Medium",
}

enforced := {"S3.1", "S3.5", "S3.8", "S3.20", "S3.22", "S3.23"}

pab_flags := ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]

finding(control, message) := {"control": control, "message": message}

buckets contains b if {
	b := input.resources[_]
	b._type == "aws_s3_bucket"
}

pab_ok(p) if {
	every flag in pab_flags {
		object.get(p, flag, false) == true
	}
}

applicable contains entry if {
	cislib.collected("aws_s3_account_public_access_block")
	entry := {"control": "S3.1", "resource": "account"}
}

account_pab_enabled if {
	p := input.resources[_]
	p._type == "aws_s3_account_public_access_block"
	pab_ok(p)
}

deny contains entry if {
	cislib.collected("aws_s3_account_public_access_block")
	not account_pab_enabled
	entry := finding("S3.1", "account-level S3 Block Public Access is not fully enabled: enable all four settings")
}

applicable contains entry if {
	b := buckets[_]
	entry := {"control": "S3.5", "resource": cislib.name(b)}
}

deny contains entry if {
	b := buckets[_]
	not ssl_enforced(b)
	entry := finding("S3.5", sprintf("S3 bucket '%s' has no policy denying non-SSL requests", [cislib.name(b)]))
}

bucket_policy_doc(b) := doc if {
	p := input.resources[_]
	p._type == "aws_s3_bucket_policy"
	object.get(p, "bucket", "") == object.get(b, "bucket", "")
	doc := json.unmarshal(object.get(p, "policy", "{}"))
} else := doc if {
	raw := object.get(b, "policy", "")
	raw != ""
	doc := json.unmarshal(raw)
}

ssl_enforced(b) if {
	doc := bucket_policy_doc(b)
	stmt := cislib.as_array(object.get(doc, "Statement", []))[_]
	object.get(stmt, "Effect", "") == "Deny"
	principal_all(object.get(stmt, "Principal", ""))
	action_all(object.get(stmt, "Action", []))
	cond := object.get(object.get(stmt, "Condition", {}), "Bool", {})
	object.get(cond, "aws:SecureTransport", "unset") in {"false", false}
}

principal_all(p) if p == "*"

principal_all(p) if object.get(p, "AWS", "") == "*"

principal_all(p) if "*" in cislib.as_array(object.get(p, "AWS", []))

action_all(a) if {
	some act in cislib.as_array(a)
	lower(act) in {"*", "s3:*"}
}

applicable contains entry if {
	cislib.collected("aws_s3_bucket_public_access_block")
	b := buckets[_]
	entry := {"control": "S3.8", "resource": cislib.name(b)}
}

bucket_pab_enabled(b) if {
	p := input.resources[_]
	p._type == "aws_s3_bucket_public_access_block"
	object.get(p, "bucket", "") == object.get(b, "bucket", "")
	pab_ok(p)
}

deny contains entry if {
	cislib.collected("aws_s3_bucket_public_access_block")
	b := buckets[_]
	not bucket_pab_enabled(b)
	entry := finding("S3.8", sprintf("S3 bucket '%s' does not fully block public access: enable all four bucket-level settings", [cislib.name(b)]))
}

lifecycle_configured(b) if count(object.get(b, "lifecycle_rule", [])) > 0

applicable contains entry if {
	b := buckets[_]
	not lifecycle_configured(b)
	entry := {"control": "S3.20", "resource": cislib.name(b)}
}

mfa_delete_enabled(b) if {
	v := object.get(b, "versioning", [])[_]
	object.get(v, "enabled", false) == true
	object.get(v, "mfa_delete", false) == true
}

mfa_delete_enabled(b) if {
	vr := input.resources[_]
	vr._type == "aws_s3_bucket_versioning"
	object.get(vr, "bucket", "") == object.get(b, "bucket", "")
	vc := object.get(vr, "versioning_configuration", [])[_]
	object.get(vc, "status", "") == "Enabled"
	object.get(vc, "mfa_delete", "") == "Enabled"
}

deny contains entry if {
	b := buckets[_]
	not lifecycle_configured(b)
	not mfa_delete_enabled(b)
	entry := finding("S3.20", sprintf("S3 bucket '%s' does not have MFA delete enabled", [cislib.name(b)]))
}

applicable contains entry if {
	cislib.collected("aws_cloudtrail")
	some control in ["S3.22", "S3.23"]
	entry := {"control": control, "resource": "account"}
}

all_bucket_selector_values := {"arn:aws:s3", "arn:aws:s3:::*", "arn:aws:s3:::*/*"}

s3_data_events_logged(rw_types) if {
	t := input.resources[_]
	t._type == "aws_cloudtrail"
	t.is_multi_region_trail == true
	object.get(t, "enable_logging", true) == true
	s := object.get(t, "event_selector", [])[_]
	object.get(s, "read_write_type", "") in rw_types
	dr := object.get(s, "data_resource", [])[_]
	object.get(dr, "type", "") == "AWS::S3::Object"
	some v in object.get(dr, "values", [])
	v in all_bucket_selector_values
}

deny contains entry if {
	cislib.collected("aws_cloudtrail")
	not s3_data_events_logged({"All", "WriteOnly"})
	entry := finding("S3.22", "no multi-Region trail logs write data events for all S3 buckets")
}

deny contains entry if {
	cislib.collected("aws_cloudtrail")
	not s3_data_events_logged({"All", "ReadOnly"})
	entry := finding("S3.23", "no multi-Region trail logs read data events for all S3 buckets")
}
