package cis_iam_test

import rego.v1

meta := {
	"account_id": "111122223333",
	"scanned_at": "2026-08-20T00:00:00Z",
	"collected_types": [
		"aws_iam_user",
		"aws_iam_credential_report_user",
		"aws_iam_account_password_policy",
		"aws_iam_server_certificate",
		"aws_iam_virtual_mfa_device",
		"aws_iam_role_policy_attachment",
		"aws_accessanalyzer_analyzer",
	],
}

cr(extra) := object.union(
	{
		"_type": "aws_iam_credential_report_user",
		"_name": "alice",
		"user": "alice",
		"password_enabled": false,
		"mfa_active": false,
		"access_key_1_active": false,
		"access_key_2_active": false,
	},
	extra,
)

root(extra) := object.union(cr(object.union({"_name": "<root_account>", "user": "<root_account>", "mfa_active": true}, extra)), {})

denials(doc, control) := d if {
	all_denies := data.cis_iam.deny with input as doc
	d := [e | some e in all_denies; e.control == control]
}

test_iam_2_fails_with_attached_policy if {
	doc := {"meta": meta, "resources": [
		{"_type": "aws_iam_user", "_name": "alice", "name": "alice"},
		{"_type": "aws_iam_user_policy_attachment", "user": "alice", "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"},
	]}
	count(denials(doc, "IAM.2")) == 1
}

test_iam_2_fails_with_inline_policy if {
	doc := {"meta": meta, "resources": [
		{"_type": "aws_iam_user", "_name": "alice", "name": "alice"},
		{"_type": "aws_iam_user_policy", "user": "alice", "name": "inline"},
	]}
	count(denials(doc, "IAM.2")) == 1
}

test_iam_2_passes_for_clean_user if {
	doc := {"meta": meta, "resources": [{"_type": "aws_iam_user", "_name": "alice", "name": "alice"}]}
	count(denials(doc, "IAM.2")) == 0
}

test_iam_3_fails_with_stale_key if {
	doc := {"meta": meta, "resources": [cr({"access_key_1_active": true, "access_key_1_last_rotated": "2026-01-01T00:00:00+00:00"})]}
	count(denials(doc, "IAM.3")) == 1
}

test_iam_3_passes_with_fresh_key if {
	doc := {"meta": meta, "resources": [cr({"access_key_1_active": true, "access_key_1_last_rotated": "2026-08-01T00:00:00+00:00"})]}
	count(denials(doc, "IAM.3")) == 0
}

test_iam_3_ignores_inactive_key if {
	doc := {"meta": meta, "resources": [cr({"access_key_1_active": false, "access_key_1_last_rotated": "2020-01-01T00:00:00+00:00"})]}
	count(denials(doc, "IAM.3")) == 0
}

test_iam_4_fails_with_root_key if {
	doc := {"meta": meta, "resources": [root({"access_key_1_active": true})]}
	count(denials(doc, "IAM.4")) == 1
}

test_iam_4_passes_without_root_key if {
	doc := {"meta": meta, "resources": [root({})]}
	count(denials(doc, "IAM.4")) == 0
}

test_iam_5_fails_console_user_without_mfa if {
	doc := {"meta": meta, "resources": [cr({"password_enabled": true, "mfa_active": false})]}
	count(denials(doc, "IAM.5")) == 1
}

test_iam_5_passes_console_user_with_mfa if {
	doc := {"meta": meta, "resources": [cr({"password_enabled": true, "mfa_active": true})]}
	count(denials(doc, "IAM.5")) == 0
}

test_iam_5_ignores_api_only_user if {
	doc := {"meta": meta, "resources": [cr({"password_enabled": false, "mfa_active": false})]}
	count(denials(doc, "IAM.5")) == 0
}

test_iam_6_fails_with_virtual_root_mfa if {
	doc := {"meta": meta, "resources": [
		root({}),
		{"_type": "aws_iam_virtual_mfa_device", "user_arn": "arn:aws:iam::111122223333:root", "serial_number": "arn:aws:iam::111122223333:mfa/root-account-mfa-device"},
	]}
	count(denials(doc, "IAM.6")) == 1
}

test_iam_6_passes_with_hardware_root_mfa if {
	doc := {"meta": meta, "resources": [root({})]}
	count(denials(doc, "IAM.6")) == 0
}

test_iam_6_fails_without_root_mfa if {
	doc := {"meta": meta, "resources": [root({"mfa_active": false})]}
	count(denials(doc, "IAM.6")) == 1
}

test_iam_9_fails_without_root_mfa if {
	doc := {"meta": meta, "resources": [root({"mfa_active": false})]}
	count(denials(doc, "IAM.9")) == 1
}

test_iam_9_passes_with_root_mfa if {
	doc := {"meta": meta, "resources": [root({})]}
	count(denials(doc, "IAM.9")) == 0
}

test_iam_15_fails_with_short_minimum if {
	doc := {"meta": meta, "resources": [{"_type": "aws_iam_account_password_policy", "_name": "policy", "minimum_password_length": 10}]}
	count(denials(doc, "IAM.15")) == 1
}

test_iam_15_fails_without_policy if {
	doc := {"meta": meta, "resources": []}
	count(denials(doc, "IAM.15")) == 1
}

test_iam_15_passes_with_long_minimum if {
	doc := {"meta": meta, "resources": [{"_type": "aws_iam_account_password_policy", "_name": "policy", "minimum_password_length": 14, "password_reuse_prevention": 24}]}
	count(denials(doc, "IAM.15")) == 0
}

test_iam_16_fails_with_low_reuse_prevention if {
	doc := {"meta": meta, "resources": [{"_type": "aws_iam_account_password_policy", "_name": "policy", "minimum_password_length": 14, "password_reuse_prevention": 5}]}
	count(denials(doc, "IAM.16")) == 1
}

test_iam_16_passes_with_full_reuse_prevention if {
	doc := {"meta": meta, "resources": [{"_type": "aws_iam_account_password_policy", "_name": "policy", "minimum_password_length": 14, "password_reuse_prevention": 24}]}
	count(denials(doc, "IAM.16")) == 0
}

test_iam_18_fails_without_support_role if {
	doc := {"meta": meta, "resources": []}
	count(denials(doc, "IAM.18")) == 1
}

test_iam_18_passes_with_support_role if {
	doc := {"meta": meta, "resources": [{"_type": "aws_iam_role_policy_attachment", "role": "support", "policy_arn": "arn:aws:iam::aws:policy/AWSSupportAccess"}]}
	count(denials(doc, "IAM.18")) == 0
}

test_iam_22_fails_with_stale_password if {
	doc := {"meta": meta, "resources": [cr({"password_enabled": true, "mfa_active": true, "password_last_used": "2026-01-01T00:00:00+00:00"})]}
	count(denials(doc, "IAM.22")) == 1
}

test_iam_22_fails_with_never_used_old_password if {
	doc := {"meta": meta, "resources": [cr({"password_enabled": true, "mfa_active": true, "password_last_used": "N/A", "password_last_changed": "2026-01-01T00:00:00+00:00"})]}
	count(denials(doc, "IAM.22")) == 1
}

test_iam_22_passes_with_recent_password_use if {
	doc := {"meta": meta, "resources": [cr({"password_enabled": true, "mfa_active": true, "password_last_used": "2026-08-10T00:00:00+00:00"})]}
	count(denials(doc, "IAM.22")) == 0
}

test_iam_22_fails_with_stale_access_key if {
	doc := {"meta": meta, "resources": [cr({"access_key_1_active": true, "access_key_1_last_rotated": "2026-08-01T00:00:00+00:00", "access_key_1_last_used_date": "2026-01-01T00:00:00+00:00"})]}
	count(denials(doc, "IAM.22")) == 1
}

test_iam_26_fails_with_expired_certificate if {
	doc := {"meta": meta, "resources": [{"_type": "aws_iam_server_certificate", "_name": "old-cert", "expiration": "2026-01-01T00:00:00Z"}]}
	count(denials(doc, "IAM.26")) == 1
}

test_iam_26_passes_with_valid_certificate if {
	doc := {"meta": meta, "resources": [{"_type": "aws_iam_server_certificate", "_name": "cert", "expiration": "2027-01-01T00:00:00Z"}]}
	count(denials(doc, "IAM.26")) == 0
}

test_iam_27_fails_with_cloudshell_policy_on_role if {
	doc := {"meta": meta, "resources": [{"_type": "aws_iam_role_policy_attachment", "role": "dev", "policy_arn": "arn:aws:iam::aws:policy/AWSCloudShellFullAccess"}]}
	count(denials(doc, "IAM.27")) == 1
}

test_iam_27_fails_with_cloudshell_policy_on_user if {
	doc := {"meta": meta, "resources": [{"_type": "aws_iam_user_policy_attachment", "user": "alice", "policy_arn": "arn:aws:iam::aws:policy/AWSCloudShellFullAccess"}]}
	count(denials(doc, "IAM.27")) == 1
}

test_iam_27_passes_without_cloudshell_policy if {
	doc := {"meta": meta, "resources": [{"_type": "aws_iam_role_policy_attachment", "role": "dev", "policy_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}]}
	count(denials(doc, "IAM.27")) == 0
}

test_iam_28_fails_without_analyzer if {
	doc := {"meta": meta, "resources": []}
	count(denials(doc, "IAM.28")) == 1
}

test_iam_28_passes_with_account_analyzer if {
	doc := {"meta": meta, "resources": [{"_type": "aws_accessanalyzer_analyzer", "_name": "external", "type": "ACCOUNT"}]}
	count(denials(doc, "IAM.28")) == 0
}

test_iam_28_unused_access_analyzer_does_not_count if {
	doc := {"meta": meta, "resources": [{"_type": "aws_accessanalyzer_analyzer", "_name": "unused", "type": "ACCOUNT_UNUSED_ACCESS"}]}
	count(denials(doc, "IAM.28")) == 1
}
