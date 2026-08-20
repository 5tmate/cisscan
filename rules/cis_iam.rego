package cis_iam

import data.cislib
import rego.v1

title := "CIS AWS Foundations Benchmark v5.0.0 — IAM"

titles := {
	"IAM.2": "IAM users should not have IAM policies attached",
	"IAM.3": "IAM users' access keys should be rotated every 90 days or less",
	"IAM.4": "IAM root user access key should not exist",
	"IAM.5": "MFA should be enabled for all IAM users that have a console password",
	"IAM.6": "Hardware MFA should be enabled for the root user",
	"IAM.9": "MFA should be enabled for the root user",
	"IAM.15": "Ensure IAM password policy requires minimum password length of 14 or greater",
	"IAM.16": "Ensure IAM password policy prevents password reuse",
	"IAM.18": "Ensure a support role has been created to manage incidents with AWS Support",
	"IAM.22": "IAM user credentials unused for 45 days should be removed",
	"IAM.26": "Expired SSL/TLS certificates managed in IAM should be removed",
	"IAM.27": "IAM identities should not have the AWSCloudShellFullAccess policy attached",
	"IAM.28": "IAM Access Analyzer external access analyzer should be enabled",
}

cis_requirements := {
	"IAM.2": "1.14",
	"IAM.3": "1.13",
	"IAM.4": "1.3",
	"IAM.5": "1.9",
	"IAM.6": "1.5",
	"IAM.9": "1.4",
	"IAM.15": "1.7",
	"IAM.16": "1.8",
	"IAM.18": "1.16",
	"IAM.22": "1.11",
	"IAM.26": "1.18",
	"IAM.27": "1.21",
	"IAM.28": "1.19",
}

severities := {
	"IAM.2": "Low",
	"IAM.3": "Medium",
	"IAM.4": "Critical",
	"IAM.5": "Medium",
	"IAM.6": "Critical",
	"IAM.9": "Critical",
	"IAM.15": "Medium",
	"IAM.16": "Low",
	"IAM.18": "Low",
	"IAM.22": "Medium",
	"IAM.26": "Medium",
	"IAM.27": "Medium",
	"IAM.28": "High",
}

enforced := {
	"IAM.2", "IAM.3", "IAM.4", "IAM.5", "IAM.6", "IAM.9", "IAM.15", "IAM.16",
	"IAM.18", "IAM.22", "IAM.26", "IAM.27", "IAM.28",
}

finding(control, message) := {"control": control, "message": message}

key_slots := ["1", "2"]

cr_rows contains r if {
	r := input.resources[_]
	r._type == "aws_iam_credential_report_user"
}

root_rows contains r if {
	r := cr_rows[_]
	r.user == "<root_account>"
}

user_rows contains r if {
	r := cr_rows[_]
	r.user != "<root_account>"
}

iam_users contains u if {
	u := input.resources[_]
	u._type == "aws_iam_user"
}

applicable contains entry if {
	u := iam_users[_]
	entry := {"control": "IAM.2", "resource": cislib.name(u)}
}

deny contains entry if {
	u := iam_users[_]
	n := object.get(u, "name", "")
	user_has_policy(n)
	entry := finding("IAM.2", sprintf("IAM user '%s' has policies attached directly: move them to a group or role", [n]))
}

user_has_policy(n) if {
	a := input.resources[_]
	a._type == "aws_iam_user_policy_attachment"
	object.get(a, "user", "") == n
}

user_has_policy(n) if {
	p := input.resources[_]
	p._type == "aws_iam_user_policy"
	object.get(p, "user", "") == n
}

applicable contains entry if {
	r := user_rows[_]
	some slot in key_slots
	object.get(r, sprintf("access_key_%s_active", [slot]), false) == true
	entry := {"control": "IAM.3", "resource": r.user}
}

deny contains entry if {
	r := user_rows[_]
	some slot in key_slots
	object.get(r, sprintf("access_key_%s_active", [slot]), false) == true
	cislib.older_than(object.get(r, sprintf("access_key_%s_last_rotated", [slot]), "N/A"), 90)
	entry := finding("IAM.3", sprintf("IAM user '%s' access key %s was last rotated more than 90 days ago", [r.user, slot]))
}

applicable contains entry if {
	root_rows[_]
	some control in ["IAM.4", "IAM.6", "IAM.9"]
	entry := {"control": control, "resource": "root"}
}

deny contains entry if {
	r := root_rows[_]
	some slot in key_slots
	object.get(r, sprintf("access_key_%s_active", [slot]), false) == true
	entry := finding("IAM.4", "the root user has an active access key: delete it")
}

applicable contains entry if {
	r := user_rows[_]
	object.get(r, "password_enabled", false) == true
	entry := {"control": "IAM.5", "resource": r.user}
}

deny contains entry if {
	r := user_rows[_]
	object.get(r, "password_enabled", false) == true
	object.get(r, "mfa_active", false) != true
	entry := finding("IAM.5", sprintf("IAM user '%s' has a console password but no MFA", [r.user]))
}

deny contains entry if {
	r := root_rows[_]
	object.get(r, "mfa_active", false) != true
	entry := finding("IAM.6", "the root user has no MFA device: enable a hardware MFA")
}

deny contains entry if {
	r := root_rows[_]
	object.get(r, "mfa_active", false) == true
	root_virtual_mfa
	entry := finding("IAM.6", "the root user MFA is a virtual device: replace it with a hardware MFA")
}

root_virtual_mfa if {
	d := input.resources[_]
	d._type == "aws_iam_virtual_mfa_device"
	endswith(object.get(d, "user_arn", ""), ":root")
}

root_virtual_mfa if {
	d := input.resources[_]
	d._type == "aws_iam_virtual_mfa_device"
	contains(object.get(d, "serial_number", ""), "root-account-mfa-device")
}

deny contains entry if {
	r := root_rows[_]
	object.get(r, "mfa_active", false) != true
	entry := finding("IAM.9", "the root user has no MFA enabled")
}

password_policies contains p if {
	p := input.resources[_]
	p._type == "aws_iam_account_password_policy"
}

applicable contains entry if {
	cislib.collected("aws_iam_account_password_policy")
	some control in ["IAM.15", "IAM.16"]
	entry := {"control": control, "resource": "account"}
}

deny contains entry if {
	cislib.collected("aws_iam_account_password_policy")
	count(password_policies) == 0
	some control in ["IAM.15", "IAM.16"]
	entry := finding(control, "the account has no IAM password policy configured")
}

deny contains entry if {
	p := password_policies[_]
	object.get(p, "minimum_password_length", 0) < 14
	entry := finding("IAM.15", "the IAM password policy requires fewer than 14 characters")
}

deny contains entry if {
	p := password_policies[_]
	object.get(p, "password_reuse_prevention", 0) < 24
	entry := finding("IAM.16", "the IAM password policy does not remember the previous 24 passwords")
}

applicable contains entry if {
	cislib.collected("aws_iam_role_policy_attachment")
	entry := {"control": "IAM.18", "resource": "account"}
}

support_role_attached if {
	a := input.resources[_]
	a._type == "aws_iam_role_policy_attachment"
	endswith(object.get(a, "policy_arn", ""), ":policy/AWSSupportAccess")
}

deny contains entry if {
	cislib.collected("aws_iam_role_policy_attachment")
	not support_role_attached
	entry := finding("IAM.18", "no IAM role has the AWSSupportAccess policy attached")
}

applicable contains entry if {
	r := user_rows[_]
	entry := {"control": "IAM.22", "resource": r.user}
}

last_activity(used, fallback) := used if cislib.known_timestamp(used)

last_activity(used, fallback) := fallback if not cislib.known_timestamp(used)

deny contains entry if {
	r := user_rows[_]
	object.get(r, "password_enabled", false) == true
	last := last_activity(object.get(r, "password_last_used", "N/A"), object.get(r, "password_last_changed", "N/A"))
	cislib.older_than(last, 45)
	entry := finding("IAM.22", sprintf("IAM user '%s' console password unused for over 45 days: disable it", [r.user]))
}

deny contains entry if {
	r := user_rows[_]
	some slot in key_slots
	object.get(r, sprintf("access_key_%s_active", [slot]), false) == true
	last := last_activity(object.get(r, sprintf("access_key_%s_last_used_date", [slot]), "N/A"), object.get(r, sprintf("access_key_%s_last_rotated", [slot]), "N/A"))
	cislib.older_than(last, 45)
	entry := finding("IAM.22", sprintf("IAM user '%s' access key %s unused for over 45 days: deactivate it", [r.user, slot]))
}

server_certs contains c if {
	c := input.resources[_]
	c._type == "aws_iam_server_certificate"
}

applicable contains entry if {
	c := server_certs[_]
	entry := {"control": "IAM.26", "resource": cislib.name(c)}
}

deny contains entry if {
	c := server_certs[_]
	exp := object.get(c, "expiration", "")
	cislib.known_timestamp(exp)
	time.parse_rfc3339_ns(exp) < cislib.now_ns
	entry := finding("IAM.26", sprintf("IAM server certificate '%s' is expired: remove it", [cislib.name(c)]))
}

attachment_kinds := {
	"aws_iam_user_policy_attachment": "user",
	"aws_iam_group_policy_attachment": "group",
	"aws_iam_role_policy_attachment": "role",
}

applicable contains entry if {
	cislib.collected("aws_iam_role_policy_attachment")
	entry := {"control": "IAM.27", "resource": "account"}
}

deny contains entry if {
	a := input.resources[_]
	kind := attachment_kinds[a._type]
	endswith(object.get(a, "policy_arn", ""), ":policy/AWSCloudShellFullAccess")
	entry := finding("IAM.27", sprintf("IAM %s '%s' has AWSCloudShellFullAccess attached: detach it", [kind, object.get(a, kind, "")]))
}

applicable contains entry if {
	cislib.collected("aws_accessanalyzer_analyzer")
	entry := {"control": "IAM.28", "resource": "account"}
}

external_analyzer_enabled if {
	a := input.resources[_]
	a._type == "aws_accessanalyzer_analyzer"
	object.get(a, "type", "ACCOUNT") in {"ACCOUNT", "ORGANIZATION"}
}

deny contains entry if {
	cislib.collected("aws_accessanalyzer_analyzer")
	not external_analyzer_enabled
	entry := finding("IAM.28", "no IAM Access Analyzer external access analyzer is enabled")
}
