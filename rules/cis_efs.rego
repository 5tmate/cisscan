package cis_efs

import data.cislib
import rego.v1

title := "CIS AWS Foundations Benchmark v5.0.0 — EFS"

titles := {
	"EFS.1": "Elastic File System should be configured to encrypt file data at-rest using AWS KMS",
	"EFS.8": "EFS file systems should be encrypted at rest",
}

cis_requirements := {"EFS.1": "2.3.1", "EFS.8": "2.3.1"}

severities := {"EFS.1": "Medium", "EFS.8": "Medium"}

enforced := {"EFS.1", "EFS.8"}

finding(control, message) := {"control": control, "message": message}

filesystems contains fs if {
	fs := input.resources[_]
	fs._type == "aws_efs_file_system"
}

applicable contains entry if {
	fs := filesystems[_]
	some control in ["EFS.1", "EFS.8"]
	entry := {"control": control, "resource": cislib.name(fs)}
}

deny contains entry if {
	fs := filesystems[_]
	object.get(fs, "encrypted", false) != true
	some control in ["EFS.1", "EFS.8"]
	entry := finding(control, sprintf("EFS file system '%s' is not encrypted at rest", [cislib.name(fs)]))
}
