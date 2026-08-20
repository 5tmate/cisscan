package cis_rds

import data.cislib
import rego.v1

title := "CIS AWS Foundations Benchmark v5.0.0 — RDS"

titles := {
	"RDS.2": "RDS DB Instances should prohibit public access, as determined by the PubliclyAccessible configuration",
	"RDS.3": "RDS DB instances should have encryption at-rest enabled",
	"RDS.5": "RDS DB instances should be configured with multiple Availability Zones",
	"RDS.13": "RDS automatic minor version upgrades should be enabled",
	"RDS.15": "RDS DB clusters should be configured for multiple Availability Zones",
}

cis_requirements := {
	"RDS.2": "2.2.3",
	"RDS.3": "2.2.1",
	"RDS.5": "2.2.4",
	"RDS.13": "2.2.2",
	"RDS.15": "2.2.4",
}

severities := {
	"RDS.2": "Critical",
	"RDS.3": "Medium",
	"RDS.5": "Medium",
	"RDS.13": "High",
	"RDS.15": "Medium",
}

enforced := {"RDS.2", "RDS.3", "RDS.5", "RDS.13", "RDS.15"}

finding(control, message) := {"control": control, "message": message}

instances contains r if {
	r := input.resources[_]
	r._type == "aws_db_instance"
}

upgradable_instances contains r if {
	r := input.resources[_]
	r._type in {"aws_db_instance", "aws_rds_cluster_instance"}
}

clusters contains c if {
	c := input.resources[_]
	c._type == "aws_rds_cluster"
}

applicable contains entry if {
	r := instances[_]
	some control in ["RDS.2", "RDS.3", "RDS.5"]
	entry := {"control": control, "resource": cislib.name(r)}
}

applicable contains entry if {
	r := upgradable_instances[_]
	entry := {"control": "RDS.13", "resource": cislib.name(r)}
}

applicable contains entry if {
	c := clusters[_]
	entry := {"control": "RDS.15", "resource": cislib.name(c)}
}

deny contains entry if {
	r := instances[_]
	object.get(r, "publicly_accessible", false) == true
	entry := finding("RDS.2", sprintf("RDS instance '%s' is publicly accessible: set publicly_accessible=false", [cislib.name(r)]))
}

deny contains entry if {
	r := instances[_]
	object.get(r, "storage_encrypted", false) != true
	entry := finding("RDS.3", sprintf("RDS instance '%s' has no storage encryption", [cislib.name(r)]))
}

deny contains entry if {
	r := instances[_]
	object.get(r, "multi_az", false) != true
	entry := finding("RDS.5", sprintf("RDS instance '%s' is not multi-AZ", [cislib.name(r)]))
}

deny contains entry if {
	r := upgradable_instances[_]
	object.get(r, "auto_minor_version_upgrade", true) != true
	entry := finding("RDS.13", sprintf("RDS instance '%s' has automatic minor version upgrades disabled", [cislib.name(r)]))
}

deny contains entry if {
	c := clusters[_]
	count(object.get(c, "availability_zones", [])) < 2
	entry := finding("RDS.15", sprintf("RDS cluster '%s' spans fewer than two Availability Zones", [cislib.name(c)]))
}
