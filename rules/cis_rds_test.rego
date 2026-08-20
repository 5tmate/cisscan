package cis_rds_test

import rego.v1

meta := {"account_id": "111122223333", "scanned_at": "2026-08-20T00:00:00Z", "collected_types": []}

db(extra) := object.union(
	{
		"_type": "aws_db_instance",
		"_name": "appdb",
		"publicly_accessible": false,
		"storage_encrypted": true,
		"multi_az": true,
		"auto_minor_version_upgrade": true,
	},
	extra,
)

denials(doc, control) := d if {
	all_denies := data.cis_rds.deny with input as doc
	d := [e | some e in all_denies; e.control == control]
}

test_rds_2_fails_when_public if {
	doc := {"meta": meta, "resources": [db({"publicly_accessible": true})]}
	count(denials(doc, "RDS.2")) == 1
}

test_rds_3_fails_when_unencrypted if {
	doc := {"meta": meta, "resources": [db({"storage_encrypted": false})]}
	count(denials(doc, "RDS.3")) == 1
}

test_rds_5_fails_without_multi_az if {
	doc := {"meta": meta, "resources": [db({"multi_az": false})]}
	count(denials(doc, "RDS.5")) == 1
}

test_rds_13_fails_without_auto_upgrade if {
	doc := {"meta": meta, "resources": [db({"auto_minor_version_upgrade": false})]}
	count(denials(doc, "RDS.13")) == 1
}

test_rds_13_covers_cluster_instances if {
	doc := {"meta": meta, "resources": [{"_type": "aws_rds_cluster_instance", "_name": "aurora-1", "auto_minor_version_upgrade": false}]}
	count(denials(doc, "RDS.13")) == 1
}

test_rds_compliant_instance_passes if {
	doc := {"meta": meta, "resources": [db({})]}
	count(denials(doc, "RDS.2")) == 0
	count(denials(doc, "RDS.3")) == 0
	count(denials(doc, "RDS.5")) == 0
	count(denials(doc, "RDS.13")) == 0
}

test_rds_15_fails_with_single_az_cluster if {
	doc := {"meta": meta, "resources": [{"_type": "aws_rds_cluster", "_name": "aurora", "availability_zones": ["ap-northeast-1a"]}]}
	count(denials(doc, "RDS.15")) == 1
}

test_rds_15_passes_with_multi_az_cluster if {
	doc := {"meta": meta, "resources": [{"_type": "aws_rds_cluster", "_name": "aurora", "availability_zones": ["ap-northeast-1a", "ap-northeast-1c"]}]}
	count(denials(doc, "RDS.15")) == 0
}
