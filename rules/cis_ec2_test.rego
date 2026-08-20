package cis_ec2_test

import rego.v1

meta := {
	"account_id": "111122223333",
	"scanned_at": "2026-08-20T00:00:00Z",
	"collected_types": ["aws_flow_log", "aws_ebs_encryption_by_default"],
}

sg(name, ingress) := {
	"_type": "aws_security_group",
	"_name": name,
	"name": name,
	"ingress": ingress,
	"egress": [],
}

denials(doc, control) := d if {
	all_denies := data.cis_ec2.deny with input as doc
	d := [e | some e in all_denies; e.control == control]
}

test_ec2_2_fails_when_default_sg_has_rules if {
	doc := {"meta": meta, "resources": [sg("default", [{"protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["10.0.0.0/8"]}])]}
	count(denials(doc, "EC2.2")) == 1
}

test_ec2_2_passes_when_default_sg_empty if {
	doc := {"meta": meta, "resources": [sg("default", [])]}
	count(denials(doc, "EC2.2")) == 0
}

test_ec2_2_ignores_non_default_sg if {
	doc := {"meta": meta, "resources": [sg("web", [{"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr_blocks": ["0.0.0.0/0"]}])]}
	count(denials(doc, "EC2.2")) == 0
}

test_ec2_6_fails_for_vpc_without_flow_log if {
	doc := {"meta": meta, "resources": [{"_type": "aws_vpc", "_name": "main", "id": "vpc-1"}]}
	count(denials(doc, "EC2.6")) == 1
}

test_ec2_6_passes_with_reject_flow_log if {
	doc := {"meta": meta, "resources": [
		{"_type": "aws_vpc", "_name": "main", "id": "vpc-1"},
		{"_type": "aws_flow_log", "vpc_id": "vpc-1", "traffic_type": "REJECT"},
	]}
	count(denials(doc, "EC2.6")) == 0
}

test_ec2_6_passes_with_all_flow_log if {
	doc := {"meta": meta, "resources": [
		{"_type": "aws_vpc", "_name": "main", "id": "vpc-1"},
		{"_type": "aws_flow_log", "vpc_id": "vpc-1", "traffic_type": "ALL"},
	]}
	count(denials(doc, "EC2.6")) == 0
}

test_ec2_6_not_judged_when_flow_logs_not_collected if {
	doc := {"meta": {"account_id": "1", "scanned_at": "2026-08-20T00:00:00Z", "collected_types": []}, "resources": [{"_type": "aws_vpc", "_name": "main", "id": "vpc-1"}]}
	count(denials(doc, "EC2.6")) == 0
}

test_ec2_7_fails_when_default_encryption_off if {
	doc := {"meta": meta, "resources": [{"_type": "aws_ebs_encryption_by_default", "_name": "ap-northeast-1", "enabled": false}]}
	count(denials(doc, "EC2.7")) == 1
}

test_ec2_7_passes_when_default_encryption_on if {
	doc := {"meta": meta, "resources": [{"_type": "aws_ebs_encryption_by_default", "_name": "ap-northeast-1", "enabled": true}]}
	count(denials(doc, "EC2.7")) == 0
}

test_ec2_8_fails_with_optional_tokens if {
	doc := {"meta": meta, "resources": [{"_type": "aws_instance", "_name": "web", "metadata_options": [{"http_tokens": "optional"}]}]}
	count(denials(doc, "EC2.8")) == 1
}

test_ec2_8_fails_without_metadata_options if {
	doc := {"meta": meta, "resources": [{"_type": "aws_instance", "_name": "web"}]}
	count(denials(doc, "EC2.8")) == 1
}

test_ec2_8_passes_with_required_tokens if {
	doc := {"meta": meta, "resources": [{"_type": "aws_instance", "_name": "web", "metadata_options": [{"http_tokens": "required"}]}]}
	count(denials(doc, "EC2.8")) == 0
}

test_ec2_8_passes_with_endpoint_disabled if {
	doc := {"meta": meta, "resources": [{"_type": "aws_instance", "_name": "web", "metadata_options": [{"http_endpoint": "disabled", "http_tokens": "optional"}]}]}
	count(denials(doc, "EC2.8")) == 0
}

nacl(ingress) := {"_type": "aws_network_acl", "_name": "main", "ingress": ingress}

test_ec2_21_fails_on_world_ssh if {
	doc := {"meta": meta, "resources": [nacl([{"action": "allow", "protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_block": "0.0.0.0/0"}])]}
	count(denials(doc, "EC2.21")) == 1
}

test_ec2_21_fails_on_ipv6_world_rdp if {
	doc := {"meta": meta, "resources": [nacl([{"action": "allow", "protocol": "tcp", "from_port": 3389, "to_port": 3389, "ipv6_cidr_block": "::/0"}])]}
	count(denials(doc, "EC2.21")) == 1
}

test_ec2_21_fails_on_all_protocols if {
	doc := {"meta": meta, "resources": [nacl([{"action": "allow", "protocol": "-1", "from_port": 0, "to_port": 0, "cidr_block": "0.0.0.0/0"}])]}
	count(denials(doc, "EC2.21")) > 0
}

test_ec2_21_ignores_deny_rules if {
	doc := {"meta": meta, "resources": [nacl([{"action": "deny", "protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_block": "0.0.0.0/0"}])]}
	count(denials(doc, "EC2.21")) == 0
}

test_ec2_21_ignores_other_ports if {
	doc := {"meta": meta, "resources": [nacl([{"action": "allow", "protocol": "tcp", "from_port": 80, "to_port": 80, "cidr_block": "0.0.0.0/0"}])]}
	count(denials(doc, "EC2.21")) == 0
}

test_ec2_53_fails_on_world_ssh if {
	doc := {"meta": meta, "resources": [sg("bastion", [{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}])]}
	count(denials(doc, "EC2.53")) == 1
}

test_ec2_53_fails_on_all_protocols_open if {
	doc := {"meta": meta, "resources": [sg("open", [{"protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]}])]}
	count(denials(doc, "EC2.53")) > 0
}

test_ec2_53_allows_https if {
	doc := {"meta": meta, "resources": [sg("web", [{"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr_blocks": ["0.0.0.0/0"]}])]}
	count(denials(doc, "EC2.53")) == 0
}

test_ec2_54_fails_on_ipv6_world_rdp if {
	doc := {"meta": meta, "resources": [sg("win", [{"protocol": "tcp", "from_port": 3389, "to_port": 3389, "cidr_blocks": [], "ipv6_cidr_blocks": ["::/0"]}])]}
	count(denials(doc, "EC2.54")) == 1
}

test_ec2_53_fails_on_udp_ssh if {
	doc := {"meta": meta, "resources": [sg("udp", [{"protocol": "udp", "from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}])]}
	count(denials(doc, "EC2.53")) == 1
}

test_ec2_53_ignores_postgres_port if {
	doc := {"meta": meta, "resources": [sg("db", [{"protocol": "tcp", "from_port": 5432, "to_port": 5432, "cidr_blocks": ["0.0.0.0/0"]}])]}
	count(denials(doc, "EC2.53")) == 0
}

test_ec2_21_skips_default_nacl if {
	doc := {"meta": meta, "resources": [{"_type": "aws_default_network_acl", "_name": "default", "ingress": [{"action": "allow", "protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_block": "0.0.0.0/0"}]}]}
	count(denials(doc, "EC2.21")) == 0
}

test_ec2_54_not_triggered_by_ipv4 if {
	doc := {"meta": meta, "resources": [sg("bastion", [{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}])]}
	count(denials(doc, "EC2.54")) == 0
}
