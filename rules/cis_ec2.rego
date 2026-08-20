package cis_ec2

import data.cislib
import rego.v1

title := "CIS AWS Foundations Benchmark v5.0.0 — EC2 and VPC"

titles := {
	"EC2.2": "VPC default security groups should not allow inbound or outbound traffic",
	"EC2.6": "VPC flow logging should be enabled in all VPCs",
	"EC2.7": "EBS default encryption should be enabled",
	"EC2.8": "EC2 instances should use Instance Metadata Service Version 2 (IMDSv2)",
	"EC2.21": "Network ACLs should not allow ingress from 0.0.0.0/0 to port 22 or port 3389",
	"EC2.53": "EC2 security groups should not allow ingress from 0.0.0.0/0 to remote server administration ports",
	"EC2.54": "EC2 security groups should not allow ingress from ::/0 to remote server administration ports",
}

cis_requirements := {
	"EC2.2": "5.5",
	"EC2.6": "3.7",
	"EC2.7": "5.1.1",
	"EC2.8": "5.7",
	"EC2.21": "5.2",
	"EC2.53": "5.3",
	"EC2.54": "5.4",
}

severities := {
	"EC2.2": "High",
	"EC2.6": "Medium",
	"EC2.7": "Medium",
	"EC2.8": "High",
	"EC2.21": "Medium",
	"EC2.53": "High",
	"EC2.54": "High",
}

enforced := {"EC2.2", "EC2.6", "EC2.7", "EC2.8", "EC2.21", "EC2.53", "EC2.54"}

admin_ports := {22, 3389}

finding(control, message) := {"control": control, "message": message}

security_groups contains sg if {
	sg := input.resources[_]
	sg._type == "aws_security_group"
}

default_sgs contains sg if {
	sg := security_groups[_]
	object.get(sg, "name", "") == "default"
}

applicable contains entry if {
	sg := default_sgs[_]
	entry := {"control": "EC2.2", "resource": cislib.name(sg)}
}

deny contains entry if {
	sg := default_sgs[_]
	count(object.get(sg, "ingress", [])) + count(object.get(sg, "egress", [])) > 0
	entry := finding("EC2.2", sprintf("default security group '%s' allows traffic: remove all ingress and egress rules", [cislib.name(sg)]))
}

vpcs contains v if {
	v := input.resources[_]
	v._type == "aws_vpc"
}

applicable contains entry if {
	cislib.collected("aws_flow_log")
	v := vpcs[_]
	entry := {"control": "EC2.6", "resource": cislib.name(v)}
}

deny contains entry if {
	cislib.collected("aws_flow_log")
	v := vpcs[_]
	not flow_logged(v)
	entry := finding("EC2.6", sprintf("VPC '%s' has no flow log capturing rejected traffic", [cislib.name(v)]))
}

flow_logged(v) if {
	fl := input.resources[_]
	fl._type == "aws_flow_log"
	object.get(fl, "vpc_id", "") == object.get(v, "id", "")
	object.get(fl, "traffic_type", "") in {"REJECT", "ALL"}
}

applicable contains entry if {
	r := input.resources[_]
	r._type == "aws_ebs_encryption_by_default"
	entry := {"control": "EC2.7", "resource": cislib.name(r)}
}

deny contains entry if {
	r := input.resources[_]
	r._type == "aws_ebs_encryption_by_default"
	object.get(r, "enabled", false) != true
	entry := finding("EC2.7", sprintf("EBS default encryption is disabled in region '%s'", [cislib.name(r)]))
}

instances contains i if {
	i := input.resources[_]
	i._type == "aws_instance"
}

applicable contains entry if {
	i := instances[_]
	entry := {"control": "EC2.8", "resource": cislib.name(i)}
}

deny contains entry if {
	i := instances[_]
	not imdsv2_ok(i)
	entry := finding("EC2.8", sprintf("EC2 instance '%s' does not require IMDSv2: set metadata_options http_tokens=required", [cislib.name(i)]))
}

imdsv2_ok(i) if object.get(i, "metadata_options", [])[0].http_tokens == "required"

imdsv2_ok(i) if object.get(i, "metadata_options", [])[0].http_endpoint == "disabled"

nacls contains n if {
	n := input.resources[_]
	n._type == "aws_network_acl"
}

applicable contains entry if {
	n := nacls[_]
	entry := {"control": "EC2.21", "resource": cislib.name(n)}
}

deny contains entry if {
	n := nacls[_]
	rule := object.get(n, "ingress", [])[_]
	lower(object.get(rule, "action", "")) == "allow"
	nacl_world_source(rule)
	some port in admin_ports
	nacl_covers(rule, port)
	entry := finding("EC2.21", sprintf("network ACL '%s' allows ingress to port %d from the internet", [cislib.name(n), port]))
}

nacl_world_source(rule) if object.get(rule, "cidr_block", "") == "0.0.0.0/0"

nacl_world_source(rule) if object.get(rule, "ipv6_cidr_block", "") == "::/0"

nacl_covers(rule, _) if object.get(rule, "protocol", "") in {"-1", "all"}

nacl_covers(rule, port) if {
	object.get(rule, "protocol", "") in {"tcp", "6"}
	to_number(object.get(rule, "from_port", -1)) <= port
	to_number(object.get(rule, "to_port", -1)) >= port
}

applicable contains entry if {
	sg := security_groups[_]
	some control in ["EC2.53", "EC2.54"]
	entry := {"control": control, "resource": cislib.name(sg)}
}

deny contains entry if {
	sg := security_groups[_]
	rule := object.get(sg, "ingress", [])[_]
	"0.0.0.0/0" in object.get(rule, "cidr_blocks", [])
	some port in admin_ports
	sg_covers(rule, port)
	entry := finding("EC2.53", sprintf("security group '%s' allows ingress to port %d from 0.0.0.0/0", [cislib.name(sg), port]))
}

deny contains entry if {
	sg := security_groups[_]
	rule := object.get(sg, "ingress", [])[_]
	"::/0" in object.get(rule, "ipv6_cidr_blocks", [])
	some port in admin_ports
	sg_covers(rule, port)
	entry := finding("EC2.54", sprintf("security group '%s' allows ingress to port %d from ::/0", [cislib.name(sg), port]))
}

sg_covers(rule, _) if object.get(rule, "protocol", "") == "-1"

sg_covers(rule, port) if {
	object.get(rule, "protocol", "") in {"tcp", "udp", "6", "17"}
	to_number(object.get(rule, "from_port", -1)) <= port
	to_number(object.get(rule, "to_port", -1)) >= port
}
