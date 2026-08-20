from botocore.exceptions import ClientError

from collectors.aws_api import (
    attempt,
    map_bucket,
    map_db_cluster,
    map_db_instance,
    map_instance,
    map_kms_key,
    map_network_acl,
    map_password_policy,
    map_security_group,
    map_trail,
    parse_credential_report,
)


def test_map_security_group_translates_rules():
    resource = map_security_group(
        {
            "GroupId": "sg-1",
            "GroupName": "bastion",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                },
                {"IpProtocol": "-1", "IpRanges": []},
            ],
            "IpPermissionsEgress": [],
        }
    )
    assert resource["_type"] == "aws_security_group"
    assert resource["name"] == "bastion"
    assert resource["ingress"][0] == {
        "protocol": "tcp",
        "from_port": 22,
        "to_port": 22,
        "cidr_blocks": ["0.0.0.0/0"],
        "ipv6_cidr_blocks": ["::/0"],
    }
    assert resource["ingress"][1]["protocol"] == "-1"
    assert resource["ingress"][1]["from_port"] == 0
    assert resource["egress"] == []


def test_map_network_acl_marks_default_type():
    resource = map_network_acl(
        {
            "NetworkAclId": "acl-1",
            "IsDefault": True,
            "Entries": [
                {
                    "Egress": False,
                    "RuleAction": "allow",
                    "Protocol": "6",
                    "CidrBlock": "0.0.0.0/0",
                    "PortRange": {"From": 22, "To": 22},
                },
                {"Egress": True, "RuleAction": "allow", "Protocol": "-1", "CidrBlock": "0.0.0.0/0"},
            ],
        }
    )
    assert resource["_type"] == "aws_default_network_acl"
    assert resource["ingress"] == [
        {"action": "allow", "protocol": "6", "cidr_block": "0.0.0.0/0", "from_port": 22, "to_port": 22}
    ]
    non_default = map_network_acl({"NetworkAclId": "acl-2", "IsDefault": False, "Entries": []})
    assert non_default["_type"] == "aws_network_acl"


def test_map_instance_reads_metadata_options_and_name_tag():
    resource = map_instance(
        {
            "InstanceId": "i-1",
            "Tags": [{"Key": "Name", "Value": "web-1"}],
            "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled"},
        }
    )
    assert resource["_type"] == "aws_instance"
    assert resource["_name"] == "web-1"
    assert resource["metadata_options"] == [{"http_tokens": "required", "http_endpoint": "enabled"}]


def test_map_trail_translates_selectors():
    resource = map_trail(
        {
            "Name": "main",
            "IsMultiRegionTrail": True,
            "KmsKeyId": "arn:aws:kms:ap-northeast-1:1:key/k",
            "LogFileValidationEnabled": True,
            "S3BucketName": "trail-logs",
        },
        is_logging=True,
        event_selectors=[
            {
                "ReadWriteType": "All",
                "IncludeManagementEvents": True,
                "DataResources": [{"Type": "AWS::S3::Object", "Values": ["arn:aws:s3"]}],
            }
        ],
        advanced_event_selectors=[],
    )
    assert resource["_type"] == "aws_cloudtrail"
    assert resource["is_multi_region_trail"] is True
    assert resource["enable_logging"] is True
    assert resource["enable_log_file_validation"] is True
    assert resource["event_selector"] == [
        {
            "read_write_type": "All",
            "include_management_events": True,
            "data_resource": [{"type": "AWS::S3::Object", "values": ["arn:aws:s3"]}],
        }
    ]


def test_parse_credential_report_types_booleans_and_keeps_na():
    text = (
        "user,arn,password_enabled,mfa_active,access_key_1_active,access_key_1_last_rotated,password_last_used\n"
        "<root_account>,arn:aws:iam::1:root,not_supported,true,false,N/A,2026-08-01T00:00:00+00:00\n"
        "alice,arn:aws:iam::1:user/alice,true,false,true,2026-01-01T00:00:00+00:00,N/A\n"
    )
    rows = parse_credential_report(text)
    root = rows[0]
    assert root["_type"] == "aws_iam_credential_report_user"
    assert root["user"] == "<root_account>"
    assert root["mfa_active"] is True
    assert root["password_enabled"] == "not_supported"
    alice = rows[1]
    assert alice["password_enabled"] is True
    assert alice["access_key_1_active"] is True
    assert alice["access_key_1_last_rotated"] == "2026-01-01T00:00:00+00:00"
    assert alice["password_last_used"] == "N/A"


def test_map_bucket_assembles_attributes():
    resource = map_bucket(
        "data",
        logging={"TargetBucket": "logs"},
        versioning={"Status": "Enabled", "MFADelete": "Enabled"},
        lifecycle_rules=[{"ID": "expire"}],
    )
    assert resource["_type"] == "aws_s3_bucket"
    assert resource["bucket"] == "data"
    assert resource["logging"] == [{"target_bucket": "logs"}]
    assert resource["versioning"] == [{"enabled": True, "mfa_delete": True}]
    assert len(resource["lifecycle_rule"]) == 1

    bare = map_bucket("empty", logging=None, versioning={}, lifecycle_rules=[])
    assert bare["logging"] == []
    assert bare["versioning"] == [{"enabled": False, "mfa_delete": False}]
    assert bare["lifecycle_rule"] == []


def test_map_kms_key_translates_spec_and_rotation():
    resource = map_kms_key(
        {"KeyId": "k-1", "KeySpec": "SYMMETRIC_DEFAULT", "KeyUsage": "ENCRYPT_DECRYPT"},
        rotation_enabled=False,
    )
    assert resource["_type"] == "aws_kms_key"
    assert resource["customer_master_key_spec"] == "SYMMETRIC_DEFAULT"
    assert resource["key_usage"] == "ENCRYPT_DECRYPT"
    assert resource["enable_key_rotation"] is False


def test_map_db_instance_splits_cluster_members():
    standalone = map_db_instance(
        {
            "DBInstanceIdentifier": "appdb",
            "PubliclyAccessible": False,
            "StorageEncrypted": True,
            "MultiAZ": True,
            "AutoMinorVersionUpgrade": True,
        }
    )
    assert standalone["_type"] == "aws_db_instance"
    assert standalone["publicly_accessible"] is False
    member = map_db_instance(
        {
            "DBInstanceIdentifier": "aurora-1",
            "DBClusterIdentifier": "aurora",
            "AutoMinorVersionUpgrade": False,
        }
    )
    assert member["_type"] == "aws_rds_cluster_instance"
    assert member["auto_minor_version_upgrade"] is False


def test_map_db_cluster_reads_availability_zones():
    resource = map_db_cluster({"DBClusterIdentifier": "aurora", "AvailabilityZones": ["a", "b"]})
    assert resource["_type"] == "aws_rds_cluster"
    assert resource["availability_zones"] == ["a", "b"]


def test_map_password_policy_translates_fields():
    resource = map_password_policy({"MinimumPasswordLength": 14, "PasswordReusePrevention": 24})
    assert resource["_type"] == "aws_iam_account_password_policy"
    assert resource["minimum_password_length"] == 14
    assert resource["password_reuse_prevention"] == 24


def test_attempt_declares_on_success_and_skips_on_denial():
    declared = set()
    result = attempt(declared, ["aws_vpc"], lambda: 42)
    assert result == 42
    assert "aws_vpc" in declared

    def denied():
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "DescribeVpcs")

    result = attempt(declared, ["aws_flow_log"], denied)
    assert result is None
    assert "aws_flow_log" not in declared
