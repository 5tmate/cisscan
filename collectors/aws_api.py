import argparse
import csv
import io
import sys
import time

import boto3
from botocore.exceptions import ClientError

from collectors.document import make_document, write_document

CREDENTIAL_REPORT_TIMESTAMP_KEYS = "last_rotated", "last_used", "last_changed", "next_rotation"


def tag_name(tags, fallback):
    for tag in tags or []:
        if tag.get("Key") == "Name":
            return tag["Value"]
    return fallback


def iso(value):
    if hasattr(value, "strftime"):
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")
    return value


def map_security_group(sg):
    def rules(permissions):
        return [
            {
                "protocol": p.get("IpProtocol", ""),
                "from_port": p.get("FromPort", 0),
                "to_port": p.get("ToPort", 0),
                "cidr_blocks": [r["CidrIp"] for r in p.get("IpRanges", [])],
                "ipv6_cidr_blocks": [r["CidrIpv6"] for r in p.get("Ipv6Ranges", [])],
            }
            for p in permissions
        ]

    return {
        "_type": "aws_security_group",
        "_name": sg.get("GroupName", sg.get("GroupId", "")),
        "id": sg.get("GroupId", ""),
        "name": sg.get("GroupName", ""),
        "ingress": rules(sg.get("IpPermissions", [])),
        "egress": rules(sg.get("IpPermissionsEgress", [])),
    }


def map_network_acl(acl):
    ingress = []
    for entry in acl.get("Entries", []):
        if entry.get("Egress", False):
            continue
        rule = {
            "action": entry.get("RuleAction", ""),
            "protocol": entry.get("Protocol", ""),
        }
        if "CidrBlock" in entry:
            rule["cidr_block"] = entry["CidrBlock"]
        if "Ipv6CidrBlock" in entry:
            rule["ipv6_cidr_block"] = entry["Ipv6CidrBlock"]
        if "PortRange" in entry:
            rule["from_port"] = entry["PortRange"].get("From", 0)
            rule["to_port"] = entry["PortRange"].get("To", 0)
        ingress.append(rule)
    kind = "aws_default_network_acl" if acl.get("IsDefault") else "aws_network_acl"
    return {
        "_type": kind,
        "_name": acl.get("NetworkAclId", ""),
        "id": acl.get("NetworkAclId", ""),
        "ingress": ingress,
    }


def map_instance(instance):
    options = instance.get("MetadataOptions", {})
    return {
        "_type": "aws_instance",
        "_name": tag_name(instance.get("Tags"), instance.get("InstanceId", "")),
        "id": instance.get("InstanceId", ""),
        "metadata_options": [
            {
                "http_tokens": options.get("HttpTokens", ""),
                "http_endpoint": options.get("HttpEndpoint", ""),
            }
        ],
    }


def map_trail(detail, is_logging, event_selectors, advanced_event_selectors):
    return {
        "_type": "aws_cloudtrail",
        "_name": detail.get("Name", ""),
        "is_multi_region_trail": detail.get("IsMultiRegionTrail", False),
        "enable_logging": is_logging,
        "enable_log_file_validation": detail.get("LogFileValidationEnabled", False),
        "kms_key_id": detail.get("KmsKeyId", ""),
        "s3_bucket_name": detail.get("S3BucketName", ""),
        "event_selector": [
            {
                "read_write_type": s.get("ReadWriteType", ""),
                "include_management_events": s.get("IncludeManagementEvents", True),
                "data_resource": [
                    {"type": d.get("Type", ""), "values": d.get("Values", [])}
                    for d in s.get("DataResources", [])
                ],
            }
            for s in event_selectors
        ],
        "advanced_event_selector": [
            {
                "field_selector": [
                    {"field": f.get("Field", ""), "equals": f.get("Equals", [])}
                    for f in s.get("FieldSelectors", [])
                ]
            }
            for s in advanced_event_selectors
        ],
    }


def parse_credential_report(text):
    rows = []
    for record in csv.DictReader(io.StringIO(text)):
        row = {"_type": "aws_iam_credential_report_user", "_name": record.get("user", "")}
        for key, value in record.items():
            if value == "true":
                row[key] = True
            elif value == "false":
                row[key] = False
            else:
                row[key] = value
        rows.append(row)
    return rows


def map_bucket(name, logging, versioning, lifecycle_rules):
    versioning = versioning or {}
    return {
        "_type": "aws_s3_bucket",
        "_name": name,
        "bucket": name,
        "logging": [{"target_bucket": logging["TargetBucket"]}] if logging else [],
        "versioning": [
            {
                "enabled": versioning.get("Status", "") == "Enabled",
                "mfa_delete": versioning.get("MFADelete", "") == "Enabled",
            }
        ],
        "lifecycle_rule": [{"id": rule.get("ID", "")} for rule in lifecycle_rules],
    }


def map_pab(scope_type, name, config, bucket=None):
    resource = {
        "_type": scope_type,
        "_name": name,
        "block_public_acls": config.get("BlockPublicAcls", False),
        "block_public_policy": config.get("BlockPublicPolicy", False),
        "ignore_public_acls": config.get("IgnorePublicAcls", False),
        "restrict_public_buckets": config.get("RestrictPublicBuckets", False),
    }
    if bucket is not None:
        resource["bucket"] = bucket
    return resource


def map_kms_key(metadata, rotation_enabled):
    return {
        "_type": "aws_kms_key",
        "_name": metadata.get("KeyId", ""),
        "customer_master_key_spec": metadata.get("KeySpec", "SYMMETRIC_DEFAULT"),
        "key_usage": metadata.get("KeyUsage", "ENCRYPT_DECRYPT"),
        "enable_key_rotation": rotation_enabled,
    }


def map_db_instance(db):
    kind = "aws_rds_cluster_instance" if db.get("DBClusterIdentifier") else "aws_db_instance"
    return {
        "_type": kind,
        "_name": db.get("DBInstanceIdentifier", ""),
        "publicly_accessible": db.get("PubliclyAccessible", False),
        "storage_encrypted": db.get("StorageEncrypted", False),
        "multi_az": db.get("MultiAZ", False),
        "auto_minor_version_upgrade": db.get("AutoMinorVersionUpgrade", True),
    }


def map_db_cluster(cluster):
    return {
        "_type": "aws_rds_cluster",
        "_name": cluster.get("DBClusterIdentifier", ""),
        "availability_zones": cluster.get("AvailabilityZones", []),
    }


def map_password_policy(policy):
    return {
        "_type": "aws_iam_account_password_policy",
        "_name": "account",
        "minimum_password_length": policy.get("MinimumPasswordLength", 0),
        "password_reuse_prevention": policy.get("PasswordReusePrevention", 0),
    }


def attempt(declared, types, fn):
    try:
        result = fn()
    except ClientError as error:
        print(f"skip {types}: {error.response['Error']['Code']}", file=sys.stderr)
        return None
    declared.update(types)
    return result


def paginate(client, operation, result_key, **kwargs):
    items = []
    for page in client.get_paginator(operation).paginate(**kwargs):
        items.extend(page.get(result_key, []))
    return items


def fetch_credential_report(iam):
    for _ in range(30):
        state = iam.generate_credential_report()["State"]
        if state == "COMPLETE":
            break
        time.sleep(1)
    text = iam.get_credential_report()["Content"].decode()
    return parse_credential_report(text)


def fetch_authorization_details(iam):
    resources = []
    pages = iam.get_paginator("get_account_authorization_details").paginate(Filter=["User", "Role", "Group"])
    users, roles, groups = [], [], []
    for page in pages:
        users.extend(page.get("UserDetailList", []))
        roles.extend(page.get("RoleDetailList", []))
        groups.extend(page.get("GroupDetailList", []))
    for user in users:
        resources.append({"_type": "aws_iam_user", "_name": user["UserName"], "name": user["UserName"]})
        for attached in user.get("AttachedManagedPolicies", []):
            resources.append(
                {
                    "_type": "aws_iam_user_policy_attachment",
                    "_name": f"{user['UserName']}/{attached.get('PolicyName', '')}",
                    "user": user["UserName"],
                    "policy_arn": attached.get("PolicyArn", ""),
                }
            )
        for inline in user.get("UserPolicyList", []):
            resources.append(
                {
                    "_type": "aws_iam_user_policy",
                    "_name": f"{user['UserName']}/{inline.get('PolicyName', '')}",
                    "user": user["UserName"],
                    "name": inline.get("PolicyName", ""),
                }
            )
    for role in roles:
        for attached in role.get("AttachedManagedPolicies", []):
            resources.append(
                {
                    "_type": "aws_iam_role_policy_attachment",
                    "_name": f"{role['RoleName']}/{attached.get('PolicyName', '')}",
                    "role": role["RoleName"],
                    "policy_arn": attached.get("PolicyArn", ""),
                }
            )
    for group in groups:
        for attached in group.get("AttachedManagedPolicies", []):
            resources.append(
                {
                    "_type": "aws_iam_group_policy_attachment",
                    "_name": f"{group['GroupName']}/{attached.get('PolicyName', '')}",
                    "group": group["GroupName"],
                    "policy_arn": attached.get("PolicyArn", ""),
                }
            )
    return resources


def collect_iam(session, declared, resources):
    iam = session.client("iam")
    details = attempt(
        declared,
        [
            "aws_iam_user",
            "aws_iam_user_policy",
            "aws_iam_user_policy_attachment",
            "aws_iam_role_policy_attachment",
            "aws_iam_group_policy_attachment",
        ],
        lambda: fetch_authorization_details(iam),
    )
    resources.extend(details or [])
    report = attempt(declared, ["aws_iam_credential_report_user"], lambda: fetch_credential_report(iam))
    resources.extend(report or [])

    def password_policy():
        try:
            return [map_password_policy(iam.get_account_password_policy()["PasswordPolicy"])]
        except iam.exceptions.NoSuchEntityException:
            return []

    resources.extend(attempt(declared, ["aws_iam_account_password_policy"], password_policy) or [])

    def virtual_mfa():
        return [
            {
                "_type": "aws_iam_virtual_mfa_device",
                "_name": d.get("SerialNumber", ""),
                "serial_number": d.get("SerialNumber", ""),
                "user_arn": d.get("User", {}).get("Arn", ""),
            }
            for d in paginate(iam, "list_virtual_mfa_devices", "VirtualMFADevices")
        ]

    resources.extend(attempt(declared, ["aws_iam_virtual_mfa_device"], virtual_mfa) or [])

    def server_certificates():
        return [
            {
                "_type": "aws_iam_server_certificate",
                "_name": c.get("ServerCertificateName", ""),
                "expiration": iso(c.get("Expiration", "")),
            }
            for c in paginate(iam, "list_server_certificates", "ServerCertificateMetadataList")
        ]

    resources.extend(attempt(declared, ["aws_iam_server_certificate"], server_certificates) or [])


def collect_s3(session, declared, resources):
    s3 = session.client("s3")

    def buckets():
        collected = []
        for bucket in s3.list_buckets().get("Buckets", []):
            name = bucket["Name"]
            logging = s3.get_bucket_logging(Bucket=name).get("LoggingEnabled")
            versioning = s3.get_bucket_versioning(Bucket=name)
            try:
                lifecycle = s3.get_bucket_lifecycle_configuration(Bucket=name).get("Rules", [])
            except ClientError:
                lifecycle = []
            collected.append(map_bucket(name, logging, versioning, lifecycle))
            try:
                policy = s3.get_bucket_policy(Bucket=name)["Policy"]
                collected.append(
                    {"_type": "aws_s3_bucket_policy", "_name": name, "bucket": name, "policy": policy}
                )
            except ClientError:
                pass
            try:
                pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                collected.append(map_pab("aws_s3_bucket_public_access_block", name, pab, bucket=name))
            except ClientError:
                pass
        return collected

    resources.extend(
        attempt(
            declared,
            ["aws_s3_bucket", "aws_s3_bucket_policy", "aws_s3_bucket_public_access_block"],
            buckets,
        )
        or []
    )

    def account_pab():
        control = session.client("s3control")
        account = session.client("sts").get_caller_identity()["Account"]
        try:
            config = control.get_public_access_block(AccountId=account)["PublicAccessBlockConfiguration"]
        except control.exceptions.NoSuchPublicAccessBlockConfiguration:
            return []
        return [map_pab("aws_s3_account_public_access_block", "account", config)]

    resources.extend(attempt(declared, ["aws_s3_account_public_access_block"], account_pab) or [])


def collect_account_contact(session, declared, resources):
    def security_contact():
        client = session.client("account")
        try:
            contact = client.get_alternate_contact(AlternateContactType="SECURITY")["AlternateContact"]
        except client.exceptions.ResourceNotFoundException:
            return []
        return [
            {
                "_type": "aws_account_alternate_contact",
                "_name": contact.get("Name", "security"),
                "alternate_contact_type": "SECURITY",
            }
        ]

    resources.extend(attempt(declared, ["aws_account_alternate_contact"], security_contact) or [])


def collect_region(session, region, declared, resources):
    ec2 = session.client("ec2", region_name=region)

    def instances():
        collected = []
        for reservation in paginate(ec2, "describe_instances", "Reservations"):
            collected.extend(map_instance(i) for i in reservation.get("Instances", []))
        return collected

    resources.extend(attempt(declared, ["aws_instance"], instances) or [])
    resources.extend(
        attempt(
            declared,
            ["aws_security_group"],
            lambda: [
                map_security_group(g) for g in paginate(ec2, "describe_security_groups", "SecurityGroups")
            ],
        )
        or []
    )
    resources.extend(
        attempt(
            declared,
            ["aws_network_acl", "aws_default_network_acl"],
            lambda: [map_network_acl(a) for a in paginate(ec2, "describe_network_acls", "NetworkAcls")],
        )
        or []
    )
    resources.extend(
        attempt(
            declared,
            ["aws_vpc"],
            lambda: [
                {"_type": "aws_vpc", "_name": v["VpcId"], "id": v["VpcId"]}
                for v in paginate(ec2, "describe_vpcs", "Vpcs")
            ],
        )
        or []
    )
    resources.extend(
        attempt(
            declared,
            ["aws_flow_log"],
            lambda: [
                {
                    "_type": "aws_flow_log",
                    "_name": f["FlowLogId"],
                    "vpc_id": f.get("ResourceId", ""),
                    "traffic_type": f.get("TrafficType", ""),
                }
                for f in paginate(ec2, "describe_flow_logs", "FlowLogs")
            ],
        )
        or []
    )
    resources.extend(
        attempt(
            declared,
            ["aws_ebs_encryption_by_default"],
            lambda: [
                {
                    "_type": "aws_ebs_encryption_by_default",
                    "_name": region,
                    "enabled": ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"],
                }
            ],
        )
        or []
    )

    efs = session.client("efs", region_name=region)
    resources.extend(
        attempt(
            declared,
            ["aws_efs_file_system"],
            lambda: [
                {
                    "_type": "aws_efs_file_system",
                    "_name": f.get("Name") or f["FileSystemId"],
                    "encrypted": f.get("Encrypted", False),
                }
                for f in paginate(efs, "describe_file_systems", "FileSystems")
            ],
        )
        or []
    )

    kms = session.client("kms", region_name=region)

    def kms_keys():
        collected = []
        for key in paginate(kms, "list_keys", "Keys"):
            metadata = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
            if metadata.get("KeyManager") != "CUSTOMER" or metadata.get("KeyState") != "Enabled":
                continue
            try:
                rotation = kms.get_key_rotation_status(KeyId=key["KeyId"])["KeyRotationEnabled"]
            except ClientError:
                rotation = False
            collected.append(map_kms_key(metadata, rotation))
        return collected

    resources.extend(attempt(declared, ["aws_kms_key"], kms_keys) or [])

    rds = session.client("rds", region_name=region)
    resources.extend(
        attempt(
            declared,
            ["aws_db_instance", "aws_rds_cluster_instance"],
            lambda: [map_db_instance(d) for d in paginate(rds, "describe_db_instances", "DBInstances")],
        )
        or []
    )
    resources.extend(
        attempt(
            declared,
            ["aws_rds_cluster"],
            lambda: [map_db_cluster(c) for c in paginate(rds, "describe_db_clusters", "DBClusters")],
        )
        or []
    )

    analyzer = session.client("accessanalyzer", region_name=region)
    resources.extend(
        attempt(
            declared,
            ["aws_accessanalyzer_analyzer"],
            lambda: [
                {
                    "_type": "aws_accessanalyzer_analyzer",
                    "_name": a.get("name", ""),
                    "type": a.get("type", ""),
                }
                for a in paginate(analyzer, "list_analyzers", "analyzers")
            ],
        )
        or []
    )

    config = session.client("config", region_name=region)

    def recorders():
        collected = []
        for r in config.describe_configuration_recorders().get("ConfigurationRecorders", []):
            group = r.get("recordingGroup", {})
            collected.append(
                {
                    "_type": "aws_config_configuration_recorder",
                    "_name": r.get("name", ""),
                    "name": r.get("name", ""),
                    "role_arn": r.get("roleARN", ""),
                    "recording_group": [{"all_supported": group.get("allSupported", False)}],
                }
            )
        for s in config.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", []):
            collected.append(
                {
                    "_type": "aws_config_configuration_recorder_status",
                    "_name": s.get("name", ""),
                    "name": s.get("name", ""),
                    "is_enabled": s.get("recording", False),
                }
            )
        return collected

    resources.extend(
        attempt(
            declared,
            ["aws_config_configuration_recorder", "aws_config_configuration_recorder_status"],
            recorders,
        )
        or []
    )

    trail = session.client("cloudtrail", region_name=region)

    def trails():
        collected = []
        for detail in trail.describe_trails(includeShadowTrails=False).get("trailList", []):
            arn = detail.get("TrailARN", detail.get("Name", ""))
            is_logging = trail.get_trail_status(Name=arn).get("IsLogging", False)
            selectors = trail.get_event_selectors(TrailName=arn)
            collected.append(
                map_trail(
                    detail,
                    is_logging,
                    selectors.get("EventSelectors", []),
                    selectors.get("AdvancedEventSelectors", []),
                )
            )
        return collected

    resources.extend(attempt(declared, ["aws_cloudtrail"], trails) or [])


def collect(profile, regions=None):
    session = boto3.Session(profile_name=profile)
    if regions is None:
        ec2 = session.client("ec2", region_name=session.region_name or "us-east-1")
        regions = [r["RegionName"] for r in ec2.describe_regions()["Regions"]]
    resources = []
    declared = set()
    collect_iam(session, declared, resources)
    collect_s3(session, declared, resources)
    collect_account_contact(session, declared, resources)
    for region in regions:
        start = len(resources)
        collect_region(session, region, declared, resources)
        for resource in resources[start:]:
            resource.setdefault("_region", region)
    return resources, declared


def main():
    parser = argparse.ArgumentParser(description="Collect CIS-relevant resources directly from AWS APIs")
    parser.add_argument("--profile", default="pulumi")
    parser.add_argument("--regions", help="comma separated, default: all enabled regions")
    parser.add_argument("--account")
    parser.add_argument("-o", "--output", default="out/resources.json")
    arguments = parser.parse_args()
    regions = arguments.regions.split(",") if arguments.regions else None
    resources, declared = collect(arguments.profile, regions)
    document = make_document(resources, declared, account_id=arguments.account)
    output = write_document(document, arguments.output)
    print(
        f"{output}: {len(document['resources'])} resources, "
        f"{len(document['meta']['collected_types'])} collected types, "
        f"account {document['meta']['account_id']}"
    )


if __name__ == "__main__":
    main()
