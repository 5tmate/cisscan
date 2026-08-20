import csv
import io


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
        "_name": f"{sg.get('GroupName', '')}_{sg.get('GroupId', '')}".strip("_"),
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
    instance_id = instance.get("InstanceId", "")
    tag = tag_name(instance.get("Tags"), "")
    return {
        "_type": "aws_instance",
        "_name": f"{tag}_{instance_id}".strip("_"),
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


def map_authorization_details(users, roles, groups):
    resources = []
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
