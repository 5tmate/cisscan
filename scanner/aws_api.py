import argparse
import sys
import time

import boto3
from botocore.exceptions import ClientError

from adapters.aws_response import (
    iso,
    map_authorization_details,
    map_bucket,
    map_db_cluster,
    map_db_instance,
    map_instance,
    map_kms_key,
    map_network_acl,
    map_pab,
    map_password_policy,
    map_security_group,
    map_trail,
    parse_credential_report,
)
from adapters.document import make_document, timestamped_output, write_document


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
        if iam.generate_credential_report()["State"] == "COMPLETE":
            break
        time.sleep(1)
    return parse_credential_report(iam.get_credential_report()["Content"].decode())


def fetch_authorization_details(iam):
    users, roles, groups = [], [], []
    pages = iam.get_paginator("get_account_authorization_details").paginate(Filter=["User", "Role", "Group"])
    for page in pages:
        users.extend(page.get("UserDetailList", []))
        roles.extend(page.get("RoleDetailList", []))
        groups.extend(page.get("GroupDetailList", []))
    return map_authorization_details(users, roles, groups)


def collect_iam(session, declared, resources):
    iam = session.client("iam")
    resources.extend(
        attempt(
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
        or []
    )
    resources.extend(
        attempt(declared, ["aws_iam_credential_report_user"], lambda: fetch_credential_report(iam)) or []
    )

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


def log(message):
    print(message, file=sys.stderr, flush=True)


def collect(profile, regions=None):
    session = boto3.Session(profile_name=profile)
    if regions is None:
        ec2 = session.client("ec2", region_name=session.region_name or "us-east-1")
        regions = [r["RegionName"] for r in ec2.describe_regions()["Regions"]]
    resources = []
    declared = set()
    log("collecting IAM (global)...")
    collect_iam(session, declared, resources)
    log("collecting S3 (global)...")
    collect_s3(session, declared, resources)
    log("collecting account contact...")
    collect_account_contact(session, declared, resources)
    for index, region in enumerate(regions, 1):
        log(f"scanning {region} ({index}/{len(regions)})...")
        start = len(resources)
        collect_region(session, region, declared, resources)
        for resource in resources[start:]:
            resource.setdefault("_region", region)
    log(f"done: {len(resources)} resources")
    return resources, declared


def main():
    parser = argparse.ArgumentParser(description="Collect CIS-relevant resources directly from AWS APIs")
    parser.add_argument("--profile", help="AWS profile; default: the standard credential chain")
    parser.add_argument("--regions", help="comma separated, default: all enabled regions")
    parser.add_argument("--account")
    parser.add_argument("-o", "--output", help="default: out/resources_<timestamp>.json")
    arguments = parser.parse_args()
    regions = arguments.regions.split(",") if arguments.regions else None
    resources, declared = collect(arguments.profile, regions)
    document = make_document(resources, declared, account_id=arguments.account)
    output = write_document(document, arguments.output or timestamped_output("resources"))
    print(
        f"{output}: {len(document['resources'])} resources, "
        f"{len(document['meta']['collected_types'])} collected types, "
        f"account {document['meta']['account_id']}"
    )


if __name__ == "__main__":
    main()
