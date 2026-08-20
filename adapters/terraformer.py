import argparse
import json
import re
from pathlib import Path

from adapters.document import make_document, write_document

NUMERIC_KEYS = {"from_port", "to_port", "rule_no", "minimum_password_length", "password_reuse_prevention"}

SERVICE_DECLARES = {
    "accessanalyzer": ["aws_accessanalyzer_analyzer"],
    "cloudtrail": ["aws_cloudtrail"],
    "config": ["aws_config_configuration_recorder", "aws_config_configuration_recorder_status"],
    "iam": [
        "aws_iam_user",
        "aws_iam_user_policy",
        "aws_iam_user_policy_attachment",
        "aws_iam_group_policy_attachment",
        "aws_iam_role_policy_attachment",
    ],
    "s3": ["aws_s3_bucket", "aws_s3_bucket_policy"],
}


def typed(key, value):
    if value == "true":
        return True
    if value == "false":
        return False
    if key in NUMERIC_KEYS and re.fullmatch(r"-?\d+", value):
        return int(value)
    return value


def _walk(root, parts):
    cur = root
    for i, part in enumerate(parts[:-1]):
        next_is_index = parts[i + 1].isdigit()
        if part.isdigit():
            idx = int(part)
            while len(cur) <= idx:
                cur.append(None)
            if cur[idx] is None:
                cur[idx] = [] if next_is_index else {}
            cur = cur[idx]
        else:
            if part not in cur:
                cur[part] = [] if next_is_index else {}
            cur = cur[part]
    return cur


def _value_key(parts):
    for part in reversed(parts):
        if not part.isdigit():
            return part
    return parts[-1]


def unflatten(attrs):
    root = {}
    for key in sorted(attrs):
        value = attrs[key]
        if key.endswith((".#", ".%")):
            parts = key[:-2].split(".")
            container = _walk(root, parts)
            last = parts[-1]
            empty = [] if key.endswith(".#") else {}
            if last.isdigit():
                idx = int(last)
                while len(container) <= idx:
                    container.append(None)
                if container[idx] is None:
                    container[idx] = empty
            elif last not in container:
                container[last] = empty
            continue
        parts = key.split(".")
        container = _walk(root, parts)
        last = parts[-1]
        converted = typed(_value_key(parts), value)
        if last.isdigit():
            idx = int(last)
            while len(container) <= idx:
                container.append(None)
            container[idx] = converted
        else:
            container[last] = converted
    return root


def load_state(path):
    doc = json.loads(Path(path).read_text())
    resources = []
    for module in doc.get("modules", []):
        for key, body in module.get("resources", {}).items():
            resource = unflatten(body.get("primary", {}).get("attributes", {}))
            resource["_type"] = body.get("type", key.split(".")[0])
            name = key.split(".", 1)[1] if "." in key else key
            resource["_name"] = name.removeprefix("tfer--")
            resources.append(resource)
    return resources


def collect(roots):
    resources = []
    declared = set()
    for root in roots:
        root = Path(root)
        for state in sorted(root.rglob("terraform.tfstate")):
            parts = state.relative_to(root).parts[:-1]
            if parts and parts[0] == "aws":
                parts = parts[1:]
            service = parts[0] if parts else "unknown"
            region = parts[1] if len(parts) > 1 else None
            loaded = load_state(state)
            if region:
                for resource in loaded:
                    resource["_region"] = region
            declared.update(SERVICE_DECLARES.get(service, []))
            resources.extend(loaded)
    return resources, declared


def build_document(roots, account_id=None, scanned_at=None):
    resources, declared = collect(roots)
    return make_document(resources, declared, account_id, scanned_at)


def main():
    parser = argparse.ArgumentParser(
        description="Convert terraformer dumps into the cisscan resource document"
    )
    parser.add_argument("dumps", nargs="+", metavar="DUMP_DIR")
    parser.add_argument("-o", "--output", default="out/resources.json")
    parser.add_argument("--account")
    arguments = parser.parse_args()
    document = build_document(arguments.dumps, account_id=arguments.account)
    output = write_document(document, arguments.output)
    print(
        f"{output}: {len(document['resources'])} resources, "
        f"{len(document['meta']['collected_types'])} collected types, "
        f"account {document['meta']['account_id']}"
    )


if __name__ == "__main__":
    main()
