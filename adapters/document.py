import json
import re
from datetime import datetime
from pathlib import Path

ACCOUNT_PATTERN = re.compile(r"arn:aws[^:]*:[^:]*:[^:]*:(\d{12}):")


def detect_account_id(resources):
    match = ACCOUNT_PATTERN.search(json.dumps(resources))
    return match.group(1) if match else "unknown"


def make_document(resources, declared_types, account_id=None, scanned_at=None):
    collected = {r["_type"] for r in resources} | set(declared_types)
    meta = {
        "account_id": account_id or detect_account_id(resources),
        "scanned_at": scanned_at or datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S%:z"),
        "collected_types": sorted(collected),
    }
    return {"meta": meta, "resources": resources}


def write_document(document, output):
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=1))
    return output
