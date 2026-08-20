import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent
RULES = REPO / "rules"

PASS, VIOLATION, BROKEN = 0, 1, 2


class GateError(Exception):
    pass


def evaluate(document):
    rule_files = sorted(p for p in RULES.glob("*.rego") if not p.name.endswith("_test.rego"))
    if not rule_files:
        raise GateError(f"no rule files found in {RULES}")
    command = ["opa", "eval"]
    for path in rule_files:
        command += ["-d", str(path)]
    command += ["-I", "-f", "json", "data"]
    result = subprocess.run(command, input=json.dumps(document), capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise GateError(f"opa eval failed: {result.stderr.strip()}")
    value = json.loads(result.stdout)["result"][0]["expressions"][0]["value"]

    report = {}
    for package, body in sorted(value.items()):
        if not isinstance(body, dict) or "deny" not in body:
            continue
        titles = body.get("titles", {})
        severities = body.get("severities", {})
        requirements = body.get("cis_requirements", {})
        controls = {
            control: {
                "title": titles[control],
                "severity": severities.get(control, ""),
                "cis": requirements.get(control, ""),
                "applicable": [],
                "deny": [],
            }
            for control in titles
        }
        for entry in body.get("applicable", []):
            controls[entry["control"]]["applicable"].append(entry["resource"])
        for entry in body.get("deny", []):
            controls[entry["control"]]["deny"].append(entry["message"])
        report[package] = {
            "title": body.get("title", package),
            "enforced": set(body.get("enforced", [])),
            "controls": controls,
        }
    if not report:
        raise GateError("no rule package exposed a 'deny' rule")
    return report


def run(resources_path):
    try:
        document = json.loads(Path(resources_path).read_text())
        if not document.get("resources"):
            raise GateError(f"{resources_path} contains no resources")
        report = evaluate(document)
    except (GateError, OSError, json.JSONDecodeError) as error:
        print(f"cisscan: {error}", file=sys.stderr)
        return BROKEN, {}
    failed = any(
        found["deny"] and control in entry["enforced"]
        for entry in report.values()
        for control, found in entry["controls"].items()
    )
    return (VIOLATION if failed else PASS), report


def control_sort_key(control):
    prefix, _, number = control.partition(".")
    return (prefix, int(number))


def render(report, meta):
    states = {"FAIL": 0, "pass": 0, "n/a": 0}
    print(f"account {meta.get('account_id', '?')} — scanned {meta.get('scanned_at', '?')}")
    for package, entry in report.items():
        print(f"\n{package}  {entry['title']}")
        for control in sorted(entry["controls"], key=control_sort_key):
            found = entry["controls"][control]
            gating = control in entry["enforced"]
            if found["deny"] and gating:
                state = f"FAIL ({len(found['deny'])})"
                states["FAIL"] += 1
            elif found["deny"]:
                state = f"off ({len(found['deny'])})"
            elif found["applicable"]:
                state = f"pass ({len(found['applicable'])} checked)" if gating else "off"
                states["pass"] += 1
            else:
                state = "n/a"
                states["n/a"] += 1
            print(f"  {control:14} {found['severity']:9} CIS {found['cis']:6} {state:18} {found['title']}")
            for message in sorted(found["deny"]):
                print(f"      - {message}")
    total = sum(states.values())
    print(f"\n{total} controls: {states['FAIL']} FAIL, {states['pass']} pass, {states['n/a']} n/a")


def main():
    parser = argparse.ArgumentParser(description="Evaluate a cisscan resource document against the CIS rules")
    parser.add_argument("resources", metavar="RESOURCES_JSON")
    arguments = parser.parse_args()
    code, report = run(arguments.resources)
    if report:
        meta = json.loads(Path(arguments.resources).read_text()).get("meta", {})
        render(report, meta)
    return code


if __name__ == "__main__":
    sys.exit(main())
