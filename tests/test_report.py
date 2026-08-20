import json

from report import run

META = {
    "account_id": "111122223333",
    "scanned_at": "2026-08-20T00:00:00Z",
    "collected_types": ["aws_security_group"],
}


def write_doc(tmp_path, resources, collected_types=None):
    meta = dict(META)
    if collected_types is not None:
        meta["collected_types"] = collected_types
    path = tmp_path / "resources.json"
    path.write_text(json.dumps({"meta": meta, "resources": resources}))
    return path


def test_run_flags_open_ssh_as_fail(tmp_path):
    path = write_doc(
        tmp_path,
        [
            {
                "_type": "aws_security_group",
                "_name": "bastion",
                "name": "bastion",
                "ingress": [
                    {"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}
                ],
                "egress": [],
            }
        ],
    )
    code, report = run(path)
    assert code == 1
    ec2_53 = report["cis_ec2"]["controls"]["EC2.53"]
    assert len(ec2_53["deny"]) == 1
    assert "bastion" in ec2_53["deny"][0]


def test_run_passes_clean_group_and_marks_uncollected_na(tmp_path):
    path = write_doc(
        tmp_path,
        [
            {
                "_type": "aws_security_group",
                "_name": "web",
                "name": "web",
                "ingress": [
                    {"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr_blocks": ["0.0.0.0/0"]}
                ],
                "egress": [],
            }
        ],
    )
    code, report = run(path)
    assert code == 0
    assert report["cis_ec2"]["controls"]["EC2.53"]["applicable"] == ["web"]
    assert report["cis_account"]["controls"]["Account.1"]["applicable"] == []
    assert report["cis_account"]["controls"]["Account.1"]["deny"] == []


def test_run_rejects_empty_document(tmp_path):
    path = tmp_path / "resources.json"
    path.write_text(json.dumps({"meta": META, "resources": []}))
    code, _ = run(path)
    assert code == 2
