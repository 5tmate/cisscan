import json

import pytest

from collectors.terraformer import build_document, load_state, unflatten

FIXTURE_STATE = {
    "version": 1,
    "modules": [
        {
            "resources": {
                "aws_security_group.tfer--web": {
                    "type": "aws_security_group",
                    "primary": {
                        "attributes": {
                            "id": "sg-1",
                            "name": "web",
                            "arn": "arn:aws:ec2:ap-northeast-1:111122223333:security-group/sg-1",
                            "ingress.#": "1",
                            "ingress.0.from_port": "22",
                            "ingress.0.to_port": "22",
                            "ingress.0.protocol": "tcp",
                            "ingress.0.cidr_blocks.#": "1",
                            "ingress.0.cidr_blocks.0": "0.0.0.0/0",
                            "egress.#": "0",
                            "tags.%": "1",
                            "tags.Name": "web",
                        }
                    },
                },
                "aws_cloudtrail.tfer--main": {
                    "type": "aws_cloudtrail",
                    "primary": {
                        "attributes": {
                            "id": "main",
                            "is_multi_region_trail": "true",
                            "enable_log_file_validation": "false",
                            "s3_bucket_name": "trail-logs",
                        }
                    },
                },
            }
        }
    ],
}


@pytest.fixture
def dump_root(tmp_path):
    state_dir = tmp_path / "aws" / "sg"
    state_dir.mkdir(parents=True)
    (state_dir / "terraform.tfstate").write_text(json.dumps(FIXTURE_STATE))
    empty_dir = tmp_path / "aws" / "cloudtrail"
    empty_dir.mkdir()
    (empty_dir / "terraform.tfstate").write_text(json.dumps({"version": 1, "modules": [{"resources": {}}]}))
    return tmp_path


def test_unflatten_builds_nested_lists_and_maps():
    result = unflatten(
        FIXTURE_STATE["modules"][0]["resources"]["aws_security_group.tfer--web"]["primary"]["attributes"]
    )
    assert result["ingress"][0]["cidr_blocks"] == ["0.0.0.0/0"]
    assert result["tags"] == {"Name": "web"}
    assert result["egress"] == []


def test_unflatten_types_ports_as_numbers_but_keeps_protocol_string():
    result = unflatten({"ingress.#": "1", "ingress.0.from_port": "22", "ingress.0.protocol": "6"})
    assert result["ingress"][0]["from_port"] == 22
    assert result["ingress"][0]["protocol"] == "6"


def test_unflatten_converts_booleans():
    result = unflatten({"is_multi_region_trail": "true", "enable_logging": "false"})
    assert result["is_multi_region_trail"] is True
    assert result["enable_logging"] is False


def test_load_state_extracts_type_and_name(dump_root):
    resources = load_state(dump_root / "aws" / "sg" / "terraform.tfstate")
    sg = next(r for r in resources if r["_type"] == "aws_security_group")
    assert sg["_name"] == "web"
    assert sg["ingress"][0]["cidr_blocks"] == ["0.0.0.0/0"]


def test_build_document_meta(dump_root):
    doc = build_document([dump_root], scanned_at="2026-08-20T00:00:00Z")
    assert doc["meta"]["account_id"] == "111122223333"
    assert doc["meta"]["scanned_at"] == "2026-08-20T00:00:00Z"
    assert "aws_cloudtrail" in doc["meta"]["collected_types"]
    assert "aws_security_group" in doc["meta"]["collected_types"]
    assert "aws_iam_credential_report_user" not in doc["meta"]["collected_types"]
    assert len(doc["resources"]) == 2


def test_build_document_region_from_layout(tmp_path):
    state_dir = tmp_path / "aws" / "vpc" / "us-east-1"
    state_dir.mkdir(parents=True)
    (state_dir / "terraform.tfstate").write_text(json.dumps(FIXTURE_STATE))
    doc = build_document([tmp_path], scanned_at="2026-08-20T00:00:00Z", account_id="1")
    assert all(r["_region"] == "us-east-1" for r in doc["resources"])
