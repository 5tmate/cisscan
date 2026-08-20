import json

import cisscan


def open_ssh_fixture():
    resources = [
        {
            "_type": "aws_security_group",
            "_name": "bastion_sg-1",
            "name": "bastion",
            "ingress": [{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}],
            "egress": [],
        }
    ]
    return resources, {"aws_security_group"}


def test_scan_pipeline_writes_document_and_reports(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cisscan.aws_api, "collect", lambda profile, regions: open_ssh_fixture())
    output = tmp_path / "resources.json"
    code = cisscan.run(profile="x", regions=None, output=output, account="111122223333")
    assert code == 1
    document = json.loads(output.read_text())
    assert document["meta"]["account_id"] == "111122223333"
    assert document["resources"][0]["_name"] == "bastion_sg-1"
    printed = capsys.readouterr().out
    assert "EC2.53" in printed
    assert "bastion_sg-1" in printed
    saved = (tmp_path / "resources.report.txt").read_text()
    assert "EC2.53" in saved


def test_scan_pipeline_from_terraformer_dump(tmp_path, monkeypatch, capsys):
    state = {
        "version": 1,
        "modules": [
            {
                "resources": {
                    "aws_security_group.tfer--web": {
                        "type": "aws_security_group",
                        "primary": {
                            "attributes": {
                                "id": "sg-9",
                                "name": "web",
                                "ingress.#": "0",
                                "egress.#": "0",
                            }
                        },
                    }
                }
            }
        ],
    }
    dump = tmp_path / "aws" / "sg"
    dump.mkdir(parents=True)
    (dump / "terraform.tfstate").write_text(json.dumps(state))
    output = tmp_path / "resources.json"
    code = cisscan.run(profile="x", regions=None, output=output, account="1", terraformer_dumps=[tmp_path])
    assert code == 0
    printed = capsys.readouterr().out
    assert "EC2.53" in printed


def test_scan_reports_friendly_error_without_credentials(tmp_path, monkeypatch, capsys):
    from botocore.exceptions import NoCredentialsError

    def boom(profile, regions):
        raise NoCredentialsError()

    monkeypatch.setattr(cisscan.aws_api, "collect", boom)
    code = cisscan.run(profile=None, regions=None, output=tmp_path / "r.json")
    assert code == 2
    assert "credential" in capsys.readouterr().err.lower()
