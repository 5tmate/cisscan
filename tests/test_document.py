import re

from adapters.document import make_document


def test_default_scanned_at_uses_local_timezone_offset():
    document = make_document([], set(), account_id="1")
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}", document["meta"]["scanned_at"])


def test_timestamped_output_name_uses_local_time():
    from adapters.document import timestamped_output

    path = timestamped_output("resources")
    assert re.fullmatch(r"out/resources_\d{8}-\d{6}\.json", str(path))
