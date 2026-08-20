import re

from adapters.document import make_document


def test_default_scanned_at_uses_local_timezone_offset():
    document = make_document([], set(), account_id="1")
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}", document["meta"]["scanned_at"])
