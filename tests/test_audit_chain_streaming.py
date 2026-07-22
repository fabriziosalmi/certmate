"""Verifying the chain must not cost as much memory as the chain is big.

Regression tests for #444. `verify_chain()` did `f.read().splitlines()`,
`load_records()` did the same, and the checkpoint cross-check then read the
whole file a second time. The chain is append-only and never truncated — it is
the one file here that only ever grows — so a verifier that must first fit the
whole history in memory puts a ceiling on how much history an instance can
keep, and makes "we should rotate it" look like the answer to a problem that is
really about how it is read (#437).

The behaviour is unchanged; only the memory profile is. The tests below pin
both halves: identical verdicts, and a peak that does not track the file size.
"""

import json
import tracemalloc

import pytest

from modules.core import audit_chain
from modules.core.audit_chain import make_line


pytestmark = [pytest.mark.unit]


def _write_chain(path, n, pad=0):
    """Write a genuine n-entry chain and return its records."""
    records = []
    prev = audit_chain.GENESIS_PREV
    with path.open("w", encoding="utf-8") as f:
        for seq in range(n):
            entry = {"operation": "renew", "resource_id": f"d{seq}.example.com"}
            if pad:
                entry["pad"] = "x" * pad
            line = make_line(seq, entry, prev)
            f.write(json.dumps(line, ensure_ascii=False) + "\n")
            prev = line["hash"]
            records.append(line)
    return records


def test_peak_memory_does_not_track_the_file_size(tmp_path):
    """The property, stated as a number: verifying a ~4 MB chain must not
    allocate anything like 4 MB."""
    path = tmp_path / "chain.jsonl"
    _write_chain(path, 4000, pad=1000)
    file_size = path.stat().st_size
    assert file_size > 4_000_000, "the fixture is not big enough to be a test"

    tracemalloc.start()
    try:
        result = audit_chain.verify_chain(path)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert result["ok"] and result["count"] == 4000
    assert peak < file_size / 10, (
        f"verify_chain peaked at {peak} bytes on a {file_size}-byte chain — "
        f"it is holding the file, not streaming it")


def test_iter_records_is_lazy(tmp_path):
    path = tmp_path / "chain.jsonl"
    _write_chain(path, 500)

    it = audit_chain.iter_records(path)
    first = next(it)

    assert first["seq"] == 0
    assert hasattr(it, "close"), "iter_records must be a generator, not a list"


def test_iter_records_and_load_records_agree(tmp_path):
    path = tmp_path / "chain.jsonl"
    _write_chain(path, 20)

    for kwargs in ({}, {"from_seq": 5}, {"to_seq": 4}, {"from_seq": 5, "to_seq": 9},
                   {"from_seq": 99}):
        assert (list(audit_chain.iter_records(path, **kwargs))
                == audit_chain.load_records(path, **kwargs)), kwargs


def test_iter_records_on_a_missing_file_yields_nothing(tmp_path):
    assert list(audit_chain.iter_records(tmp_path / "nope.jsonl")) == []


# --------------------------------------------------------------------------
# Behaviour must be identical to the buffered verifier
# --------------------------------------------------------------------------

def test_a_streamed_chain_verifies_like_its_records(tmp_path):
    path = tmp_path / "chain.jsonl"
    records = _write_chain(path, 50)

    assert audit_chain.verify_chain(path) == audit_chain.verify_records(records)


def test_blank_lines_anywhere_are_ignored(tmp_path):
    """The old implementation filtered blanks out of the whole file at once;
    streaming must not start treating a blank line as a record boundary."""
    path = tmp_path / "chain.jsonl"
    records = _write_chain(path, 5)
    body = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(["", body[0], "", *body[1:], "", ""]), encoding="utf-8")

    result = audit_chain.verify_chain(path)

    assert result["ok"] and result["count"] == 5
    assert result["head_hash"] == records[-1]["hash"]


def test_an_empty_file_is_an_empty_chain(tmp_path):
    path = tmp_path / "chain.jsonl"
    path.write_text("\n\n  \n", encoding="utf-8")

    result = audit_chain.verify_chain(path)

    assert result["ok"] and result["reason"] == "empty chain"


def test_a_truncated_last_line_is_still_the_tolerant_wording(tmp_path):
    path = tmp_path / "chain.jsonl"
    _write_chain(path, 5)
    with path.open("a", encoding="utf-8") as f:
        f.write('{"seq": 5, "entry": {"oper')

    result = audit_chain.verify_chain(path)

    assert not result["ok"]
    assert "interrupted" in result["reason"]


def test_an_unparseable_interior_line_is_localized(tmp_path):
    path = tmp_path / "chain.jsonl"
    _write_chain(path, 5)
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[2] = "{not json"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = audit_chain.verify_chain(path)

    assert not result["ok"]
    assert "unparseable line at position 2" in result["reason"]


def test_the_first_fault_in_the_file_is_the_one_reported(tmp_path):
    """Deliberate change: the buffered verifier parsed every line before
    checking any structure, so a bad line late in the file masked a tampered
    entry early in it. Streaming reports the earliest fault, which is the one
    an operator needs."""
    path = tmp_path / "chain.jsonl"
    _write_chain(path, 6)
    lines = path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[1])
    tampered["entry"]["resource_id"] = "evil.example.com"
    lines[1] = json.dumps(tampered)
    lines[4] = "}{ garbage"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = audit_chain.verify_chain(path)

    assert not result["ok"]
    assert "hash mismatch at seq 1" in result["reason"]
    assert result["error_seq"] == 1


def test_a_missing_file_still_reports_the_structured_flag(tmp_path):
    """The absent-vs-tampered decision in /api/audit/verify hangs off this."""
    result = audit_chain.verify_chain(tmp_path / "nope.jsonl")

    assert not result["ok"]
    assert result["chain_file_missing"] is True


def test_an_unreadable_file_is_not_reported_as_missing(tmp_path):
    directory = tmp_path / "a_directory"
    directory.mkdir()

    result = audit_chain.verify_chain(directory)

    assert not result["ok"]
    assert result["reason"].startswith("cannot read chain file")
    assert "chain_file_missing" not in result


def test_the_checkpoint_cross_check_accepts_a_generator(tmp_path):
    """It scans for one seq and stops, so it must not need the list."""
    path = tmp_path / "chain.jsonl"
    records = _write_chain(path, 10)
    checkpoint = {"seq": 4, "hash": records[4]["hash"]}

    ok = audit_chain.cross_check_checkpoint(
        audit_chain.iter_records(path), checkpoint)
    diverged = audit_chain.cross_check_checkpoint(
        audit_chain.iter_records(path), {"seq": 4, "hash": "0" * 64})

    assert ok["ok"]
    assert not diverged["ok"]
