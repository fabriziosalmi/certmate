"""The chain must survive a second writer, and must name the fault correctly.

Both halves of this file come from one real incident. On 2026-08-10 the chain on
a development instance failed verification at seq 45, and the verifier reported
"a deletion or reorder" — the vocabulary of tampering, on the one file whose
entire purpose is to be trustworthy evidence.

Nothing had been deleted. Seq 44 and 45 were each written twice, with identical
timestamps, on 2026-06-25, by two `migrate` operations: two processes started
against the same data directory, each recovered the same `_next_seq` at startup,
and each appended with it. The in-process `threading.Lock` cannot see another
process.

So: the append takes an advisory file lock and re-reads the head when the file
grew underneath it, and the verifier distinguishes a repeat from a gap.
"""
import json
import multiprocessing
import sys

import pytest

from modules.core import audit_chain
from modules.core.audit import AuditLogger


def _read_chain(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _make_logger(tmp_path):
    return AuditLogger(audit_log_dir=tmp_path / "logs", chain_dir=tmp_path / "chain")


# --------------------------------------------------------------------------- #
# The verifier's diagnosis
# --------------------------------------------------------------------------- #

def _chain_lines(seqs):
    """Build chain lines for the given seq order, hashes consistent per line."""
    out, prev = [], audit_chain.GENESIS_PREV
    for s in seqs:
        line = audit_chain.make_line(s, {"operation": "test", "seq_label": s}, prev)
        out.append(line)
        prev = line["hash"]
    return out


def test_a_repeated_seq_is_not_reported_as_a_deletion(tmp_path):
    """The exact shape of the real incident: 0,1,1.

    Reporting this as a deletion tells an operator their audit log was
    tampered with. It was not — it was written twice.
    """
    path = tmp_path / audit_chain.CHAIN_FILENAME
    path.write_text("".join(json.dumps(l) + "\n" for l in _chain_lines([0, 1, 1])))

    result = audit_chain.verify_chain(str(path))
    assert result["ok"] is False
    reason = result["reason"].lower()
    assert "duplicate" in reason or "written more than once" in reason, reason
    assert "deletion" not in reason, (
        f"a double write must not be described as a deletion: {result['reason']}"
    )


def test_a_missing_seq_is_still_reported_as_a_deletion(tmp_path):
    """The other direction must keep its alarming name. 0,1,3 really is a gap."""
    lines = _chain_lines([0, 1, 2, 3])
    del lines[2]                                    # drop seq 2
    path = tmp_path / audit_chain.CHAIN_FILENAME
    path.write_text("".join(json.dumps(l) + "\n" for l in lines))

    result = audit_chain.verify_chain(str(path))
    assert result["ok"] is False
    reason = result["reason"].lower()
    assert "deletion" in reason or "missing" in reason, reason
    assert "duplicate" not in reason, reason


def test_an_intact_chain_still_verifies(tmp_path):
    """The guard must not have made a good chain fail."""
    path = tmp_path / audit_chain.CHAIN_FILENAME
    path.write_text("".join(json.dumps(l) + "\n" for l in _chain_lines([0, 1, 2, 3])))
    assert audit_chain.verify_chain(str(path))["ok"] is True


def _writer_process(directory, label, count):
    """Module level so multiprocessing's spawn context can pickle it."""
    from modules.core.audit import AuditLogger as _AL
    from pathlib import Path as _P
    logger = _AL(audit_log_dir=_P(directory) / "logs",
                 chain_dir=_P(directory) / "chain")
    for i in range(count):
        logger.log_operation(operation=f"{label}{i}", resource_type="test",
                             resource_id=label, status="success")


# --------------------------------------------------------------------------- #
# The append path
# --------------------------------------------------------------------------- #

def test_a_second_writer_does_not_produce_a_duplicate_seq(tmp_path):
    """Two AuditLoggers on one directory — the two-process case, in-process.

    Each recovers its own `_next_seq` at construction, exactly as two processes
    do at startup. Before the fix the second one appended with a seq the first
    had already used.
    """
    first = _make_logger(tmp_path)
    second = _make_logger(tmp_path)          # same directory, own cached state

    first.log_operation(operation="a", resource_type="test", resource_id="x", status="success")
    second.log_operation(operation="b", resource_type="test", resource_id="y", status="success")
    first.log_operation(operation="c", resource_type="test", resource_id="z", status="success")

    chain = _read_chain(tmp_path / "chain" / audit_chain.CHAIN_FILENAME)
    seqs = [r["seq"] for r in chain]
    assert len(seqs) == len(set(seqs)), f"duplicate seq written: {seqs}"
    assert seqs == sorted(seqs), f"out of order: {seqs}"
    assert seqs == list(range(seqs[0], seqs[0] + len(seqs))), f"gap: {seqs}"

    result = audit_chain.verify_chain(
        str(tmp_path / "chain" / audit_chain.CHAIN_FILENAME))
    assert result["ok"] is True, result["reason"]


@pytest.mark.skipif(sys.platform == "win32", reason="advisory locks are POSIX")
def test_two_real_processes_do_not_corrupt_the_chain(tmp_path):
    """The actual failure mode, with actual processes.

    A `threading.Lock` is invisible across a fork; only the advisory file lock
    plus the staleness re-read keeps this chain verifiable.
    """
    ctx = multiprocessing.get_context("spawn")
    procs = [ctx.Process(target=_writer_process, args=(str(tmp_path), label, 5))
             for label in ("p1", "p2")]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=60)
        assert p.exitcode == 0, f"writer process failed: {p.exitcode}"

    path = tmp_path / "chain" / audit_chain.CHAIN_FILENAME
    seqs = [r["seq"] for r in _read_chain(path)]
    assert len(seqs) == len(set(seqs)), f"duplicate seq across processes: {seqs}"
    result = audit_chain.verify_chain(str(path))
    assert result["ok"] is True, f"{result['reason']} (seqs: {seqs})"
