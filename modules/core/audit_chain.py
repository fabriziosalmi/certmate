"""Tamper-evident hash chain for the audit log (Phase 2 of l0 #408).

A parallel, append-only ``certificate_audit.chain.jsonl`` records every audit
entry inside a SHA-256 hash chain so that deletion, modification, or reordering
by anyone who cannot recompute the whole chain is detectable and localizable.

Each chain line is the canonical JSON of::

    {"seq": <int>, "entry": <audit dict>, "prev_hash": <hex|"">, "hash": <hex>}

where ``hash = sha256(canon({"seq", "entry", "prev_hash"}))`` and ``prev_hash``
is the previous line's ``hash`` (the genesis line uses ``""``). ``seq`` is a
gap-free monotonic counter, so a missing ``seq`` proves a deletion.

Honest threat model: the chain proves these N entries are authentic and ordered.
It detects tampering by anyone WITHOUT the writer's running state, but it does
NOT bind the operator, who holds the file and can recompute the whole chain.
Constraining the operator requires external anchoring of signed checkpoints
(Phase 3), which this module deliberately does not implement.

Stdlib only (``json`` + ``hashlib``) so the verifier needs nothing else.
"""

import json
import hashlib
from typing import Any, Dict, Optional

CHAIN_FILENAME = "certificate_audit.chain.jsonl"
GENESIS_PREV = ""


def canon_bytes(obj: Any) -> bytes:
    """Byte-stable canonical serialization. MUST be identical on the writer and
    every verifier, across Python versions: sorted keys, no whitespace, UTF-8,
    non-ASCII preserved (so an IDN domain hashes the same everywhere)."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def entry_hash(seq: int, entry: Dict[str, Any], prev_hash: str) -> str:
    """SHA-256 (hex) over the canonical form of the seq/entry/prev_hash triple.
    The hash commits to the previous hash, so it transitively commits to the
    entire prefix of the chain."""
    return hashlib.sha256(
        canon_bytes({"seq": seq, "entry": entry, "prev_hash": prev_hash})
    ).hexdigest()


def make_line(seq: int, entry: Dict[str, Any], prev_hash: str) -> Dict[str, Any]:
    """Build a complete chain record (including its hash)."""
    return {
        "seq": seq,
        "entry": entry,
        "prev_hash": prev_hash,
        "hash": entry_hash(seq, entry, prev_hash),
    }


def verify_chain(path) -> Dict[str, Any]:
    """Verify a chain file end to end.

    Returns a dict::

        {ok, count, first_seq, last_seq, head_hash, error_seq, reason}

    ``ok`` is True only when every line parses, ``seq`` is gap-free from the
    first record, every ``prev_hash`` links to the prior ``hash``, and every
    ``hash`` recomputes. On the first failure, ``ok`` is False and ``reason`` /
    ``error_seq`` localize it.
    """
    result: Dict[str, Any] = {
        "ok": False, "count": 0, "first_seq": None, "last_seq": None,
        "head_hash": None, "error_seq": None, "reason": None,
    }

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw_lines = f.read().splitlines()
    except FileNotFoundError:
        result["reason"] = "chain file does not exist"
        return result
    except OSError as e:
        result["reason"] = f"cannot read chain file: {e}"
        return result

    # Ignore a trailing blank line; flag a genuinely empty chain as ok/empty.
    lines = [ln for ln in raw_lines if ln.strip()]
    if not lines:
        result["ok"] = True
        result["reason"] = "empty chain"
        return result

    # Parse each line into a record, with file-specific tolerance: a corrupt or
    # non-object FINAL line is most likely a truncated trailing write, not
    # tampering. The structural checks are delegated to verify_records.
    records = []
    for idx, raw in enumerate(lines):
        is_last = idx == len(lines) - 1
        try:
            rec = json.loads(raw)
            ok_obj = isinstance(rec, dict)
        except json.JSONDecodeError:
            ok_obj = False
        if not ok_obj:
            result["error_seq"] = None
            result["reason"] = (
                "truncated or unparseable trailing line (likely an interrupted "
                "write)" if is_last else f"unparseable line at position {idx}"
            )
            return result
        records.append(rec)

    return verify_records(records)


def verify_records(records) -> Dict[str, Any]:
    """Verify a list of parsed chain records ``[{seq, entry, prev_hash, hash}, ...]``.
    Returns the same result dict as :func:`verify_chain`. Shared by the file
    verifier and the export-bundle verifier."""
    result: Dict[str, Any] = {
        "ok": False, "count": 0, "first_seq": None, "last_seq": None,
        "head_hash": None, "error_seq": None, "reason": None,
    }
    if not records:
        result["ok"] = True
        result["reason"] = "empty chain"
        return result

    prev_hash = GENESIS_PREV
    expected_seq: Optional[int] = None
    count = 0

    for idx, rec in enumerate(records):
        if not isinstance(rec, dict):
            result["error_seq"] = expected_seq
            result["reason"] = f"malformed (non-object) record at position {idx}"
            return result

        seq = rec.get("seq")
        entry = rec.get("entry")
        rec_prev = rec.get("prev_hash")
        rec_hash = rec.get("hash")

        if not isinstance(seq, int) or entry is None or rec_hash is None:
            result["error_seq"] = expected_seq
            result["reason"] = f"malformed record at position {idx} (missing fields)"
            return result

        if expected_seq is None:
            expected_seq = seq
            result["first_seq"] = seq
        elif seq != expected_seq:
            result["error_seq"] = expected_seq
            result["reason"] = (
                f"sequence break: expected seq {expected_seq}, found {seq} "
                f"(a deletion or reorder)"
            )
            return result

        if rec_prev != prev_hash:
            result["error_seq"] = seq
            result["reason"] = (
                f"broken link at seq {seq}: prev_hash does not match the "
                f"previous record's hash"
            )
            return result

        if entry_hash(seq, entry, rec_prev) != rec_hash:
            result["error_seq"] = seq
            result["reason"] = f"hash mismatch at seq {seq}: entry was modified"
            return result

        prev_hash = rec_hash
        expected_seq += 1
        count += 1

    result["ok"] = True
    result["count"] = count
    result["last_seq"] = expected_seq - 1 if expected_seq is not None else None
    result["head_hash"] = prev_hash
    result["reason"] = "intact"
    return result


# --- Phase 3: signed export bundle + checkpoints --------------------------

CHECKPOINT_FILENAME = "certificate_audit.checkpoints.jsonl"
BUNDLE_FORMAT_VERSION = 1


def load_records(path, from_seq: Optional[int] = None, to_seq: Optional[int] = None):
    """Read the chain file into a list of valid record dicts (a truncated
    trailing line is skipped). Optional inclusive ``from_seq`` / ``to_seq``
    slice. Best-effort: returns [] if the file is missing."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw_lines = [ln for ln in f.read().splitlines() if ln.strip()]
    except OSError:
        return []
    records = []
    for raw in raw_lines:
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(rec, dict) or not isinstance(rec.get("seq"), int):
            continue
        seq = rec["seq"]
        if from_seq is not None and seq < from_seq:
            continue
        if to_seq is not None and seq > to_seq:
            continue
        records.append(rec)
    return records


def build_manifest(records, *, fingerprint, public_key_pem, exported_at,
                   algorithm) -> Dict[str, Any]:
    """Build the export-bundle manifest. The ``head_hash`` transitively commits
    to every record via the chain, so signing the manifest commits to the whole
    exported slice without per-entry signatures."""
    if records:
        seq_first = records[0]["seq"]
        seq_last = records[-1]["seq"]
        head_hash = records[-1]["hash"]
    else:
        seq_first = seq_last = None
        head_hash = GENESIS_PREV
    return {
        "format_version": BUNDLE_FORMAT_VERSION,
        "algorithm": algorithm,
        "instance_fingerprint": fingerprint,
        "public_key_pem": public_key_pem,
        "seq_first": seq_first,
        "seq_last": seq_last,
        "count": len(records),
        "head_hash": head_hash,
        "exported_at": exported_at,
    }


def manifest_signing_bytes(manifest: Dict[str, Any]) -> bytes:
    """Canonical bytes the bundle signature is computed over."""
    return canon_bytes(manifest)
