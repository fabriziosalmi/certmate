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

# Written only by an explicit operator prune (#445). Its presence means the
# chain no longer starts at the genesis: the entries before ``anchor_seq`` were
# exported, verified off the box and archived, and this file is the signed
# statement of what they were. Absent on every instance that has never pruned,
# which is the default and the expectation.
ANCHOR_FILENAME = "certificate_audit.anchor.json"


class AnchorReadError(OSError):
    """The prune anchor exists but cannot be read or understood. Callers MUST
    fail closed: treating it as "no anchor" would silently re-interpret a
    pruned chain as one that should start at the genesis."""


class CheckpointReadError(OSError):
    """The checkpoint file exists but cannot be read (permissions, I/O).
    Callers MUST treat this as "verification impossible" and fail closed —
    an unreadable checkpoint file is NOT the same as no checkpoints ever
    having been written, and conflating the two turns a tampered box into a
    clean 'absent' verdict."""


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


def _blank_result() -> Dict[str, Any]:
    """The result dict every verifier entry point returns, in its initial
    (nothing verified yet) state."""
    return {
        "ok": False, "count": 0, "first_seq": None, "last_seq": None,
        "head_hash": None, "error_seq": None, "reason": None,
    }


class _ChainVerifier:
    """Incremental verifier: fed one record at a time, holding only the running
    ``prev_hash`` / ``seq`` / count. Shared by the streaming file verifier and
    the in-memory record verifier so the two can never drift apart (#444)."""

    def __init__(self, anchor_prev_hash: str = GENESIS_PREV,
                 anchor_seq: Optional[int] = None,
                 remember_hash_at: Optional[int] = None):
        self._prev_hash = anchor_prev_hash
        self._expected_seq = anchor_seq
        self._anchor_prev_hash = anchor_prev_hash
        self._first_seq: Optional[int] = None
        self._count = 0
        self._seen = False
        # Used to cross-check an anchor against a chain that still contains the
        # entries it claims were archived (a prune interrupted between writing
        # the anchor and replacing the chain).
        self._remember_hash_at = remember_hash_at
        self.remembered_hash: Optional[str] = None

    def _fail(self, reason: str, error_seq) -> Dict[str, Any]:
        result = _blank_result()
        result["first_seq"] = self._first_seq
        result["error_seq"] = error_seq
        result["reason"] = reason
        return result

    def feed(self, rec, position: int) -> Optional[Dict[str, Any]]:
        """Verify one record against the running state. Returns a failure
        result dict, or None if the record was accepted."""
        if not isinstance(rec, dict):
            return self._fail(
                f"malformed (non-object) record at position {position}",
                self._expected_seq)

        seq = rec.get("seq")
        entry = rec.get("entry")
        rec_prev = rec.get("prev_hash")
        rec_hash = rec.get("hash")

        if not isinstance(seq, int) or entry is None or rec_hash is None:
            return self._fail(
                f"malformed record at position {position} (missing fields)",
                self._expected_seq)

        if not self._seen:
            self._seen = True
            self._first_seq = seq
        if self._expected_seq is None:
            self._expected_seq = seq
        elif seq != self._expected_seq:
            return self._fail(
                f"sequence break: expected seq {self._expected_seq}, found "
                f"{seq} (a deletion or reorder)", self._expected_seq)

        if rec_prev != self._prev_hash:
            return self._fail(
                f"broken link at seq {seq}: prev_hash does not match the "
                f"previous record's hash", seq)

        if entry_hash(seq, entry, rec_prev) != rec_hash:
            return self._fail(
                f"hash mismatch at seq {seq}: entry was modified", seq)

        if seq == self._remember_hash_at:
            self.remembered_hash = rec_hash
        self._prev_hash = rec_hash
        self._expected_seq += 1
        self._count += 1
        return None

    def finish(self) -> Dict[str, Any]:
        result = _blank_result()
        result["ok"] = True
        if not self._seen:
            result["reason"] = "empty chain"
            # The head of an empty slice is whatever it was anchored to (the
            # genesis prev_hash for a full chain), matching what build_manifest
            # records for an empty slice — so an empty signed bundle verifies
            # consistently.
            result["head_hash"] = self._anchor_prev_hash
            return result
        result["count"] = self._count
        result["first_seq"] = self._first_seq
        result["last_seq"] = self._expected_seq - 1
        result["head_hash"] = self._prev_hash
        result["reason"] = "intact"
        return result


def verify_chain(path) -> Dict[str, Any]:
    """Verify a chain file end to end.

    Returns a dict::

        {ok, count, first_seq, last_seq, head_hash, error_seq, reason}

    ``ok`` is True only when every line parses, ``seq`` is gap-free from the
    first record, every ``prev_hash`` links to the prior ``hash``, and every
    ``hash`` recomputes. On the first failure, ``ok`` is False and ``reason`` /
    ``error_seq`` localize it.

    Reads the file **one line at a time** (#444): the chain is append-only and
    never truncated, so it is the one file here that only ever grows, and a
    verifier that must first fit the whole history in memory puts a ceiling on
    how much history an instance can keep. Peak memory is now one line,
    whatever the file's size.

    One consequence of streaming, deliberate: when a file contains more than one
    fault, the reported one is the **earliest in the file**. The previous
    implementation parsed every line before checking any structure, so an
    unparseable line late in the file masked a hash mismatch early in it.
    Localizing the first fault is the more useful answer.

    If an anchor file sits next to the chain (#445), the chain no longer starts
    at the genesis and is verified from the anchor instead. The result then
    carries ``anchored`` / ``anchor_seq``, and callers MUST NOT report it as
    plain "intact": it attests the entries from the anchor forward, and the
    archived prefix is attested only by the anchor and the exported bundle an
    operator holds off the box. Verifying the anchor's *signature* needs crypto
    and is the caller's job (:meth:`AuditLogger.verify_chain` and the CLI do it)
    — this stdlib-only function checks that the chain and the anchor agree.
    """
    try:
        anchor = read_anchor(anchor_path_for(path))
    except AnchorReadError as e:
        # Fail closed. An unreadable anchor is not "no anchor": the difference
        # between the two is the difference between a pruned chain and a
        # chain that should start at the genesis.
        result = _blank_result()
        result["anchor_unreadable"] = True
        result["reason"] = str(e)
        return result
    if anchor is not None:
        return _verify_anchored_chain(path, anchor)
    return _verify_stream(path, _ChainVerifier())


def _verify_stream(path, verifier) -> Dict[str, Any]:
    """Feed every record in *path* to *verifier*, one line at a time, and
    return its verdict (or the first failure)."""
    # A corrupt or non-object FINAL line is most likely a truncated trailing
    # write, not tampering, and gets its own wording — so a line is only
    # judged once the next one proves it was not the last.
    pending: Optional[str] = None
    position = -1

    try:
        with open(path, "r", encoding="utf-8") as f:
            for raw in f:
                raw = raw.strip()
                if not raw:  # ignore blank lines, including a trailing one
                    continue
                if pending is not None:
                    position += 1
                    failure = _feed_raw(verifier, pending, position, is_last=False)
                    if failure is not None:
                        return failure
                pending = raw
    except FileNotFoundError:
        result = _blank_result()
        result["reason"] = "chain file does not exist"
        # Structured flag so callers deciding absent-vs-tampered do not have
        # to substring-match the human-readable reason.
        result["chain_file_missing"] = True
        return result
    except OSError as e:
        result = _blank_result()
        result["reason"] = f"cannot read chain file: {e}"
        return result

    if pending is not None:
        position += 1
        failure = _feed_raw(verifier, pending, position, is_last=True)
        if failure is not None:
            return failure

    return verifier.finish()


def _verify_anchored_chain(path, anchor) -> Dict[str, Any]:
    """Verify a chain that an operator prune left starting at ``anchor_seq``.

    Two on-disk states are legitimate, because a prune writes the anchor before
    it replaces the chain and can be interrupted between the two:

    1. The chain starts at ``anchor_seq`` — the completed state. It is verified
       from the anchor's ``prev_hash``.
    2. The chain still starts where it started before this prune — the
       interrupted state, where nothing was actually deleted. That is the
       genesis on a first prune, and the *superseded* anchor on a later one,
       which is why an anchor records the one it replaced. Either way the chain
       is verified from that earlier start and the new anchor is then
       cross-checked against it: the record before ``anchor_seq`` must hash to
       the anchor's ``prev_hash``. An anchor that does not match the history it
       claims to summarise is a failure, not a detail — that is exactly what a
       planted anchor would look like.
    """
    anchor_seq = anchor["anchor_seq"]
    anchor_prev = anchor["prev_hash"]
    superseded = anchor.get("supersedes") or None

    first_seq = _first_record_seq(path)
    if first_seq is None:
        # No chain to verify. An anchor without a chain is not benign: it
        # attests that entries existed.
        result = _verify_stream(path, _ChainVerifier(anchor_prev, anchor_seq))
        if result.get("ok"):
            result["ok"] = False
            result["reason"] = (
                f"the chain is empty but an anchor attests {anchor['archived_count']} "
                f"archived entries and a continuation from seq {anchor_seq}")
        result["anchored"] = True
        result["anchor_seq"] = anchor_seq
        return result

    if first_seq == anchor_seq:
        result = _verify_stream(path, _ChainVerifier(anchor_prev, anchor_seq))
        result["anchored"] = True
        result["anchor_seq"] = anchor_seq
        if result.get("ok"):
            result["reason"] = (
                f"intact from the anchor at seq {anchor_seq} "
                f"({anchor['archived_count']} earlier entries archived)")
        return result

    # The chain still holds the prefix the anchor claims was archived. Verify
    # it from wherever it legitimately started before this prune.
    start_prev, start_seq = GENESIS_PREV, None
    if superseded:
        if first_seq != superseded.get("anchor_seq"):
            result = _blank_result()
            result["anchored"] = True
            result["anchor_seq"] = anchor_seq
            result["error_seq"] = first_seq
            result["reason"] = (
                f"the chain starts at seq {first_seq}, which is neither the "
                f"anchor at seq {anchor_seq} nor the anchor it superseded at "
                f"seq {superseded.get('anchor_seq')}")
            return result
        start_prev = superseded.get("prev_hash") or GENESIS_PREV
        start_seq = superseded.get("anchor_seq")
    elif first_seq != 0:
        result = _blank_result()
        result["anchored"] = True
        result["anchor_seq"] = anchor_seq
        result["error_seq"] = first_seq
        result["reason"] = (
            f"the chain starts at seq {first_seq}, which is neither the genesis "
            f"nor the anchor at seq {anchor_seq}")
        return result
    verifier = _ChainVerifier(start_prev, start_seq,
                              remember_hash_at=anchor_seq - 1)
    result = _verify_stream(path, verifier)
    result["anchored"] = True
    result["anchor_seq"] = anchor_seq
    result["anchor_pending"] = True
    if not result.get("ok"):
        return result
    if verifier.remembered_hash != anchor_prev:
        result["ok"] = False
        result["error_seq"] = anchor_seq - 1
        result["reason"] = (
            f"the anchor claims the chain continues from seq {anchor_seq} with a "
            f"different predecessor hash than the chain's own record at seq "
            f"{anchor_seq - 1}: the anchor does not describe this chain")
        return result
    start = "the genesis" if not superseded else f"seq {superseded['anchor_seq']}"
    result["reason"] = (
        f"intact from {start}; an anchor for seq {anchor_seq} is present and "
        f"consistent, but the archived prefix is still in the chain (an "
        f"interrupted prune — re-run it or remove the anchor)")
    return result


def _first_record_seq(path) -> Optional[int]:
    """The ``seq`` of the first parseable record, or None."""
    for rec in iter_records(path):
        return rec["seq"]
    return None


def _first_record_seq_after(path, seq: int) -> Optional[int]:
    """The ``seq`` of the first record after *seq*, or None if there is none."""
    for rec in iter_records(path, from_seq=seq + 1):
        return rec["seq"]
    return None


def _feed_raw(verifier, raw: str, position: int,
              is_last: bool) -> Optional[Dict[str, Any]]:
    """Parse one raw chain line and feed it to *verifier*. Returns a failure
    result dict, or None if the line was accepted."""
    try:
        rec = json.loads(raw)
        ok_obj = isinstance(rec, dict)
    except json.JSONDecodeError:
        ok_obj = False
    if not ok_obj:
        # A fresh result, not the verifier's partial state: an unparseable line
        # says nothing trustworthy about what the prefix contained.
        failure = _blank_result()
        failure["error_seq"] = None
        failure["reason"] = (
            "truncated or unparseable trailing line (likely an interrupted "
            "write)" if is_last else f"unparseable line at position {position}"
        )
        return failure
    return verifier.feed(rec, position)


def verify_records(records, anchor_prev_hash: str = GENESIS_PREV,
                   anchor_seq: Optional[int] = None) -> Dict[str, Any]:
    """Verify a list of parsed chain records ``[{seq, entry, prev_hash, hash}, ...]``.
    Returns the same result dict as :func:`verify_chain`. Shared by the file
    verifier and the export-bundle verifier.

    By default the records must start at the genesis, i.e. the first record's
    ``prev_hash`` must be ``""``. That default is load-bearing: it is why
    removing entries from the *head* of a full chain is detected.

    A **fragment** that legitimately starts mid-chain — an incremental export
    slice (#441), and the seam of any future segmentation — passes the
    predecessor hash it continues from as *anchor_prev_hash*, optionally with
    the ``seq`` that hash is supposed to precede. The caller is responsible for
    making that anchor trustworthy: in a bundle it lives in the signed manifest,
    so the instance attests where the slice starts. Verification against an
    anchor proves the records from the anchor forward are authentic and ordered
    — it proves nothing at all about the prefix, and callers must not report it
    as if it did."""
    verifier = _ChainVerifier(anchor_prev_hash, anchor_seq)
    for position, rec in enumerate(records):
        failure = verifier.feed(rec, position)
        if failure is not None:
            return failure
    return verifier.finish()


# --- Phase 3: signed export bundle + checkpoints --------------------------

CHECKPOINT_FILENAME = "certificate_audit.checkpoints.jsonl"
# v1: the slice starts at the genesis (a full export). Byte-identical to what
#     every previously shipped version produced, so old verifiers keep working.
# v2: the slice is ANCHORED — it starts mid-chain, and the manifest carries the
#     predecessor hash it continues from (#441). Deliberately a new version
#     rather than an optional field on v1: a verifier that does not understand
#     anchoring must say "unsupported format", never mistake a legitimate
#     fragment for a broken chain.
BUNDLE_FORMAT_VERSION = 1
ANCHORED_BUNDLE_FORMAT_VERSION = 2
SUPPORTED_BUNDLE_FORMAT_VERSIONS = (BUNDLE_FORMAT_VERSION, ANCHORED_BUNDLE_FORMAT_VERSION)


def iter_records(path, from_seq: Optional[int] = None,
                 to_seq: Optional[int] = None):
    """Yield valid record dicts from the chain file, one line at a time (#444),
    so a caller that only needs to *scan* the chain — the checkpoint
    cross-check, for one — never holds more than a single record.

    A truncated trailing line is skipped. Optional inclusive ``from_seq`` /
    ``to_seq`` slice. Best-effort: yields nothing if the file is missing.

    The slice filters rather than stopping at ``to_seq``, deliberately: this
    reads a file that may have been tampered with, and monotonic ``seq`` is
    what the verifier *proves*, not something a reader may presume. Skipping
    the tail on that assumption would let a reordered chain export as a
    quietly-shorter slice. The scan it saves is linear over a file that grows
    in hundreds of KB per year."""
    try:
        f = open(path, "r", encoding="utf-8")
    except OSError:
        return
    with f:
        for raw in f:
            raw = raw.strip()
            if not raw:
                continue
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
            yield rec


def load_records(path, from_seq: Optional[int] = None, to_seq: Optional[int] = None):
    """Read the chain file into a **list** of valid record dicts. Use
    :func:`iter_records` unless the whole slice genuinely has to be held at once
    (building an export bundle does; scanning does not)."""
    return list(iter_records(path, from_seq, to_seq))


def build_manifest(records, *, fingerprint, public_key_pem, exported_at,
                   algorithm) -> Dict[str, Any]:
    """Build the export-bundle manifest. The ``head_hash`` transitively commits
    to every record via the chain, so signing the manifest commits to the whole
    exported slice without per-entry signatures.

    A slice that does not start at the genesis is marked as anchored: the
    manifest records the ``prev_hash`` its first entry continues from, and the
    signature therefore covers the anchor too (#441). Without that, the entries
    are internally consistent but the first link has nothing to check against,
    and the verifier — correctly — rejects them."""
    anchor_prev_hash = GENESIS_PREV
    if records:
        seq_first = records[0]["seq"]
        seq_last = records[-1]["seq"]
        head_hash = records[-1]["hash"]
        anchor_prev_hash = records[0].get("prev_hash") or GENESIS_PREV
    else:
        seq_first = seq_last = None
        head_hash = GENESIS_PREV
    anchored = anchor_prev_hash != GENESIS_PREV
    manifest = {
        "format_version": (
            ANCHORED_BUNDLE_FORMAT_VERSION if anchored else BUNDLE_FORMAT_VERSION
        ),
        "algorithm": algorithm,
        "instance_fingerprint": fingerprint,
        "public_key_pem": public_key_pem,
        "seq_first": seq_first,
        "seq_last": seq_last,
        "count": len(records),
        "head_hash": head_hash,
        "exported_at": exported_at,
    }
    if anchored:
        manifest["anchor_prev_hash"] = anchor_prev_hash
        manifest["anchor_seq"] = seq_first
    return manifest


def manifest_signing_bytes(manifest: Dict[str, Any]) -> bytes:
    """Canonical bytes the bundle signature is computed over."""
    return canon_bytes(manifest)


def checkpoint_signing_bytes(checkpoint: Dict[str, Any]) -> bytes:
    """Canonical bytes a checkpoint signature is computed over. MUST match the
    fields write_checkpoint signs (seq, hash, count, timestamp)."""
    return canon_bytes({
        "seq": checkpoint.get("seq"),
        "hash": checkpoint.get("hash"),
        "count": checkpoint.get("count"),
        "timestamp": checkpoint.get("timestamp"),
    })


def read_checkpoints(path):
    """Read all parseable checkpoint records (oldest first). Stdlib-only;
    verifying each checkpoint's signature is the caller's job (needs crypto).

    A missing file means no checkpoints were ever written ([]); any other
    read failure raises :class:`CheckpointReadError` — it must not be
    silently treated as "no checkpoints", or an attacker who makes the file
    unreadable (and deletes the chain) gets a benign 'absent' verdict."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw_lines = [ln for ln in f.read().splitlines() if ln.strip()]
    except FileNotFoundError:
        return []
    except OSError as e:
        raise CheckpointReadError(f"cannot read checkpoint file: {e}") from e
    out = []
    for raw in raw_lines:
        try:
            cp = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(cp, dict) and isinstance(cp.get("seq"), int) and cp.get("hash"):
            out.append(cp)
    return out


def anchor_path_for(chain_path):
    """The anchor file that belongs to *chain_path* (same directory)."""
    import os
    return os.path.join(os.path.dirname(str(chain_path)) or ".", ANCHOR_FILENAME)


ANCHOR_REQUIRED_FIELDS = (
    "anchor_seq", "prev_hash", "archived_first_seq", "archived_last_seq",
    "archived_count", "bundle_sha256", "pruned_at",
)

# The anchor an anchor replaced, ``{anchor_seq, prev_hash}`` or None on the
# first prune. Signed like the rest: without it, a prune of an already-pruned
# chain that is interrupted before the chain is replaced would leave a file
# starting at the PREVIOUS anchor with no way left to verify it — the old
# anchor having been overwritten — and the chain would read as tampered.
ANCHOR_SIGNED_FIELDS = ANCHOR_REQUIRED_FIELDS + ("supersedes",)


def anchor_signing_bytes(anchor: Dict[str, Any]) -> bytes:
    """Canonical bytes an anchor's signature is computed over: every field that
    describes what was archived, so re-pointing an anchor at a different prefix
    invalidates the signature."""
    return canon_bytes({k: anchor.get(k) for k in ANCHOR_SIGNED_FIELDS})


def read_anchor(path) -> Optional[Dict[str, Any]]:
    """Read the prune anchor, or None when there is none (the normal case).

    A malformed anchor raises :class:`AnchorReadError` rather than reading as
    absent: "no anchor" means "this chain starts at the genesis", and quietly
    concluding that about a chain whose anchor file is corrupt would turn a
    pruned chain into a chain that fails verification for the wrong reason —
    or, worse, let someone hide a prune by mangling one file."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
    except FileNotFoundError:
        return None
    except OSError as e:
        raise AnchorReadError(f"cannot read anchor file: {e}") from e
    try:
        anchor = json.loads(raw)
    except json.JSONDecodeError as e:
        raise AnchorReadError(f"anchor file is not valid JSON: {e}") from e
    if not isinstance(anchor, dict):
        raise AnchorReadError("anchor file is not an object")
    missing = [k for k in ANCHOR_REQUIRED_FIELDS if anchor.get(k) is None]
    if missing:
        raise AnchorReadError(f"anchor file is missing {', '.join(missing)}")
    if not isinstance(anchor["anchor_seq"], int) or anchor["anchor_seq"] < 1:
        raise AnchorReadError("anchor_seq is not a positive integer")
    if not anchor["prev_hash"]:
        raise AnchorReadError("anchor prev_hash is empty (that is the genesis)")
    return anchor


def cross_check_checkpoint(records, checkpoint) -> Dict[str, Any]:
    """Structural consistency of an internally-verified chain against a signed
    checkpoint. Returns ``{ok, reason}``.

    Detects tail truncation / rewind / rewrite at or below the checkpoint: the
    chain hash commits transitively, so rewriting ANY entry in the prefix
    changes the hash at ``checkpoint['seq']``, and truncating below it removes
    that seq. An attacker who cannot sign a fresh checkpoint (no signing key)
    therefore cannot roll the chain back past the last checkpoint undetected.

    NOTE: does NOT verify the checkpoint signature (the caller does, with
    crypto) and does NOT bind an operator who holds the signing key — full
    operator binding needs off-box anchoring (see the module docstring).

    *records* may be any iterable, including the :func:`iter_records`
    generator: it is consumed once and only up to the checkpointed seq."""
    cp_seq = checkpoint.get("seq")
    cp_hash = checkpoint.get("hash")
    if not isinstance(cp_seq, int) or not cp_hash:
        return {"ok": True, "reason": "checkpoint has no usable seq/hash"}
    # Close the iterable when we stop early: iter_records holds an open file,
    # and abandoning a suspended generator leaves that descriptor to whenever
    # the interpreter gets round to collecting it — immediately on CPython,
    # not on every implementation.
    match = None
    try:
        for rec in records:
            if rec.get("seq") == cp_seq:
                match = rec
                break
    finally:
        close = getattr(records, "close", None)
        if callable(close):
            close()
    if match is None:
        return {"ok": False, "reason": (
            f"chain no longer contains seq {cp_seq}, which a signed checkpoint "
            f"attests to: the tail was truncated or rewound below the checkpoint"
        )}
    if match.get("hash") != cp_hash:
        return {"ok": False, "reason": (
            f"chain hash at seq {cp_seq} does not match the signed checkpoint: "
            f"the chain was rewritten at or before that point"
        )}
    return {"ok": True, "reason": f"consistent with signed checkpoint at seq {cp_seq}"}
