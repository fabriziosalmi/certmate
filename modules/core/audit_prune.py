"""Prune an archived prefix of the audit chain (#445, part of #437).

Retention on a tamper-evident record is a policy question, not a disk question.
You cannot make deletion impossible on a file the operator owns; what you can do
is make it **non-deniable**. So this is not a background handler that quietly
rolls files away. It is one explicit command, it refuses to run unless the
prefix it is about to delete has already been exported and independently
verified, and the deletion itself is written into the chain that continues.

The order is enforced, not merely documented:

1. ``GET /api/audit/export`` (or the same call in-process) produces a signed
   bundle of the prefix.
2. The operator verifies it **off the box**::

       python -m modules.core.audit_verify --bundle prefix.json --pubkey instance.pem

3. Only then::

       python -m modules.core.audit_prune --bundle prefix.json --data-dir data/audit --yes

   which re-verifies the bundle itself, checks that it describes exactly the
   prefix of *this* chain, appends an ``archive`` audit entry, rewrites the
   chain without the archived records, and writes the signed anchor that lets
   the remainder verify.

**Deliberately CLI-only.** There is no API endpoint for this and there should
not be one: an authenticated request that deletes audit history is precisely
what someone who has just compromised an administrator account wants, and an
operator who can legitimately prune already has shell access — they have to put
the archive somewhere off the box anyway.

**CertMate must be stopped.** A running instance holds the next seq and the head
hash in memory; appending underneath it would make its next write collide. The
command refuses if the chain changes while it works, but that is a backstop, not
a substitute.
"""

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

try:  # package import
    from . import audit_chain, audit_signing, audit_verify
    from .utils import utc_now
except ImportError:  # direct execution fallback
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from core import audit_chain, audit_signing, audit_verify  # type: ignore
    from core.utils import utc_now  # type: ignore


class PruneError(Exception):
    """Refusal to prune. Every one of these is a reason the operator has to
    resolve; none of them is recoverable by trying harder."""


def sha256_file(path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def plan_prune(chain_path, bundle, bundle_sha256):
    """Decide what a prune would do, refusing if anything does not line up.

    Returns ``{anchor_seq, prev_hash, archived_first_seq, archived_last_seq,
    archived_count, bundle_sha256}``. Raises :class:`PruneError` otherwise.
    """
    verdict = audit_verify.verify_bundle(bundle)
    if not verdict["ok"]:
        raise PruneError(
            f"the archive bundle does not verify ({verdict['reason']}) — nothing "
            f"was pruned. Never delete a prefix whose only copy is unverified.")
    if not verdict["signed"]:
        raise PruneError(
            "the archive bundle is unsigned, so nothing ties it to this "
            "instance. Export it from an instance with audit signing enabled.")
    if verdict["count"] == 0:
        raise PruneError("the archive bundle is empty; there is nothing to prune")

    first_seq = verdict["first_seq"]
    last_seq = verdict["last_seq"]

    chain_first = audit_chain._first_record_seq(chain_path)
    if chain_first is None:
        raise PruneError(f"no audit chain at {chain_path}")
    if chain_first != first_seq:
        # The one rule that keeps this a prune and not a hole: the archive must
        # start where the chain currently starts. On an already-pruned chain
        # that is the previous anchor, not the genesis, which is how a second
        # prune works — its bundle is an anchored slice (#441) and verifies as
        # one.
        raise PruneError(
            f"the bundle starts at seq {first_seq} but the chain starts at seq "
            f"{chain_first}: this bundle is not a prefix of this chain")

    # The bundle's records must be the chain's own records, byte for byte at the
    # hash level. verify_bundle proved the bundle is internally consistent; this
    # proves it is a copy of THIS history and not of some other instance's.
    entries = {e["seq"]: e["hash"] for e in bundle["entries"]}
    head_at_last = None
    seen = 0
    for rec in audit_chain.iter_records(chain_path, to_seq=last_seq):
        expected = entries.get(rec["seq"])
        if expected is None:
            raise PruneError(
                f"the chain has a record at seq {rec['seq']} that the archive "
                f"bundle does not contain: the archive is incomplete")
        if expected != rec["hash"]:
            raise PruneError(
                f"the chain and the archive bundle disagree at seq {rec['seq']}: "
                f"one of them has been modified")
        seen += 1
        if rec["seq"] == last_seq:
            head_at_last = rec["hash"]
    if seen != verdict["count"]:
        raise PruneError(
            f"the archive bundle holds {verdict['count']} records but the chain "
            f"holds {seen} up to seq {last_seq}")
    if head_at_last is None:
        raise PruneError(
            f"the chain does not contain seq {last_seq}, which the bundle claims")

    remaining = audit_chain._first_record_seq_after(chain_path, last_seq)
    if remaining is None:
        raise PruneError(
            f"pruning through seq {last_seq} would empty the chain. Keep at "
            f"least the entries after the archived prefix: a chain with no "
            f"live records cannot be verified at all, only asserted.")
    if remaining != last_seq + 1:
        raise PruneError(
            f"the chain jumps from seq {last_seq} to seq {remaining}; refusing "
            f"to prune a chain that is already broken")

    # What this prune replaces, if the chain was pruned before. Recorded (and
    # signed) so that an interrupted second prune can still be verified: the
    # chain would then start at the previous anchor, whose file this one is
    # about to overwrite.
    previous = audit_chain.read_anchor(audit_chain.anchor_path_for(chain_path))
    supersedes = None
    if previous is not None:
        supersedes = {"anchor_seq": previous["anchor_seq"],
                      "prev_hash": previous["prev_hash"]}

    return {
        "anchor_seq": last_seq + 1,
        "prev_hash": head_at_last,
        "archived_first_seq": first_seq,
        "archived_last_seq": last_seq,
        "archived_count": verdict["count"],
        "bundle_sha256": bundle_sha256,
        "supersedes": supersedes,
    }


def _write_atomic(path, text: str, mode: int = 0o600) -> None:
    tmp = f"{path}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def execute_prune(chain_path, plan, signer, audit_logger=None):
    """Append the ``archive`` record, write the anchor, rewrite the chain.

    The anchor is written *before* the chain is replaced. If the process dies
    between the two, the chain still holds everything and
    :func:`audit_chain.verify_chain` reports an interrupted prune rather than a
    broken chain — the safe direction to fail in, because nothing is gone.
    """
    chain_path = Path(chain_path)

    # 1. The prune is itself an audited event, recorded in the chain that
    #    continues. This is the whole point: the deletion is not deniable.
    entry = {
        "timestamp": utc_now().isoformat(),
        "operation": "archive",
        "resource_type": "audit_chain",
        "resource_id": f"seq {plan['archived_first_seq']}-{plan['archived_last_seq']}",
        "status": "success",
        "user": "operator",
        "ip_address": "local",
        "details": {
            "archived_first_seq": plan["archived_first_seq"],
            "archived_last_seq": plan["archived_last_seq"],
            "archived_count": plan["archived_count"],
            "archived_head_hash": plan["prev_hash"],
            "bundle_sha256": plan["bundle_sha256"],
        },
        "error": None,
        "actor": {"kind": "operator", "label": "audit_prune"},
        "trigger": {"cause": "manual"},
    }
    if audit_logger is not None:
        audit_logger.log_operation(
            operation="archive", resource_type="audit_chain",
            resource_id=entry["resource_id"], status="success",
            details=entry["details"], user="operator", ip_address="local",
            actor=entry["actor"], trigger=entry["trigger"],
        )
    else:
        last = None
        for rec in audit_chain.iter_records(chain_path):
            last = rec
        line = audit_chain.make_line(last["seq"] + 1, entry, last["hash"])
        with open(chain_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(line, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())

    # Snapshot taken AFTER our own append, so the guard below detects somebody
    # else's write and not ours.
    before = chain_path.stat()

    # 2. The signed anchor: what was archived, and what the remainder continues
    #    from. Signed so a planted anchor cannot pass for a real one.
    anchor = dict(plan)
    anchor["pruned_at"] = utc_now().isoformat()
    signature = signer.sign(audit_chain.anchor_signing_bytes(anchor))
    if signature is None:
        raise PruneError("could not sign the anchor; nothing was pruned")
    anchor["signature"] = signature
    anchor["algorithm"] = audit_signing.ALGORITHM
    anchor_path = audit_chain.anchor_path_for(chain_path)
    _write_atomic(anchor_path, json.dumps(anchor, indent=2) + "\n")

    # 3. Rewrite the chain without the archived records. The concurrency guard
    #    is a backstop for the documented rule that CertMate must be stopped:
    #    a running instance holds the next seq in memory and would collide.
    kept = [
        json.dumps(rec, ensure_ascii=False)
        for rec in audit_chain.iter_records(chain_path, from_seq=plan["anchor_seq"])
    ]
    after = chain_path.stat()
    if (after.st_size, after.st_mtime_ns) != (before.st_size, before.st_mtime_ns):
        if audit_logger is None:
            raise PruneError(
                "the chain file changed while pruning — is CertMate still "
                "running? Nothing was removed (the anchor was written; re-run "
                "the prune with the service stopped).")
    _write_atomic(chain_path, "\n".join(kept) + "\n")
    return anchor


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Prune an exported, verified prefix of the CertMate audit chain.",
        epilog="CertMate must be STOPPED. Export and verify the prefix first; "
               "this command refuses to delete anything it cannot see a valid "
               "archive for.")
    parser.add_argument("--bundle", required=True,
                        help="the signed export bundle covering the prefix to prune")
    parser.add_argument("--data-dir", default="data/audit",
                        help="directory holding certificate_audit.chain.jsonl")
    parser.add_argument("--key-dir", default="data",
                        help="directory holding .audit_signing_key (to sign the anchor)")
    parser.add_argument("--yes", action="store_true",
                        help="actually prune; without it the plan is printed and nothing changes")
    args = parser.parse_args(argv)

    chain_path = Path(args.data_dir) / audit_chain.CHAIN_FILENAME
    try:
        with open(args.bundle, "r", encoding="utf-8") as f:
            bundle = json.load(f)
        bundle_sha = sha256_file(args.bundle)
    except (OSError, json.JSONDecodeError) as e:
        print(f"FAIL: cannot read bundle: {e}", file=sys.stderr)
        return 2

    try:
        plan = plan_prune(chain_path, bundle, bundle_sha)
    except PruneError as e:
        print(f"REFUSED: {e}", file=sys.stderr)
        return 1

    print(f"Archive verified: {plan['archived_count']} entries, "
          f"seq {plan['archived_first_seq']}..{plan['archived_last_seq']}")
    print(f"After pruning, the chain starts at seq {plan['anchor_seq']} and is "
          f"verified from a signed anchor, not from the genesis.")
    print(f"Keep {args.bundle} (sha256 {plan['bundle_sha256'][:16]}...) off this "
          f"box: it is the only remaining copy of those entries.")
    if not args.yes:
        print("\nDry run. Re-run with --yes to prune, with CertMate stopped.")
        return 0

    signer = audit_signing.AuditSigner(Path(args.key_dir))
    if not signer.available:
        print("FAIL: no audit signing key; the anchor could not be signed",
              file=sys.stderr)
        return 2
    try:
        execute_prune(chain_path, plan, signer)
    except PruneError as e:
        print(f"FAILED: {e}", file=sys.stderr)
        return 1

    result = audit_chain.verify_chain(chain_path)
    if not result["ok"]:
        print(f"FAIL: the pruned chain does not verify: {result['reason']}",
              file=sys.stderr)
        return 1
    print(f"\nPruned. {result['reason']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
