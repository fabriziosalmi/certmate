"""Standalone verifier for the audit hash chain.

Usage::

    python -m modules.core.audit_verify [path/to/certificate_audit.chain.jsonl]
    python -m modules.core.audit_verify --json /path/to/chain.jsonl

Exit code 0 if the chain is intact, 1 if it is broken (with the offending
``seq`` and a reason), 2 on a usage/IO error. Depends only on the Python
standard library, so an auditor can run it without installing or trusting
CertMate. Phase 2 verifies authenticity + ordering; signature verification of
an exported, signed bundle is Phase 3.
"""

import sys
import json
import argparse

try:  # package import (python -m modules.core.audit_verify)
    from . import audit_chain
except ImportError:  # direct execution fallback
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from core import audit_chain  # type: ignore


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify the integrity of a CertMate audit hash chain.")
    parser.add_argument(
        "path", nargs="?", default=audit_chain.CHAIN_FILENAME,
        help="path to certificate_audit.chain.jsonl")
    parser.add_argument("--json", action="store_true",
                        help="emit the result as JSON")
    args = parser.parse_args(argv)

    result = audit_chain.verify_chain(args.path)

    if args.json:
        print(json.dumps(result, indent=2))
    elif result["ok"]:
        print(f"OK: audit chain intact "
              f"({result['count']} entries, seq {result['first_seq']}..{result['last_seq']})")
        if result.get("head_hash"):
            print(f"head_hash: {result['head_hash']}")
    else:
        where = f" at seq {result['error_seq']}" if result.get("error_seq") is not None else ""
        print(f"FAIL: audit chain broken{where}: {result['reason']}", file=sys.stderr)

    if result["ok"]:
        return 0
    # Distinguish a missing file (usage/IO) from a genuine integrity break.
    if result.get("reason") in ("chain file does not exist",) or \
            (result.get("reason") or "").startswith("cannot read"):
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
