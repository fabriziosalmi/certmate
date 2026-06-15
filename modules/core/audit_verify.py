"""Standalone verifier for the audit hash chain and signed export bundle.

Usage::

    # Phase 2 — verify a raw chain file (stdlib only):
    python -m modules.core.audit_verify [path/to/certificate_audit.chain.jsonl]

    # Phase 3 — verify a signed export bundle (needs `cryptography`):
    python -m modules.core.audit_verify --bundle bundle.json [--pubkey key.pem]

    # JSON output for either:
    python -m modules.core.audit_verify --json ...

Exit code 0 if intact, 1 if broken (with the offending ``seq`` / reason), 2 on a
usage/IO error. The chain check depends only on the Python standard library;
bundle signature verification additionally needs the public key + ``cryptography``.
An auditor can run this without installing or trusting CertMate.
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


def _import_signing():
    try:
        from . import audit_signing
        return audit_signing
    except ImportError:  # direct execution fallback
        from core import audit_signing  # type: ignore
        return audit_signing


def verify_bundle(bundle, expected_pubkey_pem=None):
    """Verify a signed export bundle: chain structure of the entries, manifest
    consistency (head_hash + seq range commit to the entries), the Ed25519
    bundle signature, the public-key fingerprint, and optional out-of-band
    pinning against ``expected_pubkey_pem``."""
    result = {
        "ok": False, "reason": None, "signed": False, "signature_ok": False,
        "fingerprint": None, "count": 0, "first_seq": None, "last_seq": None,
        "head_hash": None, "error_seq": None,
    }
    if not isinstance(bundle, dict) or "manifest" not in bundle or "entries" not in bundle:
        result["reason"] = "not an audit export bundle (missing manifest/entries)"
        return result
    manifest = bundle.get("manifest") or {}
    entries = bundle.get("entries") or []

    # 1. Structural chain verification of the entries.
    chain = audit_chain.verify_records(entries)
    for k in ("count", "first_seq", "last_seq", "head_hash", "error_seq"):
        result[k] = chain.get(k)
    if not chain["ok"]:
        result["reason"] = f"chain invalid: {chain['reason']}"
        return result

    # 2. Manifest consistency — head_hash + seq range/count commit to the entries.
    if manifest.get("head_hash") != chain["head_hash"]:
        result["reason"] = "manifest head_hash does not match the entries"
        return result
    if (manifest.get("seq_first") != chain["first_seq"]
            or manifest.get("seq_last") != chain["last_seq"]
            or manifest.get("count") != chain["count"]):
        result["reason"] = "manifest seq range / count does not match the entries"
        return result

    # 3. Signature (when present).
    sig = bundle.get("bundle_signature")
    pem = manifest.get("public_key_pem")
    if sig and pem:
        result["signed"] = True
        signing = _import_signing()
        if not signing.verify_signature(pem, sig, audit_chain.manifest_signing_bytes(manifest)):
            result["reason"] = "bundle signature is invalid"
            return result
        fp = signing.fingerprint_from_pem(pem)
        result["fingerprint"] = fp
        if manifest.get("instance_fingerprint") and fp != manifest.get("instance_fingerprint"):
            result["reason"] = "manifest fingerprint does not match the public key"
            return result
        result["signature_ok"] = True
        # 4. Out-of-band pinning: the auditor supplied the expected public key.
        if expected_pubkey_pem is not None:
            exp_fp = signing.fingerprint_from_pem(expected_pubkey_pem)
            if exp_fp != fp:
                result["reason"] = (
                    f"public key does not match the pinned --pubkey "
                    f"(expected {exp_fp}, bundle has {fp})")
                return result
    elif expected_pubkey_pem is not None:
        result["reason"] = "bundle is unsigned but a --pubkey was provided to pin against"
        return result

    result["ok"] = True
    result["reason"] = "intact and signed" if result["signed"] else "intact (unsigned bundle)"
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify a CertMate audit hash chain or signed export bundle.")
    parser.add_argument(
        "path", nargs="?", default=audit_chain.CHAIN_FILENAME,
        help="path to certificate_audit.chain.jsonl (chain mode)")
    parser.add_argument("--bundle", help="path to a signed export bundle JSON")
    parser.add_argument("--pubkey", help="path to a PEM public key to pin the bundle against")
    parser.add_argument("--json", action="store_true", help="emit the result as JSON")
    args = parser.parse_args(argv)

    if args.bundle:
        try:
            with open(args.bundle, "r", encoding="utf-8") as f:
                bundle = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            print(f"FAIL: cannot read bundle: {e}", file=sys.stderr)
            return 2
        expected_pem = None
        if args.pubkey:
            try:
                expected_pem = open(args.pubkey, "r", encoding="utf-8").read()
            except OSError as e:
                print(f"FAIL: cannot read --pubkey: {e}", file=sys.stderr)
                return 2
        result = verify_bundle(bundle, expected_pubkey_pem=expected_pem)
        if args.json:
            print(json.dumps(result, indent=2))
        elif result["ok"]:
            tag = f"signed by {result['fingerprint']}" if result["signed"] else "UNSIGNED"
            print(f"OK: audit bundle {result['reason']} "
                  f"({result['count']} entries, seq {result['first_seq']}..{result['last_seq']}; {tag})")
        else:
            where = f" at seq {result['error_seq']}" if result.get("error_seq") is not None else ""
            print(f"FAIL: audit bundle invalid{where}: {result['reason']}", file=sys.stderr)
        return 0 if result["ok"] else 1

    # Chain mode (Phase 2).
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
    if result.get("reason") in ("chain file does not exist",) or \
            (result.get("reason") or "").startswith("cannot read"):
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
