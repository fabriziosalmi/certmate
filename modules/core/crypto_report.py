"""Cryptographic algorithm inventory & readiness report (#473).

Operators increasingly need to know which of their certificates and keys use
legacy cryptography (RSA, elliptic-curve) and how that maps against published
deprecation / crypto-agility timelines — the prerequisite for any migration
planning (and, in the EU, a crypto-inventory obligation). CertMate already has
the raw data once the inventory exists; this module turns it into a report.

Framed strictly as **inventory / readiness**: it classifies and counts what is
deployed. It does NOT change issuance and says nothing about issuing
post-quantum certificates.

The classification is deliberately **data-driven** (see
:data:`KEY_RULES` / :data:`SIGNATURE_RULES` / :data:`DEPRECATION_NOTES`) so new
algorithms — ML-DSA, composite / hybrid certificates — can be added by
extending a table, without touching the reporting logic.

Pure and offline: :func:`build_crypto_report` takes inventory records and
returns a JSON-safe report; :func:`report_to_csv` renders the per-asset table as
CSV. No Flask, no SQLite.
"""

import csv
import io

# Classification vocabulary (severity order, worst first).
CLASS_WEAK = 'weak'            # below any acceptable bar — act now
CLASS_ACCEPTABLE = 'acceptable'  # fine classically, but quantum-vulnerable
CLASS_MODERN = 'modern'       # modern classical (EdDSA)
CLASS_PQC = 'pqc'             # post-quantum (none deployed yet; table-ready)
CLASS_UNKNOWN = 'unknown'

# Elliptic curves considered acceptable strength (P-256 and up; include the
# OpenSSL alias prime256v1 for secp256r1).
_EC_ACCEPTABLE = {'secp256r1', 'prime256v1', 'secp384r1', 'secp521r1'}

# Minimum acceptable RSA modulus size.
_RSA_MIN = 2048

# Post-quantum key algorithm names — empty today, but the report classifies any
# that appear here as CLASS_PQC / not quantum-vulnerable. Extend as PQC lands.
PQC_KEY_TYPES = set()


def _classify_key(key_type, key_size, curve):
    """Return (classification, quantum_vulnerable, detail) for a public key."""
    ktype = (key_type or '').strip()
    upper = ktype.upper()

    if ktype in PQC_KEY_TYPES:
        return CLASS_PQC, False, 'post-quantum algorithm'
    if upper == 'RSA':
        if key_size and key_size < _RSA_MIN:
            return CLASS_WEAK, True, f'RSA {key_size}-bit is below {_RSA_MIN}-bit'
        return CLASS_ACCEPTABLE, True, f'RSA {key_size or "?"}-bit'
    if upper in ('ECDSA', 'EC', 'ECDH'):
        c = (curve or '').lower()
        if c and c not in _EC_ACCEPTABLE:
            return CLASS_WEAK, True, f'elliptic curve {curve} below P-256'
        return CLASS_ACCEPTABLE, True, f'elliptic curve {curve or "?"}'
    if upper in ('ED25519', 'ED448'):
        return CLASS_MODERN, True, ktype
    if upper == 'DSA':
        return CLASS_WEAK, True, 'DSA is deprecated'
    return CLASS_UNKNOWN, False, ktype or 'unknown key algorithm'


# Signature-hash rules, matched as case-insensitive substrings of the
# certificate's signatureAlgorithm (e.g. "sha256WithRSAEncryption",
# "ecdsa-with-SHA384"). First match wins; order matters.
SIGNATURE_RULES = (
    ('md5', CLASS_WEAK),
    ('sha1', CLASS_WEAK),
    ('sha224', CLASS_ACCEPTABLE),
    ('sha256', CLASS_ACCEPTABLE),
    ('sha384', CLASS_ACCEPTABLE),
    ('sha512', CLASS_ACCEPTABLE),
    ('ed25519', CLASS_MODERN),
    ('ed448', CLASS_MODERN),
)

# Informational deprecation / migration notes, keyed by classification bucket.
DEPRECATION_NOTES = {
    CLASS_WEAK: 'Below current strength baselines — replace as soon as possible.',
    CLASS_ACCEPTABLE: ('Classically strong but quantum-vulnerable. Inventory for '
                       'post-quantum migration (EU crypto-inventory obligation, '
                       'end of 2026; NIST guidance phases classical PKI toward 2030+).'),
    CLASS_MODERN: 'Modern classical algorithm; still quantum-vulnerable — track for PQC migration.',
    CLASS_PQC: 'Post-quantum algorithm.',
    CLASS_UNKNOWN: 'Algorithm not recognised; review manually.',
}

# Alias for external callers wanting to introspect/extend key rules.
KEY_RULES = {
    'rsa_min_bits': _RSA_MIN,
    'ec_acceptable_curves': sorted(_EC_ACCEPTABLE),
    'modern_key_types': ['Ed25519', 'Ed448'],
    'pqc_key_types': sorted(PQC_KEY_TYPES),
}


def _classify_signature(sig_algo):
    text = (sig_algo or '').lower()
    for needle, cls in SIGNATURE_RULES:
        if needle in text:
            return cls
    return CLASS_UNKNOWN


def _key_label(key):
    ktype = key.get('type') or 'unknown'
    if key.get('curve'):
        return f'{ktype} {key["curve"]}'
    if key.get('size'):
        return f'{ktype} {key["size"]}'
    return ktype


def build_crypto_report(records, generated_at=None):
    """Build the algorithm inventory / readiness report from inventory records.

    Returns a JSON-safe dict: overall counts, breakdowns by key algorithm,
    signature algorithm and classification, the quantum-vulnerable total, and a
    per-asset list (each with its classification + deprecation note). Every
    certificate — managed and discovered alike — is counted.
    """
    report = {
        'generated_at': generated_at,
        'total': 0,
        'quantum_vulnerable': 0,
        'by_key_algorithm': {},
        'by_signature_algorithm': {},
        'by_classification': {
            CLASS_WEAK: 0, CLASS_ACCEPTABLE: 0, CLASS_MODERN: 0,
            CLASS_PQC: 0, CLASS_UNKNOWN: 0,
        },
        'assets': [],
    }

    for record in records:
        key = record.get('key') or {}
        classification, quantum_vulnerable, detail = _classify_key(
            key.get('type'), key.get('size'), key.get('curve')
        )
        sig = record.get('signature_algorithm')
        # An asset's overall classification is the worse of key and signature —
        # but a MISSING signature must not drag a known-good key down to
        # "unknown"; only a present (and possibly weak/unrecognised) signature
        # participates.
        if sig:
            sig_class = _classify_signature(sig)
            overall = _worst(classification, sig_class)
        else:
            sig_class = None
            overall = classification

        key_label = _key_label(key)
        report['total'] += 1
        if quantum_vulnerable:
            report['quantum_vulnerable'] += 1
        report['by_key_algorithm'][key_label] = report['by_key_algorithm'].get(key_label, 0) + 1
        if sig:
            report['by_signature_algorithm'][sig] = report['by_signature_algorithm'].get(sig, 0) + 1
        report['by_classification'][overall] = report['by_classification'].get(overall, 0) + 1

        report['assets'].append({
            'fingerprint': record.get('fingerprint'),
            'subject_cn': record.get('subject_cn'),
            'key_algorithm': key.get('type'),
            'key_size': key.get('size'),
            'key_curve': key.get('curve'),
            'signature_algorithm': sig,
            'classification': overall,
            'key_classification': classification,
            'signature_classification': sig_class,
            'quantum_vulnerable': quantum_vulnerable,
            'detail': detail,
            'deprecation': DEPRECATION_NOTES.get(overall),
            'managed': bool(record.get('managed')),
            'source': record.get('source'),
            'not_after': record.get('not_after'),
        })

    return report


# Classification severity for "worst wins" (higher = worse).
_SEVERITY = {
    CLASS_PQC: 0, CLASS_MODERN: 1, CLASS_ACCEPTABLE: 2,
    CLASS_UNKNOWN: 3, CLASS_WEAK: 4,
}


def _worst(a, b):
    return a if _SEVERITY.get(a, 3) >= _SEVERITY.get(b, 3) else b


_CSV_COLUMNS = (
    'subject_cn', 'fingerprint', 'key_algorithm', 'key_size', 'key_curve',
    'signature_algorithm', 'classification', 'quantum_vulnerable', 'managed',
    'source', 'not_after', 'deprecation',
)


def report_to_csv(report):
    """Render the report's per-asset table as a CSV string."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_CSV_COLUMNS, extrasaction='ignore')
    writer.writeheader()
    for asset in report.get('assets', []):
        writer.writerow(asset)
    return buf.getvalue()
