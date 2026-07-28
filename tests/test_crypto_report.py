"""Tests for the crypto readiness report engine (``modules/core/crypto_report.py``),
#473: data-driven key/signature classification, worst-of aggregation, the
quantum-vulnerable tally, breakdowns, and CSV export."""

import pytest

from modules.core.crypto_report import (
    build_crypto_report, report_to_csv,
    CLASS_WEAK, CLASS_ACCEPTABLE, CLASS_MODERN, CLASS_UNKNOWN,
    KEY_RULES, DEPRECATION_NOTES,
)

pytestmark = [pytest.mark.unit]


def _rec(fingerprint, key, sig=None, **kw):
    base = {'fingerprint': fingerprint, 'subject_cn': fingerprint + '.example.com',
            'key': key, 'signature_algorithm': sig, 'managed': False,
            'source': 'probed', 'not_after': '2099-01-01T00:00:00Z'}
    base.update(kw)
    return base


def _one(record):
    return build_crypto_report([record])['assets'][0]


# --- key classification ---------------------------------------------------- #

def test_rsa_2048_acceptable():
    a = _one(_rec('a', {'type': 'RSA', 'size': 2048}, 'sha256WithRSAEncryption'))
    assert a['key_classification'] == CLASS_ACCEPTABLE
    assert a['quantum_vulnerable'] is True


def test_rsa_1024_weak():
    a = _one(_rec('a', {'type': 'RSA', 'size': 1024}, 'sha256WithRSAEncryption'))
    assert a['key_classification'] == CLASS_WEAK


def test_ecdsa_p256_acceptable():
    a = _one(_rec('a', {'type': 'ECDSA', 'curve': 'secp256r1'}, 'ecdsa-with-SHA256'))
    assert a['key_classification'] == CLASS_ACCEPTABLE


def test_ecdsa_weak_curve():
    a = _one(_rec('a', {'type': 'ECDSA', 'curve': 'secp192r1'}, 'ecdsa-with-SHA256'))
    assert a['key_classification'] == CLASS_WEAK


def test_ed25519_modern():
    a = _one(_rec('a', {'type': 'Ed25519', 'size': 256}, 'ED25519'))
    assert a['key_classification'] == CLASS_MODERN
    assert a['quantum_vulnerable'] is True


def test_unknown_key():
    a = _one(_rec('a', {'type': 'Frobnicate'}, 'sha256'))
    assert a['key_classification'] == CLASS_UNKNOWN
    assert a['quantum_vulnerable'] is False


# --- signature + worst-of aggregation -------------------------------------- #

def test_sha1_signature_drags_overall_to_weak():
    # Key is fine (RSA-2048 acceptable) but a SHA-1 signature is weak; the
    # overall classification is the worse of the two.
    a = _one(_rec('a', {'type': 'RSA', 'size': 2048}, 'sha1WithRSAEncryption'))
    assert a['key_classification'] == CLASS_ACCEPTABLE
    assert a['signature_classification'] == CLASS_WEAK
    assert a['classification'] == CLASS_WEAK


def test_overall_is_acceptable_when_both_acceptable():
    a = _one(_rec('a', {'type': 'ECDSA', 'curve': 'secp384r1'}, 'ecdsa-with-SHA384'))
    assert a['classification'] == CLASS_ACCEPTABLE


def test_missing_signature_does_not_downgrade_good_key():
    # A record with no signature_algorithm (e.g. a CT entry that only carried
    # subject + fingerprint) must not be dragged to 'unknown' — the key drives it.
    a = _one(_rec('a', {'type': 'RSA', 'size': 2048}, sig=None))
    assert a['key_classification'] == CLASS_ACCEPTABLE
    assert a['signature_classification'] is None
    assert a['classification'] == CLASS_ACCEPTABLE


def test_deprecation_note_present():
    a = _one(_rec('a', {'type': 'RSA', 'size': 2048}, 'sha256'))
    assert a['deprecation'] == DEPRECATION_NOTES[CLASS_ACCEPTABLE]


# --- aggregation ----------------------------------------------------------- #

def test_report_counts_and_breakdowns():
    records = [
        _rec('a', {'type': 'RSA', 'size': 2048}, 'sha256WithRSAEncryption'),
        _rec('b', {'type': 'RSA', 'size': 1024}, 'sha1WithRSAEncryption'),
        _rec('c', {'type': 'ECDSA', 'curve': 'secp256r1'}, 'ecdsa-with-SHA256'),
        _rec('d', {'type': 'Ed25519', 'size': 256}, 'ED25519'),
    ]
    rep = build_crypto_report(records, generated_at='2026-07-28T00:00:00Z')
    assert rep['generated_at'] == '2026-07-28T00:00:00Z'
    assert rep['total'] == 4
    assert rep['quantum_vulnerable'] == 4
    assert rep['by_classification'][CLASS_WEAK] == 1     # the RSA-1024/sha1 cert
    assert rep['by_classification'][CLASS_ACCEPTABLE] == 2
    assert rep['by_classification'][CLASS_MODERN] == 1
    assert rep['by_key_algorithm']['RSA 2048'] == 1
    assert rep['by_key_algorithm']['ECDSA secp256r1'] == 1
    assert rep['by_signature_algorithm']['ED25519'] == 1


def test_empty_report():
    rep = build_crypto_report([])
    assert rep['total'] == 0
    assert rep['assets'] == []


def test_key_rules_are_introspectable():
    assert KEY_RULES['rsa_min_bits'] == 2048
    assert 'secp256r1' in KEY_RULES['ec_acceptable_curves']


# --- CSV ------------------------------------------------------------------- #

def test_csv_export():
    rep = build_crypto_report([
        _rec('a', {'type': 'RSA', 'size': 2048}, 'sha256WithRSAEncryption'),
    ])
    csv_text = report_to_csv(rep)
    lines = csv_text.strip().splitlines()
    assert lines[0].startswith('subject_cn,fingerprint,key_algorithm')
    assert len(lines) == 2
    assert 'RSA' in lines[1]


def test_csv_empty_is_header_only():
    csv_text = report_to_csv(build_crypto_report([]))
    assert len(csv_text.strip().splitlines()) == 1


def test_csv_formula_injection_is_neutralised():
    # A cert whose subject CN is attacker-controlled (probed/CT) and starts with
    # a formula lead must be prefixed with a quote in the CSV export.
    rep = build_crypto_report([
        _rec('a', {'type': 'RSA', 'size': 2048}, 'sha256'),
    ])
    rep['assets'][0]['subject_cn'] = '=HYPERLINK("http://evil","x")'
    rep['assets'][0]['signature_algorithm'] = '+SUM(A1:A9)'
    csv_text = report_to_csv(rep)
    data_line = csv_text.strip().splitlines()[1]
    assert data_line.startswith("'=HYPERLINK") or '"\'=HYPERLINK' in data_line
    assert "'+SUM(A1:A9)" in csv_text


def test_hyphenated_signature_still_classified():
    # RSASSA-PSS / hyphenated renderings like 'sha-256' must not fall to unknown.
    a = _one(_rec('a', {'type': 'RSA', 'size': 2048}, 'RSASSA-PSS-sha-256'))
    assert a['signature_classification'] == CLASS_ACCEPTABLE
    assert a['classification'] == CLASS_ACCEPTABLE


def test_unrecognised_signature_does_not_downgrade_good_key():
    # A present-but-unrecognised signature keeps the key's classification rather
    # than dragging a strong key to 'unknown'.
    a = _one(_rec('a', {'type': 'RSA', 'size': 2048}, 'totally-bespoke-algo'))
    assert a['signature_classification'] == CLASS_UNKNOWN
    assert a['classification'] == CLASS_ACCEPTABLE
