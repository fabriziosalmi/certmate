"""
Phase 3 of the agentic audit trail (l0 #408): Ed25519 signing, signed
checkpoints, the signed export bundle, and the upgraded standalone verifier.
"""

import json
import copy
from types import SimpleNamespace

import pytest
from flask import Flask

from modules.core.audit import AuditLogger
from modules.core.audit_signing import (
    AuditSigner, verify_signature, fingerprint_from_pem, SIGNING_KEY_FILENAME,
)
from modules.core import audit_chain, audit_verify
from modules.web.misc_routes import register_misc_routes


@pytest.fixture
def make_audit():
    created = []

    def _make(dir_path, **kw):
        a = AuditLogger(dir_path, **kw)
        created.append(a)
        return a

    yield _make
    for a in created:
        a.audit_logger.removeHandler(a.file_handler)
        a.file_handler.close()


def _emit(audit, n):
    for i in range(n):
        audit.log_operation('renew', 'certificate', f'd{i}.example.com', 'success',
                            actor={'kind': 'agent', 'id': 'k1'}, trigger={'cause': 'agent'})


# --------------------------------------------------------------------------
# AuditSigner: key lifecycle + sign/verify
# --------------------------------------------------------------------------

def test_signer_available_and_signs(tmp_path):
    s = AuditSigner(tmp_path)
    assert s.available
    sig = s.sign(b'hello')
    assert verify_signature(s.public_key_pem(), sig, b'hello')
    assert not verify_signature(s.public_key_pem(), sig, b'tampered')


def test_signer_fingerprint_matches_pubkey(tmp_path):
    s = AuditSigner(tmp_path)
    assert s.fingerprint() == fingerprint_from_pem(s.public_key_pem())
    assert len(s.fingerprint()) == 16


def test_signer_persists_same_identity_across_instances(tmp_path):
    s1 = AuditSigner(tmp_path)
    assert (tmp_path / SIGNING_KEY_FILENAME).exists()
    s2 = AuditSigner(tmp_path)
    assert s1.fingerprint() == s2.fingerprint()  # same persisted key


def test_signer_corrupt_key_disables_not_regenerates(tmp_path):
    AuditSigner(tmp_path)  # create the key
    (tmp_path / SIGNING_KEY_FILENAME).write_text('not a valid PEM key')
    s = AuditSigner(tmp_path)
    assert s.available is False          # disabled, not silently regenerated
    assert s.sign(b'x') is None
    assert s.fingerprint() is None


def test_signer_env_override(tmp_path, monkeypatch):
    # Generate a key off-box, point AUDIT_SIGNING_KEY_FILE at it.
    src = AuditSigner(tmp_path / 'box1')
    keyfile = (tmp_path / 'box1' / SIGNING_KEY_FILENAME)
    monkeypatch.setenv('AUDIT_SIGNING_KEY_FILE', str(keyfile))
    s = AuditSigner(tmp_path / 'box2')   # different data dir, same key via env
    assert s.fingerprint() == src.fingerprint()


# --------------------------------------------------------------------------
# Signed checkpoints
# --------------------------------------------------------------------------

def test_checkpoints_written_every_interval(make_audit, tmp_path):
    audit = make_audit(tmp_path, signer=AuditSigner(tmp_path), checkpoint_interval=3)
    _emit(audit, 7)  # checkpoints at 3 and 6
    lines = [l for l in (tmp_path / audit_chain.CHECKPOINT_FILENAME).read_text().splitlines() if l.strip()]
    assert len(lines) == 2
    cp = json.loads(lines[0])
    assert cp['seq'] == 2 and cp['count'] == 3 and cp['signature']


def test_checkpoint_signature_verifies(make_audit, tmp_path):
    signer = AuditSigner(tmp_path)
    audit = make_audit(tmp_path, signer=signer, checkpoint_interval=100)
    _emit(audit, 2)
    cp = audit.write_checkpoint()
    data = audit_chain.canon_bytes({'seq': cp['seq'], 'hash': cp['hash'],
                                    'count': cp['count'], 'timestamp': cp['timestamp']})
    assert verify_signature(signer.public_key_pem(), cp['signature'], data)


def test_no_checkpoint_without_signer(make_audit, tmp_path):
    audit = make_audit(tmp_path, checkpoint_interval=1)  # no signer
    _emit(audit, 3)
    assert audit.write_checkpoint() is None
    assert not (tmp_path / audit_chain.CHECKPOINT_FILENAME).exists()


# --------------------------------------------------------------------------
# Signed export bundle + verifier
# --------------------------------------------------------------------------

def _signed_bundle(make_audit, tmp_path, n=5):
    signer = AuditSigner(tmp_path)
    audit = make_audit(tmp_path, signer=signer)
    _emit(audit, n)
    return audit.export_bundle(), signer


def test_export_bundle_shape_and_signed(make_audit, tmp_path):
    bundle, signer = _signed_bundle(make_audit, tmp_path, 5)
    m = bundle['manifest']
    assert len(bundle['entries']) == 5
    assert bundle['bundle_signature']
    assert m['count'] == 5 and m['seq_first'] == 0 and m['seq_last'] == 4
    assert m['instance_fingerprint'] == signer.fingerprint()
    assert m['head_hash'] == bundle['entries'][-1]['hash']


def test_verify_bundle_intact(make_audit, tmp_path):
    bundle, _ = _signed_bundle(make_audit, tmp_path)
    r = audit_verify.verify_bundle(bundle)
    assert r['ok'] and r['signed'] and r['signature_ok']


def test_verify_bundle_detects_tampered_entry(make_audit, tmp_path):
    bundle, _ = _signed_bundle(make_audit, tmp_path)
    bad = copy.deepcopy(bundle)
    bad['entries'][1]['entry']['resource_id'] = 'evil.example.com'
    r = audit_verify.verify_bundle(bad)
    assert not r['ok'] and 'chain invalid' in r['reason']


def test_verify_bundle_detects_manifest_forgery(make_audit, tmp_path):
    # Re-sign nothing: just flip a manifest field -> signature no longer matches.
    bundle, _ = _signed_bundle(make_audit, tmp_path)
    bad = copy.deepcopy(bundle)
    bad['manifest']['exported_at'] = '1999-01-01T00:00:00'
    r = audit_verify.verify_bundle(bad)
    assert not r['ok'] and 'signature' in r['reason']


def test_verify_bundle_wrong_and_right_pinned_pubkey(make_audit, tmp_path):
    bundle, signer = _signed_bundle(make_audit, tmp_path)
    other = AuditSigner(tmp_path / 'other')
    bad = audit_verify.verify_bundle(bundle, expected_pubkey_pem=other.public_key_pem())
    assert not bad['ok'] and 'pinned' in bad['reason']
    good = audit_verify.verify_bundle(bundle, expected_pubkey_pem=signer.public_key_pem())
    assert good['ok']


def test_unsigned_bundle_verifies_chain_only(make_audit, tmp_path):
    audit = make_audit(tmp_path)  # no signer
    _emit(audit, 3)
    bundle = audit.export_bundle()
    assert bundle['bundle_signature'] is None
    r = audit_verify.verify_bundle(bundle)
    assert r['ok'] and r['signed'] is False
    # pinning against an unsigned bundle is rejected
    s = AuditSigner(tmp_path / 'k')
    assert not audit_verify.verify_bundle(bundle, expected_pubkey_pem=s.public_key_pem())['ok']


def test_empty_signed_bundle_verifies(make_audit, tmp_path):
    # An export with no entries (e.g. ?from_seq past the end, or before the first
    # audit event) must still verify consistently, not fail on head_hash.
    audit = make_audit(tmp_path, signer=AuditSigner(tmp_path))
    _emit(audit, 3)
    bundle = audit.export_bundle(from_seq=99)  # nothing at/after seq 99
    assert bundle['entries'] == []
    r = audit_verify.verify_bundle(bundle)
    assert r['ok'] and r['signed']


def test_half_signed_bundle_is_rejected(make_audit, tmp_path):
    bundle, _ = _signed_bundle(make_audit, tmp_path)
    no_pem = copy.deepcopy(bundle)
    no_pem['manifest']['public_key_pem'] = None
    assert not audit_verify.verify_bundle(no_pem)['ok']
    no_sig = copy.deepcopy(bundle)
    no_sig['bundle_signature'] = None
    assert not audit_verify.verify_bundle(no_sig)['ok']


def test_unsupported_format_is_rejected(make_audit, tmp_path):
    # 2 is the anchored-slice format (#441); 99 is nobody's format.
    bundle, _ = _signed_bundle(make_audit, tmp_path)
    bad = copy.deepcopy(bundle)
    bad['manifest']['format_version'] = 99
    r = audit_verify.verify_bundle(bad)
    assert not r['ok'] and 'format_version' in r['reason']


def test_cli_bundle_mode(make_audit, tmp_path):
    bundle, _ = _signed_bundle(make_audit, tmp_path)
    p = tmp_path / 'bundle.json'
    p.write_text(json.dumps(bundle))
    assert audit_verify.main(['--bundle', str(p)]) == 0
    # tamper -> exit 1
    bundle['entries'][0]['entry']['status'] = 'forged'
    p.write_text(json.dumps(bundle))
    assert audit_verify.main(['--bundle', str(p)]) == 1


# --------------------------------------------------------------------------
# Endpoints: /api/audit/public-key + /api/audit/export
# --------------------------------------------------------------------------

def _passthrough(*_a, **_k):
    def deco(fn):
        return fn
    return deco


def _app(managers):
    app = Flask(__name__)
    auth_manager = SimpleNamespace(require_role=_passthrough)
    register_misc_routes(app, managers, _passthrough, auth_manager)
    return app


def test_public_key_endpoint(make_audit, tmp_path):
    audit = make_audit(tmp_path, signer=AuditSigner(tmp_path))
    r = _app({'audit': audit}).test_client().get('/api/audit/public-key')
    assert r.status_code == 200
    body = r.get_json()
    assert body['algorithm'] == 'ed25519' and body['fingerprint'] and 'BEGIN PUBLIC KEY' in body['public_key_pem']


def test_public_key_endpoint_404_without_signer(make_audit, tmp_path):
    audit = make_audit(tmp_path)  # no signer
    r = _app({'audit': audit}).test_client().get('/api/audit/public-key')
    assert r.status_code == 404


def test_export_endpoint_returns_verifiable_bundle(make_audit, tmp_path):
    audit = make_audit(tmp_path, signer=AuditSigner(tmp_path))
    _emit(audit, 4)
    r = _app({'audit': audit}).test_client().get('/api/audit/export')
    assert r.status_code == 200
    bundle = r.get_json()
    assert audit_verify.verify_bundle(bundle)['ok']
