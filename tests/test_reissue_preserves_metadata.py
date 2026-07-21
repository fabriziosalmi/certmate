"""A reissue must not silently discard per-certificate configuration.

Regression test for #421. `create_certificate` built `metadata` as a fresh
dict and wrote metadata.json wholesale, so `replace=True` (Edit & Reissue)
dropped every key the PATCH endpoint had stored there — `deployment_protocol`,
`deployment_port`, `deployment_host` (which resources.py goes out of its way
to preserve on a *partial* PATCH), plus `deployment_status` and `renewed_at`.

Concretely: an operator sets a mail server's probe to smtp-starttls:587, then
adds a SAN via Edit & Reissue. The probe reverts to https-tls:443 and the
dashboard reports the mail server as "not deployed".

The reissue stays authoritative for the issuance fields — including clearing a
domain alias that the reissue dropped, which a naive merge would inherit.
"""

import json
from unittest.mock import MagicMock

import pytest

from modules.core.certificates import (
    CertificateManager,
    _REISSUE_OWNED_METADATA_KEYS,
)


pytestmark = [pytest.mark.unit]


@pytest.fixture
def mgr(tmp_path):
    settings_mgr = MagicMock()
    settings_mgr.load_settings.return_value = {}
    return CertificateManager(
        cert_dir=tmp_path,
        settings_manager=settings_mgr,
        dns_manager=MagicMock(),
        storage_manager=None,
        ca_manager=None,
    )


def _write_metadata(mgr, domain, payload):
    d = mgr.cert_dir / domain
    d.mkdir(parents=True, exist_ok=True)
    mgr._metadata_path(domain).write_text(json.dumps(payload))


def _reissue_metadata(mgr, domain, new_issuance):
    """Exercise the real merge used by create_certificate(replace=True)."""
    return mgr._merge_reissue_metadata(domain, new_issuance)


def test_deployment_probe_config_survives_a_reissue(mgr):
    _write_metadata(mgr, 'mail.example.com', {
        'domain': 'mail.example.com',
        'dns_provider': 'cloudflare',
        'san_domains': [],
        'deployment_protocol': 'smtp-starttls',
        'deployment_port': 587,
        'deployment_host': 'mail.example.com',
        'deployment_status': {'deployed': True},
        'renewed_at': '2026-07-01T00:00:00',
    })

    merged = _reissue_metadata(mgr, 'mail.example.com', {
        'domain': 'mail.example.com',
        'dns_provider': 'cloudflare',
        'san_domains': ['smtp.example.com'],
        'created_at': '2026-07-21T00:00:00',
    })

    assert merged['deployment_protocol'] == 'smtp-starttls'
    assert merged['deployment_port'] == 587
    assert merged['deployment_host'] == 'mail.example.com'
    assert merged['deployment_status'] == {'deployed': True}
    assert merged['renewed_at'] == '2026-07-01T00:00:00'
    # ...while the reissue still owns the issuance fields.
    assert merged['san_domains'] == ['smtp.example.com']
    assert merged['created_at'] == '2026-07-21T00:00:00'


def test_a_reissue_that_drops_the_alias_actually_clears_it(mgr):
    """The failure mode a naive merge would introduce."""
    _write_metadata(mgr, 'app.example.com', {
        'domain': 'app.example.com',
        'domain_alias': '_acme-challenge.validation.example.org',
        'alias_dns_provider': 'route53',
        'deployment_port': 8443,
    })

    merged = _reissue_metadata(mgr, 'app.example.com', {
        'domain': 'app.example.com',
        'dns_provider': 'cloudflare',
        'san_domains': [],
    })

    assert 'domain_alias' not in merged, "a cleared alias came back from disk"
    assert 'alias_dns_provider' not in merged
    assert merged['deployment_port'] == 8443


def test_a_stale_storage_warning_does_not_outlive_the_reissue(mgr):
    _write_metadata(mgr, 'x.example.com', {
        'domain': 'x.example.com',
        'storage_warning': 'Certificate issued but NOT saved to vault',
    })

    merged = _reissue_metadata(mgr, 'x.example.com', {
        'domain': 'x.example.com',
        'dns_provider': 'cloudflare',
        'san_domains': [],
    })

    assert 'storage_warning' not in merged


def test_unknown_keys_from_future_versions_are_preserved(mgr):
    _write_metadata(mgr, 'y.example.com', {
        'domain': 'y.example.com',
        'some_future_setting': {'nested': True},
    })

    merged = _reissue_metadata(mgr, 'y.example.com', {
        'domain': 'y.example.com',
        'dns_provider': 'cloudflare',
        'san_domains': [],
    })

    assert merged['some_future_setting'] == {'nested': True}


def test_a_first_issuance_has_nothing_to_preserve(mgr):
    merged = _reissue_metadata(mgr, 'new.example.com', {
        'domain': 'new.example.com',
        'dns_provider': 'cloudflare',
        'san_domains': [],
    })
    assert merged == {
        'domain': 'new.example.com',
        'dns_provider': 'cloudflare',
        'san_domains': [],
    }


def test_owned_key_set_covers_every_field_the_reissue_writes():
    """Guard against a new issuance field being added without being declared
    owned — it would then be preserved from the previous issuance forever."""
    written_by_reissue = {
        'domain', 'san_domains', 'dns_provider', 'challenge_type',
        'created_at', 'email', 'staging', 'account_id', 'ca_provider',
        'ca_account_id', 'domain_alias', 'alias_dns_provider',
        'storage_warning',
    }
    assert written_by_reissue == set(_REISSUE_OWNED_METADATA_KEYS)
