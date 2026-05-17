"""
Regression test for renewal job N+1 settings reads.

The settings request-scoped cache (commit f0b77c3) only fires inside a
Flask request context. APScheduler's renewal job runs in a background
thread with no request context, so before this fix every domain in
`check_renewals` triggered a full settings.json reload via
get_certificate_info -> _parse_certificate_info. 1000 domains = 1001
reads of the same file in a single hourly tick.

The fix threads the once-loaded settings dict through
get_certificate_info(settings=...) and _parse_certificate_info(settings=...).
Both methods fall back to load_settings() when settings is None so
existing call sites keep working unchanged.

This test pins:
- check_renewals reads settings exactly ONCE regardless of domain count
- the optional `settings` parameter is honoured (not silently ignored)
- existing single-call sites that pass no settings still trigger a load
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from modules.core.certificates import CertificateManager


def _make_manager(tmp_path, domains, load_call_counter):
    """Build a CertificateManager whose load_settings tracks call count."""
    settings_mgr = MagicMock()

    settings_payload = {
        'auto_renew': True,
        'domains': [{'domain': d, 'auto_renew': True} for d in domains],
    }

    def counted_load():
        load_call_counter[0] += 1
        return dict(settings_payload)  # defensive: don't share refs

    settings_mgr.load_settings.side_effect = counted_load
    settings_mgr.migrate_domains_format.side_effect = lambda s: s
    settings_mgr.get_domain_dns_provider.return_value = 'cloudflare'

    mgr = CertificateManager(
        cert_dir=tmp_path,
        settings_manager=settings_mgr,
        dns_manager=MagicMock(),
        storage_manager=None,
        ca_manager=None,
    )
    return mgr


def test_check_renewals_reads_settings_once_for_many_domains(tmp_path):
    """The whole point of the fix: 50 domains, 1 load_settings call."""
    domains = [f'domain-{i}.example.com' for i in range(50)]
    counter = [0]

    mgr = _make_manager(tmp_path, domains, counter)

    # Stub get_certificate_info so the renewal loop exits quickly per cert.
    # IMPORTANT: this is the path we are protecting. Verify it's called with
    # `settings=` so the renewal loop is honouring the new signature.
    seen_kwargs = []

    real_get_cert_info = mgr.get_certificate_info

    def spy_get_cert_info(domain, settings=None):
        seen_kwargs.append({'domain': domain, 'settings': settings})
        # Return a cert_info dict that does NOT need renewal so renew is not called.
        return {'domain': domain, 'exists': True, 'needs_renewal': False}

    mgr.get_certificate_info = spy_get_cert_info

    mgr.check_renewals()

    assert counter[0] == 1, (
        f"check_renewals must call load_settings exactly once for any number "
        f"of domains. Got {counter[0]} reads for 50 domains."
    )

    # And the settings dict was actually threaded through every per-domain call.
    assert len(seen_kwargs) == 50
    for kw in seen_kwargs:
        assert kw['settings'] is not None, (
            f"get_certificate_info was called without settings= for "
            f"{kw['domain']}; the renewal job is still triggering N+1 reads"
        )


def test_get_certificate_info_passthrough_when_settings_none(tmp_path):
    """When called without the optional settings kwarg (e.g. the
    dashboard /api/certificates endpoint), the method must still load
    settings on its own so existing callers are unaffected."""
    counter = [0]
    mgr = _make_manager(tmp_path, [], counter)

    # Create a fake cert structure on disk so get_certificate_info reaches
    # the path that needs settings.
    cert_dir = tmp_path / "example.com"
    cert_dir.mkdir()
    (cert_dir / "cert.pem").write_bytes(b"-----BEGIN CERTIFICATE-----\nfake\n")

    # Patch _parse_certificate_info to a stub so we don't actually shell out.
    with patch.object(mgr, '_parse_certificate_info', return_value={'domain': 'example.com'}):
        mgr.get_certificate_info('example.com')  # no settings kwarg

    # The fallback dns_provider lookup runs only if metadata didn't carry
    # dns_provider; with no metadata.json on disk, get_certificate_info
    # falls back to settings — so we expect exactly one load.
    assert counter[0] == 1, (
        f"Without a caller-supplied settings dict, get_certificate_info "
        f"must still do its own load. Got {counter[0]} reads."
    )


def test_explicit_settings_overrides_load_settings(tmp_path):
    """When a caller passes settings= explicitly, load_settings must
    NOT be touched. Confirms the parameter is honoured, not silently
    discarded."""
    counter = [0]
    mgr = _make_manager(tmp_path, [], counter)

    cert_dir = tmp_path / "example.com"
    cert_dir.mkdir()
    (cert_dir / "cert.pem").write_bytes(b"-----BEGIN CERTIFICATE-----\nfake\n")

    pre_loaded_settings = {'domains': [], 'dns_provider': 'cloudflare'}

    with patch.object(mgr, '_parse_certificate_info', return_value={'domain': 'example.com'}) as p:
        mgr.get_certificate_info('example.com', settings=pre_loaded_settings)

    assert counter[0] == 0, (
        f"When settings is supplied, get_certificate_info must not reload "
        f"from disk. Got {counter[0]} reads."
    )
    # And the pre-loaded settings was passed through to _parse_certificate_info.
    call_kwargs = p.call_args.kwargs
    assert call_kwargs.get('settings') is pre_loaded_settings


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
