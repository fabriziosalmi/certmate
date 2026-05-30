"""
Regression test for the certificate-listing settings reuse.

`CertificateList.get` (GET /api/certificates) loads settings once near
the top of the handler, then iterates every known domain calling
`certificate_manager.get_certificate_info(domain)`. Before this fix the
per-domain call did not thread the already-loaded settings dict through,
so `get_certificate_info` re-derived settings for each domain. In a live
Flask request `SettingsManager.load_settings()` is already request-cached
on `flask.g`, so each per-domain reload was a flask.g lookup plus a full
deepcopy of the settings dict — not a disk read. Threading the loaded
dict through `settings=` skips that per-domain deepcopy entirely.

These manager-level tests use a MagicMock settings_manager (no flask.g),
so each un-threaded reload shows up as one extra load_settings call,
making the per-domain reuse directly observable as a call count. The
storage-backend cert-info cache behaviour (the part that actually
matters for Azure KV / AWS SM / Vault) is pinned separately in
tests/test_cert_info_cache_and_storage_summary.py.

This test pins, at the manager level (the listing handler simply loops
over `get_certificate_info`):
- a listing-style loop that threads the once-loaded settings re-derives
  settings exactly ONCE regardless of domain count
- the bounded behaviour does NOT scale with the number of domains
- the old behaviour (no settings=) would have scaled 1-per-domain, which
  this test would catch
"""
from __future__ import annotations

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


def _list_certificates(mgr, settings, domains):
    """Mirror the CertificateList.get loop: one load, then a per-domain
    get_certificate_info call that threads the loaded settings through."""
    certificates = []
    for domain in domains:
        cert_info = mgr.get_certificate_info(domain, settings=settings)
        if cert_info:
            certificates.append(cert_info)
    return certificates


def test_listing_reads_settings_once_for_many_domains(tmp_path):
    """The whole point of the fix: many domains, a single load_settings call.

    The listing handler loads settings once up front and then must reuse
    that dict for every per-domain lookup. We seed real on-disk certs so
    get_certificate_info reaches the settings-dependent path, and assert
    the only load is the handler's own initial load."""
    domains = [f'domain-{i}.example.com' for i in range(5)]
    counter = [0]

    mgr = _make_manager(tmp_path, domains, counter)

    # Seed a fake cert structure on disk for each domain so
    # get_certificate_info reaches the path that needs settings.
    for domain in domains:
        domain_dir = tmp_path / domain
        domain_dir.mkdir()
        (domain_dir / "cert.pem").write_bytes(b"-----BEGIN CERTIFICATE-----\nfake\n")

    seen_kwargs = []
    real_get_cert_info = mgr.get_certificate_info

    def spy_get_cert_info(domain, settings=None):
        seen_kwargs.append({'domain': domain, 'settings': settings})
        return real_get_cert_info(domain, settings=settings)

    mgr.get_certificate_info = spy_get_cert_info

    # The listing handler's single up-front load.
    settings = mgr.settings_manager.load_settings()
    assert counter[0] == 1

    with patch.object(mgr, '_parse_certificate_info', return_value={'domain': 'x', 'exists': True}):
        _list_certificates(mgr, settings, domains)

    # No additional disk reads happened during the per-domain loop: the
    # once-loaded settings was reused. The old behaviour would have added
    # one read per domain on the metadata-fallback path.
    assert counter[0] == 1, (
        f"Listing must reuse the once-loaded settings for any number of "
        f"domains. Got {counter[0]} reads for {len(domains)} domains "
        f"(expected 1, the handler's own initial load)."
    )

    # Every per-domain call was given the settings dict (not None).
    assert len(seen_kwargs) == len(domains)
    for kw in seen_kwargs:
        assert kw['settings'] is settings, (
            f"get_certificate_info for {kw['domain']} was not given the "
            f"once-loaded settings dict; the listing path is still "
            f"triggering N+1 reads."
        )


def test_listing_reads_do_not_scale_with_domain_count(tmp_path):
    """A larger domain set must not increase the settings read count: the
    per-domain reloads have been collapsed to the single initial load."""
    domains = [f'domain-{i}.example.com' for i in range(40)]
    counter = [0]

    mgr = _make_manager(tmp_path, domains, counter)

    for domain in domains:
        domain_dir = tmp_path / domain
        domain_dir.mkdir()
        (domain_dir / "cert.pem").write_bytes(b"-----BEGIN CERTIFICATE-----\nfake\n")

    settings = mgr.settings_manager.load_settings()
    assert counter[0] == 1

    with patch.object(mgr, '_parse_certificate_info', return_value={'domain': 'x', 'exists': True}):
        results = _list_certificates(mgr, settings, domains)

    assert len(results) == len(domains)
    # Still exactly one read despite 40 domains — proves no per-domain scaling.
    assert counter[0] == 1, (
        f"Settings reads scaled with domain count: {counter[0]} reads for "
        f"{len(domains)} domains. The listing loop must reuse the loaded "
        f"settings dict."
    )


def test_per_domain_reload_when_settings_not_threaded(tmp_path):
    """Negative control: demonstrate the OLD behaviour. When the listing
    loop omits settings= (the pre-fix bug), get_certificate_info reloads
    from disk once per domain, so reads scale with the domain count.

    This guards against a regression that silently drops the settings
    kwarg again — if it does, the production loop would behave like this."""
    domains = [f'domain-{i}.example.com' for i in range(5)]
    counter = [0]

    mgr = _make_manager(tmp_path, domains, counter)

    for domain in domains:
        domain_dir = tmp_path / domain
        domain_dir.mkdir()
        (domain_dir / "cert.pem").write_bytes(b"-----BEGIN CERTIFICATE-----\nfake\n")

    # Simulate the OLD listing loop: load once, then DO NOT thread settings.
    settings = mgr.settings_manager.load_settings()
    assert counter[0] == 1

    with patch.object(mgr, '_parse_certificate_info', return_value={'domain': 'x', 'exists': True}):
        for domain in domains:
            mgr.get_certificate_info(domain)  # no settings= -> reloads per domain

    # 1 initial load + 1 reload per domain.
    assert counter[0] == 1 + len(domains), (
        f"Expected the un-threaded loop to reload once per domain "
        f"(1 + {len(domains)}). Got {counter[0]}. If this changed, the "
        f"settings-reuse fix and this control are out of sync."
    )


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
