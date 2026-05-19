"""
Integration test for ``CertificateManager._dns_config_for_strategy`` on
the Azure code path.

Pins the wiring that turns ``"Azure only hosts the parent zone"`` from a
hard failure into a working cert request:

1. The discovery hook is consulted (stubbed here — no Azure SDK calls).
2. Each cert FQDN (primary + SANs) is resolved against the discovered
   zones via ``find_covering_zone``.
3. A deduplicated, longest-first ``_zone_domains`` list is injected into
   the strategy config; the legacy ``_zone_domain`` string is NOT used
   when the discovery hook is registered.
4. An uncovered FQDN raises a ``ValueError`` with a message naming both
   the offending FQDN and the configured zones — the cert-issuance
   layer surfaces this to the API caller.

The discovery layer itself is exercised in test_dns_zone_discovery.py;
this test focuses on the bridge inside CertificateManager.
"""
import pytest

from modules.core.certificates import CertificateManager
from modules.core import dns_zone_discovery as discovery_mod


pytestmark = [pytest.mark.unit]


class _StubDiscovery:
    def __init__(self, zones):
        self.zones = list(zones)
        self.call_count = 0
        self.last_account = None

    def list_zones(self, account_config):
        self.call_count += 1
        self.last_account = account_config
        return list(self.zones)


@pytest.fixture
def azure_account():
    return {
        'subscription_id': 'SUB',
        'resource_group': 'rg',
        'tenant_id': 't',
        'client_id': 'c',
        'client_secret': 's',
    }


def _swap_azure_discovery(monkeypatch, zones):
    stub = _StubDiscovery(zones)
    monkeypatch.setitem(discovery_mod._ZONE_DISCOVERY, 'azure', stub)
    return stub


class TestAzureDnsConfigForStrategy:
    def test_primary_wildcard_matches_parent_zone(
            self, monkeypatch, azure_account):
        """The user's reported scenario: Azure only hosts ``example.com``,
        cert asks for ``*.example2.example.com``. Result: a single
        ``_zone_domains=['example.com']`` injection."""
        _swap_azure_discovery(monkeypatch, ['example.com'])
        out = CertificateManager._dns_config_for_strategy(
            'azure', azure_account, '*.example2.example.com',
        )
        assert out['_zone_domains'] == ['example.com']
        # Legacy single-zone field is not used on the discovery path.
        assert '_zone_domain' not in out

    def test_san_spanning_two_zones_produces_both_in_order(
            self, monkeypatch, azure_account):
        _swap_azure_discovery(
            monkeypatch, ['example.com', 'anotherdomain.org'],
        )
        out = CertificateManager._dns_config_for_strategy(
            'azure', azure_account, 'app.example.com',
            san_domains=['*.api.anotherdomain.org'],
        )
        # Longest-first dedup so the resulting azure.ini ordering is
        # stable and the plugin's longest-prefix match is unambiguous.
        assert out['_zone_domains'] == ['anotherdomain.org', 'example.com']

    def test_subdomain_zone_wins_over_parent(
            self, monkeypatch, azure_account):
        """User-stated priority: subdomain zone first, parent next."""
        _swap_azure_discovery(
            monkeypatch, ['example.com', 'staging.example.com'],
        )
        out = CertificateManager._dns_config_for_strategy(
            'azure', azure_account, 'api.staging.example.com',
        )
        assert out['_zone_domains'] == ['staging.example.com']

    def test_uncovered_fqdn_raises_with_actionable_message(
            self, monkeypatch, azure_account):
        _swap_azure_discovery(monkeypatch, ['example.com'])
        with pytest.raises(ValueError) as exc:
            CertificateManager._dns_config_for_strategy(
                'azure', azure_account, 'foo.unrelated.org',
            )
        msg = str(exc.value)
        assert 'foo.unrelated.org' in msg
        assert 'example.com' in msg

    def test_one_san_covered_one_not_still_raises(
            self, monkeypatch, azure_account):
        """Partial coverage is not enough: if any FQDN in the cert is
        unreachable from the configured zones, fail-early."""
        _swap_azure_discovery(monkeypatch, ['example.com'])
        with pytest.raises(ValueError) as exc:
            CertificateManager._dns_config_for_strategy(
                'azure', azure_account, 'example.com',
                san_domains=['*.unrelated.org'],
            )
        assert '*.unrelated.org' in str(exc.value)

    def test_non_azure_provider_bypasses_discovery_entirely(self):
        """Cloudflare et al. self-discover inside their certbot plugin —
        CertMate must NOT touch their dns_config."""
        out = CertificateManager._dns_config_for_strategy(
            'cloudflare', {'api_token': 'foo'}, '*.example.com',
        )
        assert out == {'api_token': 'foo'}
