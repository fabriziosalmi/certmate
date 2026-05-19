"""
Tests for the per-provider DNS zone-discovery layer that enables
nested-subdomain wildcard certs against a parent hosted zone.

Three layers under test:

* ``find_covering_zone`` — pure longest-match-with-TLD-guard logic.
* ``AzureZoneDiscovery`` — Azure SDK adapter (with the SDK mocked at the
  ``DnsManagementClient`` boundary so no network call is made).
* ``resolve_zones_for_domains`` — orchestrator that calls the discovery
  hook once per cert and maps each FQDN to its longest covering zone,
  raising a user-actionable ``ValueError`` on misses.
"""
from unittest.mock import MagicMock, patch

import pytest

from modules.core.dns_zone_discovery import (
    AzureZoneDiscovery,
    _NullZoneDiscovery,
    get_zone_discovery,
    has_zone_discovery,
    resolve_zones_for_domains,
)
from modules.core.utils import find_covering_zone


pytestmark = [pytest.mark.unit]


# --- find_covering_zone (pure logic) -------------------------------------


class TestFindCoveringZone:
    def test_exact_match_returns_zone(self):
        assert find_covering_zone(
            'example.com', ['example.com']
        ) == 'example.com'

    def test_subdomain_matches_parent_zone(self):
        """The user's reported case: Azure hosts the parent, cert is for
        a nested subdomain."""
        assert find_covering_zone(
            'example2.example.com', ['example.com']
        ) == 'example.com'

    def test_wildcard_prefix_is_stripped_before_matching(self):
        """The ACME challenge for ``*.example2.example.com`` lives under
        ``example2.example.com``, so the matcher treats them identically.
        """
        assert find_covering_zone(
            '*.example2.example.com', ['example.com']
        ) == 'example.com'

    def test_longest_match_wins(self):
        """Subdomain-zone wins over parent-zone when both are configured.
        Mirrors the user's stated priority order: subdomain first, parent
        next, …"""
        zones = ['example.com', 'staging.example.com']
        assert find_covering_zone(
            'api.staging.example.com', zones
        ) == 'staging.example.com'

    def test_returns_none_when_nothing_covers(self):
        assert find_covering_zone(
            'foo.bar.unrelated.org', ['example.com']
        ) is None

    def test_case_insensitive(self):
        assert find_covering_zone(
            'API.Example.COM', ['Example.com']
        ) == 'example.com'

    def test_trailing_dots_are_normalised(self):
        assert find_covering_zone(
            'api.example.com.', ['example.com.']
        ) == 'example.com'

    def test_tld_guard_rejects_bare_top_level_domains(self):
        """A zone with fewer than 2 labels (a bare TLD) is never matched.
        This is defence-in-depth: discovery never surfaces TLDs, but a
        hand-edited config that included ``com`` must not cause a
        whole-TLD match."""
        assert find_covering_zone(
            'example.com', ['com']
        ) is None

    def test_empty_inputs_return_none(self):
        assert find_covering_zone('', ['example.com']) is None
        assert find_covering_zone('example.com', []) is None
        assert find_covering_zone(None, ['example.com']) is None  # type: ignore[arg-type]

    def test_zone_must_be_label_aligned_not_substring(self):
        """``foo.example.com`` must NOT match zone ``ample.com`` — the
        endswith check has to be on a dot boundary."""
        assert find_covering_zone(
            'foo.example.com', ['ample.com']
        ) is None


# --- AzureZoneDiscovery (Azure SDK adapter) -------------------------------


class TestAzureZoneDiscovery:
    def _account(self, **overrides):
        cfg = {
            'subscription_id': 'sub-123',
            'resource_group': 'rg-prod',
            'tenant_id': 'tenant-xyz',
            'client_id': 'client-aaa',
            'client_secret': 'shhh',
        }
        cfg.update(overrides)
        return cfg

    def test_list_zones_returns_sorted_lowercase_names(self):
        zone_a = MagicMock()
        zone_a.name = 'Example.com'
        zone_b = MagicMock()
        zone_b.name = 'another.org.'
        fake_client = MagicMock()
        fake_client.zones.list_by_resource_group.return_value = iter(
            [zone_b, zone_a]
        )

        with patch(
            'azure.identity.ClientSecretCredential'
        ) as mock_cred, patch(
            'azure.mgmt.dns.DnsManagementClient',
            return_value=fake_client,
        ) as mock_client_ctor:
            zones = AzureZoneDiscovery().list_zones(self._account())

        mock_cred.assert_called_once_with(
            tenant_id='tenant-xyz',
            client_id='client-aaa',
            client_secret='shhh',
        )
        mock_client_ctor.assert_called_once()
        _args, kwargs = mock_client_ctor.call_args
        assert kwargs['subscription_id'] == 'sub-123'
        fake_client.zones.list_by_resource_group.assert_called_once_with(
            resource_group_name='rg-prod'
        )
        # Normalised: lower-case, trailing dot stripped, sorted alpha.
        assert zones == ['another.org', 'example.com']

    def test_missing_credentials_raises_value_error(self):
        with pytest.raises(ValueError, match='missing credentials'):
            AzureZoneDiscovery().list_zones(self._account(client_secret=''))

    def test_sdk_failure_wraps_with_context(self):
        fake_client = MagicMock()
        fake_client.zones.list_by_resource_group.side_effect = RuntimeError(
            'auth failed (403)'
        )
        with patch('azure.identity.ClientSecretCredential'), patch(
            'azure.mgmt.dns.DnsManagementClient', return_value=fake_client
        ):
            with pytest.raises(RuntimeError, match='rg-prod'):
                AzureZoneDiscovery().list_zones(self._account())

    def test_skips_zones_with_falsy_names(self):
        """Defensive — Azure shouldn't return nameless zones, but the
        SDK is wide enough that a None name in a paged response must
        not crash discovery."""
        zone_named = MagicMock()
        zone_named.name = 'example.com'
        zone_nameless = MagicMock()
        zone_nameless.name = None
        fake_client = MagicMock()
        fake_client.zones.list_by_resource_group.return_value = iter(
            [zone_nameless, zone_named]
        )
        with patch('azure.identity.ClientSecretCredential'), patch(
            'azure.mgmt.dns.DnsManagementClient', return_value=fake_client
        ):
            zones = AzureZoneDiscovery().list_zones(self._account())
        assert zones == ['example.com']


# --- Registry --------------------------------------------------------------


def test_registry_has_azure():
    assert has_zone_discovery('azure')
    assert isinstance(get_zone_discovery('azure'), AzureZoneDiscovery)


def test_unregistered_provider_returns_noop():
    """Providers without a hook get a no-op discovery, preserving the
    legacy ``_zone_domain`` path for every certbot plugin that already
    self-discovers (cloudflare, route53, google, …)."""
    assert not has_zone_discovery('cloudflare')
    assert isinstance(get_zone_discovery('cloudflare'), _NullZoneDiscovery)
    assert get_zone_discovery('cloudflare').list_zones({}) == []


# --- resolve_zones_for_domains --------------------------------------------


class _StubDiscovery:
    """Test double that returns a canned zone list and counts calls."""

    def __init__(self, zones):
        self.zones = list(zones)
        self.call_count = 0

    def list_zones(self, account_config):  # noqa: ARG002
        self.call_count += 1
        return list(self.zones)


def _patched_resolve(monkeypatch, provider, zones):
    """Helper: swap the registry entry for *provider* with a stub."""
    from modules.core import dns_zone_discovery as mod
    stub = _StubDiscovery(zones)
    monkeypatch.setitem(mod._ZONE_DISCOVERY, provider, stub)
    return stub


class TestResolveZonesForDomains:
    def test_single_fqdn_matches_parent_zone(self, monkeypatch):
        _patched_resolve(monkeypatch, 'azure', ['example.com'])
        zones = resolve_zones_for_domains(
            'azure', {}, ['*.example2.example.com']
        )
        assert zones == ['example.com']

    def test_san_list_spanning_two_zones_writes_both(self, monkeypatch):
        _patched_resolve(
            monkeypatch, 'azure',
            ['example.com', 'anotherdomain.org'],
        )
        zones = resolve_zones_for_domains(
            'azure', {},
            ['app.example.com', '*.api.anotherdomain.org'],
        )
        # Longest-first ordering for stable azure.ini output.
        assert zones == ['anotherdomain.org', 'example.com']

    def test_longest_match_wins_for_each_fqdn(self, monkeypatch):
        """Mirrors the user's stated priority: subdomain-zone first,
        parent-zone next."""
        _patched_resolve(
            monkeypatch, 'azure',
            ['example.com', 'staging.example.com'],
        )
        zones = resolve_zones_for_domains(
            'azure', {}, ['api.staging.example.com'],
        )
        assert zones == ['staging.example.com']

    def test_unmatched_fqdn_raises_with_zone_list_in_message(self, monkeypatch):
        _patched_resolve(monkeypatch, 'azure', ['example.com'])
        with pytest.raises(ValueError) as exc:
            resolve_zones_for_domains(
                'azure', {}, ['foo.unrelated.org'],
            )
        msg = str(exc.value)
        assert 'foo.unrelated.org' in msg
        assert 'example.com' in msg

    def test_no_zones_at_all_raises_actionable_error(self, monkeypatch):
        _patched_resolve(monkeypatch, 'azure', [])
        with pytest.raises(ValueError, match='no hosted zones'):
            resolve_zones_for_domains(
                'azure', {}, ['example.com'],
            )

    def test_cache_short_circuits_repeated_discovery(self, monkeypatch):
        """A cert renewal batch calling resolve repeatedly with the same
        account_config must hit the discovery API at most once."""
        stub = _patched_resolve(monkeypatch, 'azure', ['example.com'])
        cache = {}
        account = {
            'tenant_id': 't', 'client_id': 'c',
            'subscription_id': 's', 'resource_group': 'r',
        }
        resolve_zones_for_domains('azure', account, ['a.example.com'], cache=cache)
        resolve_zones_for_domains('azure', account, ['b.example.com'], cache=cache)
        resolve_zones_for_domains('azure', account, ['c.example.com'], cache=cache)
        assert stub.call_count == 1
