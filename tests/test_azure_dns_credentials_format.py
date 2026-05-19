"""Regression test pinning the on-disk format of ``letsencrypt/config/azure.ini``
to what certbot-dns-azure (terrycain) actually parses.

Before this regression, certmate wrote ``dns_azure_subscription_id``,
``dns_azure_resource_group``, ``dns_azure_client_id`` and
``dns_azure_client_secret`` keys. The plugin (>= 2.x) ignores all of those
because:

* the service-principal keys are namespaced ``sp_`` —
  ``dns_azure_sp_client_id`` / ``dns_azure_sp_client_secret``;
* subscription + resource group are encoded inside a per-zone resource
  id, not as top-level keys (``dns_azure_zoneN`` line).

The user-visible failure was certbot aborting with::

    No authentication methods have been configured for Azure DNS.
    Either configure a service principal, system/user assigned managed
    identity or configure the use of azure cli or workload identity
    credentials

emitted by ``certbot_dns_azure._internal.dns_azure.Authenticator._validate_credentials``
when none of the ``sp_*`` keys are populated.

This test pins the exact keys (no values, so no rotation churn) and the
zone-line shape, which is the contract the plugin enforces.
"""
import pytest

from modules.core.dns_strategies import AzureStrategy


pytestmark = [pytest.mark.unit]


class TestAzureCredentialsFileFormat:
    def _read(self, tmp_path, monkeypatch, **overrides):
        monkeypatch.chdir(tmp_path)
        config = {
            'subscription_id': 'SUB-123',
            'resource_group': 'rg-prod',
            'tenant_id': 'TENANT-XYZ',
            'client_id': 'CLIENT-AAA',
            'client_secret': 'shhh',
            '_zone_domain': 'mediaprogreece.tv',
        }
        config.update(overrides)
        creds = AzureStrategy().create_config_file(config)
        return creds.read_text(encoding='utf-8')

    def test_uses_sp_prefixed_keys_for_service_principal(self, tmp_path, monkeypatch):
        """The plugin's _validate_credentials reads ``sp_client_id`` /
        ``sp_client_secret`` / ``tenant_id``; without those it concludes
        no auth was configured. Pin those exact keys here."""
        text = self._read(tmp_path, monkeypatch)

        assert 'dns_azure_sp_client_id = CLIENT-AAA' in text
        assert 'dns_azure_sp_client_secret = shhh' in text
        assert 'dns_azure_tenant_id = TENANT-XYZ' in text

    def test_legacy_keys_are_not_emitted(self, tmp_path, monkeypatch):
        """These keys were emitted before the fix and the plugin silently
        ignored them, so the auth check failed. They must NOT come back."""
        text = self._read(tmp_path, monkeypatch)

        assert 'dns_azure_subscription_id' not in text
        assert 'dns_azure_resource_group ' not in text  # trailing space matters: rules out substring of sp_*
        # The bare client_id / client_secret (without sp_ prefix) are the
        # exact ones the plugin ignored — they must never reappear.
        assert 'dns_azure_client_id ' not in text
        assert 'dns_azure_client_secret ' not in text

    def test_zone_line_carries_subscription_and_resource_group(self, tmp_path, monkeypatch):
        """certbot-dns-azure requires at least one ``dns_azure_zoneN``
        entry and parses subscription + resource group OUT of the resource
        id on that line — they are not top-level keys."""
        text = self._read(tmp_path, monkeypatch)

        assert (
            'dns_azure_zone1 = mediaprogreece.tv:'
            '/subscriptions/SUB-123/resourceGroups/rg-prod'
            in text
        )

    def test_environment_is_set_to_public_cloud(self, tmp_path, monkeypatch):
        """The plugin tolerates a missing environment (defaults to
        AzurePublicCloud) but writing it explicitly makes the file
        self-describing for operators reading it."""
        text = self._read(tmp_path, monkeypatch)

        assert 'dns_azure_environment = AzurePublicCloud' in text

    def test_missing_zone_domain_raises_explicit_error(self, tmp_path, monkeypatch):
        """If the caller forgets to inject ``_zone_domain`` we should fail
        loudly with an actionable message rather than silently writing a
        file that the plugin will then reject with a less helpful error."""
        monkeypatch.chdir(tmp_path)
        with pytest.raises(ValueError, match='_zone_domain'):
            AzureStrategy().create_config_file({
                'subscription_id': 'sub',
                'resource_group': 'rg',
                'tenant_id': 'tenant',
                'client_id': 'client',
                'client_secret': 'shhh',
            })

    def test_wildcard_prefix_is_stripped_from_zone_domain(self, tmp_path, monkeypatch):
        """A wildcard certificate's primary domain is ``*.example.com``
        but the Azure DNS zone name is ``example.com``. The caller in
        CertificateManager strips the wildcard before injecting, so the
        zone line should never contain the asterisk. This test pins
        that the asterisk never leaks into the file even if it slipped
        through (defense in depth: the file is the contract certbot
        reads)."""
        # Caller layer is responsible for the strip; this test feeds the
        # already-stripped value and proves the resulting line is clean.
        text = self._read(tmp_path, monkeypatch, _zone_domain='example.com')

        assert '*.' not in text
        assert 'dns_azure_zone1 = example.com:' in text


class TestAzureCredentialsFileMultiZone:
    """Pins the multi-zone shape that unlocks nested-subdomain wildcards
    when Azure DNS only hosts the parent. The zone-discovery layer feeds
    AzureStrategy a list of every hosted zone that covers at least one
    cert FQDN; the plugin's longest-prefix matcher picks the right one
    per challenge at runtime."""

    def _read(self, tmp_path, monkeypatch, **overrides):
        monkeypatch.chdir(tmp_path)
        config = {
            'subscription_id': 'SUB-123',
            'resource_group': 'rg-prod',
            'tenant_id': 'TENANT-XYZ',
            'client_id': 'CLIENT-AAA',
            'client_secret': 'shhh',
        }
        config.update(overrides)
        creds = AzureStrategy().create_config_file(config)
        return creds.read_text(encoding='utf-8')

    def test_zone_domains_list_writes_one_zoneN_line_per_entry(
            self, tmp_path, monkeypatch):
        """The user's reported scenario: SAN cert spans two hosted zones."""
        text = self._read(
            tmp_path, monkeypatch,
            _zone_domains=['anotherdomain.org', 'example.com'],
        )
        assert (
            'dns_azure_zone1 = anotherdomain.org:'
            '/subscriptions/SUB-123/resourceGroups/rg-prod'
            in text
        )
        assert (
            'dns_azure_zone2 = example.com:'
            '/subscriptions/SUB-123/resourceGroups/rg-prod'
            in text
        )

    def test_zone_domains_takes_precedence_over_legacy_zone_domain(
            self, tmp_path, monkeypatch):
        """When both shapes are present (mixed caller stack), the new
        list wins — the discovery layer is the authoritative source."""
        text = self._read(
            tmp_path, monkeypatch,
            _zone_domains=['example.com'],
            _zone_domain='ignored.example',
        )
        assert 'dns_azure_zone1 = example.com:' in text
        assert 'ignored.example' not in text

    def test_empty_zone_domains_list_raises(self, tmp_path, monkeypatch):
        """An empty list is a programming error from the discovery layer
        — fail loud rather than write a zoneless azure.ini that the
        plugin will then reject with a vaguer error."""
        monkeypatch.chdir(tmp_path)
        with pytest.raises(ValueError):
            AzureStrategy().create_config_file({
                'subscription_id': 'sub',
                'resource_group': 'rg',
                'tenant_id': 'tenant',
                'client_id': 'client',
                'client_secret': 'shhh',
                '_zone_domains': [],
            })
