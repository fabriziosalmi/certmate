"""Change-detector for the certbot credentials-file key contract.

CertMate writes the INI credentials file each certbot DNS plugin reads. The
key names are an unversioned, undocumented contract: certbot derives them as
``<entry_point_name with '-' -> '_'>_<credential var>`` (see
``certbot.plugins.common.dest_namespace`` + ``DNSAuthenticator.dest``), and a
drifted key fails only at issuance time with the plugin's "Property not
found" error — or, worse, with a baffling plugin-selection failure when the
entry-point name itself is wrong. This is exactly how the porkbun bug
(#364: ``dns_porkbun_api_key`` instead of ``dns_porkbun_key``) shipped.

Every expected value below is pinned against the plugin source:

* plugins installed in the venv were read directly
  (``certbot_dns_<x>/...``, the ``_configure_credentials`` /
  ``_add_provider_option`` calls);
* plugins NOT importable here (he-ddns 0.1.0, dynudns 0.0.6, scaleway 0.0.7,
  desec 1.3.2, powerdns 0.2.1, infomaniak, namecheap 1.0.0) were pinned from
  their sdist source / README, as noted per entry.

This is the guard for the future certbot-5.x migration: bump a plugin, and a
changed credential contract fails HERE instead of in production.
"""
from importlib.metadata import entry_points

import pytest

from modules.core.dns_strategies import DNSStrategyFactory
from modules.core.utils import (
    _MULTI_PROVIDER_TEMPLATE_MAP,
    create_arvancloud_config,
    create_cloudflare_config,
    create_digitalocean_config,
    create_duckdns_config,
    create_edgedns_config,
    create_gandi_config,
    create_infomaniak_config,
    create_linode_config,
    create_namecheap_config,
    create_ovh_config,
    create_powerdns_config,
)
from modules.core import utils as utils_module


pytestmark = [pytest.mark.unit]


# ---------------------------------------------------------------------------
# Generic multi-providers (_MULTI_PROVIDER_TEMPLATE_MAP)
# ---------------------------------------------------------------------------

# provider -> (certbot entry-point name, {expected ini key, ...}).
# Provenance is cited per entry; "venv" means read from the installed plugin
# in this repo's virtualenv, "sdist" from the downloaded source distribution.
EXPECTED_MULTI_PROVIDER_CONTRACT = {
    # venv certbot-dns-vultr 1.1.0: _configure_credentials var 'key'.
    'vultr': ('dns-vultr', {'dns_vultr_key'}),
    # venv certbot-dns-dnsmadeeasy 2.10.0 (lexicon): options 'api-key',
    # 'secret-key'.
    'dnsmadeeasy': ('dns-dnsmadeeasy',
                    {'dns_dnsmadeeasy_api_key', 'dns_dnsmadeeasy_secret_key'}),
    # venv certbot-dns-nsone 2.10.0 (lexicon): option 'api-key'.
    'nsone': ('dns-nsone', {'dns_nsone_api_key'}),
    # venv certbot-dns-rfc2136 2.10.0: required 'server', 'name', 'secret';
    # 'algorithm' is a documented optional.
    'rfc2136': ('dns-rfc2136',
                {'dns_rfc2136_server', 'dns_rfc2136_name',
                 'dns_rfc2136_secret', 'dns_rfc2136_algorithm'}),
    # venv certbot-dns-hetzner 3.0.0: var 'api_token'.
    'hetzner': ('dns-hetzner', {'dns_hetzner_api_token'}),
    # venv certbot-dns-hetzner-cloud 1.0.5: var 'api_token'.
    'hetzner-cloud': ('dns-hetzner-cloud', {'dns_hetzner_cloud_api_token'}),
    # venv certbot-dns-porkbun 0.11.0: vars 'key', 'secret' (the #364 bug:
    # CertMate wrote dns_porkbun_api_key / dns_porkbun_secret_key).
    'porkbun': ('dns-porkbun', {'dns_porkbun_key', 'dns_porkbun_secret'}),
    # venv certbot-dns-godaddy 2.8.0 (lexicon): options 'key', 'secret'.
    'godaddy': ('dns-godaddy', {'dns_godaddy_key', 'dns_godaddy_secret'}),
    # sdist certbot-dns-he-ddns 0.1.0: only 'password' is required
    # (dns_he_ddns.py). The username line CertMate also writes is not read
    # by the plugin; certbot ignores unknown ini keys, so it is harmless,
    # but it must never REPLACE the required password key.
    'he-ddns': ('dns-he-ddns',
                {'dns_he_ddns_username', 'dns_he_ddns_password'}),
    # sdist certbot-dns-dynudns 0.0.6: entry point 'dns-dynu' (NOT
    # dns-dynudns) with var 'auth-token' -> dns_dynu_auth_token.
    'dynudns': ('dns-dynu', {'dns_dynu_auth_token'}),
    # sdist certbot-dns-desec 1.3.2: var 'token'.
    'desec': ('dns-desec', {'dns_desec_token'}),
    # sdist certbot-dns-scaleway 0.0.7: var 'application_token'.
    'scaleway': ('dns-scaleway', {'dns_scaleway_application_token'}),
}


def test_contract_covers_every_template_provider():
    """Adding a provider to the template map without extending this contract
    must fail loudly, or the change-detector silently stops detecting."""
    assert set(EXPECTED_MULTI_PROVIDER_CONTRACT) == set(_MULTI_PROVIDER_TEMPLATE_MAP)


@pytest.mark.parametrize('provider', sorted(EXPECTED_MULTI_PROVIDER_CONTRACT))
def test_multi_provider_ini_keys_match_plugin_contract(provider):
    _, expected_keys = EXPECTED_MULTI_PROVIDER_CONTRACT[provider]
    generated_keys = set(_MULTI_PROVIDER_TEMPLATE_MAP[provider])
    assert generated_keys == expected_keys, (
        f"{provider}: generated ini keys {sorted(generated_keys)} do not match "
        f"the certbot plugin's credential keys {sorted(expected_keys)} — the "
        f"plugin would fail at issuance with 'Property not found'"
    )


@pytest.mark.parametrize('provider', sorted(EXPECTED_MULTI_PROVIDER_CONTRACT))
def test_strategy_plugin_name_matches_entry_point(provider):
    """--authenticator, --<name>-credentials and the ini key prefix all key on
    the plugin's ENTRY-POINT name; a mismatch selects nothing (the dynudns
    bug: the plugin registers 'dns-dynu', not 'dns-dynudns')."""
    expected_plugin, _ = EXPECTED_MULTI_PROVIDER_CONTRACT[provider]
    strategy = DNSStrategyFactory.get_strategy(provider)
    assert strategy.plugin_name == expected_plugin


@pytest.mark.parametrize('provider', sorted(EXPECTED_MULTI_PROVIDER_CONTRACT))
def test_ini_key_prefix_matches_certbot_dest_namespace(provider):
    """certbot resolves ini keys as dest_namespace(entry_point_name) + var
    ('-' -> '_'), so every generated key must carry that exact prefix."""
    expected_plugin, _ = EXPECTED_MULTI_PROVIDER_CONTRACT[provider]
    prefix = expected_plugin.replace('-', '_') + '_'
    for ini_key in _MULTI_PROVIDER_TEMPLATE_MAP[provider]:
        assert ini_key.startswith(prefix), (
            f"{provider}: ini key '{ini_key}' does not start with the "
            f"dest namespace '{prefix}' of plugin '{expected_plugin}'"
        )


def _installed_certbot_plugins():
    return {ep.name for ep in entry_points(group='certbot.plugins')}


@pytest.mark.parametrize('provider', sorted(EXPECTED_MULTI_PROVIDER_CONTRACT))
def test_expected_entry_point_exists_when_plugin_installed(provider):
    """For plugins present in this venv, the expected entry-point name must be
    REAL (registered), not just internally consistent. Skips plugins that are
    documented as install-separately."""
    expected_plugin, _ = EXPECTED_MULTI_PROVIDER_CONTRACT[provider]
    installed = _installed_certbot_plugins()
    if expected_plugin not in installed:
        pytest.skip(f"plugin {expected_plugin} not installed in this venv")
    assert expected_plugin in installed


# ---------------------------------------------------------------------------
# Dedicated create_*_config creators (single-provider ini writers)
# ---------------------------------------------------------------------------

def _captured_ini_keys(monkeypatch, creator, *args):
    """Run a create_*_config creator with _create_config_file stubbed out and
    return the set of ini keys it would have written."""
    captured = {}

    def _fake_create(plugin_name, content):
        captured['content'] = content
        return f'/dev/null/{plugin_name}.ini'

    monkeypatch.setattr(utils_module, '_create_config_file', _fake_create)
    creator(*args)
    return {
        line.split('=')[0].strip()
        for line in captured['content'].splitlines() if '=' in line
    }


# creator -> (args, expected ini keys). Provenance per entry.
DEDICATED_CREATOR_CONTRACT = {
    # venv certbot-dns-cloudflare 2.10.0: 'api-token' (token auth path).
    create_cloudflare_config: (('tok',), {'dns_cloudflare_api_token'}),
    # venv certbot-dns-digitalocean 2.10.0: var 'token'.
    create_digitalocean_config: (('tok',), {'dns_digitalocean_token'}),
    # venv certbot-dns-linode 2.10.0: required 'key'; 'version' is a
    # documented optional the plugin reads to select API v3/v4.
    create_linode_config: (('k',), {'dns_linode_key', 'dns_linode_version'}),
    # venv certbot-dns-gandi 1.6.1: 'token' (personal access token).
    create_gandi_config: (('tok',), {'dns_gandi_token'}),
    # venv certbot-dns-ovh 2.10.0 (lexicon): endpoint / application-key /
    # application-secret / consumer-key.
    create_ovh_config: (('e', 'ak', 'as', 'ck'),
                        {'dns_ovh_endpoint', 'dns_ovh_application_key',
                         'dns_ovh_application_secret', 'dns_ovh_consumer_key'}),
    # venv certbot-dns-duckdns 1.8.0: var 'token'.
    create_duckdns_config: (('tok',), {'dns_duckdns_token'}),
    # venv certbot-dns-arvancloud 0.1.0: var 'api_token' (was drifted:
    # CertMate wrote dns_arvancloud_api_key, which the plugin never reads).
    create_arvancloud_config: (('tok',), {'dns_arvancloud_api_token'}),
    # venv certbot-plugin-edgedns 0.1.0: entry point 'edgedns' (no dns-
    # prefix), keys client_token / client_secret / access_token / host.
    create_edgedns_config: (('ct', 'cs', 'at', 'h'),
                            {'edgedns_client_token', 'edgedns_client_secret',
                             'edgedns_access_token', 'edgedns_host'}),
    # certbot-dns-powerdns 0.2.1 (NOT importable here — pinned from its
    # README): dns_powerdns_api_url / dns_powerdns_api_key.
    create_powerdns_config: (('https://pdns', 'k'),
                             {'dns_powerdns_api_url', 'dns_powerdns_api_key'}),
    # certbot-dns-infomaniak (NOT importable here — pinned from its README):
    # dns_infomaniak_token.
    create_infomaniak_config: (('tok',), {'dns_infomaniak_token'}),
    # certbot-dns-namecheap 1.0.0 (alpha; NOT importable on Python 3.12 —
    # pinned from its README): dns_namecheap_username / dns_namecheap_api_key.
    create_namecheap_config: (('u', 'k'),
                              {'dns_namecheap_username', 'dns_namecheap_api_key'}),
}


@pytest.mark.parametrize(
    'creator', sorted(DEDICATED_CREATOR_CONTRACT, key=lambda f: f.__name__))
def test_dedicated_creator_ini_keys_match_plugin_contract(creator, monkeypatch):
    args, expected_keys = DEDICATED_CREATOR_CONTRACT[creator]
    generated = _captured_ini_keys(monkeypatch, creator, *args)
    assert generated == expected_keys, (
        f"{creator.__name__}: writes {sorted(generated)}, plugin expects "
        f"{sorted(expected_keys)}"
    )
