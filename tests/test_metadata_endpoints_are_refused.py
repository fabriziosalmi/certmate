"""The admin-set HTTP clients refuse a cloud-metadata or link-local URL.

OIDC, Vault, Infisical and the DNS alias hook each talk to a URL an admin
configured. The deploy, webhook and probe paths already refuse the addresses
that are never a legitimate endpoint; these four did not. A link-local or
metadata address (169.254.169.254 and the cloud variants) is refused now, so a
mistyped or hostile URL cannot turn one of these into a read of the instance's
metadata service. An ordinary internal address is still allowed: an internal
IdP, Vault or DNS API lives on one.
"""
import pytest

from modules.core.pinned_https import UnsafeDestination, refuse_metadata_endpoint

pytestmark = [pytest.mark.unit]

ALLOWED_IPS = ['http://10.0.0.5:8200/', 'http://127.0.0.1:8200/', 'https://192.168.1.9/']


@pytest.mark.parametrize('url', ['http://169.254.169.254/latest/', 'http://[fd00:ec2::254]/',
                                 'http://100.100.100.200/', 'http://0.0.0.0/'])
def test_a_metadata_address_is_refused(url):
    with pytest.raises(UnsafeDestination):
        refuse_metadata_endpoint(url)


@pytest.mark.parametrize('url', ALLOWED_IPS)
def test_an_internal_address_is_allowed(url):
    refuse_metadata_endpoint(url)  # does not raise


def test_oidc_refuses_a_metadata_issuer():
    from modules.core.oidc import OIDCConfigError, OIDCManager
    with pytest.raises(OIDCConfigError, match=r'metadata|link-local'):
        OIDCManager._validate_config({'enabled': True, 'issuer_url': 'https://169.254.169.254/realms/x',
                                      'client_id': 'x'})


def test_vault_refuses_a_metadata_url():
    from modules.core.storage_backends import HashiCorpVaultBackend
    with pytest.raises(ValueError, match='vault_url'):
        HashiCorpVaultBackend({'vault_url': 'http://169.254.169.254/', 'vault_token': 'x' * 20})


def test_the_dns_alias_hook_refuses_a_metadata_api_url():
    from modules.core.dns_alias_hook import DNSAliasError, _json_request
    with pytest.raises(DNSAliasError, match=r'metadata|link-local'):
        _json_request('GET', 'http://169.254.169.254/', {})
