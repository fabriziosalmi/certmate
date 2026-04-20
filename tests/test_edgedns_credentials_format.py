"""
Tests for Akamai Edge DNS credentials file format.

certbot-plugin-edgedns v0.1.0 uses certbot's standard dns_common
CredentialsConfiguration. That parser expects a *flat* INI (no section
header) with keys prefixed by the plugin namespace (``edgedns_``).

A previous CertMate version wrote a raw Akamai ``.edgerc`` file
(``[default]`` section + unprefixed keys) which configobj groups under
the section, so the plugin's top-level lookup found nothing and raised:

    Either an edgerc_path or individual edgegrid credentials are required
    when using the EdgeDNS API

Reported on issue #99 by @SpeeDFireCZE; this test pins the format so
the regression cannot recur.
"""
import pytest

from modules.core.utils import create_edgedns_config


@pytest.fixture
def edgedns_ini(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return create_edgedns_config(
        client_token='akab-CLIENTTOKEN-xxx',
        client_secret='secretsecretsecret==',
        access_token='akab-ACCESSTOKEN-yyy',
        host='akab-host-zzz.luna.akamaiapis.net',
    )


def test_no_section_header(edgedns_ini):
    """A `[section]` header would cause configobj to nest the keys, hiding
    them from the plugin's top-level lookup (issue #99 root cause)."""
    content = edgedns_ini.read_text()
    assert '[' not in content, (
        f"Edge DNS credentials INI must be flat (no section header) — "
        f"certbot's CredentialsConfiguration reads top-level keys only. "
        f"Got:\n{content}"
    )


def test_keys_use_edgedns_prefix(edgedns_ini):
    """certbot dns_common translates self.credentials.conf('client_token')
    into a lookup for the key 'edgedns_client_token'. Without the prefix
    every credential is silently treated as missing."""
    content = edgedns_ini.read_text()
    expected_keys = {
        'edgedns_client_token',
        'edgedns_client_secret',
        'edgedns_access_token',
        'edgedns_host',
    }
    for key in expected_keys:
        assert f'{key} = ' in content, (
            f"Missing required key '{key}' in edgedns INI:\n{content}"
        )


def test_no_unprefixed_keys(edgedns_ini):
    """Belt and braces: an unprefixed `client_token = ...` line written
    in addition to the prefixed one would not break the plugin but would
    leak the credential to anything else searching the file."""
    content = edgedns_ini.read_text()
    for unprefixed in ('client_token', 'client_secret', 'access_token', 'host'):
        # The string `<unprefixed> = ` must only appear as part of the
        # prefixed `edgedns_<unprefixed> = ` form.
        bare = f'\n{unprefixed} = '
        assert bare not in '\n' + content, (
            f"Unexpected unprefixed key '{unprefixed}' in edgedns INI:\n{content}"
        )


def test_file_permissions_are_0600(edgedns_ini):
    """Credentials file must not be world-readable."""
    assert (edgedns_ini.stat().st_mode & 0o777) == 0o600


def test_filename_is_edgedns_ini(edgedns_ini):
    """Path is referenced by certbot --edgedns-credentials; pinning the
    filename so we don't break that contract by accident."""
    assert edgedns_ini.name == 'edgedns.ini'


def test_certbot_credentials_parser_reads_all_four_keys(edgedns_ini):
    """End-to-end check: feed our INI to the same certbot machinery the
    plugin uses (dns_common.CredentialsConfiguration with the edgedns
    namespace mapper) and verify all four credentials surface.

    Reproduces the user-side path: when this returns the expected values,
    the plugin's _validate_credentials() will accept the file and proceed
    to call the Akamai API. When it returns None for any key, the plugin
    raises the "Either an edgerc_path or individual edgegrid credentials"
    error reported in issue #99.
    """
    pytest.importorskip('certbot.plugins.dns_common')
    from certbot.plugins.dns_common import CredentialsConfiguration

    # The plugin's auth namespace is "edgedns"; the mapper certbot installs
    # is roughly lambda var: f"edgedns_{var}".  Replicate that exact lookup.
    creds = CredentialsConfiguration(str(edgedns_ini), lambda v: f"edgedns_{v}")
    assert creds.conf('client_token') == 'akab-CLIENTTOKEN-xxx'
    assert creds.conf('client_secret') == 'secretsecretsecret=='
    assert creds.conf('access_token') == 'akab-ACCESSTOKEN-yyy'
    assert creds.conf('host') == 'akab-host-zzz.luna.akamaiapis.net'
