"""GET /api/dns/providers says which DNS providers this instance can issue with.

The published image carries the certbot plugins of 20 providers out of 29
(docs/dns-providers.md, Availability). The setup wizard offered all of them
alike, and a provider whose plugin is missing was refused at the first
issuance, after the operator had created a token and typed it in. The wizard
now asks the instance, which asks certbot, and marks the providers it cannot
use. These tests hold the answer to the decision the issuance preflight takes,
to what the real certbot prints, and to "unknown" when certbot cannot be asked.
"""
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

from modules.core import dns_availability
from modules.core.certificates import CertificateManager
from modules.core.dns_providers import DNSManager

pytestmark = [pytest.mark.unit]

REPO = Path(__file__).resolve().parent.parent
WIZARD = (REPO / 'static' / 'js' / 'setup-wizard.js').read_text(encoding='utf-8')

# The DNS plugins `certbot plugins` listed in the published image on 2026-10-17.
IMAGE_PLUGINS = {
    'dns-arvancloud', 'dns-cloudflare', 'dns-desec', 'dns-digitalocean', 'dns-dnsmadeeasy',
    'dns-duckdns', 'dns-gandi', 'dns-godaddy', 'dns-google', 'dns-hetzner', 'dns-hetzner-cloud',
    'dns-infomaniak', 'dns-linode', 'dns-nsone', 'dns-ovh', 'dns-porkbun', 'dns-rfc2136',
    'dns-route53', 'dns-vultr', 'edgedns',
}


def _listing(plugins):
    """`certbot plugins` output, in the form certbot prints it."""
    rule = '- ' * 40
    return '\n' + rule.strip() + '\n' + '\n'.join(
        f'* {name}\nDescription: a plugin\nInterfaces: Authenticator, Plugin\n'
        f"Entry point: EntryPoint(name='{name}',\nvalue='x:Authenticator',\ngroup='certbot.plugins')\n"
        for name in sorted(plugins)) + rule.strip() + '\n'


class _Shell:
    def __init__(self, stdout='', returncode=0, raises=None):
        self.stdout, self.returncode, self.raises = stdout, returncode, raises
        self.calls = []

    def run(self, cmd, **kwargs):
        self.calls.append(cmd)
        if self.raises:
            raise self.raises
        return subprocess.CompletedProcess(cmd, self.returncode, self.stdout, '')


@pytest.fixture(autouse=True)
def _no_cached_answer():
    dns_availability.forget()
    yield
    dns_availability.forget()


def _preflight_refuses(provider, plugins):
    """Does the issuance preflight refuse *provider* when certbot has *plugins*?"""
    manager = SimpleNamespace(settings_manager=None)
    with mock.patch('modules.core.certificates.check_certbot_plugin_installed',
                    side_effect=lambda plugin: plugin in plugins):
        try:
            CertificateManager._resolve_challenge_and_dns(
                manager, mock.MagicMock(), 'example.com', 'dns-01', provider,
                {'credential': 'set'}, None, None, None)
        except RuntimeError as error:
            assert 'is not installed' in str(error), error
            return True
    return False


@pytest.mark.parametrize('installed', [IMAGE_PLUGINS, set()], ids=['the-image', 'no-plugin'])
def test_the_answer_is_the_preflights_decision(installed):
    answer = {p['provider']: p['available'] for p in dns_availability.availability(installed)}
    assert set(answer) == set(DNSManager.SUPPORTED_PROVIDERS)
    differ = {provider: available for provider, available in answer.items()
              if available == _preflight_refuses(provider, installed)}
    assert not differ, f'the API and the issuance preflight disagree on {differ}'


def test_the_image_issues_with_24_of_29():
    """The published image: 20 plugins, plus the four providers CertMate drives itself and ACME-DNS."""
    answer = dns_availability.availability(IMAGE_PLUGINS)
    missing = sorted(p['provider'] for p in answer if not p['available'])
    assert missing == ['dynudns', 'he-ddns', 'namecheap', 'powerdns', 'scaleway']
    assert {p['provider'] for p in answer if p['plugin'] is None} == {
        'acme-dns', 'azure', 'custom-script', 'solidserver'}


def test_the_parser_reads_what_certbot_prints():
    shell = _Shell(_listing(IMAGE_PLUGINS | {'standalone', 'webroot'}))
    assert dns_availability.installed_plugins(shell) == IMAGE_PLUGINS | {'standalone', 'webroot'}
    assert shell.calls == [['certbot', 'plugins']]


def test_the_parser_reads_the_real_certbot():
    """The format above is a copy; this is the original, when certbot is installed beside the tests."""
    certbot = Path(sys.executable).parent / 'certbot'
    if not certbot.exists():
        pytest.skip('no certbot beside this interpreter')
    result = subprocess.run([str(certbot), 'plugins'], capture_output=True, text=True, timeout=60)
    shell = _Shell(result.stdout, result.returncode)
    found = dns_availability.installed_plugins(shell)
    assert found is not None and {'dns-cloudflare', 'dns-route53', 'standalone', 'webroot'} <= found


@pytest.mark.parametrize('shell', [
    None,
    _Shell(raises=FileNotFoundError('certbot')),
    _Shell(raises=subprocess.TimeoutExpired(['certbot', 'plugins'], 30)),
    _Shell('Traceback (most recent call last):', returncode=1),
], ids=['no-executor', 'not-installed', 'timed-out', 'failed'])
def test_a_certbot_that_cannot_be_asked_is_unknown_not_missing(shell):
    answer = dns_availability.current(shell)
    assert answer['certbot_answered'] is False
    for entry in answer['providers']:
        assert entry['available'] is (True if entry['plugin'] is None else None), entry


def test_the_answer_is_kept_five_minutes():
    clock = [1000.0]
    shell = _Shell(_listing({'dns-cloudflare'}))
    first = dns_availability.current(shell, now=lambda: clock[0])
    clock[0] += dns_availability.CACHE_SECONDS - 1
    assert dns_availability.current(shell, now=lambda: clock[0]) is first
    assert len(shell.calls) == 1
    clock[0] += 1
    dns_availability.current(shell, now=lambda: clock[0])
    assert len(shell.calls) == 2


def test_the_route_asks_the_applications_certbot():
    from tests import contract_support as support
    app, token = support.build_app()
    answered = _listing({'dns-cloudflare'})

    def run(self, cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, answered, '')

    with mock.patch('modules.core.shell.ShellExecutor.run', run):
        response = app.test_client().get(
            '/api/dns/providers', headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200, response.get_data(as_text=True)
    body = response.get_json()
    assert body['certbot_answered'] is True and body['checked_at'].endswith('Z')
    answer = {p['provider']: p for p in body['providers']}
    assert answer['cloudflare'] == {'provider': 'cloudflare', 'plugin': 'dns-cloudflare', 'available': True}
    assert answer['route53']['available'] is False
    assert answer['azure'] == {'provider': 'azure', 'plugin': None, 'available': True}


def test_the_wizard_asks_and_keeps_the_fixed_notices_when_it_cannot():
    assert "fetch('/api/dns/providers'" in WIZARD
    fallback = WIZARD[WIZARD.index('function availabilityNotice('):]
    fallback = fallback[:fallback.index('\n    }\n')]
    assert "if (!known) return AVAILABILITY[provider] || '';" in fallback
