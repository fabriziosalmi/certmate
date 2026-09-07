"""The certbot command create_certificate builds is a contract (#666).

`create_certificate` is F(115), ~590 lines, and one `try` block of 517 of them.
It is the highest-risk single unit in the system and the one that handles
private keys. Decomposing it moves hundreds of lines through a hot path where
the inline comments memorialise past regressions — privkey copied last,
metadata clobbered, renewal omitting the CA bundle.

So this is written BEFORE anything moves, and it pins the thing the
decomposition must not change: for a matrix of inputs covering the branches
inside that try, the exact certbot argv.

The expectations are inline rather than in a golden file with a regenerate
flag. A refactor that changes the command then shows up as a diff a reviewer
reads, instead of a file someone re-blesses without looking.

Paths that legitimately vary are normalised: the certificate directory, the
per-config credentials hash, the per-run dns-alias temp config, the repo root,
and the interpreter. Everything else is asserted literally.
"""
import pathlib
import re
import tempfile
from unittest.mock import MagicMock

import pytest

from modules.core.certificates import CertificateManager
from modules.core.shell import MockShellExecutor

pytestmark = [pytest.mark.unit]

BASE_SETTINGS = {
    'default_ca': 'letsencrypt',
    'challenge_type': 'dns-01',
    'dns_propagation_seconds': {'cloudflare': 30, 'route53': 45},
    'default_key_type': 'ecdsa',
    'default_elliptic_curve': 'secp384r1',
}

# name -> (create_certificate kwargs, settings overrides, dns account config)
CASES = {
    'baseline dns-01 cloudflare': ({}, {}, None),
    'http-01': ({'challenge_type': 'http-01'}, {}, None),
    'with SANs': ({'san_domains': ['www.example.com', 'api.example.com']}, {}, None),
    'rsa 4096': ({'key_type': 'rsa', 'key_size': 4096}, {}, None),
    'ecdsa p-256': ({'key_type': 'ecdsa', 'elliptic_curve': 'secp256r1'}, {}, None),
    'staging flag': ({'staging': True}, {}, None),
    'ca_provider letsencrypt_staging': ({'ca_provider': 'letsencrypt_staging'}, {}, None),
    'replace': ({'replace': True}, {}, None),
    'route53': ({'dns_provider': 'route53'}, {},
                {'access_key_id': 'AKIA', 'secret_access_key': 's'}),
    'no propagation configured': ({'dns_provider': 'digitalocean'},
                                  {'dns_propagation_seconds': {}},
                                  {'api_token': 'do-token'}),
    'domain alias': ({'domain_alias': 'alias.example.net',
                      'alias_dns_provider': 'cloudflare'}, {}, None),
}

EXPECTED = {
    'baseline dns-01 cloudflare': [
        'certbot', 'certonly', '--non-interactive', '--agree-tos',
        '--email', 'a@b.com', '--cert-name', 'example.com', '--config-dir',
        '<CERTS>/example.com', '--work-dir', '<CERTS>/example.com/work',
        '--logs-dir', '<CERTS>/example.com/logs', '-d', 'example.com',
        '--key-type', 'ecdsa', '--elliptic-curve', 'secp384r1',
        '--authenticator', 'dns-cloudflare',
        '--dns-cloudflare-credentials',
        'letsencrypt/config/cloudflare-<HASH>.ini',
        '--dns-cloudflare-propagation-seconds', '30',
    ],
    'http-01': [
        'certbot', 'certonly', '--non-interactive', '--agree-tos',
        '--email', 'a@b.com', '--cert-name', 'example.com', '--config-dir',
        '<CERTS>/example.com', '--work-dir', '<CERTS>/example.com/work',
        '--logs-dir', '<CERTS>/example.com/logs', '-d', 'example.com',
        '--key-type', 'ecdsa', '--elliptic-curve', 'secp384r1',
        '--webroot', '-w', '<REPO>/data/acme-challenges',
    ],
    'with SANs': [
        'certbot', 'certonly', '--non-interactive', '--agree-tos',
        '--email', 'a@b.com', '--cert-name', 'example.com', '--config-dir',
        '<CERTS>/example.com', '--work-dir', '<CERTS>/example.com/work',
        '--logs-dir', '<CERTS>/example.com/logs', '-d', 'example.com',
        '-d', 'www.example.com', '-d', 'api.example.com', '--key-type',
        'ecdsa', '--elliptic-curve', 'secp384r1', '--authenticator',
        'dns-cloudflare', '--dns-cloudflare-credentials',
        'letsencrypt/config/cloudflare-<HASH>.ini',
        '--dns-cloudflare-propagation-seconds', '30',
    ],
    'rsa 4096': [
        'certbot', 'certonly', '--non-interactive', '--agree-tos',
        '--email', 'a@b.com', '--cert-name', 'example.com', '--config-dir',
        '<CERTS>/example.com', '--work-dir', '<CERTS>/example.com/work',
        '--logs-dir', '<CERTS>/example.com/logs', '-d', 'example.com',
        '--key-type', 'rsa', '--rsa-key-size', '4096', '--authenticator',
        'dns-cloudflare', '--dns-cloudflare-credentials',
        'letsencrypt/config/cloudflare-<HASH>.ini',
        '--dns-cloudflare-propagation-seconds', '30',
    ],
    'ecdsa p-256': [
        'certbot', 'certonly', '--non-interactive', '--agree-tos',
        '--email', 'a@b.com', '--cert-name', 'example.com', '--config-dir',
        '<CERTS>/example.com', '--work-dir', '<CERTS>/example.com/work',
        '--logs-dir', '<CERTS>/example.com/logs', '-d', 'example.com',
        '--key-type', 'ecdsa', '--elliptic-curve', 'secp256r1',
        '--authenticator', 'dns-cloudflare',
        '--dns-cloudflare-credentials',
        'letsencrypt/config/cloudflare-<HASH>.ini',
        '--dns-cloudflare-propagation-seconds', '30',
    ],
    'staging flag': [
        'certbot', 'certonly', '--non-interactive', '--agree-tos',
        '--email', 'a@b.com', '--cert-name', 'example.com', '--config-dir',
        '<CERTS>/example.com', '--work-dir', '<CERTS>/example.com/work',
        '--logs-dir', '<CERTS>/example.com/logs', '-d', 'example.com',
        '--staging', '--key-type', 'ecdsa', '--elliptic-curve',
        'secp384r1', '--authenticator', 'dns-cloudflare',
        '--dns-cloudflare-credentials',
        'letsencrypt/config/cloudflare-<HASH>.ini',
        '--dns-cloudflare-propagation-seconds', '30',
    ],
    'ca_provider letsencrypt_staging': [
        'certbot', 'certonly', '--non-interactive', '--agree-tos',
        '--email', 'a@b.com', '--cert-name', 'example.com', '--config-dir',
        '<CERTS>/example.com', '--work-dir', '<CERTS>/example.com/work',
        '--logs-dir', '<CERTS>/example.com/logs', '-d', 'example.com',
        '--staging', '--key-type', 'ecdsa', '--elliptic-curve',
        'secp384r1', '--authenticator', 'dns-cloudflare',
        '--dns-cloudflare-credentials',
        'letsencrypt/config/cloudflare-<HASH>.ini',
        '--dns-cloudflare-propagation-seconds', '30',
    ],
    'replace': [
        'certbot', 'certonly', '--non-interactive', '--agree-tos',
        '--email', 'a@b.com', '--cert-name', 'example.com', '--config-dir',
        '<CERTS>/example.com', '--work-dir', '<CERTS>/example.com/work',
        '--logs-dir', '<CERTS>/example.com/logs', '-d', 'example.com',
        '--renew-with-new-domains', '--force-renewal', '--authenticator',
        'dns-cloudflare', '--dns-cloudflare-credentials',
        'letsencrypt/config/cloudflare-<HASH>.ini',
        '--dns-cloudflare-propagation-seconds', '30',
    ],
    'route53': [
        'certbot', 'certonly', '--non-interactive', '--agree-tos',
        '--email', 'a@b.com', '--cert-name', 'example.com', '--config-dir',
        '<CERTS>/example.com', '--work-dir', '<CERTS>/example.com/work',
        '--logs-dir', '<CERTS>/example.com/logs', '-d', 'example.com',
        '--key-type', 'ecdsa', '--elliptic-curve', 'secp384r1',
        '--authenticator', 'dns-route53',
    ],
    'no propagation configured': [
        'certbot', 'certonly', '--non-interactive', '--agree-tos',
        '--email', 'a@b.com', '--cert-name', 'example.com', '--config-dir',
        '<CERTS>/example.com', '--work-dir', '<CERTS>/example.com/work',
        '--logs-dir', '<CERTS>/example.com/logs', '-d', 'example.com',
        '--key-type', 'ecdsa', '--elliptic-curve', 'secp384r1',
        '--authenticator', 'dns-digitalocean',
        '--dns-digitalocean-credentials',
        'letsencrypt/config/digitalocean-<HASH>.ini',
        '--dns-digitalocean-propagation-seconds', '120',
    ],
    'domain alias': [
        'certbot', 'certonly', '--non-interactive', '--agree-tos',
        '--email', 'a@b.com', '--cert-name', 'example.com', '--config-dir',
        '<CERTS>/example.com', '--work-dir', '<CERTS>/example.com/work',
        '--logs-dir', '<CERTS>/example.com/logs', '-d', 'example.com',
        '--key-type', 'ecdsa', '--elliptic-curve', 'secp384r1', '--manual',
        '--preferred-challenges', 'dns', '--manual-auth-hook', '<PY>',
        '<REPO>/modules/core/dns_alias_hook.py', '--config', '<ALIAS_CFG>',
        '--action', 'auth', '--manual-cleanup-hook', '<PY>',
        '<REPO>/modules/core/dns_alias_hook.py', '--config', '<ALIAS_CFG>',
        '--action', 'cleanup',
    ],
}


def _normalise(cmd, certs_dir, repo):
    out = []
    for token in cmd.split():
        token = token.replace(str(certs_dir), '<CERTS>')
        token = token.replace(repo, '<REPO>')
        # The credentials file name carries a hash of the account config.
        token = re.sub(r'([a-z0-9_-]+)-[0-9a-f]{8,}\.ini', r'\1-<HASH>.ini', token)
        # The dns-alias hook config is a per-run temp file; on macOS that lives
        # under /var/folders, not /tmp.
        token = re.sub(r'\S*certmate-dns-alias-\w+\.json', '<ALIAS_CFG>', token)
        token = re.sub(r'^(/private)?(/var/folders|/tmp)/\S*', '<TMP>', token)
        # The interpreter differs between a venv and a bare python.
        token = re.sub(r'^\S*/(python3?(\.\d+)?)$', '<PY>', token)
        out.append(token)
    return out


def _build_command(kwargs, settings_over, account_cfg):
    """Run create_certificate with a non-executing shell and return the argv."""
    certs = pathlib.Path(tempfile.mkdtemp())
    shell = MockShellExecutor()
    shell.set_next_result(returncode=0)

    settings = dict(BASE_SETTINGS)
    settings.update(settings_over)
    settings_manager = MagicMock()
    settings_manager.load_settings.return_value = settings
    settings_manager.get_domain_dns_provider.return_value = kwargs.get(
        'dns_provider', 'cloudflare')

    dns_manager = MagicMock()
    dns_manager.get_dns_provider_account_config.return_value = (
        account_cfg or {'api_token': 'cf-token'}, 'default')

    manager = CertificateManager(
        cert_dir=certs, settings_manager=settings_manager,
        dns_manager=dns_manager, storage_manager=None, ca_manager=None,
        shell_executor=shell)

    call = {'domain': 'example.com', 'email': 'a@b.com',
            'dns_provider': 'cloudflare'}
    call.update(kwargs)
    manager.create_certificate(**call)

    assert shell.commands_executed, 'no certbot command was built at all'
    repo = str(pathlib.Path(__file__).resolve().parent.parent)
    return _normalise(shell.commands_executed[0], certs, repo)


@pytest.mark.parametrize('name', list(CASES))
def test_the_certbot_command_is_unchanged(name):
    kwargs, settings_over, account_cfg = CASES[name]
    assert _build_command(kwargs, settings_over, account_cfg) == EXPECTED[name]


def test_every_case_builds_a_distinct_command():
    """CONTROL: a matrix whose cases all produce the same argv would pass
    while pinning one branch. Each case here exists because it exercises a
    different part of the 517-line try block, so each must differ from the
    baseline."""
    baseline = EXPECTED['baseline dns-01 cloudflare']
    same = [name for name, argv in EXPECTED.items()
            if name != 'baseline dns-01 cloudflare' and argv == baseline]
    assert not same, (
        f'these cases build the same command as the baseline, so they pin '
        f'nothing extra: {same}'
    )


def test_the_expectations_cover_the_branch_shapes_that_matter():
    """CONTROL on the matrix itself: adding a case is cheap, and a decomposition
    is only as safe as the branches the net covers. These are the flags whose
    presence or absence the refactor could silently drop."""
    flat = {token for argv in EXPECTED.values() for token in argv}
    for flag in ('--webroot', '--staging', '--force-renewal', '--key-type',
                 '--rsa-key-size', '--elliptic-curve', '--manual',
                 '--manual-auth-hook', '--manual-cleanup-hook',
                 '--authenticator', '--cert-name', '--config-dir'):
        assert flag in flat, f'no case in the matrix produces {flag}'
