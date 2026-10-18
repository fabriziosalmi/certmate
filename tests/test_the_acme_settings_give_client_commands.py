"""The commands Settings > ACME shows for a new EAB key carry what the clients need (#476, H4).

static/js/acme-snippets.js fills, for certbot, lego, acme.sh and cert-manager,
the directory URL, the EAB key identifier and its HMAC key, a name the key may
order. acme.sh is given no --days, which would replace the server's renewal
window. Run under node, as the other frontend unit tests are.
"""
import json
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

SCRIPT = Path(__file__).resolve().parent.parent / 'static/js/acme-snippets.js'
DIRECTORY = 'https://certmate.example.internal/acme/directory'


def _snippets(node, **overrides):
    given = {'directory': DIRECTORY, 'kid': 'team-a', 'hmac': 'hmac-key-value',
             'patterns': ['*.lab.internal'], 'validityDays': 45}
    given.update(overrides)
    program = (f"require({json.dumps(str(SCRIPT))});"
               f"process.stdout.write(JSON.stringify(globalThis.CertMateAcme.snippets({json.dumps(given)})))")
    return json.loads(subprocess.run([node, '-e', program], capture_output=True, text=True, check=True).stdout)


def test_every_client_gets_the_directory_the_key_and_a_name_it_may_order(node):
    commands = _snippets(node)
    assert set(commands) == {'certbot', 'lego', 'acmesh', 'certmanager'}
    for client, text in commands.items():
        assert DIRECTORY in text and 'team-a' in text and 'hmac-key-value' in text, client
    for client in ('certbot', 'lego', 'acmesh'):
        assert 'host.lab.internal' in commands[client], client


def test_each_command_uses_its_clients_own_flags(node):
    commands = _snippets(node)
    assert '--eab-kid team-a --eab-hmac-key hmac-key-value' in commands['certbot']
    assert commands['lego'].startswith('lego run --server ')
    assert '--eab --eab.kid team-a --eab.hmac hmac-key-value' in commands['lego']
    assert commands['acmesh'].startswith('acme.sh --register-account --server ')
    assert 'keyID: team-a' in commands['certmanager'] and 'secret: hmac-key-value' in commands['certmanager']


def test_an_exact_name_is_used_as_it_is(node):
    assert '-d nas.office.internal' in _snippets(node, patterns=['nas.office.internal'])['certbot']


@pytest.mark.parametrize('validity', [1, 7, 30, 44, 45, 90])
def test_acme_sh_is_left_to_the_servers_renewal_window(node, validity):
    """Given --days, acme.sh 3.1.5 renews by it and not by the window, which is
    also how a revoked certificate is renewed on the next run."""
    assert '--days' not in _snippets(node, validityDays=validity)['acmesh']
