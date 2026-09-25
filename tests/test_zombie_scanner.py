import re
import socket
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests
from flask import Flask
from flask_restx import Api, Namespace

from modules.core.zombie import ZombieScanner
from modules.api.models import create_api_models
from modules.api.resources import create_api_resources


pytestmark = [pytest.mark.unit]


def _passthrough_decorator(_min_role):
    def deco(fn):
        return fn
    return deco


def _build_app(managers, *, data_dir=None):
    app = Flask(__name__)
    app.config['TESTING'] = True
    if data_dir is not None:
        app.config['DATA_DIR'] = str(data_dir)
    api = Api(app, prefix='/api')
    models = create_api_models(api)
    resources = create_api_resources(api, models, managers)

    ns = Namespace('certificates', description='certificates')
    api.add_namespace(ns)
    ns.add_resource(resources['ZombieScan'], '/zombies/scan')
    return app


@pytest.fixture
def managers(tmp_path):
    auth_manager = MagicMock()
    auth_manager.require_role = MagicMock(side_effect=_passthrough_decorator)
    auth_manager.domain_matches_scope = MagicMock(return_value=True)

    cert_manager = MagicMock()
    cert_manager.cert_dir = Path(tmp_path)
    cert_manager.get_certificate_info = MagicMock(side_effect=lambda domain, settings=None, use_cache=True: {
        'domain': domain,
        'san_domains': ['www.' + domain] if domain == 'example.com' else []
    })

    settings_manager = MagicMock()
    settings_manager.load_settings.return_value = {
        'domains': [
            'example.com',
            {'domain': 'zombie.com'}
        ]
    }

    return {
        'auth': auth_manager,
        'settings': settings_manager,
        'certificates': cert_manager,
        'file_ops': MagicMock(),
        'cache': MagicMock(),
        'dns': MagicMock(),
    }


def test_a_wildcard_is_not_probed_at_its_apex():
    """This test used to assert the defect (#924).

    It read:

        status = scanner.check_domain('*.wildcard.com')
        assert status == 'alive'
        mock_dns.assert_called_with('wildcard.com', None)

    — the apex being resolved, and the certificate called `alive` on that
    basis. A wildcard does not cover its own apex (RFC 6125), so the apex is
    frequently a name that resolves to nothing or serves nothing while every
    host the certificate protects is up: the scanner then said `zombie`, which
    is its word for "delete this". The assertion was about the mechanism —
    which name was passed to DNS — and the mechanism was the defect.
    """
    scanner = ZombieScanner()
    with patch('socket.getaddrinfo') as mock_dns, patch('requests.head') as mock_head:
        mock_dns.return_value = [None]
        mock_head.return_value = MagicMock()

        status = scanner.check_domain('*.wildcard.com')

        assert status == 'unverifiable'
        mock_dns.assert_not_called()
        mock_head.assert_not_called()


def test_a_wildcard_with_a_probe_host_is_checked_there():
    """The stand-in the operator configured, which is what makes the check
    possible at all — and the same field the deployment-status probe reads."""
    scanner = ZombieScanner()
    with patch('socket.getaddrinfo') as mock_dns, patch('requests.head') as mock_head:
        mock_dns.return_value = [None]
        mock_head.return_value = MagicMock()

        status = scanner.check_domain('*.wildcard.com',
                                      probe_host='www.wildcard.com')

        assert status == 'alive'
        mock_dns.assert_called_with('www.wildcard.com', None)


def test_a_wildcard_certificate_reads_deployment_host():
    """THE regression at the level the endpoint uses. `deployment_port` was
    honoured here and `deployment_host` was not read at all."""
    scanner = ZombieScanner()
    with patch('socket.getaddrinfo') as mock_dns, patch('requests.head') as mock_head:
        mock_dns.return_value = [None]
        mock_head.return_value = MagicMock()

        result = scanner.scan_certificate({
            'domain': '*.wildcard.com',
            'san_domains': [],
            'deployment_host': 'www.wildcard.com',
        })

        assert result['status'] == 'alive'
        mock_dns.assert_called_with('www.wildcard.com', None)


def test_a_wildcard_with_no_stand_in_says_why():
    """Not `alive`, not `zombie`, and it names the fix. An operator told
    "zombie" about a live estate has no way to tell that from a real finding.
    """
    scanner = ZombieScanner()
    with patch('socket.getaddrinfo') as mock_dns:
        result = scanner.scan_certificate({'domain': '*.wildcard.com',
                                           'san_domains': []})

        assert result['status'] == 'unverifiable'
        reason = result['reason']
        assert '*.wildcard.com' in reason, 'the reason does not name the certificate'
        assert 'deployment_host' in reason, 'the reason does not name the fix'

        # The suggested name is EXTRACTED and then checked for the property
        # that matters — that the wildcard actually covers it — rather than
        # compared as a substring. Two drafts of this searched the sentence
        # for a bare hostname and CodeQL flagged both
        # (py/incomplete-url-substring-sanitization); it is right about the
        # pattern, and it is right here for a concrete reason: `'wildcard.com'
        # in reason` passes on a message that suggests the APEX, which is the
        # one name a wildcard does not cover and the whole defect this test is
        # about.
        # The sentence reads '(for example www.wildcard.com)', so the
        # closing paren has to come off — the first run of this caught it
        # by failing on 'www.wildcard.com)'.
        suggested = re.search(r'for example ([^\s)]+)', reason)
        assert suggested, f'the reason suggests no name to use: {reason}'
        name = suggested.group(1)
        assert name.endswith('.wildcard.com'), name
        assert name.count('.') == 2, (
            f'{name} is not a name this wildcard covers — `*.` matches exactly '
            f'one label')
        mock_dns.assert_not_called()


def test_the_concrete_sans_of_a_wildcard_are_still_probed():
    """CONTROL. The stand-in replaces the wildcard, not the whole
    certificate: a concrete SAN is probe-able as itself and one live SAN is
    what makes the certificate alive."""
    scanner = ZombieScanner()
    with patch('socket.getaddrinfo') as mock_dns, patch('requests.head') as mock_head:
        mock_dns.return_value = [None]
        mock_head.return_value = MagicMock()

        result = scanner.scan_certificate({
            'domain': '*.wildcard.com',
            'san_domains': ['api.wildcard.com'],
        })

        assert result['status'] == 'alive'
        assert result['domains']['*.wildcard.com'] == 'unverifiable'
        assert result['domains']['api.wildcard.com'] == 'alive'


def test_a_scan_that_crashed_is_not_a_finding():
    """The same mistake one layer up: a scanner failure was reported as
    `zombie`, so the tool's own error became a statement about the estate."""
    scanner = ZombieScanner()
    with patch.object(ZombieScanner, 'scan_certificate',
                      side_effect=RuntimeError('boom')):
        res = scanner.scan_certificates([{'domain': 'whatever.com'}])

    assert res['summary']['zombie'] == 0
    assert res['summary']['unverifiable'] == 1
    assert res['results'][0]['status'] == 'unverifiable'


def test_scanner_classification():
    scanner = ZombieScanner()

    with patch('socket.getaddrinfo') as mock_dns, patch('requests.head') as mock_head:
        # Case 1: Alive (DNS OK, HTTP OK)
        mock_dns.return_value = [None]
        mock_head.return_value = MagicMock()
        assert scanner.check_domain('alive.com') == 'alive'

        # Case 2: Suspect (DNS OK, HTTP fails)
        mock_head.side_effect = requests.RequestException('connection refused')
        assert scanner.check_domain('suspect.com') == 'suspect'

        # Case 3: Zombie (DNS fails)
        mock_dns.side_effect = socket.gaierror('name not resolved')
        assert scanner.check_domain('zombie.com') == 'zombie'


def test_scan_certificates_aggregation():
    scanner = ZombieScanner()

    with patch.object(ZombieScanner, 'check_domain') as mock_check:
        def check_side_effect(d, port=None, probe_host=None):
            if 'alive' in d:
                return 'alive'
            if 'suspect' in d:
                return 'suspect'
            return 'zombie'
        mock_check.side_effect = check_side_effect

        certs = [
            {'domain': 'alive.com', 'san_domains': ['www.alive.com']},
            {'domain': 'suspect.com', 'san_domains': []},
            {'domain': 'zombie.com', 'san_domains': ['sub.zombie.com']}
        ]

        res = scanner.scan_certificates(certs)
        assert res['summary']['total'] == 3
        assert res['summary']['alive'] == 1
        assert res['summary']['suspect'] == 1
        assert res['summary']['zombie'] == 1
        assert res['summary']['unverifiable'] == 0


def test_zombie_scan_api_endpoint(managers, tmp_path):
    app = _build_app(managers, data_dir=tmp_path)
    
    with patch('socket.getaddrinfo') as mock_dns, patch('requests.head') as mock_head:
        mock_dns.return_value = [None]
        mock_head.return_value = MagicMock()

        # Create actual cert domain directory on disk
        (tmp_path / 'fs-only.com').mkdir()
        (tmp_path / 'fs-only.com' / 'cert.pem').touch()

        # Update get_certificate_info mock to handle fs-only.com
        managers['certificates'].get_certificate_info.side_effect = lambda domain, settings=None, use_cache=True: {
            'domain': domain,
            'san_domains': []
        }

        r = app.test_client().post('/api/certificates/zombies/scan')
        assert r.status_code == 200
        body = r.get_json()

        assert 'summary' in body
        assert 'results' in body
        assert body['summary']['total'] == 3
        assert body['summary']['alive'] == 3
