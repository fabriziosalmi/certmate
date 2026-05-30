import json
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


def test_scanner_wildcard_cleanup():
    scanner = ZombieScanner()
    with patch('socket.getaddrinfo') as mock_dns, patch('requests.head') as mock_head:
        mock_dns.return_value = [None]
        mock_head.return_value = MagicMock()

        status = scanner.check_domain('*.wildcard.com')
        assert status == 'alive'
        mock_dns.assert_called_with('wildcard.com', None)


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
        def check_side_effect(d):
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
