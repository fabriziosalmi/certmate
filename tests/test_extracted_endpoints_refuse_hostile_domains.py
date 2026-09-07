"""Every extracted endpoint that takes a domain refuses a hostile one.

Code scanning reports path expressions and log lines across the modules that
came out of `create_api_resources` (#667). All of them sit behind
`validate_domain_path`, which is the right answer — but "the validator handles
it" is exactly the claim that turns out to be wrong when it is wrong, and an
extraction is precisely the operation that can apply a guard on one path and
drop it on another.

So this drives the shapes through the endpoints rather than reasoning about
them, and counts the log records each one emits: a refusal that still logs the
raw value has not refused anything that matters.
"""
import io
import logging
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from flask import Flask, request as flask_request
from flask_restx import Api

from modules.api.resource_context import ApiContext

pytestmark = [pytest.mark.unit]

HOSTILE = [
    'evil\nCRITICAL forged log line',
    '../../etc/passwd',
    'example.com/../../secret',
    '\x00example.com',
    'example.com\x00.evil',
    'example.com\n',
]

# (module, factory, resource, method)
ENDPOINTS = [
    ('modules.api.resources_certificates', 'create_certificates_resources',
     'CertificateDetail', 'get'),
    ('modules.api.resources_certificates', 'create_certificates_resources',
     'CertificateDetail', 'delete'),
    ('modules.api.resources_deployment', 'create_deployment_resources',
     'CertificateDeploymentStatus', 'get'),
    ('modules.api.resources_deployment', 'create_deployment_resources',
     'CertificateRunDeploy', 'post'),
    ('modules.api.resources_lifecycle', 'create_lifecycle_resources',
     'CertificateAutoRenew', 'put'),
]

MODELS = {k: MagicMock() for k in (
    'certificate_model', 'create_cert_model', 'reissue_cert_model',
    'deployment_status_model', 'browser_deployment_reports_model')}


def _build(module_name, factory_name, capture):
    import importlib

    module = importlib.import_module(module_name)
    handler = logging.StreamHandler(capture)
    handler.setFormatter(logging.Formatter('%(levelname)s %(message)s'))
    module.logger.handlers = [handler]
    module.logger.propagate = False
    module.logger.setLevel(logging.DEBUG)

    root = Path(tempfile.mkdtemp())
    (root / 'certs').mkdir()
    file_ops = MagicMock()
    file_ops.cert_dir = root / 'certs'

    auth = MagicMock()
    auth.require_role = lambda role: (lambda fn: fn)
    auth.user_can_access_domain = lambda user, d: True
    ctx = ApiContext(
        auth=auth, settings=MagicMock(), certificates=MagicMock(),
        file_ops=file_ops, cache=MagicMock(), dns=MagicMock(),
        deployer=MagicMock(), audit=None, cert_service=MagicMock(),
        cert_executor=None, managers={})

    app = Flask(__name__)
    api = Api(app, prefix='/api')
    return app, getattr(module, factory_name)(api, MODELS, ctx)


@pytest.mark.parametrize('hostile', HOSTILE)
@pytest.mark.parametrize('module_name,factory_name,resource,method', ENDPOINTS)
def test_a_hostile_domain_is_refused_without_being_logged(
        module_name, factory_name, resource, method, hostile):
    capture = io.StringIO()
    app, resources = _build(module_name, factory_name, capture)

    with app.test_request_context('/', json={}):
        flask_request.current_user = {'username': 'admin', 'role': 'admin'}
        try:
            result = getattr(resources[resource](), method)(hostile)
        except Exception as exc:  # noqa: BLE001 - reported, not swallowed
            pytest.fail(f'{resource}.{method} raised {type(exc).__name__} for '
                        f'{hostile!r} instead of refusing it')

    status = result[1] if isinstance(result, tuple) and len(result) >= 2 \
        else 200
    assert status in (400, 403, 404), (
        f'{resource}.{method} answered {status} for {hostile!r}'
    )

    emitted = [line for line in capture.getvalue().split('\n') if line.strip()]
    assert not emitted, (
        f'{resource}.{method} refused {hostile!r} but logged it anyway: '
        f'{emitted}. Under the plain log format an unscrubbed value there can '
        f'write a record of its own.'
    )


@pytest.mark.parametrize('module_name,factory_name,resource,method', ENDPOINTS)
def test_a_real_domain_is_not_refused_by_the_same_check(
        module_name, factory_name, resource, method):
    """CONTROL: endpoints that refuse everything would satisfy the above.

    A legitimate domain must get past the validator. It may well fail later —
    there is no certificate on disk here — but it must not be turned away with
    the "invalid domain" answer.
    """
    capture = io.StringIO()
    app, resources = _build(module_name, factory_name, capture)

    with app.test_request_context('/', json={'enabled': True}):
        flask_request.current_user = {'username': 'admin', 'role': 'admin'}
        try:
            result = getattr(resources[resource](), method)('example.com')
        except Exception:  # noqa: BLE001 - a later failure is acceptable here
            return

    body = result[0] if isinstance(result, tuple) else result
    rendered = str(body).lower()
    assert 'invalid domain' not in rendered, (
        f'{resource}.{method} rejected a legitimate domain: {body}'
    )
