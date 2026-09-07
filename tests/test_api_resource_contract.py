"""The set of API resource classes is a contract, pinned before it is moved.

`create_api_resources` is a single 3,700-line function holding 41 classes as
closures, which is why no route can be imported or tested without constructing
the whole manager graph — and therefore why the HTTP layer is the least covered
code in the project (#662, #667).

Breaking it up moves thousands of lines. This exists so that the move is
verifiable rather than hopeful: whatever the internal arrangement, the factory
must keep returning exactly the same resource names, and every one must still
be a usable Flask-RESTX resource. Written before the first line is moved, so
the net is in place during the work rather than after it.
"""
import inspect

import pytest
from flask import Flask
from flask_restx import Api, Resource

from modules.api.models import create_api_models
from modules.api.resources import create_api_resources

pytestmark = [pytest.mark.unit]

# The names the factory returned before any decomposition. Adding a resource is
# a deliberate change to this list; losing one silently is the failure this
# guards against.
EXPECTED_RESOURCES = {
    'HealthCheck', 'MetricsList', 'DiagnosticsSnapshot',
    'Settings', 'DNSProviders', 'CAProviderTest',
    'CacheStats', 'CacheClear',
    'CertificateList', 'CreateCertificate', 'CertificateDetail',
    'CertificateDeploymentStatus', 'CertificateDeploymentBrowserReports',
    'DownloadCertificate', 'DownloadCertificateFile',
    'RenewCertificate', 'CertificateReissue',
    'CertificateJob', 'CertificateJobs', 'CertificateAutoRenew',
    'CertificateRunDeploy', 'CheckDNSAlias', 'CertificateDNSAliasCheck',
    'InventoryList', 'InventoryConfig', 'InventoryScan',
    'InventoryCryptoReport', 'InventoryAdopt', 'ZombieScan',
    'BackupList', 'BackupCreate', 'BackupDownload', 'BackupRestore',
    'BackupDelete',
    'BackupUpload',
}


class _Managers(dict):
    """Supplies a stub for any manager the factory reaches for."""

    def __missing__(self, key):
        from unittest.mock import MagicMock
        value = MagicMock()
        self[key] = value
        return value


@pytest.fixture(scope='module')
def resources():
    from unittest.mock import MagicMock

    app = Flask(__name__)
    app.config['TESTING'] = True
    api = Api(app, prefix='/api')

    auth_manager = MagicMock()
    auth_manager.require_role = lambda role: (lambda fn: fn)

    return create_api_resources(api, create_api_models(api),
                                _Managers(auth=auth_manager))


def test_the_factory_returns_exactly_the_expected_resources(resources):
    returned = set(resources)
    missing = sorted(EXPECTED_RESOURCES - returned)
    added = sorted(returned - EXPECTED_RESOURCES)
    assert not missing, (
        f'these resources are no longer returned, so their routes cannot be '
        f'registered and the endpoints disappear silently: {missing}'
    )
    assert not added, (
        f'these resources are new; if that is intended, add them to '
        f'EXPECTED_RESOURCES deliberately: {added}'
    )


def test_every_returned_resource_is_a_usable_flask_restx_resource(resources):
    """CONTROL: the names alone are not the contract.

    A decomposition that returned the right keys pointing at something that is
    not a Resource would satisfy a name-only check and still break every route.
    """
    wrong = sorted(
        name for name, cls in resources.items()
        if not (inspect.isclass(cls) and issubclass(cls, Resource))
    )
    assert not wrong, f'not Flask-RESTX Resource subclasses: {wrong}'


def test_every_resource_exposes_at_least_one_http_verb(resources):
    """A Resource with no verb registers a route that answers 405 to everything.

    Moving code between modules is exactly how a method ends up outside the
    class it belonged to.
    """
    verbs = ('get', 'post', 'put', 'patch', 'delete', 'head', 'options')
    verbless = sorted(
        name for name, cls in resources.items()
        if not any(callable(getattr(cls, verb, None)) for verb in verbs)
    )
    assert not verbless, (
        f'these resources define no HTTP verb, so their routes would answer '
        f'405 to every request: {verbless}'
    )
