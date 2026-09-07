"""An extracted resource group must build without the whole manager graph.

That is the entire point of the decomposition. While all 41 classes lived
inside `create_api_resources`, reaching one route meant constructing every
manager, which is why the HTTP layer ended up both the largest module and the
least covered (#662, #667).

This asserts the property directly for each group as it moves out, so a later
change that quietly reintroduces a dependency on the full graph fails here
rather than showing up as coverage that cannot be written.
"""
from unittest.mock import MagicMock

import pytest
from flask import Flask
from flask_restx import Api, Resource

from modules.api.resource_context import ApiContext
from modules.api.resources_backup import create_backup_resources
from modules.api.resources_cache import create_cache_resources
from modules.api.resources_ca import create_ca_resources
from modules.api.resources_health import create_health_resources
from modules.api.resources_inventory import create_inventory_resources
from modules.api.resources_settings import create_settings_resources
from modules.api.resources_storage import create_storage_resources

pytestmark = [pytest.mark.unit]


def _minimal_context(**overrides):
    """A context with only the managers a group genuinely needs."""
    fields = dict(
        auth=MagicMock(), settings=None, certificates=None, file_ops=None,
        cache=None, dns=None, deployer=None, audit=None,
        cert_service=None, cert_executor=None,
    )
    fields.update(overrides)
    fields['auth'].require_role = lambda role: (lambda fn: fn)
    return ApiContext(**fields)


@pytest.fixture
def api():
    app = Flask(__name__)
    app.config['TESTING'] = True
    return Api(app, prefix='/api')


def test_the_cache_group_builds_from_a_minimal_context(api):
    models = {
        'cache_stats_model': MagicMock(),
        'cache_clear_response_model': MagicMock(),
    }
    resources = create_cache_resources(api, models,
                                       _minimal_context(cache=MagicMock()))

    assert set(resources) == {'CacheStats', 'CacheClear'}
    for name, cls in resources.items():
        assert issubclass(cls, Resource), f'{name} is not a Resource'


def test_the_cache_group_needs_no_certificate_manager(api):
    """CONTROL: names the dependency that used to be unavoidable.

    Every class in the old closure could reach the certificate manager whether
    it needed one or not. If cache endpoints start requiring it, that coupling
    has come back.
    """
    models = {
        'cache_stats_model': MagicMock(),
        'cache_clear_response_model': MagicMock(),
    }
    ctx = _minimal_context(cache=MagicMock(), certificates=None)
    resources = create_cache_resources(api, models, ctx)
    assert resources, 'the group must build with no certificate manager at all'


def test_the_health_group_builds_from_a_minimal_context(api):
    """Diagnostics reaches across the application by nature, so its context
    carries the manager mapping — but it must still build without the closure.
    """
    models = {'health_model': MagicMock(), 'metrics_model': MagicMock()}
    ctx = _minimal_context(
        settings=MagicMock(), certificates=MagicMock(), file_ops=MagicMock(),
        managers={},
    )
    resources = create_health_resources(api, models, ctx)

    assert set(resources) == {
        'HealthCheck', 'MetricsList', 'DiagnosticsSnapshot'}
    for name, cls in resources.items():
        assert issubclass(cls, Resource), f'{name} is not a Resource'


def test_the_health_group_tolerates_an_empty_manager_mapping(api):
    """CONTROL: the long-tail managers are optional, as they were in the
    closure — a diagnostics endpoint must degrade, not refuse to build."""
    models = {'health_model': MagicMock(), 'metrics_model': MagicMock()}
    ctx = _minimal_context(settings=MagicMock(), certificates=MagicMock(),
                           file_ops=MagicMock(), managers={})
    assert create_health_resources(api, models, ctx)


BACKUP_MODELS = {'backup_model': MagicMock(), 'backup_list_model': MagicMock()}


def test_the_backup_group_builds_from_a_minimal_context(api):
    ctx = _minimal_context(settings=MagicMock(), file_ops=MagicMock(),
                           audit=MagicMock(), managers={})
    resources = create_backup_resources(api, BACKUP_MODELS, ctx)

    assert set(resources) == {
        'BackupList', 'BackupCreate', 'BackupDownload', 'BackupRestore',
        'BackupDelete', 'BackupUpload'}
    for name, cls in resources.items():
        assert issubclass(cls, Resource), f'{name} is not a Resource'


def test_the_backup_group_needs_no_certificate_manager(api):
    """CONTROL: backups are taken through file_ops, not the cert manager.

    In the closure every class could reach `certificate_manager` regardless of
    whether it used one, so this coupling was invisible. If it returns, the
    group stops being movable and this fails.
    """
    ctx = _minimal_context(settings=MagicMock(), file_ops=MagicMock(),
                           audit=MagicMock(), certificates=None, managers={})
    assert create_backup_resources(api, BACKUP_MODELS, ctx)


def test_the_backup_group_resolves_the_managers_it_looks_up_by_name(api, tmp_path):
    """Building a group proves nothing about the names it reads at request time.

    BackupDelete does not use the named `file_ops` field; it looks the manager
    up out of the mapping by string key, and answers 503 when that lookup comes
    back empty. Every test above would pass with that key misspelt, because
    none of them call the method — which is exactly how a broken key survived
    the move here once already.

    So this one calls it, with a real file to delete, and asserts the endpoint
    actually did the work.
    """
    backup_dir = tmp_path / 'unified'
    backup_dir.mkdir()
    victim = backup_dir / 'backup_20260101_120000.zip'
    victim.write_bytes(b'PK\x03\x04')

    file_ops = MagicMock()
    file_ops.backup_dir = tmp_path
    ctx = _minimal_context(settings=MagicMock(), file_ops=file_ops,
                           audit=None, managers={'file_ops': file_ops})

    resources = create_backup_resources(api, BACKUP_MODELS, ctx)
    app = Flask(__name__)
    with app.test_request_context('/'):
        body, status = resources['BackupDelete']().delete(
            'unified', 'backup_20260101_120000.zip')

    assert status != 503, (
        f'the endpoint could not find the file_ops manager in the context '
        f'mapping, so a lookup key is wrong: {body}'
    )
    assert status == 200, f'expected the delete to succeed, got {status}: {body}'
    assert not victim.exists(), 'the endpoint returned 200 without deleting'


def test_the_backup_group_builds_without_an_audit_logger(api):
    """CONTROL: the audit logger is optional in the manager set, and the
    closure guarded every use with `if audit_logger`. Building without one has
    to keep working, or the extraction changed behaviour rather than location.
    """
    ctx = _minimal_context(settings=MagicMock(), file_ops=MagicMock(),
                           audit=None, managers={})
    assert create_backup_resources(api, BACKUP_MODELS, ctx)


STORAGE_MODELS = {
    'storage_config_model': MagicMock(),
    'storage_test_config_model': MagicMock(),
    'storage_migration_config_model': MagicMock(),
}


def test_the_storage_group_builds_from_a_minimal_context(api):
    ctx = _minimal_context(settings=MagicMock(), audit=MagicMock(),
                           managers={})
    resources = create_storage_resources(api, STORAGE_MODELS, ctx)

    assert set(resources) == {
        'StorageBackendInfo', 'StorageBackendConfig', 'StorageBackendTest',
        'StorageBackendMigrate', 'StorageAzureKeyVaultBackfill'}
    for name, cls in resources.items():
        assert issubclass(cls, Resource), f'{name} is not a Resource'


def test_the_storage_group_reaches_the_storage_manager_by_the_right_name(api):
    """Building the group says nothing about the key it reads at request time.

    These endpoints take the storage manager out of the mapping by string, and
    answer 503 when it is missing — so a wrong key is a total outage that looks
    exactly like an unconfigured backend. test_manager_lookup_keys_are_real.py
    checks every such key statically; this confirms the endpoint really does
    resolve one and get past the 503 guard.
    """
    storage = MagicMock()
    storage.get_backend_name.return_value = 'local_filesystem'
    settings = MagicMock()
    settings.load_settings.return_value = {'certificate_storage': {}}

    ctx = _minimal_context(settings=settings, audit=None,
                           managers={'storage': storage})
    resources = create_storage_resources(api, STORAGE_MODELS, ctx)

    app = Flask(__name__)
    with app.test_request_context('/'):
        result = resources['StorageBackendInfo']().get()

    body = result[0] if isinstance(result, tuple) else result
    status = result[1] if isinstance(result, tuple) else 200
    assert status != 503, (
        f'the endpoint could not resolve the storage manager from the context '
        f'mapping, so its lookup key is wrong: {body}'
    )
    assert body['current_backend'] == 'local_filesystem'


def test_the_inventory_group_builds_from_a_minimal_context(api):
    ctx = _minimal_context(managers={})
    resources = create_inventory_resources(api, {}, ctx)

    assert set(resources) == {
        'InventoryList', 'InventoryConfig', 'InventoryScan',
        'InventoryCryptoReport', 'InventoryAdopt'}
    for name, cls in resources.items():
        assert issubclass(cls, Resource), f'{name} is not a Resource'


def test_the_inventory_group_applies_scope_through_the_shared_helper(api):
    """The first group whose classes use the scope helpers.

    The closure defined thin wrappers over the context-taking functions in
    resource_context; this module reproduces them so the call sites could move
    verbatim. If a wrapper were wired to the wrong function — or dropped so a
    call resolved to the module-level one with the wrong arity — the endpoint
    would either crash or, far worse, stop filtering and return the whole
    inventory to a scoped caller. So this calls it and checks what comes back.
    """
    inventory = MagicMock()
    inventory.list_all.return_value = [
        {'subject_cn': 'mine.example.com', 'sans': []},
        {'subject_cn': 'theirs.example.net', 'sans': []},
    ]
    ctx = _minimal_context(managers={'cert_inventory': inventory})
    # Scope the caller to one of the two records.
    ctx.auth.domain_matches_scope = lambda domain, scope: (
        scope is None or domain in scope)

    resources = create_inventory_resources(api, {}, ctx)
    app = Flask(__name__)
    with app.test_request_context('/'):
        from flask import request as flask_request
        flask_request.current_user = {
            'username': 'someone', 'allowed_domains': ['mine.example.com']}
        result = resources['InventoryList']().get()

    status = result[1] if isinstance(result, tuple) else 200
    body = result[0] if isinstance(result, tuple) else result
    assert status != 503, f'the inventory manager was not resolved: {body}'

    # Read the subjects out of the response rather than searching its repr: a
    # substring match would also be satisfied by a domain that merely contains
    # the expected one, and would report the wrong thing when it failed.
    returned = sorted(
        entry.get('subject_cn')
        for group in body.values() if isinstance(group, list)
        for entry in group if isinstance(entry, dict)
    )
    assert returned == ['mine.example.com'], (
        f'the scoped caller should see exactly its own record; got {returned}. '
        f'Anything else means the scope helper is not being applied — which '
        f'would hand a restricted caller the whole inventory.'
    )


def test_the_ca_group_builds_from_a_minimal_context(api):
    resources = create_ca_resources(api, {'ca_test_config_model': MagicMock()},
                                    _minimal_context(managers={}))
    assert set(resources) == {'CAProviderTest'}
    assert issubclass(resources['CAProviderTest'], Resource)


def test_the_settings_group_builds_from_a_minimal_context(api):
    models = {
        'settings_model': MagicMock(),
        'dns_providers_model': MagicMock(),
    }
    ctx = _minimal_context(settings=MagicMock(), dns=MagicMock(),
                           audit=MagicMock(), managers={})
    resources = create_settings_resources(api, models, ctx)

    assert set(resources) == {
        'Settings', 'DNSProviders', 'DNSAccounts', 'DNSAccountDetail'}
    for name, cls in resources.items():
        assert issubclass(cls, Resource), f'{name} is not a Resource'
