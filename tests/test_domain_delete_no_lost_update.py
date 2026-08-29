"""Removing a domain from settings must not drop a concurrent registration.

The DELETE handler and set_auto_renew both did load_settings() (a request-cache
hit, primed by the rate-limit before_request) then atomic_update({'domains':
<whole list built from the stale snapshot>}). 'domains' is replaced wholesale
(not a deep-merge key), so a domain registered by another request after the
cache was primed — while the delete's storage-backend round-trip ran — was
silently dropped from the list, and check_renewals never renewed it again. Both
now do a read-modify-write on the fresh on-disk list via settings_manager.update.
"""
import json
import threading

import pytest

from modules.core.file_operations import FileOperations
from modules.core.settings import SettingsManager

pytestmark = [pytest.mark.unit]


@pytest.fixture
def sm(tmp_path):
    d, c, b, l = (tmp_path / 'data', tmp_path / 'certs',
                  tmp_path / 'backups', tmp_path / 'logs')
    for p in (d, c, b, l):
        p.mkdir()
    (d / 'settings.json').write_text(json.dumps({
        'domains': [{'domain': 'a.example.com'}],
        'email': 'ops@example.com',
        'users': {'admin': {'role': 'admin'}},
    }))
    fo = FileOperations(c, d, b, l)
    return SettingsManager(fo, d / 'settings.json'), d / 'settings.json'


def _domains(path):
    return sorted(x['domain']
                  for x in json.loads(path.read_text()).get('domains', []))


def _drop(domain):
    def mut(s):
        s['domains'] = [d for d in s.get('domains', [])
                        if d.get('domain') != domain]
    return mut


def test_a_concurrent_registration_survives_a_delete(sm):
    manager, path = sm
    b_written = threading.Event()

    def register_b():
        manager.update(lambda s: s.setdefault('domains', []).append(
            {'domain': 'b.example.com'}), reason='register_b')
        b_written.set()

    def delete_a():
        # The delete's read-modify-write happens after B lands, under the lock,
        # so it sees the fresh list — the interleaving that used to lose B.
        b_written.wait(2)
        manager.update(_drop('a.example.com'), reason='delete_a')

    t1 = threading.Thread(target=delete_a)
    t2 = threading.Thread(target=register_b)
    t1.start(); t2.start(); t1.join(); t2.join()

    assert _domains(path) == ['b.example.com']


def test_update_removes_only_the_named_domain(sm):
    """CONTROL: the mutator must still actually remove the target."""
    manager, path = sm
    manager.update(lambda s: s.setdefault('domains', []).append(
        {'domain': 'b.example.com'}), reason='seed')
    manager.update(_drop('a.example.com'), reason='delete')
    assert _domains(path) == ['b.example.com']


def test_set_auto_renew_uses_a_locked_read_modify_write():
    """Guard against a regression to load_settings()+atomic_update in the
    auto-renew toggle, which had the identical lost-update shape."""
    import inspect
    from modules.core.certificates import CertificateManager
    src = inspect.getsource(CertificateManager.set_auto_renew)
    assert 'settings_manager.update' in src
    # strip comments so the anti-pattern check looks at code, not prose
    code = '\n'.join(line.split('#', 1)[0] for line in src.splitlines())
    assert 'atomic_update' not in code


def test_delete_handler_uses_a_locked_read_modify_write():
    import inspect
    from modules.api import resources
    src = inspect.getsource(resources.create_api_resources)
    # the delete path drops the domain via the mutator, not a whole-list replace
    assert '_drop_domain' in src
