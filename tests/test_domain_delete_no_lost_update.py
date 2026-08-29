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


def test_the_stale_snapshot_approach_loses_b_but_the_mutator_does_not(sm):
    """Directly contrast the two approaches on the SAME interleaving: A reads
    the domain list, B registers concurrently, then A removes its domain.

    - the old shape (snapshot taken early, then atomic_update({'domains': list
      built from that snapshot})) writes the stale list back and drops B;
    - the new shape (update(mutator) re-reads the fresh list under the lock)
      keeps B.
    """
    manager, path = sm
    b_written = threading.Event()
    snapshot_taken = threading.Event()

    # --- old shape: snapshot then whole-list atomic_update ---
    def delete_a_stale():
        snap = manager.load_settings(use_cache=False)   # taken before B lands
        snapshot_taken.set()
        b_written.wait(2)
        kept = [d for d in snap.get('domains', [])
                if d.get('domain') != 'a.example.com']
        manager.atomic_update({'domains': kept})

    def register_b():
        snapshot_taken.wait(2)                          # let delete snapshot first
        manager.update(lambda s: s.setdefault('domains', []).append(
            {'domain': 'b.example.com'}), reason='register_b')
        b_written.set()

    t1 = threading.Thread(target=delete_a_stale)
    t2 = threading.Thread(target=register_b)
    t1.start(); t2.start(); t1.join(); t2.join()
    assert 'b.example.com' not in _domains(path), \
        "precondition: the stale-snapshot approach must lose B here"

    # reset and run the SAME interleaving with the mutator (the fix)
    (path).write_text(json.dumps({
        'domains': [{'domain': 'a.example.com'}], 'email': 'ops@example.com',
        'users': {'admin': {'role': 'admin'}}}))
    b_written.clear()

    def delete_a_mutator():
        b_written.wait(2)
        manager.update(_drop('a.example.com'), reason='delete_a')

    t3 = threading.Thread(target=delete_a_mutator)
    t4 = threading.Thread(target=register_b)
    t3.start(); t4.start(); t3.join(); t4.join()
    assert _domains(path) == ['b.example.com'], \
        "the mutator re-reads under the lock and keeps B"


def test_a_no_op_delete_does_not_persist(sm):
    """Removing a domain that is not present must not write settings (nor
    trigger an automatic backup) — a no-op stays a no-op."""
    manager, path = sm
    manager.load_settings(use_cache=False)   # let any migration settle first
    before = path.read_text()

    class _AlreadyAbsent(Exception):
        pass

    def guarded(s):
        current = s.get('domains', []) or []
        kept = [d for d in current if d.get('domain') != 'zzz.example.com']
        if len(kept) == len(current):
            raise _AlreadyAbsent
        s['domains'] = kept

    with pytest.raises(_AlreadyAbsent):
        manager.update(guarded, reason='noop')
    # the mutator raised before save_settings, so the file is byte-identical
    assert path.read_text() == before, "a no-op delete must not rewrite settings"


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
