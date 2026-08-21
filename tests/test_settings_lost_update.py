"""Two overlapping writes must both survive.

`test_settings_request_scoped_cache.py` pins the cache's contract and every
one of its six assertions is still true. What it never asked is what the cache
does to a read-modify-write, and the answer was: it turns every one of them
into a lost update.

`update()` and `atomic_update()` hold `self._lock` for the whole
read-modify-write, so two writes cannot interleave. But the "read" was
`load_settings()`, which inside a request returns the dict cached on `flask.g`
when the request STARTED. The lock was protecting a snapshot, not the file.

The window is not theoretical and it is not milliseconds. On the synchronous
issuance path — the default, since async is opt-in — `cert_service.py` loads
settings at :183, runs certbot, and writes at :242. Everything between those
two lines happens in the same request thread, so for the whole duration of an
issuance any other write to settings.json was silently rolled back: a user
created, a domain registered, a DNS credential saved.

The second test is the one that decides whether this is a nuisance or a
security defect. `atomic_update`'s `protected_keys` exists to stop a partial
settings POST from dropping `users` and `api_keys`; it restores them from
`existing`. With `existing` coming from the cache it restored them from the
stale snapshot — so an account deleted by a concurrent request came back,
password hash included, and `delete_user` had already reported success.

Both tests fail on the pre-fix code. Neither uses a mock: the threads are real,
the request contexts are real, and the file on disk is the judge.
"""
from __future__ import annotations

import threading

import pytest
from flask import Flask

from modules.core.file_operations import FileOperations
from modules.core.settings import SettingsManager

pytestmark = [pytest.mark.unit]

TIMEOUT = 15  # generous: a stuck thread must fail the test, not hang the suite


@pytest.fixture
def settings_manager(tmp_path):
    dirs = {name: tmp_path / name for name in
            ("certificates", "data", "backups", "logs")}
    for d in dirs.values():
        d.mkdir()
    file_ops = FileOperations(
        cert_dir=dirs["certificates"], data_dir=dirs["data"],
        backup_dir=dirs["backups"], logs_dir=dirs["logs"],
    )
    manager = SettingsManager(
        file_ops=file_ops, settings_file=dirs["data"] / "settings.json")
    manager.save_settings({
        'email': 'seed@example.com',
        'dns_provider': 'cloudflare',
        'domains': [],
        'users': {'bob': {'password_hash': 'sha256:seeded', 'role': 'operator'}},
    })
    return manager


def _run(*targets):
    """Run the callables as threads and re-raise whatever they raised.

    A thread that dies with an exception otherwise leaves the test asserting
    on a half-finished state and reporting a confusing failure.
    """
    errors = []

    def guard(target):
        def wrapped():
            try:
                target()
            except BaseException as error:      # noqa: BLE001 - re-raised below
                errors.append(error)
        return wrapped

    threads = [threading.Thread(target=guard(t), daemon=True) for t in targets]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=TIMEOUT)
    alive = [t for t in threads if t.is_alive()]
    assert not alive, f"{len(alive)} thread(s) did not finish within {TIMEOUT}s"
    if errors:
        raise errors[0]


def test_a_long_request_does_not_roll_back_a_concurrent_write(settings_manager):
    """The issuance shape: load, spend minutes in certbot, then write."""
    app = Flask(__name__)
    holding_snapshot = threading.Event()
    other_write_landed = threading.Event()

    def slow_issuance():
        # cert_service.prepare_create -> load_settings (caches on flask.g)
        with app.test_request_context('/api/certificates/create'):
            settings_manager.load_settings()
            holding_snapshot.set()
            # ... certbot runs here, for minutes, in this same thread ...
            assert other_write_landed.wait(timeout=TIMEOUT)

            def add_domain(settings):
                settings.setdefault('domains', []).append(
                    {'domain': 'issued.example.com', 'dns_provider': 'cloudflare'})

            settings_manager.update(add_domain, 'certificate_created')

    def concurrent_settings_write():
        assert holding_snapshot.wait(timeout=TIMEOUT)
        with app.test_request_context('/api/settings'):
            def set_email(settings):
                settings['email'] = 'changed@example.com'

            settings_manager.update(set_email, 'settings_updated')
        other_write_landed.set()

    _run(slow_issuance, concurrent_settings_write)

    final = settings_manager.load_settings()
    assert final['email'] == 'changed@example.com', (
        "the issuance wrote back a snapshot taken before certbot ran and "
        "reverted a settings change made while it was running"
    )
    assert [d['domain'] for d in final.get('domains', [])] == ['issued.example.com'], (
        "the newly issued domain is missing from settings — a domain that is "
        "not in settings['domains'] is never visited by check_renewals again"
    )


def test_a_deleted_user_does_not_come_back(settings_manager):
    """`protected_keys` must protect the file, not the caller's snapshot."""
    app = Flask(__name__)
    holding_snapshot = threading.Event()
    user_deleted = threading.Event()

    def long_request_then_partial_settings_post():
        with app.test_request_context('/api/web/settings'):
            settings_manager.load_settings()          # snapshot still has bob
            holding_snapshot.set()
            assert user_deleted.wait(timeout=TIMEOUT)
            # A settings POST that carries no 'users' key at all: the shape
            # protected_keys was written for.
            settings_manager.atomic_update({'email': 'partial@example.com'})

    def admin_deletes_the_user():
        assert holding_snapshot.wait(timeout=TIMEOUT)
        with app.test_request_context('/api/users/bob'):
            def drop_bob(settings):
                settings.get('users', {}).pop('bob', None)

            settings_manager.update(drop_bob, 'user_management')
        user_deleted.set()

    _run(long_request_then_partial_settings_post, admin_deletes_the_user)

    final = settings_manager.load_settings()
    assert 'bob' not in final.get('users', {}), (
        "a revoked account was restored — password hash included — by a "
        "concurrent settings POST, after delete_user reported success"
    )
    assert final['email'] == 'partial@example.com', (
        "the settings POST itself was lost, which would be the same bug "
        "pointing the other way"
    )


def test_the_write_path_still_sees_its_own_earlier_write(settings_manager):
    """Reading from disk must not break read-your-own-writes within a request.

    The cache exists because `/api/certificates` re-reads settings 15+ times
    per request. Forcing the write path to disk must leave that intact: a
    route that writes and then reads still sees what it just wrote.
    """
    app = Flask(__name__)
    with app.test_request_context('/api/settings'):
        settings_manager.load_settings()

        def set_email(settings):
            settings['email'] = 'self@example.com'

        assert settings_manager.update(set_email, 'settings_updated')
        assert settings_manager.load_settings()['email'] == 'self@example.com'


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
