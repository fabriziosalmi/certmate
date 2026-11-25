"""Two user writes at the same time both land, or one is refused (#1544).

`create_user`, `update_user` and `delete_user` read the users, checked them,
hashed a password, and wrote the whole map back. The write ran under the
settings lock, but the read did not, so two requests that read before either
wrote each wrote their own snapshot, and the second erased the first. Both
were answered as successes. Reproduced on 2026-11-24: two creates, bob and
carol, both "User created successfully", and only bob stored.

These run real writes from threads released together, against the real
settings file, and read what is stored. No internal is held at a barrier: the
race is the one an admin gets by clicking twice, with the password hash (slow
on purpose) between the read and the write.
"""
import threading

import pytest

from tests.test_oidc_manager import auth_manager, settings_manager  # noqa: F401

pytestmark = [pytest.mark.unit]

PASSWORD = 'correct horse battery staple 1544'


def _together(*calls):
    """Run each call on its own thread, released at once; their results in order."""
    start = threading.Barrier(len(calls))
    results = [None] * len(calls)

    def run(index, call):
        start.wait()
        results[index] = call()

    threads = [threading.Thread(target=run, args=(i, c)) for i, c in enumerate(calls)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(60)
    return results


def _stored(settings_manager):  # noqa: F811
    return settings_manager.load_settings(use_cache=False).get('users') or {}


def _admin(auth_manager):  # noqa: F811
    assert auth_manager.create_user('admin', PASSWORD, role='admin')[0]


def test_users_created_at_the_same_time_are_all_stored(auth_manager, settings_manager):  # noqa: F811
    names = [f'user{i}' for i in range(6)]
    results = _together(*[
        (lambda n=n: auth_manager.create_user(n, PASSWORD, email=f'{n}@example.com'))
        for n in names])
    assert all(ok for ok, _ in results), results
    assert sorted(_stored(settings_manager)) == sorted(names)


def test_one_name_created_twice_at_once_is_one_user_and_one_refusal(auth_manager, settings_manager):  # noqa: F811
    results = _together(
        lambda: auth_manager.create_user('dana', PASSWORD, email='one@example.com'),
        lambda: auth_manager.create_user('dana', PASSWORD, email='two@example.com'))
    assert sorted(ok for ok, _ in results) == [False, True], results
    assert [m for ok, m in results if not ok] == ['User already exists']
    assert list(_stored(settings_manager)) == ['dana']


def test_one_address_taken_twice_at_once_belongs_to_one_user(auth_manager, settings_manager):  # noqa: F811
    results = _together(
        lambda: auth_manager.create_user('erin', PASSWORD, email='shared@example.com'),
        lambda: auth_manager.create_user('fred', PASSWORD, email='Shared@Example.com'))
    assert sorted(ok for ok, _ in results) == [False, True], results
    holders = [n for n, u in _stored(settings_manager).items()
               if (u.get('email') or '').lower() == 'shared@example.com']
    assert len(holders) == 1, holders


def test_an_update_and_a_create_at_once_both_land(auth_manager, settings_manager):  # noqa: F811
    _admin(auth_manager)
    assert auth_manager.create_user('gina', PASSWORD, email='gina@example.com')[0]
    results = _together(
        lambda: auth_manager.update_user('gina', password=PASSWORD + ' new', email='gina@new.example.com'),
        lambda: auth_manager.create_user('hank', PASSWORD))
    assert all(ok for ok, _ in results), results
    stored = _stored(settings_manager)
    assert sorted(stored) == ['admin', 'gina', 'hank']
    assert stored['gina']['email'] == 'gina@new.example.com'


def test_a_delete_and_a_create_at_once_both_land(auth_manager, settings_manager):  # noqa: F811
    _admin(auth_manager)
    assert auth_manager.create_user('ivan', PASSWORD)[0]
    results = _together(
        lambda: auth_manager.delete_user('ivan'),
        lambda: auth_manager.create_user('jill', PASSWORD))
    assert all(ok for ok, _ in results), results
    assert sorted(_stored(settings_manager)) == ['admin', 'jill']


def test_two_admins_demoted_at_once_leave_one_admin(auth_manager, settings_manager):  # noqa: F811
    """The last-admin guard is a check on the users: done before the lock,
    both demotions saw two admins, and none was left."""
    _admin(auth_manager)
    assert auth_manager.create_user('kate', PASSWORD, role='admin')[0]
    results = _together(
        lambda: auth_manager.update_user('admin', role='operator'),
        lambda: auth_manager.update_user('kate', role='operator'))
    assert sorted(ok for ok, _ in results) == [False, True], results
    admins = [n for n, u in _stored(settings_manager).items() if u.get('role') == 'admin']
    assert len(admins) == 1, admins


def test_a_refused_write_changes_nothing(auth_manager, settings_manager):  # noqa: F811
    assert auth_manager.create_user('lena', PASSWORD, email='lena@example.com')[0]
    before = _stored(settings_manager)
    assert auth_manager.create_user('lena', PASSWORD) == (False, 'User already exists')
    assert auth_manager.update_user('nobody', role='admin') == (False, 'User not found')
    assert auth_manager.delete_user('nobody') == (False, 'User not found')
    assert _stored(settings_manager) == before
