"""A promote interrupted half-way must not survive the restart that follows it.

Publishing a renewed certificate stages four PEMs and then promotes them with
four separate renames. That is not a transaction. A process killed between the
second and the third leaves the served directory holding a mixed generation,
and `privkey.pem` is last in `CERTIFICATE_FILES` — so the state a crash
actually produces is a **new certificate beside the previous private key**: a
pair that cannot complete a handshake, served straight off local disk by
`/api/certificates/<domain>/download` and pushed to every deploy hook.

That state was already reconciled, but only by the renewal sweep, in its
not-yet-due branch — up to a day later. The cause of a torn promote is a
process dying, and a process that dies is a process about to be restarted, so
startup is the first moment the state can be noticed. `create_app` now calls
`reconcile_served_copies`, which compares each domain's served files against
certbot's `live/` copy and republishes the ones that disagree.

The tests below build the torn state on disk directly rather than trying to
kill a process mid-rename: the repair has to work from what is on disk, and
what is on disk is the whole input.
"""
import logging

import pytest

from modules.core.certificates import CertificateManager

pytestmark = [pytest.mark.unit]

NEW = {
    'cert.pem': b'-----BEGIN CERTIFICATE-----\nNEW\n',
    'chain.pem': b'-----BEGIN CERTIFICATE-----\nNEWCHAIN\n',
    'fullchain.pem': b'-----BEGIN CERTIFICATE-----\nNEWFULL\n',
    'privkey.pem': b'-----BEGIN PRIVATE KEY-----\nNEWKEY\n',
}
OLD_KEY = b'-----BEGIN PRIVATE KEY-----\nOLDKEY\n'


@pytest.fixture
def manager(tmp_path):
    return CertificateManager(tmp_path / 'certificates', None,
                              dns_manager=None)


def _domain(manager, domain='example.com', served=None, live=NEW):
    """Lay out one domain: certbot's live/ copy, and what is being served."""
    domain_dir = manager.cert_dir / domain
    live_dir = domain_dir / 'live' / domain
    live_dir.mkdir(parents=True)
    for name, data in live.items():
        (live_dir / name).write_bytes(data)
    if served is not None:
        for name, data in served.items():
            (domain_dir / name).write_bytes(data)
    return domain_dir


def _served(domain_dir):
    return {p.name: p.read_bytes()
            for p in domain_dir.iterdir() if p.suffix == '.pem'}


# --- the state a crash actually leaves ----------------------------------

def test_a_new_certificate_beside_the_previous_key_is_repaired(manager):
    """The exact torn state: three renames landed, the fourth did not."""
    torn = dict(NEW, **{'privkey.pem': OLD_KEY})
    domain_dir = _domain(manager, served=torn)

    summary = manager.reconcile_served_copies()

    assert summary['republished'] == ['example.com']
    assert _served(domain_dir) == NEW, (
        'the served copy still holds a certificate its key does not match'
    )


def test_the_repair_is_reported_so_it_is_not_silent(manager, caplog):
    """An instance that quietly fixes itself teaches nobody that it broke."""
    _domain(manager, served=dict(NEW, **{'privkey.pem': OLD_KEY}))
    with caplog.at_level(logging.WARNING):
        manager.reconcile_served_copies()

    # Assert on the record's arguments rather than searching its rendered
    # text: the domain is passed as a lazy-formatting argument, so this pins
    # that the message actually names the domain it repaired instead of
    # matching a substring that could come from anywhere in the line.
    assert any('example.com' in (r.args or ()) for r in caplog.records), (
        'the repair was not logged, or was logged without naming the domain'
    )


def test_a_consistent_domain_is_left_alone(manager):
    """CONTROL: republishing on every start would rewrite four files per
    domain per boot and hide the signal this exists to raise."""
    domain_dir = _domain(manager, served=dict(NEW))
    before = {p.name: p.stat().st_mtime_ns for p in domain_dir.iterdir()
              if p.suffix == '.pem'}

    summary = manager.reconcile_served_copies()

    assert summary == {'checked': 1, 'republished': [], 'failed': {}}
    after = {p.name: p.stat().st_mtime_ns for p in domain_dir.iterdir()
             if p.suffix == '.pem'}
    assert before == after, 'a healthy domain was rewritten'


def test_a_missing_served_file_is_republished(manager):
    """A crash between the first and second rename leaves files absent, not
    merely different."""
    domain_dir = _domain(manager,
                         served={'cert.pem': NEW['cert.pem']})
    manager.reconcile_served_copies()
    assert _served(domain_dir) == NEW


# --- what must not be touched -------------------------------------------

def test_an_imported_certificate_with_no_live_directory_is_skipped(manager):
    """Externally managed certificates have nothing to reconcile against, and
    republishing them would mean deleting them."""
    domain_dir = manager.cert_dir / 'imported.example.com'
    domain_dir.mkdir(parents=True)
    (domain_dir / 'cert.pem').write_bytes(b'imported')

    summary = manager.reconcile_served_copies()

    assert summary == {'checked': 0, 'republished': [], 'failed': {}}
    assert (domain_dir / 'cert.pem').read_bytes() == b'imported'


def test_a_stray_file_in_the_certificate_directory_is_not_a_domain(manager):
    manager.cert_dir.mkdir(parents=True, exist_ok=True)
    (manager.cert_dir / 'README.txt').write_text('not a domain')
    assert manager.reconcile_served_copies()['checked'] == 0


def test_no_certificate_directory_at_all_is_not_an_error(tmp_path):
    manager = CertificateManager(tmp_path / 'never-created', None,
                                 dns_manager=None)
    assert manager.reconcile_served_copies() == {
        'checked': 0, 'republished': [], 'failed': {}}


# --- one bad domain must not take the instance down ---------------------

def test_a_domain_that_cannot_be_repaired_does_not_stop_the_others(manager,
                                                                   monkeypatch):
    """Refusing to start would turn one broken certificate into a total
    outage, and the instance is more useful serving the rest."""
    _domain(manager, 'broken.example.com',
            served=dict(NEW, **{'privkey.pem': OLD_KEY}))
    good = _domain(manager, 'good.example.com',
                   served=dict(NEW, **{'privkey.pem': OLD_KEY}))

    real_publish = manager._publish_flat_files

    def publish(src_dir, dest_dir):
        if dest_dir.name == 'broken.example.com':
            raise OSError('read-only file system')
        return real_publish(src_dir, dest_dir)

    monkeypatch.setattr(manager, '_publish_flat_files', publish)

    summary = manager.reconcile_served_copies()

    assert summary['republished'] == ['good.example.com']
    assert 'broken.example.com' in summary['failed']
    assert _served(good) == NEW


def test_a_failure_is_logged_at_error_naming_the_consequence(manager,
                                                             monkeypatch,
                                                             caplog):
    _domain(manager, served=dict(NEW, **{'privkey.pem': OLD_KEY}))
    monkeypatch.setattr(manager, '_publish_flat_files',
                        lambda *a: (_ for _ in ()).throw(OSError('nope')))

    with caplog.at_level(logging.ERROR):
        manager.reconcile_served_copies()

    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert errors, 'an unrepairable mismatch was not logged at ERROR'
    assert 'private key' in errors[0].getMessage()


# --- the wiring ----------------------------------------------------------

def test_a_real_create_app_repairs_a_torn_publish(tmp_path, monkeypatch):
    """The wiring, exercised rather than grepped for.

    Lay the torn state down where a real `create_app` will find it, boot the
    application, and check the served copy afterwards. A grep for the call
    would pass just as well with the call in dead code.
    """
    from modules.core.factory import create_app

    project_root = tmp_path / 'certmate'
    module_dir = project_root / 'modules' / 'core'
    module_dir.mkdir(parents=True)
    (module_dir / 'factory.py').write_text('# test path anchor\n')
    monkeypatch.setattr('modules.core.factory.__file__',
                        str(module_dir / 'factory.py'))
    monkeypatch.setenv('FLASK_ENV', 'testing')
    monkeypatch.setenv('TESTING', 'true')

    domain_dir = project_root / 'certificates' / 'torn.example.com'
    live_dir = domain_dir / 'live' / 'torn.example.com'
    live_dir.mkdir(parents=True)
    for name, data in NEW.items():
        (live_dir / name).write_bytes(data)
        (domain_dir / name).write_bytes(data)
    (domain_dir / 'privkey.pem').write_bytes(OLD_KEY)   # the fourth rename lost

    create_app()

    assert (domain_dir / 'privkey.pem').read_bytes() == NEW['privkey.pem'], (
        'booting the application left a certificate beside the previous key'
    )


def test_the_startup_wrapper_never_raises(monkeypatch):
    """CONTROL: a repair that can crash the boot is worse than the defect it
    repairs — the instance would not come back at all."""
    from modules.core import factory

    class Boom:
        def reconcile_served_copies(self):
            raise RuntimeError('disk gone')

    class Container:
        managers = {'certificates': Boom()}

    factory.reconcile_served_copies(Container())


def test_the_startup_wrapper_tolerates_a_missing_manager():
    from modules.core import factory

    class Container:
        managers = {}

    factory.reconcile_served_copies(Container())
