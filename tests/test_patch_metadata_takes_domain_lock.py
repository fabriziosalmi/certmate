"""PATCH config must serialise against an in-flight renewal via the per-domain lock.

The PATCH handler did a metadata.json read-modify-write with no lock, while
renew_certificate reads metadata at the start of its certbot run and writes that
pre-renewal snapshot back at the end (holding the per-domain lock the whole
time). A PATCH landing in that window was silently reverted: settings.json got
the new dns_provider (its settings write is locked) while metadata.json — which
renew resolves the provider from — kept the old one, so every later renewal used
the decommissioned credential.

The metadata read-modify-write now runs under certificate_manager.domain_lock,
the same lock create/renew hold, so PATCH either waits for issuance to finish or
returns 409 — never interleaves.
"""
import threading
import time

import pytest

from modules.core.certificates import (
    CertificateManager,
    DomainOperationInProgress,
)

pytestmark = [pytest.mark.unit]


@pytest.fixture
def cm():
    m = CertificateManager.__new__(CertificateManager)
    m._domain_locks = {}
    m._domain_locks_mutex = threading.Lock()
    m._domain_lock_timeout = lambda: 0.3
    return m


def test_the_lock_serialises_a_patch_against_a_holder(cm):
    held = threading.Event()
    outcome = {}

    def renew_holds():
        with cm.domain_lock('example.com'):
            held.set()
            time.sleep(0.6)

    def patch_tries():
        held.wait(1)
        try:
            with cm.domain_lock('example.com'):
                outcome['v'] = 'entered'
        except DomainOperationInProgress:
            outcome['v'] = '409'

    t1 = threading.Thread(target=renew_holds)
    t2 = threading.Thread(target=patch_tries)
    t1.start(); t2.start(); t1.join(); t2.join()
    assert outcome['v'] == '409'


def test_the_lock_is_released_after_the_block(cm):
    with cm.domain_lock('example.com'):
        pass
    # a second acquire must succeed — no leak
    with cm.domain_lock('example.com'):
        pass


def test_no_contention_enters(cm):
    """CONTROL: without a holder the block runs."""
    ran = []
    with cm.domain_lock('example.com'):
        ran.append(True)
    assert ran == [True]


def test_renew_uses_the_same_lock_object(cm):
    """The whole point: PATCH's lock and renew's lock are the same object for a
    domain, so they actually serialise."""
    a = cm._get_domain_lock('example.com')
    b = cm._get_domain_lock('example.com')
    assert a is b


def test_update_config_takes_the_lock_and_reports_contention(tmp_path):
    """Where the lock lives now, asserted by BEHAVIOUR rather than by source.

    The handler moved out of the closure in #667, and the read-modify-write
    moved again in #672 — from the route into CertificateService.update_config.
    Each move broke a source-scanning version of this test, which is the
    argument for not writing another one: hold the lock, call the service, and
    require it to refuse.
    """
    from unittest.mock import MagicMock

    from modules.core.cert_service import CertificateService

    manager = CertificateManager.__new__(CertificateManager)
    manager._domain_locks = {}
    manager._domain_locks_mutex = threading.Lock()
    manager._domain_lock_timeout = lambda: 0.2
    manager._load_metadata = lambda domain: {}
    manager._save_metadata = lambda domain, metadata: True

    service = CertificateService(manager, MagicMock(), MagicMock())

    with manager.domain_lock('example.com'):
        with pytest.raises(DomainOperationInProgress):
            service.update_config('example.com', {'dns_provider': 'route53'})


def test_update_config_writes_when_nothing_holds_the_lock(tmp_path):
    """CONTROL: a test that only proves refusal would pass on a service that
    always refuses."""
    from unittest.mock import MagicMock

    from modules.core.cert_service import CertificateService

    written = {}
    manager = CertificateManager.__new__(CertificateManager)
    manager._domain_locks = {}
    manager._domain_locks_mutex = threading.Lock()
    manager._domain_lock_timeout = lambda: 0.2
    manager._load_metadata = lambda domain: {'dns_provider': 'cloudflare'}
    manager._save_metadata = lambda domain, metadata: written.update(metadata) or True

    service = CertificateService(manager, MagicMock(), MagicMock())
    metadata, old = service.update_config('example.com',
                                          {'dns_provider': 'route53'})

    assert old == 'cloudflare'
    assert metadata['dns_provider'] == 'route53'
    assert written['dns_provider'] == 'route53'


def test_the_route_still_turns_contention_into_409():
    """The half that stays at the HTTP layer: the service raises, the adapter
    maps it. Source-level, because the mapping IS the route's only job here.
    """
    import inspect
    from modules.api import resources_certificates

    src = inspect.getsource(resources_certificates.create_certificates_resources)
    assert 'except DomainOperationInProgress' in src, (
        'the handler no longer reports a concurrent operation as 409'
    )
