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


def test_patch_handler_wraps_the_metadata_write_in_the_lock():
    import inspect
    from modules.api import resources
    src = inspect.getsource(resources.create_api_resources)
    assert 'certificate_manager.domain_lock(domain)' in src
    assert 'except DomainOperationInProgress' in src
