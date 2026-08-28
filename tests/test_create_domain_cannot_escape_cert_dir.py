"""The domain used on the create path is always a bare hostname.

`validate_domain` returns the normalised name as its second value (URL netloc
extracted, lowercased). The create path used to check only the boolean and
keep the caller's raw string, so a value that validated but was not a bare
hostname could reach path construction — `cert_dir / domain`, the certbot
--cert-name, and the per-domain lock key — carrying characters it should not.

Two layers are pinned here:
  * the sources (prepare_create, the batch route) rebind to the normalised
    name, so a URL form becomes a bare hostname;
  * create_certificate itself rejects any domain carrying '/', '\\', '..' or a
    NUL before it builds a path or takes the per-domain lock — the last line
    every caller crosses, including the batch route, which does not go through
    prepare_create.
"""
import threading
from pathlib import Path

import pytest

from modules.core.certificates import CertificateManager
from modules.core.utils import validate_domain

pytestmark = [pytest.mark.unit]


ESCAPES = [
    'https://x.com/../../../some/nested/path',
    '../escape',
    'a/b/c',
    'x\\y',
    'foo\x00bar',
]


# --- the source normalises rather than keeps the raw string ------------------

@pytest.mark.parametrize('url,expected', [
    ('https://x.com/../../../some/path', 'x.com'),
    ('https://Example.COM/whatever', 'example.com'),
    ('example.com', 'example.com'),
])
def test_validate_domain_returns_a_bare_hostname(url, expected):
    ok, normalized = validate_domain(url)
    assert ok
    assert normalized == expected
    assert '/' not in normalized and '..' not in normalized


# --- the sink rejects anything that could build a path outside cert_dir ------

@pytest.fixture
def bare_manager(tmp_path):
    cm = CertificateManager.__new__(CertificateManager)
    cm._domain_locks = {}
    cm._domain_locks_mutex = threading.Lock()
    cm.cert_dir = tmp_path / 'certificates'
    cm.cert_dir.mkdir()
    return cm


@pytest.mark.parametrize('bad', ESCAPES)
def test_create_certificate_rejects_a_path_bearing_domain(bare_manager, bad):
    with pytest.raises(ValueError, match='Invalid domain name'):
        bare_manager.create_certificate(domain=bad, email='a@b.c')


def test_the_rejection_happens_before_any_directory_is_created(bare_manager):
    """The guard runs before cert_dir/<domain> could be made — nothing is
    written for a rejected domain."""
    bad = 'https://x.com/../../../escape/here'
    with pytest.raises(ValueError):
        bare_manager.create_certificate(domain=bad, email='a@b.c')
    # No stray directories anywhere under or beside cert_dir.
    assert list(bare_manager.cert_dir.iterdir()) == []
    assert not (bare_manager.cert_dir.parent / 'escape').exists()


def test_a_bare_hostname_passes_the_guard(bare_manager):
    """CONTROL. A legitimate domain must get past the guard — otherwise the
    guard would simply break issuance. It fails later (no settings manager on
    this bare instance), which is past the guard; it must not raise the
    'Invalid domain name' ValueError."""
    try:
        bare_manager.create_certificate(domain='example.com', email='a@b.c')
    except ValueError as e:
        assert 'Invalid domain name' not in str(e)
    except Exception:
        pass  # anything else means we got past the guard, which is the point
