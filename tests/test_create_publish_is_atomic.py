"""The create/reissue flat-file publish must be atomic, like the renew path.

create_certificate published the served flat PEMs with an in-place loop over
CERTIFICATE_FILES — privkey.pem last, no staging, no rollback. A failure on the
fourth write left a new cert.pem beside the previous privkey.pem, a pair that
cannot complete a TLS handshake, served straight off disk and pushed to deploy
hooks. This is the create AND the replace=True reissue path. It now goes through
_publish_flat_files (stage all four, promote by rename, roll back on error), the
same helper the renew path already uses.
"""
from pathlib import Path
from unittest.mock import patch

import pytest

from modules.core.certificates import CertificateManager
from modules.core.constants import CERTIFICATE_FILES

pytestmark = [pytest.mark.unit]


@pytest.fixture
def instance(tmp_path):
    cm = CertificateManager.__new__(CertificateManager)
    cm.cert_dir = tmp_path
    dom = tmp_path / 'example.com'
    live = dom / 'live' / 'example.com'
    live.mkdir(parents=True)
    for n, v in {'cert.pem': 'OLD-CERT', 'chain.pem': 'OLD-CH',
                 'fullchain.pem': 'OLD-FULL', 'privkey.pem': 'OLD-KEY'}.items():
        (dom / n).write_text(v)
    for n, v in {'cert.pem': 'NEW-CERT', 'chain.pem': 'NEW-CH',
                 'fullchain.pem': 'NEW-FULL', 'privkey.pem': 'NEW-KEY'}.items():
        (live / n).write_text(v)
    return cm, dom, live


def test_a_failure_on_the_last_file_leaves_the_served_pair_intact(instance):
    cm, dom, live = instance
    orig = Path.write_bytes

    def failing(self, data):
        if self.name == 'privkey.pem.staging':
            raise OSError(28, 'ENOSPC')
        return orig(self, data)

    with pytest.raises(OSError):
        with patch.object(Path, 'write_bytes', failing):
            cm._publish_flat_files(live, dom)

    # every served file is still the OLD generation — no mixed pair
    served = {n: (dom / n).read_text() for n in CERTIFICATE_FILES}
    assert all(v.startswith('OLD') for v in served.values()), served
    # no staging leftovers
    assert list(dom.glob('*.staging')) == []


def test_a_successful_publish_promotes_all_four_and_returns_bytes(instance):
    cm, dom, live = instance
    result = cm._publish_flat_files(live, dom)
    for n in CERTIFICATE_FILES:
        assert (dom / n).read_text().startswith('NEW')
    # same {name: bytes} shape create_certificate feeds to _store_in_backend
    assert set(result) == set(CERTIFICATE_FILES)
    assert result['privkey.pem'] == b'NEW-KEY'


def test_privkey_keeps_restrictive_mode_through_the_publish(instance):
    cm, dom, live = instance
    import os
    os.chmod(live / 'privkey.pem', 0o600)
    cm._publish_flat_files(live, dom)
    assert (dom / 'privkey.pem').stat().st_mode & 0o777 == 0o600


def test_create_certificate_no_longer_writes_the_flat_files_in_place():
    """Guard against a regression to the non-atomic loop: create_certificate
    must not write the served files directly; it must go through the helper."""
    import inspect
    src = inspect.getsource(CertificateManager.create_certificate)
    # strip comments so the check looks at code, not the explanatory comment
    code = '\n'.join(line.split('#', 1)[0] for line in src.splitlines())
    assert '_publish_flat_files' in code, \
        "create_certificate must publish via _publish_flat_files"
    # and the non-atomic loop must be gone: no direct dst write of the served
    # files. The old loop wrote `dst_file.write_bytes(data)` over cert_output_dir.
    assert 'dst_file.write_bytes' not in code, \
        "create_certificate must not write the served files in place"
