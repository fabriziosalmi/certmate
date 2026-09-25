"""`get_certificate_info` was 163 lines at C(28); it is four units now (#666).

The last function that issue names by number, and the one with the widest
reach: every listing endpoint, the dashboard, the digest, the metrics
collector and the renewal sweep all call it, once per certificate.

It held **two independent implementations of one question** — what the storage
backend says about a certificate, and what the files on disk say — in one
body, and that is not an aesthetic complaint. #830 is what it cost: the
private-key rule was fixed on the disk path and the backend path kept deciding
from the shape of a dict, so on a default installation (where a StorageManager
always exists) every certificate reported `key_state: unknown`, and a
certificate with no key at all reported healthy. That is the exact sentence
#608 had been closed for, on the path #608's fix never ran.

The four units:

* `_storage_retrieve` — the backend's answer, or None, with the shape checked
  rather than unpacked hopefully;
* `_storage_key_state` — which key state the backend's answer justifies. The
  #830 rule, now one function with a name;
* `_certificate_info_from_backend` — cache, retrieve, parse, cache;
* `_certificate_info_from_disk` — the original path.

`get_certificate_info` is the three-line dispatch between the last two.
"""
import re
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from modules.core.certificates import CertificateManager

pytestmark = [pytest.mark.unit]

REPO = Path(__file__).resolve().parent.parent

# Measured 11 for the backend path after the extraction, and ≤10 for the other
# three. The entry point is under 10 and must stay a dispatch.
ENTRY_CEILING = 10
UNIT_CEILING = 15

UNITS = ('_storage_retrieve', '_storage_key_state',
         '_certificate_info_from_backend', '_certificate_info_from_disk')


def _complexity_over(limit):
    """What flake8 reports over *limit*. The same instrument the gate uses."""
    result = subprocess.run(
        [sys.executable, '-m', 'flake8', 'modules/core/certificates.py',
         '--select=C901', f'--max-complexity={limit}'],
        cwd=REPO, capture_output=True, text=True, timeout=300)
    assert result.returncode in (0, 1), result.stderr
    pattern = re.compile(r".+?:\d+:\d+: C901 '(.+?)' is too complex \((\d+)\)")
    found = {}
    for line in result.stdout.splitlines():
        match = pattern.match(line.strip())
        assert match, f'unparsed flake8 line: {line}'
        found[match.group(1)] = int(match.group(2))
    return found


def _manager(storage_manager=None, tmp_path=None):
    settings = MagicMock()
    settings.load_settings.return_value = {}
    return CertificateManager(
        cert_dir=tmp_path or Path('/nonexistent'),
        settings_manager=settings,
        dns_manager=MagicMock(),
        storage_manager=storage_manager,
        ca_manager=None,
    )


# --- the ratchet -----------------------------------------------------------

def test_the_entry_point_is_a_dispatch():
    """THE ratchet. It was 28."""
    over = _complexity_over(ENTRY_CEILING)

    assert 'CertificateManager.get_certificate_info' not in over, (
        f"get_certificate_info is at "
        f"{over.get('CertificateManager.get_certificate_info')}; it is meant to "
        f"choose between the backend and the disk and nothing else")


def test_the_complexity_did_not_just_move():
    """CONTROL. Folding 28 into one helper would satisfy the test above and
    change nothing about the reason this was worth doing."""
    over = _complexity_over(UNIT_CEILING)

    for unit in UNITS:
        assert f'CertificateManager.{unit}' not in over, (
            f'{unit} is at {over[f"CertificateManager.{unit}"]}')


def test_the_entry_point_delegates_to_both_paths():
    import ast
    import inspect
    import textwrap

    source = inspect.getsource(CertificateManager.get_certificate_info)
    called = {node.func.attr
              for node in ast.walk(ast.parse(textwrap.dedent(source)))
              if isinstance(node, ast.Call)
              and isinstance(node.func, ast.Attribute)}

    assert '_certificate_info_from_backend' in called
    assert '_certificate_info_from_disk' in called


# --- the key-state rule, now a unit ---------------------------------------

def test_a_key_that_is_here_is_compared_not_believed():
    """cert.pem from one issuance beside privkey.pem from another cannot
    complete a handshake, so the pair is checked rather than counted."""
    manager = _manager()
    manager.key_state_for_bytes = MagicMock(return_value='mismatched')

    state = manager._storage_key_state(
        'example.com', {'cert.pem': b'CERT', 'privkey.pem': b'KEY'}, {})

    assert state == 'mismatched'
    manager.key_state_for_bytes.assert_called_once_with(
        'example.com', b'KEY', b'CERT', {})


def test_a_csr_only_certificate_says_external():
    """It has no key ANYWHERE and the metadata says so, so `unknown` would be
    honest and useless — and `missing` would reissue it nightly (#599)."""
    manager = _manager()

    state = manager._storage_key_state(
        'example.com', {'cert.pem': b'CERT'}, {'key_management': 'external'})

    assert state == 'external'


def test_a_backend_that_would_have_reported_a_key_means_it_is_gone():
    """THE #830 distinction. A backend that fetches everything and finds no
    key knows the key is gone."""
    backend = MagicMock()
    backend.info_includes_private_key.return_value = True
    manager = _manager(backend)

    state = manager._storage_key_state('example.com', {'cert.pem': b'CERT'}, {})

    assert state == 'missing'


def test_a_backend_that_never_looked_means_unknown():
    """The other half, and the one that matters more: reading "I did not look"
    as "it is gone" marks every certificate as needing renewal."""
    backend = MagicMock()
    backend.info_includes_private_key.return_value = False
    manager = _manager(backend)

    assert manager._storage_key_state(
        'example.com', {'cert.pem': b'CERT'}, {}) == 'unknown'


@pytest.mark.parametrize('answer', [
    'yes',        # a truthy non-True
    1,
    None,
    MagicMock(),  # a double that answers every attribute with another double
])
def test_only_a_literal_true_counts_as_knowing(answer):
    """`is True`, not truthiness. A backend that does not implement the
    question and a test double that answers everything both have to land on
    `unknown`, which is the safe side of being wrong."""
    backend = MagicMock()
    backend.info_includes_private_key.return_value = answer
    manager = _manager(backend)

    assert manager._storage_key_state(
        'example.com', {'cert.pem': b'CERT'}, {}) == 'unknown'


def test_a_backend_that_raises_the_question_is_unknown_too():
    backend = MagicMock()
    backend.info_includes_private_key.side_effect = RuntimeError('no')
    manager = _manager(backend)

    assert manager._storage_key_state(
        'example.com', {'cert.pem': b'CERT'}, {}) == 'unknown'


# --- the retrieve, and its shape ------------------------------------------

def test_the_cheap_info_path_is_used_when_it_answers_properly():
    backend = MagicMock()
    backend.retrieve_certificate_info.return_value = ({'cert.pem': b'C'}, {'a': 1})
    manager = _manager(backend)

    assert manager._storage_retrieve('example.com') == ({'cert.pem': b'C'}, {'a': 1})
    backend.retrieve_certificate.assert_not_called()


def test_an_answer_of_the_wrong_shape_falls_back_to_the_full_bundle():
    """Unpacking a malformed answer into two variables fails somewhere less
    obvious than here."""
    backend = MagicMock()
    backend.retrieve_certificate_info.return_value = {'cert.pem': b'C'}   # not a pair
    backend.retrieve_certificate.return_value = ({'cert.pem': b'FULL'}, {})
    manager = _manager(backend)

    assert manager._storage_retrieve('example.com') == ({'cert.pem': b'FULL'}, {})
    backend.retrieve_certificate.assert_called_once_with('example.com')


def test_no_certificate_is_not_a_fallback():
    """CONTROL: None from the cheap path means the backend does not hold it,
    which is different from answering badly. Fetching the whole bundle to
    confirm an absence would cost a round trip per missing certificate."""
    backend = MagicMock()
    backend.retrieve_certificate_info.return_value = None
    manager = _manager(backend)

    assert manager._storage_retrieve('example.com') is None
    backend.retrieve_certificate.assert_not_called()


def test_a_backend_without_the_cheap_path_uses_the_full_one():
    backend = MagicMock(spec=['retrieve_certificate', 'get_backend_name'])
    backend.retrieve_certificate.return_value = ({'cert.pem': b'C'}, {})
    manager = _manager(backend)

    assert manager._storage_retrieve('example.com') == ({'cert.pem': b'C'}, {})


# --- falling through to the disk ------------------------------------------

@pytest.mark.parametrize('name,configure', [
    ('the backend holds nothing',
     lambda b: setattr(b, 'retrieve_certificate_info', MagicMock(return_value=None))),
    ('the bundle has no cert.pem',
     lambda b: setattr(b, 'retrieve_certificate_info',
                       MagicMock(return_value=({'chain.pem': b'C'}, {})))),
    ('the backend raises',
     lambda b: setattr(b, 'retrieve_certificate_info',
                       MagicMock(side_effect=RuntimeError('down')))),
])
def test_every_decline_from_the_backend_reaches_the_disk(name, configure, tmp_path):
    """None for each of them, which is what makes the filesystem fallback
    reachable on exactly the conditions it was reachable on before. A method
    that raised instead would take the dashboard out whenever a backend was
    briefly unavailable."""
    backend = MagicMock()
    configure(backend)
    manager = _manager(backend, tmp_path)

    assert manager._certificate_info_from_backend(
        'example.com', {}, use_cache=False) is None, name


def test_the_entry_point_answers_from_disk_when_the_backend_declines(tmp_path):
    """End to end over the seam: no backend answer, and the result is the
    empty-certificate shape the disk path produces for a domain it does not
    hold — not None, and not an exception."""
    backend = MagicMock()
    backend.retrieve_certificate_info.return_value = None
    manager = _manager(backend, tmp_path)

    info = manager.get_certificate_info('absent.example.com', settings={})

    assert info is not None
    assert info['domain'] == 'absent.example.com'
    assert info['exists'] is False


def test_no_domain_is_still_none(tmp_path):
    """The one case that answers None, and it is the caller's mistake rather
    than an absence of information."""
    assert _manager(None, tmp_path).get_certificate_info('') is None
