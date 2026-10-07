"""A name that is a path cannot make a storage or delete method leave the certificate root.

The methods that take a certificate's name and turn it into a directory (or, in
the other stores, a key or a path) trusted their callers. The callers did
validate, so nothing reached them with a bad name, but the rule was kept at the
doors and not at the sink, and a sink that is not guarded is one new caller away
from being reached. The rest of the application already works the other way:
`create_certificate`, `renew_certificate` and the five others call
`_reject_path_escaping_domain` themselves, and the remote backends call
`_validate_storage_domain` when they store. These did not:

* `CertificateManager.delete_certificate`, which removes the directory;
* the four methods of `LocalFileSystemBackend` (store, retrieve, exists,
  delete), the default backend;
* `StorageManager`, which dispatches to every backend, and through which the
  retrieve, delete and exists of the remote ones were unguarded.

A table of hostile names is tried against each, with a directory beside the
certificate root that holds files that must stay as they are and that must not
be read back. Every public method of `CertificateManager` that takes a domain is
then tried the same way, found by introspection, so a method added later is
covered without anyone remembering to add it.
"""
import ast
import inspect
import pathlib
import threading
from unittest.mock import MagicMock

import pytest

from modules.core import storage_backends
from modules.core.certificates import CertificateManager
from modules.core.storage_backends import LocalFileSystemBackend, StorageManager

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent

HOSTILE = ['../outside', '../outside/', '..', '.', 'a/b', 'x\\y', 'foo\x00bar', 'a/../../outside',
           '..\\outside', 'https://example.com/../../outside', 'ABSOLUTE']
LEGITIMATE = ['example.com', '*.example.com', 'sub.example.org', 'xn--bcher-kva.example']


def _snapshot(root):
    return {str(p.relative_to(root)): (p.read_bytes() if p.is_file() else None) for p in sorted(root.rglob('*'))}


@pytest.fixture
def sandbox(tmp_path):
    """`certificates/` is the root; `outside/` is beside it and holds a certificate's files."""
    root = tmp_path / 'certificates'
    root.mkdir()
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'cert.pem').write_bytes(b'CANARY-CERT')
    (outside / 'privkey.pem').write_bytes(b'CANARY-KEY')
    (outside / 'metadata.json').write_bytes(b'{"canary": true}')
    return tmp_path, root, outside


def _name(bad, outside):
    return str(outside) if bad == 'ABSOLUTE' else bad


# --- the local backend ----------------------------------------------------------------------------------

@pytest.mark.parametrize('bad', HOSTILE)
def test_the_local_backend_refuses_a_name_that_leaves_its_root(sandbox, bad):
    tmp, root, outside = sandbox
    backend = LocalFileSystemBackend(root)
    name = _name(bad, outside)
    before = _snapshot(tmp)

    assert backend.store_certificate(name, {'cert.pem': b'REPLACED'}, {'replaced': True}) is False
    assert backend.retrieve_certificate(name) is None, 'files came back from outside the certificate root'
    assert backend.certificate_exists(name) is False
    assert backend.delete_certificate(name) is False

    assert _snapshot(tmp) == before


@pytest.mark.parametrize('name', LEGITIMATE)
def test_the_local_backend_still_serves_a_name_that_belongs_to_it(sandbox, name):
    """CONTROL: the guard is not simply refusing everything."""
    _, root, _ = sandbox
    backend = LocalFileSystemBackend(root)

    assert backend.store_certificate(name, {'cert.pem': b'C', 'privkey.pem': b'K'}, {'a': 1}) is True
    assert backend.certificate_exists(name) is True
    files, metadata = backend.retrieve_certificate(name)
    assert files == {'cert.pem': b'C', 'privkey.pem': b'K'} and metadata == {'a': 1}
    assert backend.delete_certificate(name) is True
    assert backend.certificate_exists(name) is False


# --- the manager that dispatches to every backend -----------------------------------------------------

@pytest.fixture
def dispatching(monkeypatch):
    backend = MagicMock()
    manager = StorageManager.__new__(StorageManager)
    monkeypatch.setattr(StorageManager, 'get_backend', lambda self: backend)
    return manager, backend


@pytest.mark.parametrize('bad', [b for b in HOSTILE if b != 'ABSOLUTE'])
def test_the_storage_manager_does_not_hand_a_bad_name_to_any_backend(dispatching, bad):
    manager, backend = dispatching

    assert manager.store_certificate(bad, {}, {}) is False
    assert manager.retrieve_certificate(bad) is None
    assert manager.retrieve_certificate_info(bad) is None
    assert manager.delete_certificate(bad) is False
    assert manager.certificate_exists(bad) is False

    assert backend.method_calls == [], backend.method_calls


def test_the_storage_manager_still_hands_a_good_name_to_the_backend(dispatching):
    """CONTROL."""
    manager, backend = dispatching

    manager.store_certificate('example.com', {}, {})
    manager.retrieve_certificate('example.com')
    manager.retrieve_certificate_info('example.com')
    manager.delete_certificate('example.com')
    manager.certificate_exists('example.com')

    assert [call[0] for call in backend.method_calls] == [
        'store_certificate', 'retrieve_certificate', 'retrieve_certificate_info',
        'delete_certificate', 'certificate_exists']


# --- the certificate manager ------------------------------------------------------------------------------

def _certificate_manager(root):
    manager = CertificateManager.__new__(CertificateManager)
    manager._domain_locks = {}
    manager._domain_locks_mutex = threading.Lock()
    manager.cert_dir = root
    manager.storage_manager = None
    manager.settings_manager = MagicMock()
    manager._invalidate_certificate_info_cache = lambda *args, **kwargs: None
    return manager


@pytest.mark.parametrize('bad', HOSTILE)
def test_delete_certificate_refuses_a_name_that_leaves_the_root(sandbox, bad):
    tmp, root, outside = sandbox
    manager = _certificate_manager(root)
    before = _snapshot(tmp)

    with pytest.raises(ValueError, match='Invalid domain name'):
        manager.delete_certificate(_name(bad, outside))

    assert _snapshot(tmp) == before
    assert outside.is_dir()


def test_delete_certificate_still_deletes_what_is_inside_the_root(sandbox):
    """CONTROL."""
    _, root, _ = sandbox
    (root / 'example.com').mkdir()
    (root / 'example.com' / 'cert.pem').write_bytes(b'C')
    manager = _certificate_manager(root)

    assert manager.delete_certificate('example.com') is True
    assert not (root / 'example.com').exists()


# Methods that take a domain and do nothing with the filesystem or are answered
# by a refusal of their own; the table below is for the rest. One reason each.
NOT_ABOUT_THE_FILESYSTEM = {
    'check_dns_alias_records': 'looks names up in DNS and writes nothing',
    'domain_lock': 'returns a context manager over an in-memory lock',
    'every_name_matches': 'compares names with a scope',
    'key_state_for_bytes': 'takes the key bytes and not a path',
}


def test_every_public_method_that_takes_a_domain_leaves_the_tree_alone_for_a_bad_one(tmp_path_factory):
    names = [n for n, f in inspect.getmembers(CertificateManager, inspect.isfunction)
             if not n.startswith('_') and 'domain' in inspect.signature(f).parameters
             and n not in NOT_ABOUT_THE_FILESYSTEM]

    assert len(names) >= 10, f'only {len(names)} methods found: the introspection has lost its subject'
    touched = []
    for name in names:
        tmp = tmp_path_factory.mktemp(name)
        root = tmp / 'certificates'
        root.mkdir()
        outside = tmp / 'outside'
        outside.mkdir()
        (outside / 'cert.pem').write_bytes(b'CANARY')
        (outside / 'metadata.json').write_bytes(b'{"canary": true}')
        manager = _certificate_manager(root)
        before = _snapshot(tmp)
        method = getattr(manager, name)
        arguments = {}
        for parameter, spec in inspect.signature(method).parameters.items():
            if parameter == 'domain':
                arguments[parameter] = '../outside'
            elif spec.default is inspect.Parameter.empty:
                arguments[parameter] = 'a@example.com' if parameter == 'email' else MagicMock()
        try:
            method(**arguments)
        except Exception:                       # a refusal, or a failure on the stand-ins: either is fine
            pass
        if _snapshot(tmp) != before:
            touched.append(name)

    assert touched == [], f'these changed files outside the certificate root for the name `../outside`: {touched}'


# --- what the sinks are held to ------------------------------------------------------------------------

def _functions(path):
    tree = ast.parse((REPO / path).read_text(encoding='utf-8'))
    return {(cls.name, fn.name): fn for cls in tree.body if isinstance(cls, ast.ClassDef)
            for fn in cls.body if isinstance(fn, ast.FunctionDef)}


def _asks(function, helper):
    return any(isinstance(n, ast.Call) and getattr(n.func, 'id', '') == helper for n in ast.walk(function))


def test_the_sinks_ask_before_they_act():
    """Pinned by name: the next method added to these classes that takes a name has to be added
    here, which is when someone decides whether it asks."""
    storage = _functions('modules/core/storage_backends.py')
    certificates = _functions('modules/core/certificates.py')

    unguarded = [f'{cls}.{fn}' for cls, fn in [
        ('LocalFileSystemBackend', 'store_certificate'), ('LocalFileSystemBackend', 'retrieve_certificate'),
        ('LocalFileSystemBackend', 'certificate_exists'), ('LocalFileSystemBackend', 'delete_certificate'),
        ('StorageManager', 'store_certificate'), ('StorageManager', 'retrieve_certificate'),
        ('StorageManager', 'retrieve_certificate_info'), ('StorageManager', 'delete_certificate'),
        ('StorageManager', 'certificate_exists'),
    ] if not _asks(storage[(cls, fn)], '_acceptable_storage_name')]
    unguarded += ['CertificateManager.delete_certificate'
                  for _ in [0] if not _asks(certificates[('CertificateManager', 'delete_certificate')],
                                            '_reject_path_escaping_domain')]

    assert unguarded == [], f'these take a name, build a path or a key from it and do not ask first: {unguarded}'


def test_the_structural_check_does_see_a_method_that_does_not_ask():
    """CONTROL: against source where one method asks and one does not."""
    tree = ast.parse('def asks(d):\n    _acceptable_storage_name(d, "x")\n\ndef does_not(d):\n    return d\n')
    asking, silent = tree.body

    assert _asks(asking, '_acceptable_storage_name') and not _asks(silent, '_acceptable_storage_name')
    assert hasattr(storage_backends, '_acceptable_storage_name')


# --- the validator every route asks first -------------------------------------------------------------

@pytest.mark.parametrize('name', ['example.com\n', 'example.com\r\nERROR forged', 'example.com\r', '\nexample.com',
                                  'example.com\x1b[31m', 'example.com' + chr(0x2028) + 'x', 'exa\tmple.com'])
def test_the_route_validator_refuses_a_name_with_a_line_break_or_a_control_character(tmp_path, name):
    """A route logs the domain it was given after this has accepted it. Code scanning cannot see
    that, and asks whether the value can end a log line. It cannot: the pattern is anchored with
    `\\Z`, where `$` would let a trailing newline through (it did once)."""
    from modules.api.path_validation import validate_domain_path

    path, error = validate_domain_path(name, tmp_path)

    assert path is None and error


def test_the_route_validator_accepts_a_plain_name(tmp_path):
    """CONTROL."""
    from modules.api.path_validation import validate_domain_path

    path, error = validate_domain_path('example.com', tmp_path)

    assert path is not None and not error
