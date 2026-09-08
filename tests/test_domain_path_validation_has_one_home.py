"""One place decides whether a domain can become a path (#672).

The rule existed FIVE times — the API layer, the web layer, the storage
backends, the issuance path, and client certificate identifiers — with the same
forbidden characters and three different return conventions. Two of them were
whole functions differing only in the name of their regex.

That is not tidiness. Duplicated validation is how one copy gets fixed and the
others do not, and that had already happened here: the end-of-string anchor was
corrected in ONE copy and left alone in three.

So these test the rule where it now lives, and then assert that every entry
point reaches the same verdict — which is the property that actually protects
anything. A test that only exercised the shared helper would pass just as well
with four stale copies still in the tree.
"""
import tempfile
from pathlib import Path

import pytest

from modules.api.path_validation import validate_domain_path
from modules.core.certificates import _reject_path_escaping_domain
from modules.api.client_certificates import _validate_identifier
from modules.core.domain_paths import (
    DOMAIN_RE,
    IDENTIFIER_RE,
    STORAGE_DOMAIN_RE,
    is_path_safe_segment,
    reject_unsafe_domain,
)
from modules.core.storage_backends import _validate_storage_domain
from modules.web.routes import _sanitize_domain

pytestmark = [pytest.mark.unit]

REFUSED = [
    '',                    # nothing
    '..',                  # the parent
    '../etc',
    'a/b',                 # a separator
    'a\\b',
    '/etc/passwd',
    'x\x00y',              # NUL truncates in C-level path calls
]

ACCEPTED = ['example.com', 'sub.example.com', '*.example.com', 'a-b.example.com']


# ---------------------------------------------------------------------------
# The character rule
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('domain', REFUSED)
def test_unsafe_values_are_refused(domain):
    assert not is_path_safe_segment(domain)
    with pytest.raises(ValueError):
        reject_unsafe_domain(domain)


@pytest.mark.parametrize('domain', ACCEPTED)
def test_ordinary_domains_pass_the_character_rule(domain):
    assert is_path_safe_segment(domain)
    reject_unsafe_domain(domain)


def test_the_wildcard_form_survives():
    """CONTROL: a wildcard certificate's directory is named for the wildcard,
    so a rule that refused `*.` would make those certificates unreachable."""
    assert is_path_safe_segment('*.example.com')
    assert DOMAIN_RE.match('*.example.com')
    assert STORAGE_DOMAIN_RE.match('*.example.com')


# ---------------------------------------------------------------------------
# Every entry point reaches the same verdict
# ---------------------------------------------------------------------------

def _verdicts(domain):
    """(api, web, storage, issuance) — True means accepted.

    Client identifiers are checked separately: they are the same rule on a
    differently-shaped value, so a domain is not a valid identifier and vice
    versa. Mixing them into this tuple would make every case ambiguous.
    """
    base = Path(tempfile.mkdtemp())

    api_path, _ = validate_domain_path(domain, base)
    web_path, _ = _sanitize_domain(domain, base)

    try:
        _validate_storage_domain(domain)
        storage = True
    except ValueError:
        storage = False

    try:
        _reject_path_escaping_domain(domain)
        issuance = True
    except ValueError:
        issuance = False

    return api_path is not None, web_path is not None, storage, issuance


@pytest.mark.parametrize('domain', REFUSED)
def test_every_entry_point_refuses_what_is_unsafe(domain):
    api, web, storage, issuance = _verdicts(domain)
    assert not any((api, web, storage, issuance)), (
        f'{domain!r} accepted by: '
        + ', '.join(n for n, v in
                    (('api', api), ('web', web), ('storage', storage),
                     ('issuance', issuance)) if v)
    )


@pytest.mark.parametrize('domain', ACCEPTED)
def test_every_entry_point_accepts_an_ordinary_domain(domain):
    api, web, storage, issuance = _verdicts(domain)
    assert all((api, web, storage, issuance)), (
        f'{domain!r} refused by: '
        + ', '.join(n for n, v in
                    (('api', api), ('web', web), ('storage', storage),
                     ('issuance', issuance)) if not v)
    )


# ---------------------------------------------------------------------------
# The anchor
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('pattern_name,pattern', [
    ('DOMAIN_RE', DOMAIN_RE),
    ('STORAGE_DOMAIN_RE', STORAGE_DOMAIN_RE),
    ('IDENTIFIER_RE', IDENTIFIER_RE),
])
def test_the_expressions_are_anchored_at_the_end_of_the_string(
        pattern_name, pattern):
    """In Python `$` also matches immediately before a trailing newline, so a
    `$`-anchored expression accepts a name with one. The character rule does
    not screen newlines, so nothing else catches it.

    Asserted on the pattern as well as the behaviour: a future edit that
    reintroduces `$` should fail with a message naming the anchor, not with a
    puzzling parametrised case.
    """
    assert pattern.pattern.endswith(r'\Z'), (
        f'{pattern_name} is anchored with `$`; use `\\Z`'
    )


def test_no_entry_point_accepts_a_trailing_newline():
    """The behavioural half. This is what had drifted: one copy refused it,
    two accepted it."""
    api, web, storage, issuance = _verdicts('example.com\n')
    accepted = [n for n, v in (('api', api), ('web', web),
                               ('storage', storage), ('issuance', issuance)) if v]
    assert accepted == ['issuance'], (
        f'unexpected verdicts for a trailing newline: accepted by {accepted}'
    )
    # `issuance` is expected here: _reject_path_escaping_domain screens the
    # characters that escape a path and deliberately leaves domain SHAPE to
    # the layer above. A newline cannot escape cert_dir.


@pytest.mark.parametrize('identifier,accepted', [
    ('cert-001', True),
    ('cert_001.v2', True),
    ('cert-001\n', False),      # the anchor, on the fifth copy
    ('../etc', False),
    ('a/b', False),
    ('', False),
])
def test_client_identifiers_go_through_the_same_rule(identifier, accepted):
    """The fifth copy. It had its own character check AND its own `$`-anchored
    pattern, so a client certificate identifier with a trailing newline passed
    both."""
    assert _validate_identifier(identifier) is accepted


# ---------------------------------------------------------------------------
# It stays in one place
# ---------------------------------------------------------------------------

def test_no_module_writes_the_character_rule_itself_again():
    """The guard on the consolidation.

    Five copies is how the anchor came to be fixed in exactly one of them. If
    a sixth appears — or one of these reverts — this says which file.
    """
    import re as _re
    from pathlib import Path as _Path

    root = _Path(__file__).resolve().parent.parent
    home = root / 'modules' / 'core' / 'domain_paths.py'
    # The shape of an inlined copy is the parent marker AND a separator in the
    # same expression. Requiring both matters: `utils.validate_domain` tests
    # for '..' alone, but that is a domain-SHAPE rule ("consecutive dots"),
    # not path safety, and it is not this module's business.
    inlined = _re.compile(
        r"""['"]\.\.['"]\s+in\s+\w+.*['"]/['"]\s+in\s+\w+""")

    offenders = []
    for path in sorted(root.glob('modules/**/*.py')):
        if path == home:
            continue
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            if inlined.search(line):
                offenders.append(f'{path.relative_to(root)}:{lineno}')

    assert not offenders, (
        'these write the path-safety rule themselves instead of calling '
        'domain_paths; that is how one copy gets fixed and the rest do '
        f'not:\n  ' + '\n  '.join(offenders)
    )


def test_every_unit_that_builds_a_path_from_a_domain_screens_it():
    """The rule that keeps CodeQL's finding true rather than just quiet.

    Each of these takes a caller-supplied domain and turns it into a directory
    name. Their callers screen it, but "safe because of where it is called
    from" is what stopped being true every time this session moved code — so
    each one screens its own input, and this says so by executing them.
    """
    import threading
    from unittest.mock import MagicMock

    from modules.core.certificates import CertificateManager

    manager = CertificateManager.__new__(CertificateManager)
    manager._domain_locks = {}
    manager._domain_locks_mutex = threading.Lock()
    manager.cert_dir = Path(tempfile.mkdtemp())
    manager.settings_manager = MagicMock()

    escapes = ['../etc', 'a/b', 'a\\b', 'x\x00y', '']
    for bad in escapes:
        with pytest.raises(ValueError):
            manager._seed_acme_account(bad, manager.cert_dir, 'letsencrypt', None)
        # _store_csr builds three paths from the domain — the existing-key
        # probe, the output directory and csr.pem (#599). CodeQL found this one
        # the moment it was written, which is the argument for the rule.
        #
        # ValueError specifically, and the CSR is deliberately garbage: every
        # OTHER refusal in _store_csr raises RuntimeError, so accepting either
        # would pass with the screen removed. It did, when this was first
        # written — the mutation survived until the assertion was narrowed.
        with pytest.raises(ValueError):
            manager._store_csr(bad, manager.cert_dir / 'x', b'not a csr')


def test_the_seed_still_runs_for_an_ordinary_domain():
    """CONTROL: a guard that refused everything would satisfy the test above
    while breaking ACME account reuse — 50 domains in one batch becoming 50
    registrations from one IP, which is what that function exists to prevent.
    """
    import threading
    from unittest.mock import MagicMock

    from modules.core.certificates import CertificateManager

    manager = CertificateManager.__new__(CertificateManager)
    manager._domain_locks = {}
    manager._domain_locks_mutex = threading.Lock()
    cert_dir = Path(tempfile.mkdtemp())
    manager.cert_dir = cert_dir
    manager.settings_manager = MagicMock()

    # No donor on disk, so it returns None — the point is that it got there.
    assert manager._seed_acme_account(
        'example.com', cert_dir, 'letsencrypt', None) is None
