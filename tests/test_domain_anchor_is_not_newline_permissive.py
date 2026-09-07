"""A domain validator must not accept a domain with a newline on the end.

Python's `$` matches at the end of the string OR immediately before a trailing
newline. Both domain patterns in this project were anchored with `$`, so
"example.com\\n" satisfied a check whose failure message is "Invalid domain
format" — and the character screen beside it does not look at newlines either,
so nothing else caught it.

Neither was exploitable when found. In the API path validator the resolved path
still lands under the certificate directory, so it is a 404 rather than an
escape; in the allowed_domains validator the caller strips each entry before
matching. The second is inert by accident, which is the reason to fix it: the
next caller need not strip.

Anchored with `\\Z` now, and pinned here — `$` is the natural thing to write,
so this will be reintroduced by someone who has not met this behaviour.
"""
import tempfile

import pytest

from modules.api.path_validation import DOMAIN_RE, validate_domain_path
from modules.core.auth import AuthManager

pytestmark = [pytest.mark.unit]

REAL_DOMAINS = [
    'example.com',
    '*.example.com',
    'sub.example.co.uk',
    'xn--bcher-kva.example.com',
    'a-b.example.com',
]

TRAILING = ['example.com\n', 'example.com\r', 'example.com\n\n', '*.example.com\n']


@pytest.mark.parametrize('domain', REAL_DOMAINS)
def test_real_domains_are_still_accepted(domain):
    """CONTROL first: tightening an anchor is the kind of change that quietly
    starts refusing legitimate input, and here that would make a certificate
    unreachable."""
    assert DOMAIN_RE.match(domain), f'{domain!r} was refused'
    assert AuthManager._ALLOWED_DOMAIN_RE.match(domain), f'{domain!r} was refused'


@pytest.mark.parametrize('domain', TRAILING)
def test_a_trailing_newline_is_not_a_domain(domain):
    assert not DOMAIN_RE.match(domain), (
        f'{domain!r} matched the API domain pattern; the anchor is `$` again, '
        f'which matches before a trailing newline'
    )
    assert not AuthManager._ALLOWED_DOMAIN_RE.match(domain), (
        f'{domain!r} matched the allowed_domains pattern; the anchor is `$` '
        f'again'
    )


@pytest.mark.parametrize('domain', TRAILING)
def test_the_path_validator_refuses_it_too(domain):
    """The regex is not reached directly by callers — this is."""
    path, err = validate_domain_path(domain, tempfile.gettempdir())
    assert path is None and err, f'{domain!r} produced a path: {path}'


def test_a_real_domain_still_produces_a_path():
    """CONTROL: a validator that refused everything would satisfy the above."""
    path, err = validate_domain_path('example.com', tempfile.gettempdir())
    assert err is None and path is not None
