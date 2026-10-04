"""What create accepts, every other route must be able to name.

`utils.validate_domain` screens the domain on create and reissue; every route
that later reads, patches, deploys or deletes the certificate screens it with
`DOMAIN_RE` through `validate_domain_path`. The two disagreed on one point: the
TLD was checked with `isalpha()`, which is true for any Unicode letter, so
`example.cοm` (a Greek omicron) passed create and was refused everywhere
else. Run against the published 2.48.0 image, create made the directory,
certbot refused the name ("Non-ASCII domain names not supported"), and the
directory stayed: not in `GET /api/certificates`, and `DELETE` answered 400.
"""
import pytest

from modules.core.domain_paths import DOMAIN_RE
from modules.core.utils import validate_domain

pytestmark = [pytest.mark.unit]


@pytest.mark.parametrize('domain', [
    'example.cοm',      # Greek omicron in the TLD
    'example.çom',      # c-cedilla
    'example.сom',      # Cyrillic es
    'a.cöm',            # o-umlaut
    'example.ｃom',      # fullwidth c
])
def test_a_tld_with_a_non_ascii_letter_is_refused(domain):
    ok, message = validate_domain(domain)
    assert not ok, f'{domain!r} was accepted as {message!r}'
    assert 'Top-Level Domain' in message


@pytest.mark.parametrize('domain', [
    'example.com',
    'EXAMPLE.COM',
    '*.example.com',
    'a.b.example.co',
    'xn--exmple-cua.com',
    'https://example.org/path',
    'example.com.',
    'example.cοm',
    'exämple.com',
    'example.çom',
    'example.c0m',
    'example.c',
])
def test_what_create_accepts_the_path_rule_accepts(domain):
    """Agreement in the direction that strands a directory: anything create
    accepts must pass DOMAIN_RE, or no later route can reach it. (The other
    direction is allowed to differ: create normalises a URL and a trailing dot,
    which DOMAIN_RE was never asked to.)"""
    ok, result = validate_domain(domain)
    if ok:
        assert DOMAIN_RE.match(result), (
            f'create accepts {domain!r} as {result!r}, which every later route '
            f'refuses'
        )


def test_an_ascii_name_still_passes():
    """CONTROL: the change must not refuse the names it exists to let through."""
    assert validate_domain('shop.example.com') == (True, 'shop.example.com')
    assert validate_domain('*.example.com') == (True, '*.example.com')
    assert validate_domain('xn--exmple-cua.com') == (True, 'xn--exmple-cua.com')
