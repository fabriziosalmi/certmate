"""What `validate_domain` gives back can be joined to a path and written to a log.

The dashboard's create and batch routes read the domain from `request.json`.
CodeQL follows it from there to the certificate directory and to log lines in
`certificates.py` and `storage_backends.py`, and reports path and log
injection there, because it does not read `validate_domain` as a sanitizer.

Every such flow passes `prepare_create`, which keeps only the name
`validate_domain` returns and raises on the other branch. So the property those
reports are dismissed against is the one pinned here: whatever comes in, the
name that comes back holds only lower-case letters, digits, hyphens and dots,
with an optional leading `*.`. No separator, no `..`, no line break.
"""
import re

import pytest

from modules.core.utils import validate_domain

pytestmark = [pytest.mark.unit]

# A bare host name, as a path segment and as a log value.
CLEAN = re.compile(r'(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,}\Z')

HOSTILE = [
    'example.com\n', 'example.com\r\n', '\nexample.com', 'a\nb.example.com', 'a\rb.example.com',
    'example.com\nINFO forged entry', 'example.co\nm', 'exa mple.com', 'example.com\t',
    '../example.com', '..', '.', 'example..com', 'x/y.example.com', '/abs.example.com',
    'x\\y.example.com', 'example.com/../../etc/passwd', 'https://x.example.com/../../etc',
    'https://x.example.com:443/', 'https://user@x.example.com/', 'file:///etc/passwd',
    'example.com\x00', 'EXAMPLE.COM', '*.example.com', '*.*.example.com', 'xn--bcher-kva.example',
    'example.c\N{GREEK SMALL LETTER OMICRON}m', 'example.com.', 'example.com..',
]


@pytest.mark.parametrize('raw', HOSTILE)
def test_a_name_is_refused_or_comes_back_clean(raw):
    ok, value = validate_domain(raw)
    if ok:
        assert CLEAN.match(value), repr(value)


@pytest.mark.parametrize('raw', [
    'a\nb.example.com', 'a\rb.example.com', 'example.com\nINFO forged entry',
    'example.co\nm', 'x/y.example.com', 'x\\y.example.com', '../example.com', 'example.com\x00x',
])
def test_a_line_break_or_a_separator_inside_a_name_is_refused(raw):
    ok, _ = validate_domain(raw)
    assert ok is False, raw


def test_the_value_a_failure_returns_is_a_message_and_not_a_name():
    """The second element on the failure branch is an error message that can
    carry the raw input. `prepare_create` raises with it and never uses it as a
    name; this is the branch CodeQL follows into the sinks without seeing the
    raise."""
    ok, value = validate_domain('a\nb.example.com')
    assert ok is False
    assert not CLEAN.match(value)
