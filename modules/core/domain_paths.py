"""Turning a caller-supplied domain into a path, safely — in one place (#672).

These rules existed **four** times: here (as `modules/api/path_validation`),
in `modules/web/routes._sanitize_domain`, in
`modules/core/storage_backends._validate_storage_domain`, and in
`modules/core/certificates._reject_path_escaping_domain`. Same character set in
all four, three different return conventions, and two of them whole functions
that differed only in the name of their regex.

That is not a tidiness problem. Duplicated *security* validation is how one
copy gets fixed and the others do not, which is exactly what had happened: the
`\\Z` anchor below was corrected once and left as `$` in two of the copies.

It lives in `modules/core/` rather than `modules/api/` because `web` and
`storage_backends` both need it, and having core import from api would deepen
the layering inversion in #668.

The rules, in the order they are applied:

1. reject the separators and NUL outright — cheap, and unambiguous;
2. require a plausible domain shape;
3. confirm the resolved path is still under the certificate directory.

The last is the one that matters. The first two can be reasoned about;
``resolve()`` is what actually answers the question once symlinks and ``..``
have been taken into account.
"""
import os
import re
from pathlib import Path

# Characters that make a domain unusable as a single path segment. Kept as a
# tuple rather than inlined so the rule has one definition and the callers
# that raise, the callers that return an error pair, and the callers that only
# ask a yes/no question all apply the same one.
_PATH_UNSAFE = ('..', '/', '\\', '\x00')

# Note the leading `*.` alternative: a wildcard certificate's directory is
# named for the wildcard, so refusing it here would make those certificates
# unreachable.
#
# `\Z`, not `$`. In Python `$` also matches immediately BEFORE a trailing
# newline, so a `$`-anchored expression accepts "example.com\n" as a valid
# domain — and the character check above does not screen newlines either, so
# nothing else catches it. That name is not a traversal (the resolved path
# still sits under the certificate directory) but it is not a domain, and a
# validator that reports "Invalid domain format" for everything else should not
# make an exception for it.
DOMAIN_RE = re.compile(
    r'^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\Z')

# Storage backends key secrets by domain and accept a wider shape than a
# certificate directory does (dots and underscores inside, up to 253 chars).
# Different rule, same anchor: the reason `$` is wrong does not depend on which
# characters are allowed.
STORAGE_DOMAIN_RE = re.compile(
    r'^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9._-]{0,253}[a-zA-Z0-9])?\Z')


# Client certificate identifiers are a different shape from domains but the
# same kind of value: a caller-supplied string that becomes a directory name.
# `\Z` for the same reason as the two above — this expression was anchored with
# `$` and accepted a trailing newline.
IDENTIFIER_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}\Z')


def is_path_safe_segment(value):
    """True when *value* can be used as one path segment.

    The single definition of the character rule. Says nothing about whether the
    value looks like a domain — that is ``DOMAIN_RE``'s job — only that it
    cannot escape or split a path.

    Named for the segment rather than the domain because client certificate
    identifiers go through it too: same rule, same consequence, different kind
    of name.
    """
    if not value:
        return False
    return not any(bad in value for bad in _PATH_UNSAFE)


def reject_unsafe_domain(domain, message='Invalid domain name'):
    """Raise ``ValueError`` unless *domain* is safe as a path segment.

    For call sites that cannot carry an error value — deep inside issuance,
    where reaching the sink with path characters means something upstream
    already failed and the request must not proceed.
    """
    if not is_path_safe_segment(domain):
        raise ValueError(message)


def validate_domain_path(domain, cert_base_dir):
    """Validate a domain used as a directory name. Returns ``(Path, error)``.

    On refusal the path is ``None`` and the caller must not fall back to
    building one itself — that is the whole point of returning a pair.
    """
    if not is_path_safe_segment(domain):
        return None, 'Invalid domain name'
    if not DOMAIN_RE.match(domain):
        return None, 'Invalid domain format'
    cert_dir = Path(cert_base_dir) / domain
    try:
        resolved = cert_dir.resolve()
        base_resolved = Path(cert_base_dir).resolve()
        if not str(resolved).startswith(str(base_resolved) + os.sep) \
                and resolved != base_resolved:
            return None, 'Invalid domain path'
    except (OSError, ValueError):
        return None, 'Invalid domain path'
    return cert_dir, None
