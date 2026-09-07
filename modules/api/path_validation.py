"""Turning a caller-supplied domain into a path, safely.

Extracted from `resources.py` (#667). It sat there because that is where the
endpoints are, and it is called from thirteen of them — which is exactly why it
had to move: a resource group in a module of its own could not reach it without
importing `resources.py`, which imports the group back.

Nothing here is new. The rules are the ones the endpoints have always applied,
in the order they applied them: reject the separators and NUL outright, then
require a plausible domain, then confirm the resolved path is still under the
certificate directory. The last check is the one that matters — the first two
can be reasoned about, while `resolve()` is what actually answers the question
after symlinks and `..` have been taken into account.
"""
import os
import re
from pathlib import Path

# Note the leading `*.` alternative: a wildcard certificate's directory is
# named for the wildcard, so refusing it here would make those certificates
# unreachable.
#
# `\Z`, not `$`. In Python `$` also matches immediately BEFORE a trailing
# newline, so the previous expression accepted "example.com\n" as a valid
# domain — and the character check below does not screen newlines either,
# so nothing else caught it. That name is not a traversal (the resolved path
# still sits under the certificate directory) but it is not a domain, and a
# validator that reports "Invalid domain format" for everything else should
# not make an exception for it.
DOMAIN_RE = re.compile(
    r'^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\Z')


def validate_domain_path(domain, cert_base_dir):
    """Validate a domain used as a directory name. Returns ``(Path, error)``.

    On refusal the path is ``None`` and the caller must not fall back to
    building one itself — that is the whole point of returning a pair.
    """
    if not domain or '..' in domain or '/' in domain or '\\' in domain \
            or '\x00' in domain:
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
