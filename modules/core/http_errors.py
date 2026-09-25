"""The machine-readable half of an HTTP-level error body.

One function, in its own module, because of where it used to live. It was
defined in `core/factory.py` — the composition root — and
`api/client_certificates.py` imported it back from there, which is the return
leg of the import cycle #668 is about: `core` imports `api` and `web` to
compose them, and `api` imported `core.factory` for this.

The cycle was one function wide. Nothing about deriving `NOT_FOUND` from 404
belongs to the composition root, so it stops being reachable only through it.
"""

import re


def error_code_for_status(status, name=None):
    """The symbolic `code` for an HTTP-level failure, e.g. 404 -> NOT_FOUND.

    `code` is the machine-readable half of an error body and it is a string
    everywhere the application produces one: CERTIFICATE_NOT_FOUND,
    DOMAIN_OUT_OF_SCOPE, ACME_RATE_LIMITED. The two handlers below used to put
    the HTTP status INTEGER in the same field, so one API answered with two
    incompatible types under one name and a client could not branch on it
    without type-checking first — while the SDK this repository publishes
    already documented it as "CertMate's machine-readable error code (e.g.
    DOMAIN_OUT_OF_SCOPE) when present".

    Derived from Werkzeug's own name so a status this function has never seen
    still produces a usable symbol rather than falling back to a number. The
    HTTP status itself is not lost: it is the status line, and it stays in
    `status` for the handlers that carry it.
    """
    text = (name or '').strip()
    if not text:
        return f'HTTP_{status}'
    return re.sub(r'[^A-Z0-9]+', '_', text.upper()).strip('_') or f'HTTP_{status}'
