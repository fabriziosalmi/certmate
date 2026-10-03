"""One form for every date-time the API answers with (#1127): ISO 8601, UTC, with a `Z`.

Measured on the route walk before this: of the 55 date-time fields in API answers, 39 were ISO
8601 without an offset (`2026-10-02T22:26:14.669591`), 2 the space form `expiry_date`, 9 had a
`Z` and 5 `+00:00`, mixed inside single answers (`POST /api/keys` had `created_at` without an
offset and `expires_at` with one). The values without an offset were UTC, written naive on
purpose so the files on disk keep the form older versions wrote; a caller could not know that,
and `datetime.fromisoformat()` and `new Date()` both read them as local time.

The files on disk keep their form. The answer is rewritten on its way out, in one place, for the
fields this module names: a value with no offset, or with `+00:00`, gets the `Z`. Named fields
only, never every string that looks like a date: an operator's note can hold a date and is not
one. `expiry_date` keeps its own form (`2026-11-30 09:17:11`), which clients parse today; it is
deprecated, and `expires_at` carries the same instant in this form.

tests/test_one_form_for_every_date_time.py walks every route and fails on a date-time in any
answer that is not in this form, so a new field is named here or the test says which.
"""
import json
import re

# The leaf names of the fields that carry a date-time, wherever they sit in an answer.
TIMESTAMP_KEYS = frozenset({
    'timestamp', 'created', 'created_at', 'renewed_at', 'expires_at', 'revoked_at',
    'superseded_at', 'submitted_at', 'started_at', 'finished_at', 'first_seen', 'last_seen',
    'checked_at', 'generated_at', 'exported_at', 'probed_at', 'this_update', 'next_update',
    'last_update', 'not_before', 'not_after', 'window_start', 'window_end', 'renew_at',
    'renews_at', 'acme_profile_withdrawn_at', 'updated_at', 'last_used_at', 'confirmed_at',
})

_NAIVE_OR_ZERO_OFFSET = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)(?:[+-]00:00)?$')


def with_z(value):
    """`2026-10-02T22:26:14.669591` or `...+00:00` -> `...Z`; anything else unchanged."""
    if not isinstance(value, str):
        return value
    match = _NAIVE_OR_ZERO_OFFSET.match(value)
    return match.group(1) + 'Z' if match else value


def normalize(payload):
    """(payload, changed): every named date-time field in `payload`, at any depth, in the one form."""
    changed = False

    def visit(node):
        nonlocal changed
        if isinstance(node, dict):
            for key, value in node.items():
                if key in TIMESTAMP_KEYS and isinstance(value, str):
                    new = with_z(value)
                    if new != value:
                        node[key] = new
                        changed = True
                else:
                    visit(value)
        elif isinstance(node, list):
            for item in node:
                visit(item)

    visit(payload)
    return payload, changed


def apply_timestamp_form(app):
    """Rewrite the date-times of every JSON answer under /api/ on its way out. A response that
    carries none, or is not JSON, or is streamed, is passed through untouched."""
    from flask import request

    @app.after_request
    def _one_form(response):
        if (not request.path.startswith('/api/') or response.is_streamed
                or response.direct_passthrough or response.mimetype != 'application/json'):
            return response
        try:
            payload = json.loads(response.get_data())
        except ValueError:
            return response
        payload, changed = normalize(payload)
        if changed:
            response.set_data(json.dumps(payload) + '\n')
        return response
