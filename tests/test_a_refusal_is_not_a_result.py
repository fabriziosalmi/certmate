"""A rejected request must answer like a rejection, not like an empty result.

`GET /api/certificates` without a credential returned 401 with this body:

    {"domain": null, "exists": null, "expiry_date": null, "days_left": null, ...}

Every field of a certificate, all null. Not `{"error": ..., "code": ...}`. A
client reading the body rather than the status sees a certificate object whose
fields are merely unknown, which is the difference between "you are not allowed
to look" and "there is nothing there" — the same confusion between *unknown*
and *fine* that #829 and #830 were about, in the response envelope this time.

The cause is decorator order, not a missing branch. flask-restx's
`marshal_with` wraps whatever the view returns, and `require_role` rejects by
returning `({'error': ..., 'code': ...}, 401)`. When the marshaller is the
outer decorator it reshapes that rejection into the success model: keys the
model does not declare are dropped, so `error` and `code` disappear, and every
declared key is filled with null. When `require_role` is outer, the rejection
never reaches the marshaller.

Four of seven marshalled resources had the wrong order: CertificateList,
BackupList, CacheStats and CacheClear. The codebase had already met the symptom
without naming the cause — `modules/api/models.py` declares `error` and `code`
on the deployment-status model with a comment saying that `marshal_with` would
otherwise strip `code` from a 403 body. That patches one model; this checks the
behaviour everywhere, so the next resource to gain a marshaller cannot
reintroduce it.

`/api/auth/me` is deliberately exempt: it answers `{"user": null}` with 401 as
its documented contract for a UI deciding whether to render a login form, and
it is not a marshalled resource.
"""
import json
import pathlib
import secrets

import pytest

pytestmark = [pytest.mark.unit]


# Answers without a credential by design: a health check a load balancer polls,
# and the OIDC descriptor the login page reads before anyone has logged in.
PUBLIC = frozenset({'/api/health', '/api/auth/oidc/config', '/api/auth/oidc/login'})

# Documented to answer {"user": null} with 401; see the module docstring.
EXEMPT = frozenset({'/api/auth/me'})


def _refusable_paths(app):
    """Every parameterless /api/ GET route, so the probe needs no fixtures."""
    seen = set()
    for rule in app.url_map.iter_rules():
        path = str(rule)
        if not path.startswith('/api/') or '<' in path:
            continue
        if 'GET' not in rule.methods:
            continue
        seen.add(path)
    return sorted(seen)


@pytest.fixture(scope="module")
def app():
    """The application, built under a temporary root.

    Anchoring `modules.core.factory.__file__` to a temp tree is the pattern
    tests/test_advertised_endpoints_exist.py already uses: `setup_directories()`
    creates data/, certificates/ and logs/ relative to that module's file, so a
    test that only wants to make requests would otherwise write into the
    working tree and fail on a read-only checkout.
    """
    import tempfile

    root = pathlib.Path(tempfile.mkdtemp()) / "certmate"
    module_dir = root / "modules" / "core"
    module_dir.mkdir(parents=True)
    anchor = module_dir / "factory.py"
    anchor.write_text("# test path anchor\n", encoding="utf-8")

    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("TESTING", "true")
        patch.setenv("FLASK_ENV", "testing")
        # A real token, so the instance is NOT in setup mode: setup mode makes
        # every caller an admin, and then nothing refuses anything and this
        # test would pass by having found no refusals to check.
        patch.setenv("API_BEARER_TOKEN", secrets.token_urlsafe(32))
        from modules.core.factory import create_app
        patch.setattr("modules.core.factory.__file__", str(anchor))
        result = create_app()
    return result[0] if isinstance(result, tuple) else result


def test_an_unauthenticated_request_is_refused_with_an_error_envelope(app):
    client = app.test_client()

    offenders = []
    checked = 0
    for path in _refusable_paths(app):
        if path in PUBLIC or path in EXEMPT:
            continue
        response = client.get(path)
        if response.status_code not in (401, 403):
            # Not every route is credentialed; this test is only about those
            # that refuse. A route that answers 200 here is a different
            # question, asked by the auth tests.
            continue
        checked += 1
        body = response.get_json(silent=True)
        # docs/api.md, "Error Response Format": every failure carries a
        # human-readable `error` and a machine-readable `code`. Asserting only
        # `error` would let a refusal through that a client still cannot
        # branch on.
        if not isinstance(body, dict) or 'error' not in body or 'code' not in body:
            offenders.append(f'{path} -> {response.status_code} {json.dumps(body)[:100]}')

    assert checked, 'no credentialed GET route answered 401/403; the probe found nothing to check'
    assert not offenders, (
        'these refusals answer with a success-shaped body instead of an error '
        'envelope, so a client reading the body cannot tell a refusal from an '
        'empty result:\n  ' + '\n  '.join(offenders)
    )
