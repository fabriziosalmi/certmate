"""Every route is authenticated, or is on this list with the reason it is not.

Route protection here is expressed three ways, and all three are legitimate:

* the `require_role` / `require_auth` decorators, and `require_web_auth` for
  HTML pages;
* an inline check inside the view — `/` reads the session cookie itself so the
  context processor sees the user. `/api/events/stream` used to be the second
  such route; it now carries `require_session_role('viewer')`, which is that
  same rule expressed once, so it appears in the protected set rather than in
  the list below;
* a redirect to a route that is itself checked — `/audit` redirects to
  `/activity`, `/certificates` to `/`.

What was missing is the *census*. Nothing enumerated the URL map, so a route
added without any check looked exactly like the ones that are public on
purpose: an absence, indistinguishable from every other absence. On a product
that holds private keys, "we think they are all covered" is not a control.

This file is the control. It walks `app.url_map`, reads the protection off each
view — including flask-restx resources, where the guard sits on the Resource
class rather than on the registered view function — and fails when a route is
neither protected nor named below with a reason.

Measured when this was written: **134 rules over 125 distinct paths, 99
protected and 26 public.** The audit finding that prompted this said eighteen
were public; the number was never checked, because nothing could check it.

Adding a route to PUBLIC_ROUTES is the reviewable act. It should be as hard to
do quietly as adding one to the codebase, and the reason has to be one someone
can disagree with in review.
"""
import pathlib
import tempfile

import pytest

pytestmark = [pytest.mark.unit]

# Routes that serve unauthenticated callers on purpose, and why. The reason is
# the point: a path with no reason is a route nobody decided about.
PUBLIC_ROUTES = {
    # --- protocol endpoints: public by specification -------------------
    '/.well-known/acme-challenge/<path:filename>':
        'HTTP-01 validation. The ACME server fetches this anonymously; '
        'requiring auth would break every http-01 issuance.',
    '/api/crl/download/<string:format_type>':
        'A CRL distribution point is fetched by relying parties that have no '
        'account here. That is what publishing a CRL means.',
    '/api/ocsp/status/<int:serial_number>':
        'OCSP status is queried by TLS clients validating a certificate this '
        'instance issued. Same reason as the CRL.',

    # --- getting in ----------------------------------------------------
    '/login':
        'The login page. Gating it would leave no way to authenticate, and '
        'the redirect target of every other gate points here.',
    '/api/auth/login':
        'Rate-limited to 5 attempts per minute per IP, and the credential '
        'check it performs IS the gate.',
    '/api/auth/logout':
        'Ending a session has to work even when the session is already '
        'invalid, which is exactly when a gate would refuse the call.',
    '/api/auth/me':
        'Tells the UI which controls to render. Enforces its own session '
        'check and returns the setup-mode bypass shape during onboarding, so '
        'it never discloses a real user to an anonymous caller.',
    '/api/auth/oidc/login':
        'Starts the SSO redirect, at which point there is no session yet by '
        'definition — that is what the caller is trying to obtain.',
    '/api/auth/oidc/callback':
        'The identity provider redirects the browser here. The state and code '
        'are the credential.',
    '/api/auth/oidc/config':
        'Public affordances only — whether to draw an SSO button and where it '
        'points. Secrets stay private; it fails closed to disabled.',

    # --- checked inline, not by decorator ------------------------------
    '/':
        'Reads and validates the session cookie itself, then redirects to '
        '/login, so that the template context processor sees the user. The '
        'decorator would authenticate but not populate request.current_user '
        'in the same way.',

    # --- redirects to a route that is checked --------------------------
    '/audit':
        'Redirects to /activity, which is role-gated. The page it named never '
        'existed.',
    '/certificates':
        'Redirects to /, which enforces auth inline. Same history: the page '
        'it named never existed and the route used to 500.',

    # --- probes: their whole purpose is to answer before you are in ----
    '/health':
        'Liveness. Load balancers and the container healthcheck poll it '
        'unauthenticated; it reports state, never certificate data.',
    '/health/ready':
        'Readiness, polled by orchestrators to decide whether to route '
        'traffic here. It reports scheduler and certbot state, never data.',
    '/api/health':
        'The API-shaped health probe, documented in the OpenAPI surface and '
        'polled by the same kind of caller as /health.',

    # --- the API description, not the API ------------------------------
    '/api':
        'The API root banner: name, version and a pointer to the docs. It '
        'names no certificate and no setting.',
    '/api/swagger.json':
        'The OpenAPI document. It describes the surface, which is already '
        'public in the README and the docs site; it exposes no data and no '
        'endpoint that is not itself gated.',
    '/docs/':
        'Swagger UI, which renders the document above and is useless without '
        'it; gating one and not the other would only break the page.',
    '/swaggerui/<path:filename>':
        'Swagger UI static assets, mounted by flask-restx and loaded by the '
        'page above before any credential is offered.',

    # --- static ---------------------------------------------------------
    '/static/<path:filename>':
        'Static assets. Gating them would require a session to load the '
        'stylesheet the login page is built from.',
    '/favicon.ico':
        'Browser chrome. The tab icon is requested before any session exists '
        'and by clients that will never have one.',
    '/apple-touch-icon.png':
        'Browser chrome, same as the favicon: requested by the OS when a page '
        'is added to a home screen, with no session.',
    '/certmate_logo.png':
        'Rendered on the login page, which is necessarily reached before any '
        'session exists.',
    '/certmate_logo_256.png':
        'The same logo at a second size, rendered on the same login page.',
}

HTTP_VERBS = ('get', 'post', 'put', 'patch', 'delete', 'head', 'options')


@pytest.fixture(scope='module')
def app():
    """The real application, built under a temporary root.

    `setup_directories()` creates data/, certificates/ and logs/ relative to
    `modules.core.factory.__file__`, so anchoring that keeps a test that only
    reads the route table from writing into the working tree — the pattern
    tests/test_advertised_endpoints_exist.py established.
    """
    root = pathlib.Path(tempfile.mkdtemp()) / 'certmate'
    module_dir = root / 'modules' / 'core'
    module_dir.mkdir(parents=True)
    anchor = module_dir / 'factory.py'
    anchor.write_text('# test path anchor\n', encoding='utf-8')

    with pytest.MonkeyPatch.context() as patch:
        patch.setenv('TESTING', 'true')
        patch.setenv('FLASK_ENV', 'testing')
        from modules.core.factory import create_app
        patch.setattr('modules.core.factory.__file__', str(anchor))
        result = create_app()
    return result[0] if isinstance(result, tuple) else result


def protection_of(view, verbs):
    """What guards this view, or None.

    Three shapes have to be read, because the codebase uses three:

    * a plain function carrying the marker the decorators set;
    * a flask-restx Resource with `method_decorators = [require_role(...)]`,
      where the guard is the decorator itself and is never applied at import;
    * a Resource whose individual methods are decorated.

    A Resource with SOME methods guarded and one bare is reported unprotected.
    That asymmetry is the exact defect this is looking for — a POST added to a
    read-only resource without picking up its neighbours' guard.
    """
    marker = getattr(view, '_certmate_protection', None)
    if marker:
        return marker

    resource = getattr(view, 'view_class', None)
    if resource is None:
        return None

    shared = [getattr(d, '_certmate_protection', None)
              for d in getattr(resource, 'method_decorators', None) or []]
    shared = [m for m in shared if m]

    found = set(shared)
    for verb in verbs:
        method = getattr(resource, verb.lower(), None)
        if method is None:
            continue
        own = getattr(method, '_certmate_protection', None)
        if own:
            found.add(own)
        elif not shared:
            return None            # this verb is served with no guard at all
    return ','.join(sorted(found)) or None


def census(app):
    """(protected, public) — every path, split by whether anything guards it.

    Judged per RULE and aggregated conservatively: several paths here are
    served by more than one rule on separate endpoints — `/api/settings` by
    three — and keeping whichever rule iterated last would let a guarded GET
    vouch for an unguarded POST at the same path. A path is public if ANY of
    its rules is unguarded.
    """
    guards, unguarded = {}, {}
    for rule in app.url_map.iter_rules():
        verbs = sorted(m for m in rule.methods if m not in ('HEAD', 'OPTIONS'))
        path = str(rule)
        guard = protection_of(app.view_functions.get(rule.endpoint), verbs)
        if guard:
            guards.setdefault(path, set()).add(guard)
        else:
            unguarded.setdefault(path, set()).update(verbs)

    public = {path: sorted(verbs) for path, verbs in unguarded.items()}
    protected = {path: ','.join(sorted(found))
                 for path, found in guards.items() if path not in public}
    return protected, public


# --- the census itself ---------------------------------------------------

def test_every_unprotected_route_is_listed_with_a_reason(app):
    _, public = census(app)
    undeclared = sorted(set(public) - set(PUBLIC_ROUTES))
    assert not undeclared, (
        'these routes serve unauthenticated callers and nothing says they are '
        'meant to. Add a guard, or add the path to PUBLIC_ROUTES with the '
        'reason:\n  ' + '\n  '.join(undeclared)
    )


def test_the_list_does_not_outlive_its_routes(app):
    """A stale allowlist entry is a standing permission for a path that may
    come back meaning something else."""
    _, public = census(app)
    known = {str(rule) for rule in app.url_map.iter_rules()}
    gone = sorted(set(PUBLIC_ROUTES) - known)
    assert not gone, (
        'PUBLIC_ROUTES names routes that no longer exist: ' + ', '.join(gone))

    now_protected = sorted(set(PUBLIC_ROUTES) - set(public))
    assert not now_protected, (
        'these are now protected — good, but remove them from PUBLIC_ROUTES '
        'so the list keeps meaning "these are public": '
        + ', '.join(now_protected))


def test_every_reason_is_one_someone_could_disagree_with(app):
    for path, reason in PUBLIC_ROUTES.items():
        assert len(reason.strip()) > 25, (
            f'{path} is listed as public with no usable reason: {reason!r}')


# --- controls on the detector -------------------------------------------
# Without these the file passes whether or not it measures anything, which is
# how a census becomes a decoration.

def test_the_detector_finds_the_protection_that_is_there(app):
    """Measured at 99 protected paths against 26 public when this was
    written. The floor is well below that: its job is to fail when the
    detector reads nothing and reports a serenely empty census, not to pin an
    exact number that every new endpoint would move."""
    protected, public = census(app)
    assert len(protected) > 80, (
        f'only {len(protected)} paths were seen as protected, against '
        f'{len(public)} public. The detector is reading the wrong thing, and '
        f'this file is passing on an empty measurement.'
    )
    assert len(protected) > 2 * len(public), (
        'the protected majority collapsed; either a lot of routes lost their '
        'guard or the detector stopped seeing one of the three shapes'
    )


@pytest.mark.parametrize('path, expected', [
    ('/api/settings', 'require_role:admin'),
    ('/settings', 'require_role:admin'),
    ('/api/certificates/create', 'require_role:operator'),
    ('/api/client-certs', 'require_role:viewer'),
])
def test_known_routes_report_the_guard_they_actually_carry(app, path, expected):
    """Pins the three declaration shapes: a decorated page, a decorated restx
    method, and a Resource-level `method_decorators`."""
    protected, _ = census(app)
    assert path in protected, f'{path} was not seen as protected at all'
    assert expected in protected[path], (
        f'{path} reports {protected[path]!r}, expected to contain {expected!r}')


def test_a_resource_with_one_unguarded_verb_is_reported(app):
    """CONTROL, and the defect shape most likely to happen: a POST added to a
    resource whose GET is guarded, without picking up the guard."""
    class Bare:
        method_decorators = []

        def get(self):                          # guarded
            pass
        get._certmate_protection = 'require_role:viewer'

        def post(self):                         # not
            pass

    class View:
        view_class = Bare

    assert protection_of(View, ['GET']) == 'require_role:viewer'
    assert protection_of(View, ['GET', 'POST']) is None


def test_a_resource_guarded_at_class_level_covers_every_verb(app):
    def guard(f):
        return f
    guard._certmate_protection = 'require_role:operator'

    class Shared:
        method_decorators = [guard]

        def get(self):
            pass

        def post(self):
            pass

    class View:
        view_class = Shared

    assert protection_of(View, ['GET', 'POST']) == 'require_role:operator'


def test_an_unmarked_plain_function_is_reported(app):
    def bare_view():
        pass

    assert protection_of(bare_view, ['GET']) is None


# --- the markers the detector reads --------------------------------------

def test_the_decorators_mark_what_they_protect():
    """If the markers stop being set, `census` reports every route public and
    the first test fails loudly — but only if the markers are what it reads.
    Pin them at the source too."""
    from unittest.mock import MagicMock
    from modules.core.auth import AuthManager

    auth = AuthManager.__new__(AuthManager)
    auth.settings_manager = MagicMock()

    def view():
        pass

    assert AuthManager.require_auth(auth, view)._certmate_protection == \
        'require_auth'
    factory = AuthManager.require_role(auth, 'operator')
    assert factory._certmate_protection == 'require_role:operator'
    assert factory(view)._certmate_protection == 'require_role:operator'


def test_require_web_auth_marks_itself():
    source = (pathlib.Path(__file__).resolve().parent.parent / 'modules'
              / 'web' / 'routes.py').read_text()
    assert "decorated._certmate_protection = 'require_web_auth'" in source, (
        'require_web_auth no longer marks the views it guards, so every HTML '
        'page it protects would be reported public'
    )

