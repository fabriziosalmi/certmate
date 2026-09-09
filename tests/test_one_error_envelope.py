"""One API, one shape for a failure.

Measured against a running instance before this change, three unauthenticated
404s produced three different bodies:

    GET /api/certificates/<unknown>   {"error": "Certificate not found for domain: X"}
    GET /api/does-not-exist           {"code": 404, "error": "Not Found", "message": "..."}
    GET /api/client-certs/<unknown>   {"message": "Certificate not found: X. You have
                                       requested this URI [...] but did you mean
                                       /api/client-certs/<string:identifier>/download/... ?"}

So `code` was a string symbol on some endpoints, the status INTEGER on others,
and absent from the most common 404 of all — including on two endpoints
reporting the identical condition, one of which set CERTIFICATE_NOT_FOUND while
the other set nothing. A client could not branch on the field without checking
its type first, which is the same as not having the field. The SDK this
repository publishes already documented it as "CertMate's machine-readable
error code (e.g. DOMAIN_OUT_OF_SCOPE) when present", so the string was the
intended type all along.

The third shape came from flask-restx's own `abort`, which attaches its keyword
arguments to the exception as `data` and returns that verbatim — so no
`@api.errorhandler` can reshape it, and it also narrated matching routes to an
unauthenticated caller because RESTX_ERROR_404_HELP defaults to on. (The
codebase had set ERROR_404_HELP, which is flask-restful's name for it and does
nothing here.)

These tests drive the real application rather than asserting on source, because
the defect was invisible in every file taken on its own.
"""
import json
import pathlib

import pytest

pytestmark = [pytest.mark.unit]


@pytest.fixture(scope='module')
def client(tmp_path_factory):
    """The whole app, under a temporary root.

    Anchoring modules.core.factory.__file__ is the pattern the suite already
    uses: setup_directories derives the state directories from the module's
    location, so without it a test that only wants to make requests creates
    data/ and certificates/ in the working tree.
    """
    root = tmp_path_factory.mktemp('envelope') / 'certmate'
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
    app = result[0] if isinstance(result, tuple) else result
    return app.test_client()


# Every layer that can refuse a request: the application itself, the HTTP layer
# below it, and flask-restx in between.
REFUSALS = [
    ('application', 'get', '/api/certificates/nope.example.com', 404),
    ('http layer', 'get', '/api/no-such-endpoint', 404),
    ('http layer', 'post', '/api/certificates', 405),
    ('flask-restx', 'get', '/api/client-certs/nope', 404),
    ('flask-restx', 'get', '/api/client-certs/bad!identifier', 400),
]


def _body(client, verb, path):
    response = getattr(client, verb)(path)
    assert response.mimetype == 'application/json', (
        f'{verb.upper()} {path} answered {response.mimetype}, so a client that '
        f'pipes the response through .json() gets a parse error (#164)')
    return response.status_code, response.get_json()


@pytest.mark.parametrize('layer,verb,path,status', REFUSALS,
                         ids=[f'{r[0]}:{r[2]}' for r in REFUSALS])
def test_every_refusal_carries_error_and_code(client, layer, verb, path, status):
    """THE regression. Whichever layer refuses, the answer has both halves:
    something for a person and something for a program."""
    got, body = _body(client, verb, path)

    assert got == status
    assert body.get('error'), f'{layer} refused with no human-readable error'
    assert body.get('code'), f'{layer} refused with no machine-readable code'


@pytest.mark.parametrize('layer,verb,path,status', REFUSALS,
                         ids=[f'{r[0]}:{r[2]}' for r in REFUSALS])
def test_the_code_is_always_a_string(client, layer, verb, path, status):
    """The defect itself. One field, one type — a client that has to ask
    `typeof err.code` before branching does not have a contract."""
    _, body = _body(client, verb, path)

    assert isinstance(body['code'], str), (
        f'{layer} answered code={body["code"]!r} ({type(body["code"]).__name__}); '
        f'application errors use string symbols, so this one is unbranchable')
    assert body['code'] == body['code'].upper()


def test_the_same_condition_reports_the_same_code(client):
    """It was possible for one condition to have a code on one endpoint and
    none on another: the certificate listing said nothing while the download
    path said CERTIFICATE_NOT_FOUND, for the same missing certificate."""
    _, listing = _body(client, 'get', '/api/certificates/nope.example.com')
    _, download = _body(client, 'get',
                        '/api/certificates/nope.example.com/download')

    assert listing['code'] == download['code'] == 'CERTIFICATE_NOT_FOUND'


def test_an_http_layer_refusal_still_carries_the_number(client):
    """CONTROL for the retype: the status integer that `code` used to hold is
    not lost, it moved to `status`. That is the one-line migration for anyone
    who was reading the number."""
    got, body = _body(client, 'get', '/api/no-such-endpoint')

    assert body['status'] == got == 404
    assert body['code'] == 'NOT_FOUND'


def test_a_refusal_does_not_narrate_the_route_table(client):
    """flask-restx appends "you have requested this URI ... but did you mean"
    with matching rules from the route table, to anyone, authenticated or not.
    It is switched off by RESTX_ERROR_404_HELP — the name that works."""
    _, body = _body(client, 'get', '/api/client-certs/nope')

    rendered = json.dumps(body)
    assert 'did you mean' not in rendered
    assert '<string:identifier>' not in rendered


def test_the_flask_restful_spelling_is_not_the_one_used():
    """CONTROL for the line above. ERROR_404_HELP is flask-restful's name for
    this setting; flask-restx reads RESTX_ERROR_404_HELP. Setting the old one
    looks right and changes nothing, which is how the narration survived being
    turned off."""
    factory = (pathlib.Path(__file__).resolve().parent.parent / 'modules'
               / 'core' / 'factory.py').read_text(encoding='utf-8')

    assert "'RESTX_ERROR_404_HELP'" in factory
    assert "app.config['ERROR_404_HELP']" not in factory


def test_the_symbol_is_derived_not_enumerated():
    """A status this code has never seen must still produce a usable symbol
    rather than falling back to a number, or the type guarantee holds only for
    the statuses somebody remembered."""
    from modules.core.factory import error_code_for_status

    assert error_code_for_status(404, 'Not Found') == 'NOT_FOUND'
    assert error_code_for_status(413, 'Request Entity Too Large') == \
        'REQUEST_ENTITY_TOO_LARGE'
    assert error_code_for_status(599, '') == 'HTTP_599'
    assert error_code_for_status(418, None) == 'HTTP_418'


def test_the_contract_version_records_the_retype():
    """The rule written beside the constant says a retyped response field is a
    MAJOR bump. This is that retype."""
    from modules.core.constants import API_CONTRACT_VERSION

    assert API_CONTRACT_VERSION.startswith('2.'), (
        'code changed type on the HTTP-layer responses; the contract version '
        'is how a client finds out')


def test_the_documented_envelope_is_the_implemented_one(client):
    """docs/api.md described {error, code, status} with `code` as a string, and
    then illustrated it with an example showing code: 404 — for an endpoint
    that in fact answered with neither field. Whatever the document says now,
    the example in it has to be true."""
    api_doc = (pathlib.Path(__file__).resolve().parent.parent / 'docs'
               / 'api.md').read_text(encoding='utf-8')

    assert '"code": 404' not in api_doc, (
        'the API reference still shows a numeric code, which is the shape this '
        'change removed')
    for name in ('CERTIFICATE_NOT_FOUND', 'DOMAIN_OPERATION_IN_PROGRESS',
                 'INSUFFICIENT_ROLE', 'ACME_RATE_LIMITED'):
        assert name in api_doc, (
            f'{name} is a code the API emits and the reference does not list, '
            f'so a client author cannot discover it without reading the source')
