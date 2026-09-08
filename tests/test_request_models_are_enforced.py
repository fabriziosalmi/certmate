"""The published request models must be a boundary, not a description of one.

Ten endpoints declare a Flask-RESTX model with `@api.expect` and publish it in
the Swagger document. Nothing validated against it — no `validate=True`, no
`RESTX_VALIDATE` — so a caller reading the document was told about a boundary
that did not exist.

`RESTX_VALIDATE` is now on. What that actually buys was measured rather than
assumed, and it is narrower than it sounds:

* **required fields** are enforced — a create without `domain` is refused at
  the boundary with a message naming the field;
* **types** are enforced, which nothing else did — `{"key_size": "big"}` used
  to reach the application;
* **enums are NOT enforced.** A `key_size` of 1024 still passes validation and
  is refused by `validate_key_options`, with a better message than JSON Schema
  would give: *"key_size must be one of [2048, 3072, 4096], got 1024"*.

That last point is why the enums stay in the models rather than being deleted
as unenforced decoration: they are true, and they are what the Swagger document
tells an API consumer. What was missing is anything tying them to the code that
does the enforcing — so this file pins each one against its validator. An enum
that drifts from its validator is a document that lies in one direction or a
boundary that rejects valid input in the other.

**One behaviour change is deliberate and stated here so it is a decision:** an
explicit `null` for an optional typed field is now a 400 rather than being
ignored. Omitting the field is how you say "use the default", and that is what
the UI and the clients do — verified by reading the only site that constructs
these payloads and by running the Playwright suite against the real container.
"""
import pathlib
import re

import pytest

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent
MODELS = REPO / 'modules' / 'api' / 'models.py'


def _enum_of(field_name):
    """The enum literal declared for a field in models.py, as a Python list."""
    source = MODELS.read_text(encoding='utf-8')
    match = re.search(
        rf"'{field_name}':\s*fields\.\w+\((.*?)\),?\n\s*'", source, re.S)
    if not match:
        return None
    enum = re.search(r'enum=(\[.*?\])', match.group(1), re.S)
    return eval(enum.group(1)) if enum else None      # noqa: S307 - our source


# --- validation is actually on ------------------------------------------

def test_validation_is_enabled():
    source = (REPO / 'modules' / 'core' / 'factory.py').read_text()
    assert "app.config['RESTX_VALIDATE'] = True" in source, (
        'the request models are published and unenforced again: a caller '
        'reading the Swagger document is told about a boundary that does not '
        'exist'
    )


def test_endpoints_still_declare_their_models():
    """CONTROL: RESTX_VALIDATE only does anything where @api.expect is used.
    Turning it on and then dropping the decorators would leave the flag as
    decoration."""
    declared = 0
    for path in (REPO / 'modules' / 'api').glob('*.py'):
        declared += len(re.findall(r'@api\.expect\(', path.read_text()))
    assert declared >= 10, (
        f'only {declared} endpoints declare a request model; validation now '
        f'covers less than it did when it was switched on'
    )


# --- the enums say what the validators do -------------------------------

def test_the_rsa_key_size_enum_matches_the_validator():
    from modules.core.utils import VALID_RSA_KEY_SIZES
    for field in ('key_size', 'default_key_size'):
        assert set(_enum_of(field) or []) == set(VALID_RSA_KEY_SIZES), (
            f'the Swagger document offers {_enum_of(field)} for {field} but '
            f'the application accepts {sorted(VALID_RSA_KEY_SIZES)}'
        )


def test_the_curve_enum_matches_the_validator():
    from modules.core.utils import VALID_ELLIPTIC_CURVES
    for field in ('elliptic_curve', 'default_elliptic_curve'):
        assert set(_enum_of(field) or []) == set(VALID_ELLIPTIC_CURVES), (
            f'the Swagger document offers {_enum_of(field)} for {field} but '
            f'the application accepts {sorted(VALID_ELLIPTIC_CURVES)}'
        )


def test_the_storage_backend_enum_matches_the_dispatch():
    """This one is a hand-written literal, and the dispatch it describes is a
    chain of elif branches — the shape that drifts."""
    dispatch = (REPO / 'modules' / 'core' / 'storage_backends.py').read_text()
    handled = set(re.findall(r"backend_type == '([a-z0-9_]+)'", dispatch))
    declared = set(_enum_of('backend') or [])
    assert declared == handled, (
        f'the Swagger document offers {sorted(declared)} as storage backends '
        f'and the code dispatches on {sorted(handled)}'
    )


def test_the_dns_provider_enum_is_still_derived_not_written():
    """It was a hand-maintained literal that listed 24 of 26 providers. It is
    derived now, and must stay that way — with validation on, a missing entry
    would be a document that omits a provider rather than only a stale list."""
    source = MODELS.read_text(encoding='utf-8')
    assert 'dns_provider_enum = list(DNSManager.SUPPORTED_PROVIDERS)' in source


# --- what the boundary now does -----------------------------------------

@pytest.fixture(scope='module')
def client():
    import os
    import tempfile
    root = pathlib.Path(tempfile.mkdtemp()) / 'certmate'
    module_dir = root / 'modules' / 'core'
    module_dir.mkdir(parents=True)
    anchor = module_dir / 'factory.py'
    anchor.write_text('# test path anchor\n')
    for shared in ('templates', 'static'):
        source = REPO / shared
        if source.is_dir():
            (root / shared).symlink_to(source)

    with pytest.MonkeyPatch.context() as patch:
        patch.setenv('TESTING', 'true')
        patch.setenv('FLASK_ENV', 'testing')
        patch.setattr('modules.core.factory.__file__', str(anchor))
        os.environ.setdefault('FLASK_ENV', 'testing')
        from modules.core.factory import create_app
        app, _ = create_app()
    return app.test_client()


def test_a_missing_required_field_is_refused_and_named(client):
    """Refused either way — the application returns DOMAIN_REQUIRED too — so
    this pins the property a client cares about (the refusal names the field)
    rather than which layer produced it. `test_validation_is_enabled` is what
    pins the layer, and turning the flag off leaves this passing, which is how
    that division was found."""
    response = client.post('/api/certificates/create', json={'key_type': 'rsa'})
    assert response.status_code == 400
    body = response.get_json()
    assert 'domain' in str(body), (
        f'the refusal does not name the missing field: {body}'
    )


def test_a_wrong_type_is_refused(client):
    """The one thing validation adds that nothing else did."""
    response = client.post('/api/certificates/create',
                           json={'domain': 'x.example.com',
                                 'key_type': 'rsa', 'key_size': 'big'})
    assert response.status_code == 400
    assert 'key_size' in str(response.get_json())


def test_omitting_an_optional_field_is_fine(client):
    """CONTROL, and the compatibility case that matters: leaving a field out
    is how a caller says "use the default". If validation refused that, every
    existing client would break."""
    response = client.post('/api/certificates/create',
                           json={'domain': 'x.example.com'})
    body = str(response.get_json())
    assert 'validation failed' not in body, (
        f'omitting the optional key options was refused by validation: {body}'
    )


def test_a_value_outside_an_enum_is_refused_by_the_application(client):
    """Not by validation — measured. The application's message is the better
    one, which is why the enum is documentation and the validator is the
    boundary."""
    response = client.post('/api/certificates/create',
                           json={'domain': 'x.example.com',
                                 'key_type': 'rsa', 'key_size': 1024})
    assert response.status_code == 400
    body = str(response.get_json())
    assert 'key_size must be one of' in body, (
        f'nothing refused a key size outside the documented set: {body}'
    )
    assert 'validation failed' not in body, (
        'enum checking started happening at the boundary, which changes the '
        'error message clients see — update this test and the comment in '
        'factory.py rather than deleting the assertion'
    )
