"""A certificate created from the dashboard fired no deploy hook.

`certificate_created` and `certificate_renewed` were published by the
flask-restx resources and by nothing else. The `/api/web/...` routes — the
ones the dashboard actually calls — go to `CertificateService` directly, so
nothing on that path ever reached the event bus.

Measured side by side before the fix:

    POST /api/certificates/create          -> 201, EVENTS=['certificate_created']
    POST /api/web/certificates/create      -> 200, EVENTS=[]
    POST /api/certificates/<d>/renew       -> 200, EVENTS=['certificate_renewed']
    POST /api/web/certificates/<d>/renew   -> 200, EVENTS=[]
    POST /api/web/certificates/batch       -> 200, EVENTS=[]

Which means no deploy hook, no webhook and no notification for anything an
operator did through the interface the product ships with — and the failure
was silent at both ends: the certificate was issued, and the hook simply
never ran.

The publish lives in `CertificateService.issue_create` / `issue_renew` now,
the one place every adapter passes: web, RESTX and the async
`IssuanceExecutor`. Copying it into the web routes instead would have made a
second home for a rule that already had one, which is the shape of most of
the defects this sweep has been closing.
"""
import os
import secrets
import time

import pytest

pytestmark = [pytest.mark.unit]

TOKEN = secrets.token_urlsafe(32)


@pytest.fixture(scope='module')
def instance(tmp_path_factory):
    """A real app, with the real service and the real bus."""
    tmp = tmp_path_factory.mktemp('adapters')
    with pytest.MonkeyPatch.context() as patch:
        for var, sub in (('CERTMATE_CERT_DIR', 'certs'),
                         ('CERTMATE_DATA_DIR', 'data'),
                         ('CERTMATE_BACKUP_DIR', 'backups'),
                         ('CERTMATE_LOGS_DIR', 'logs')):
            (tmp / sub).mkdir(exist_ok=True)
            patch.setenv(var, str(tmp / sub))
        patch.setenv('FLASK_ENV', 'testing')
        patch.setenv('TESTING', 'true')
        patch.setenv('API_BEARER_TOKEN', TOKEN)
        os.environ['API_BEARER_TOKEN'] = TOKEN
        from modules.core.factory import create_app
        app, container = create_app()
        yield app, container


class _StubManager:
    """A certificate manager that succeeds without touching certbot."""

    def create_certificate(self, **kwargs):
        return {'success': True, 'domain': kwargs['domain'],
                'dns_provider': 'cloudflare', 'ca_provider': 'letsencrypt'}

    def renew_certificate(self, domain, force=False):
        return {'success': True, 'renewed': True}


@pytest.fixture
def watched(instance):
    """The service with a stubbed manager, and a list of what reaches the bus."""
    app, container = instance
    service = container.managers['cert_service']
    original = service._certs
    service._certs = _StubManager()

    seen = []
    app.config['EVENT_BUS'].add_listener(
        lambda event, data: seen.append(event))
    yield service, seen
    service._certs = original


def _prepared_create(domain):
    return {
        'domain': domain, 'email': 'ops@example.com',
        'dns_provider': 'cloudflare', 'account_id': None,
        'ca_provider': 'letsencrypt', 'ca_account_id': None,
        'domain_alias': None, 'alias_dns_provider': None,
        'san_domains': [], 'challenge_type': 'dns-01',
        'key_type': None, 'key_size': None, 'elliptic_curve': None,
        'csr_pem': None, '_settings_dns_provider': 'cloudflare',
        '_audit_ctx': None,
    }


def _settled(seen, expected, timeout=3):
    """The bus is asynchronous: wait for delivery rather than sleeping."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if seen.count(expected) >= 1:
            time.sleep(0.15)      # let a second (wrong) one arrive too
            return
        time.sleep(0.02)


# --- the event is announced where every adapter passes -------------------

def test_issuing_announces_it(watched):
    """THE regression: this is the call the web route makes."""
    service, seen = watched

    service.issue_create(_prepared_create('web.example.com'))
    _settled(seen, 'certificate_created')

    assert seen.count('certificate_created') == 1, seen


def test_renewing_announces_it(watched):
    service, seen = watched

    service.issue_renew({'domain': 'web.example.com', '_audit_ctx': None})
    _settled(seen, 'certificate_renewed')

    assert seen.count('certificate_renewed') == 1, seen


def test_a_no_op_renewal_announces_nothing(watched):
    """CONTROL. `renewed: False` is certbot's "not yet due": nothing was
    replaced, so a deploy hook must not fire. This is why the publish could
    not simply be unconditional."""
    service, seen = watched

    class _NotDue(_StubManager):
        def renew_certificate(self, domain, force=False):
            return {'success': True, 'renewed': False}

    service._certs = _NotDue()
    service.issue_renew({'domain': 'web.example.com', '_audit_ctx': None})
    time.sleep(0.3)

    assert 'certificate_renewed' not in seen


def test_the_routes_no_longer_announce_it_themselves(watched):
    """The move is only a fix if the old copy went away. Two publishes mean
    two deploy runs, two webhooks and two notifications per certificate."""
    import ast
    import inspect

    from modules.api import resources_lifecycle

    tree = ast.parse(inspect.getsource(resources_lifecycle))
    published = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == 'publish'
                and node.args
                and isinstance(node.args[0], ast.Constant)):
            published.add(node.args[0].value)

    # Reissue and the auto-renew toggle are different service calls and keep
    # their own publishes — `certificate_renewed` still appears in this file
    # for reissue, so it cannot be asserted absent. `certificate_created` can:
    # the only route that published it was the create the service now covers.
    assert 'certificate_created' not in published, (
        f'the create route publishes again, so a created certificate would '
        f'run its deploy hooks twice: {sorted(published)}')

    renew_source = inspect.getsource(resources_lifecycle)
    renew_block = renew_source[renew_source.index('class RenewCertificate'):]
    renew_block = renew_block[:renew_block.index('class CertificateReissue')]
    assert 'publish(' not in renew_block, (
        'the renew route publishes again: ' + renew_block)


def test_the_service_is_the_one_that_announces():
    """Named here so the next person moving this finds the reason rather
    than the outcome."""
    import ast
    import inspect

    from modules.core import cert_service

    tree = ast.parse(inspect.getsource(cert_service))
    published = {node.args[0].value for node in ast.walk(tree)
                 if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute)
                 and node.func.attr == '_publish'
                 and node.args and isinstance(node.args[0], ast.Constant)}

    assert {'certificate_created', 'certificate_renewed',
            'certificate_failed'} <= published


def test_every_construction_of_the_service_gets_a_bus():
    """There are three: the container, and two fallbacks for route tests. A
    fallback without a bus is an instance that silently announces nothing —
    the defect again, one layer down."""
    import ast
    import pathlib

    repo = pathlib.Path(__file__).resolve().parent.parent
    for relative in ('modules/core/factory.py',
                     'modules/web/cert_routes.py',
                     'modules/api/resource_context.py'):
        source = (repo / relative).read_text(encoding='utf-8')
        calls = [ast.unparse(node) for node in ast.walk(ast.parse(source))
                 if isinstance(node, ast.Call)
                 and 'CertificateService' in ast.unparse(node.func)]
        assert calls, f'{relative} no longer builds the service'
        for call in calls:
            assert 'event_bus' in call, (
                f'{relative} builds a CertificateService with no bus: {call}')
