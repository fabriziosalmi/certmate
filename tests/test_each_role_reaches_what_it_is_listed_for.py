"""Every call of the route walk, tried first with no credentials, as a viewer and as an operator.

The route walk (tests/contract_routes.py) calls 108 of the 111 routes with
requests valid for each. Here each of those requests is made first by three
callers that are not the owner, and what each of them reaches is compared, in
both directions, with what is written down for it below:

* a request with no credentials reaches the routes that are public by design;
* a viewer reads, and changes nothing but the four things listed;
* an operator does a certificate's and a client certificate's work, and
  nothing of the instance's.

A route added to the application has to be added to the walk (the contract
tests require it), so it is tried here, and it fails this test until someone
has written down who may reach it. A route that stops answering a role fails
it too, so the lists cannot go stale.

Two more things are checked on every answer to those three: that a private
key is answered only where listed, and that no secret the owner sent during
the walk (a token, a password, a credential) comes back to any of them.

tests/test_a_restricted_key_meets_nothing_outside_its_domains.py is the same
walk for the other axis: keys restricted with `allowed_domains`.
"""
import io
import re
import secrets
import zipfile

import pytest

from modules.core import metrics
from tests import contract_routes, contract_support
from tests import contract_world as world

pytestmark = [pytest.mark.unit]

REFUSED = (401, 403)

# No credentials at all. What a relying party, a load balancer or the login page needs.
PUBLIC = {
    'GET /api/health',
    'GET /api/auth/oidc/config',        # the login page asks whether SSO is on, before anyone is signed in
    'GET /api/client-certs/ca',
    'GET /api/crl/download/<X>',
    'GET /api/ocsp/status/<X>',
}

VIEWER_READS = PUBLIC | {
    'GET /api/activity', 'GET /api/auth/config', 'GET /api/backups', 'GET /api/cache/stats',
    'GET /api/certificates', 'GET /api/certificates/<X>',
    'GET /api/certificates/<X>/deployment-status', 'GET /api/certificates/<X>/dns-alias-check',
    'GET /api/certificates/<X>/download', 'GET /api/certificates/<X>/download/<X>',
    'GET /api/client-certs', 'GET /api/client-certs/<X>', 'GET /api/client-certs/<X>/download/<X>',
    'GET /api/client-certs/stats',
    'GET /api/inventory', 'GET /api/inventory/<X>/adopt', 'GET /api/inventory/config',
    'GET /api/inventory/crypto-report', 'GET /api/inventory/domains', 'GET /api/inventory/health',
    'GET /api/metrics', 'GET /api/settings', 'GET /api/settings/dns-providers',
    'GET /api/storage/info', 'GET /api/web/update-check',
}

# What a viewer may do that is not a read: three lookups that store nothing,
# and the report its own dashboard sends.
VIEWER_ACTS = {
    'POST /api/certificates/check-caa',
    'POST /api/certificates/check-dns-alias',
    'POST /api/probe',
    'POST /api/certificates/deployment-status/browser',
}

# The two forms of the bundle download that carry the key. The walk asks for
# the bundle with neither, so they are asked here, for the seeded certificate.
KEY_BEARING_FORMS = {'file=privkey.pem': {'file': 'privkey.pem'}, 'format=json': {'format': 'json'}}
BUNDLE = 'GET /api/certificates/<X>/download'

OPERATOR_READS = VIEWER_READS | {'GET /api/certificates/jobs', 'GET /api/certificates/jobs/<X>'} | {
    f'{BUNDLE}?{form}' for form in KEY_BEARING_FORMS}

OPERATOR_ACTS = VIEWER_ACTS | {
    'POST /api/certificates/create', 'POST /api/certificates/<X>/renew',
    'POST /api/certificates/<X>/reissue', 'POST /api/certificates/reissue-keyless',
    'PATCH /api/certificates/<X>', 'PUT /api/certificates/<X>/auto-renew',
    'POST /api/client-certs/create', 'POST /api/client-certs/batch',
    'POST /api/client-certs/<X>/renew',
    'POST /api/inventory/<X>/adopt', 'DELETE /api/inventory/<X>',
}

# Where a private key is answered, and to whom.
PRIVATE_KEY = {
    'anonymous': set(),
    'viewer': set(),
    'operator': {BUNDLE, 'GET /api/certificates/<X>/download/<X>',
                 'GET /api/client-certs/<X>/download/<X>'} | {
        f'{BUNDLE}?{form}' for form in KEY_BEARING_FORMS},
}

# --- the routes the walk does not have: the pages, and the dashboard's own /api/web/ routes.
# Asked with nothing (GET) or an empty body, on an application built the ordinary way; what is
# listed is what answers 2xx. Enough to see who is answered, not to prove a valid request is
# refused: the walk is what proves that, for the routes it has.
SWEPT_PUBLIC = {
    'GET /',                            # the sign-in or the setup page, never the dashboard's data
    'GET /health', 'GET /health/ready', 'GET /docs/', 'GET /api/swagger.json',
    'GET /favicon.ico', 'GET /apple-touch-icon.png', 'GET /certmate_logo.png', 'GET /certmate_logo_256.png',
}
SWEPT_VIEWER = SWEPT_PUBLIC | {
    'GET /activity', 'GET /help', 'GET /inventory', 'GET /inventory/crypto-report',
    'GET /notifications', 'GET /redoc', 'GET /metrics',
    'GET /api/web/settings', 'GET /api/web/cache/stats', 'GET /api/web/certificates/dns-providers',
}
SWEPT_OPERATOR = SWEPT_VIEWER | {'POST /api/web/certificates/<X>/renew'}
SWEPT = {'anonymous': SWEPT_PUBLIC, 'viewer': SWEPT_VIEWER, 'operator': SWEPT_OPERATOR}
# The OpenAPI document says "PRIVATE KEY" where it describes a PEM field.
DOCUMENTS = {'GET /api/swagger.json'}

LISTED = {
    'anonymous': (PUBLIC, set()),
    'viewer': (VIEWER_READS, VIEWER_ACTS),
    'operator': (OPERATOR_READS, OPERATOR_ACTS),
}

SECRET_FIELD = re.compile(r'token|secret|password|passphrase|credential|private_key|api_key', re.I)


def _readable(response):
    """An answer as text, with what an archive holds laid open.

    A bundle is a ZIP, and a key inside one is compressed: looking for
    "PRIVATE KEY" in the bytes would not find it. Its members are read. A
    PKCS#12 bundle holds a key by definition and cannot be opened without its
    password, so it is named for what it is. An event stream has no end and is
    not read.
    """
    if response.mimetype == 'text/event-stream':
        return ''
    raw = response.get_data()
    text = raw.decode('utf-8', 'replace')
    if raw[:2] == b'PK':
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                text += ''.join(archive.read(name).decode('utf-8', 'replace') for name in archive.namelist())
        except zipfile.BadZipFile:
            pass
    if 'pkcs12' in (response.mimetype or ''):
        text += ' PRIVATE KEY (a PKCS#12 bundle)'
    return text


def _secrets_in(value, under_a_secret_name=False):
    """The values the owner sends under a name that says they are secret."""
    if isinstance(value, dict):
        for name, inner in value.items():
            yield from _secrets_in(inner, under_a_secret_name or bool(SECRET_FIELD.search(str(name))))
    elif isinstance(value, (list, tuple)):
        for inner in value:
            yield from _secrets_in(inner, under_a_secret_name)
    elif under_a_secret_name and isinstance(value, str) and len(value) >= 12:
        yield value


class ByRole(contract_routes.Plan):
    """The walk's plan, with each of its calls tried first by the three callers."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.callers = None
        self.secrets = set()
        self.reached = {who: set() for who in LISTED}       # anything but a refusal
        self.acted = {who: set() for who in LISTED}         # not a GET, and it succeeded
        self.keys = {who: set() for who in LISTED}
        self.swept = {who: set() for who in LISTED}         # outside the walk, answered 2xx
        self.findings = []
        self.tried = 0
        self.swept_tried = 0

    def _callers(self):
        if self.callers is None:
            auth = self.container.managers['auth']
            self.callers = {'anonymous': {}}
            for role in ('viewer', 'operator'):
                ok, key = auth.create_api_key(f'plain-{role}', role=role)
                assert ok, key
                self.callers[role] = {'Authorization': f"Bearer {key['token']}"}
                self.secrets.add(key['token'])
        return self.callers

    def call(self, verb, template, path=None, body=None, client=None, headers=None,
             stream=False, query=None, data=None, keep=False, limited=False, defect=None):
        key = f'{verb.upper()} {re.sub(r"<[^>]+>", "<X>", template)}'
        attempts = []
        # Only the calls the walk makes as the owner (see the other walk).
        if headers is None and client is None and not limited:
            for who, credentials in self._callers().items():
                kwargs = {'headers': credentials}
                if body is not None:
                    kwargs['json'] = body
                if query:
                    kwargs['query_string'] = query
                response = getattr(self.admin, verb)(path or template, **kwargs)
                attempts.append((key, who, response.status_code, _readable(response)))
                response.close()
                if key == BUNDLE and not query and path == f'/api/certificates/{world.DOMAIN}/download':
                    for form, parameters in KEY_BEARING_FORMS.items():
                        variant = self.admin.get(path, headers=credentials, query_string=parameters)
                        attempts.append((f'{key}?{form}', who, variant.status_code, _readable(variant)))
                        variant.close()
        for attempted, who, status, text in attempts:
            self._judge(attempted, path or template, verb.upper(), who, status, text)
        # After the attempts: what this call sends is a secret from here on.
        self.secrets.update(_secrets_in(body))
        return super().call(
            verb, template, path=path, body=body, client=client, headers=headers,
            stream=stream, query=query, data=data, keep=keep, limited=limited, defect=defect)

    def _judge(self, key, path, verb, who, status, text):
        self.tried += 1
        where = f'{key} [{who}: {status}] {path}'
        if status >= 500:
            self.findings.append(f'{where}: a server error')
        if status in REFUSED:
            return
        self.reached[who].add(key)
        if verb != 'GET' and status < 300:
            self.acted[who].add(key)
        self._look_for_keys_and_secrets(key, where, who, text, self.callers[who])

    def _look_for_keys_and_secrets(self, key, where, who, text, credentials):
        if 'PRIVATE KEY' in text and key not in DOCUMENTS:
            self.keys[who].add(key)
        own = credentials.get('Authorization', '')[7:]
        for secret in self.secrets:
            if secret != own and secret in text:
                self.findings.append(f'{where}: answers a secret the owner sent ({secret[:4]}…, {len(secret)} characters)')


@pytest.fixture(scope='module')
def walk(tmp_path_factory):
    built = {}

    class Recording(ByRole):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            built['plan'] = self

    app, token = contract_support.build_app()
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(contract_routes, 'Plan', Recording)
        contract_routes.run(app, token)
    plan = built['plan']
    plan.secrets.add(token)
    try:
        _sweep(plan, tmp_path_factory.mktemp('role-sweep'))
    finally:
        # The sweep scrapes /metrics, and the collector gathers at most once per
        # interval for the whole process: left fresh for whichever test scrapes next.
        metrics.metrics_collector.last_collection = 0
    return plan


def _sweep(plan, tmp):
    token = secrets.token_urlsafe(32)
    with pytest.MonkeyPatch.context() as patch:
        for var, sub in (('CERTMATE_CERT_DIR', 'certs'), ('CERTMATE_DATA_DIR', 'data'),
                         ('CERTMATE_BACKUP_DIR', 'backups'), ('CERTMATE_LOGS_DIR', 'logs')):
            (tmp / sub).mkdir()
            patch.setenv(var, str(tmp / sub))
        patch.setenv('FLASK_ENV', 'testing')
        patch.setenv('TESTING', 'true')
        patch.setenv('API_BEARER_TOKEN', token)
        from modules.factory import create_app
        app, container = create_app()
        with world.certbot_standing_in(world.Certbot()):
            seeded = world.seed(container, 0)
            # The seed gives the DNS account a credential: the one a settings route must not answer.
            plan.secrets.update({token, 'w' * 24})
            callers = {'anonymous': {}}
            for role in ('viewer', 'operator'):
                ok, key = container.managers['auth'].create_api_key(f'plain-{role}', role=role)
                assert ok, key
                callers[role] = {'Authorization': f"Bearer {key['token']}"}
                plan.secrets.add(key['token'])
            limiter = container.managers.get('rate_limiter')
            client = app.test_client()
            walked = set(plan.seen)
            for rule in app.url_map.iter_rules():
                template = str(rule)
                if template.startswith('/static'):
                    continue
                for verb in sorted(rule.methods - {'HEAD', 'OPTIONS'}):
                    key = f'{verb} {re.sub(r"<[^>]+>", "<X>", template)}'
                    if key in walked:
                        continue
                    path = re.sub(r'<[^>]+>', seeded.domain, template)
                    for who, credentials in callers.items():
                        if limiter is not None:
                            limiter.requests.clear()
                        kwargs = {'headers': credentials}
                        if verb != 'GET':
                            kwargs['json'] = {}
                        response = client.open(path, method=verb, **kwargs)
                        text = _readable(response)
                        status = response.status_code
                        response.close()
                        plan.swept_tried += 1
                        where = f'{key} [{who}: {status}] {path}'
                        if status >= 500:
                            plan.findings.append(f'{where}: a server error')
                        if 200 <= status < 300:
                            plan.swept[who].add(key)
                        plan._look_for_keys_and_secrets(key, where, who, text, credentials)


def _difference(listed, seen, what):
    more = sorted(seen - listed)
    less = sorted(listed - seen)
    lines = []
    if more:
        lines.append(f'{what}, and not listed for it: {more}')
    if less:
        lines.append(f'listed, and no longer {what}: {less}')
    return lines


@pytest.mark.parametrize('who', sorted(LISTED))
def test_a_caller_reaches_the_routes_listed_for_it_and_no_other(walk, who):
    reads, acts = LISTED[who]
    problems = _difference(reads | acts, walk.reached[who], f'reached by {who}')
    assert not problems, (
        '\n'.join(problems) + '\nA route answers a caller it is not listed for, or stopped '
        'answering one it is. Decide which is right, then change the route or the list above.')


@pytest.mark.parametrize('who', sorted(LISTED))
def test_a_caller_changes_only_what_is_listed_for_it(walk, who):
    _reads, acts = LISTED[who]
    problems = _difference(acts, walk.acted[who], f'done by {who}')
    assert not problems, '\n'.join(problems)


@pytest.mark.parametrize('who', sorted(SWEPT))
def test_outside_the_walk_a_caller_is_answered_where_listed_and_nowhere_else(walk, who):
    problems = _difference(SWEPT[who], walk.swept[who], f'answered 2xx to {who}')
    assert not problems, '\n'.join(problems)


@pytest.mark.parametrize('who', sorted(PRIVATE_KEY))
def test_a_private_key_is_answered_only_where_listed(walk, who):
    problems = _difference(PRIVATE_KEY[who], walk.keys[who], f'a private key answered to {who}')
    assert not problems, '\n'.join(problems)


def test_no_secret_the_owner_sent_comes_back_and_nothing_breaks(walk):
    assert not walk.findings, f'{len(walk.findings)}:\n  ' + '\n  '.join(walk.findings[:30])


def test_the_walk_was_tried_and_there_were_secrets_to_look_for(walk):
    """CONTROL: without this, callers that were never tried, or a walk that
    sent no secret, would pass everything above."""
    assert walk.tried > 600, walk.tried
    assert walk.swept_tried > 100, walk.swept_tried
    assert len(walk.secrets) >= 6, sorted(s[:4] for s in walk.secrets)
    assert len(walk.reached['operator']) > len(walk.reached['viewer']) > len(walk.reached['anonymous']) > 0
