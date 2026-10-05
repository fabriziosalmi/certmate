"""Every call of the route walk, tried first by keys restricted to other domains.

The route walk (tests/contract_routes.py) calls 108 of the 111 routes on the
real application with requests that are valid for each of them, on an instance
seeded with certificates, an inventory, client certificates, backups and
users. Here every one of those requests is made first with three API keys
restricted to a domain that owns nothing on the instance:

* a viewer and an operator, the roles a restricted key can have;
* a key stored with the admin role and `allowed_domains`, which acts as an
  operator (tests/test_an_admin_key_restricted_to_domains_acts_as_an_operator.py).

Whatever the walk names belongs to someone else, so a restricted key may be
refused, or may get an answer that names none of it. It may not get a name it
has no claim on, key or certificate material, or a change made. A route added
to the application has to be added to the walk (the contract tests require
it), and so is tried here without anyone remembering to.

The exceptions are written down with their reason, and each is checked for
still being one, so the list cannot outlive what it excuses.

What this does not try, and what does:

* a key whose scope covers some of a certificate's names and not others. These
  keys own nothing here, so the first name already refuses them.
  tests/test_a_scoped_key_needs_every_name_of_a_certificate.py tries that.
* a valid request on the pages: `_sweep` sends every route the walk does not
  have an empty one. The dashboard's /api/web/ routes that take a body and are
  open to these roles get a valid one from `dashboard`, at the end.
"""
import contextlib
import io
import json
import re
import secrets
import zipfile

import pytest

from modules.core import metrics
from tests import contract_routes, contract_support
from tests import contract_world as world
from tests.restricted_keys import stored_as_admin_with_domains

pytestmark = [pytest.mark.unit]

NOT_THEIRS = ['*.nothing.example']

# What the seeded instance and the walk name. The instance's own contact address
# (`ops@example.test`) is not one of them: it has no label before the domain.
SOMEONE_ELSES = re.compile(r'[a-z0-9-]+\.example\.test|(?:alice|bob)@example\.test', re.I)
MATERIAL = re.compile(r'BEGIN (?:[A-Z ]+ )?PRIVATE KEY|BEGIN CERTIFICATE')

# Routes that are known to name the instance's data to a restricted key, each
# with the decision taken about it. Empty, and meant to stay so: the test fails
# on an entry that is no longer needed, so one cannot be left behind.
KNOWN_EXPOSED = {}

# Routes that answer a restricted key something other than a refusal when it
# sends a request the instance would act on for its owner. Each with why that
# is right.
MAY_ANSWER = {
    'POST /api/certificates/deployment-status/browser':
        'records nothing for a name outside the key\'s scope, and says which it skipped',
    'POST /api/certificates/reissue-keyless': 'acts only on certificates in the key\'s scope: here, none',
}

# Answered to anyone, with no credentials, by design: what a relying party needs.
PUBLIC_MATERIAL = {
    'GET /api/client-certs/ca', 'GET /api/crl/download/<X>', 'GET /api/ocsp/status/<X>',
    # The OpenAPI document: it says "BEGIN CERTIFICATE" where it describes a PEM field.
    'GET /api/swagger.json',
}

REFUSED = (401, 403)


class Shadow(contract_routes.Plan):
    """The walk's plan, with each of its calls tried first by the restricted keys."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.restricted = None
        self.findings = []
        self.tried = 0
        self.refused = 0
        self.exposed = set()
        self.answered = set()
        self.owner_saw_names = 0
        self.swept = 0
        self.trace = [] if self.trace is None else self.trace

    def _keys(self):
        if self.restricted is None:
            auth = self.container.managers['auth']
            self.restricted = {}
            for role in ('viewer', 'operator'):
                ok, key = auth.create_api_key(f'restricted-{role}', role=role, allowed_domains=NOT_THEIRS)
                assert ok, key
                self.restricted[role] = {'Authorization': f"Bearer {key['token']}"}
            legacy = stored_as_admin_with_domains(self.container, 'restricted-stored-admin', NOT_THEIRS)
            self.restricted['stored-admin'] = {'Authorization': f"Bearer {legacy['token']}"}
        return self.restricted

    def call(self, verb, template, path=None, body=None, client=None, headers=None,
             stream=False, query=None, data=None, keep=False, limited=False, defect=None):
        key = f'{verb.upper()} {re.sub(r"<[^>]+>", "<X>", template)}'
        attempts = []
        # Only the calls the walk makes as the instance's owner. The ones it makes
        # with a session, with no credentials or to reach the rate limit are about
        # something else.
        if headers is None and client is None and not limited:
            for who, credentials in self._keys().items():
                kwargs = {'headers': credentials}
                if body is not None:
                    kwargs['json'] = body
                if query:
                    kwargs['query_string'] = query
                response = getattr(self.admin, verb)(path or template, **kwargs)
                # A stream is not read: an event stream has no end. That it was
                # opened at all is what is judged.
                text = '' if stream else response.get_data(as_text=True)
                sent = f'{path or template} {json.dumps(body, default=str)} {json.dumps(query, default=str)}'
                attempts.append((who, response.status_code, text, sent))
                response.close()
        response, payload = super().call(
            verb, template, path=path, body=body, client=client, headers=headers,
            stream=stream, query=query, data=data, keep=keep, limited=limited, defect=defect)
        if attempts and SOMEONE_ELSES.search(json.dumps(payload, default=str)):
            self.owner_saw_names += 1
        for who, status, text, sent in attempts:
            self._judge(key, path or template, verb.upper(), stream, who, status, text,
                        response.status_code, sent=sent, about_a_domain='<domain>' in template)
        return response, payload

    def _judge(self, key, path, verb, stream, who, status, text, owner_status, sent='',
               about_a_domain=False):
        self.tried += 1
        where = f'{key} [{who}: {status}] {path}'
        if status in REFUSED:
            self.refused += 1
            return
        if status >= 500:
            self.findings.append(f'{where}: a server error')
            return
        if about_a_domain and status != 400:
            # Every domain the walk names is outside the key's scope. Anything
            # but a refusal tells the key something about that domain: a 404
            # says no certificate exists for it, where a 403 says nothing.
            # (400 is for a name that is not a domain at all.)
            self.findings.append(f'{where}: a route about a domain did not refuse')
        # A name the caller sent, said back to it, is not a name it learned.
        named = next((m.group(0) for m in SOMEONE_ELSES.finditer(text)
                      if m.group(0).lower() not in sent.lower()), None)
        if named:
            if key in KNOWN_EXPOSED:
                self.exposed.add(key)
            else:
                self.findings.append(f'{where}: names {named!r}')
        if MATERIAL.search(text) and key not in PUBLIC_MATERIAL:
            self.findings.append(f'{where}: certificate or key material')
        if status < 300 and stream and key not in PUBLIC_MATERIAL:
            self.findings.append(f'{where}: a download was opened')
        # A 404 where the owner succeeded is a refusal by another name: the
        # route hides what the key may not see, existing or not.
        acted = verb != 'GET' and (status < 300 or (owner_status < 300 and status != 404))
        if acted:
            if key in MAY_ANSWER:
                self.answered.add(key)
            else:
                self.findings.append(
                    f'{where}: not refused (the owner got {owner_status}); '
                    f'refuse it, or list the route in MAY_ANSWER with the reason')


@pytest.fixture(scope='module')
def shadow(tmp_path_factory):
    built = {}

    class Recording(Shadow):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            built['plan'] = self

    app, token = contract_support.build_app()
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(contract_routes, 'Plan', Recording)
        contract_routes.run(app, token)
    plan = built['plan']
    try:
        _sweep(plan, tmp_path_factory.mktemp('restricted-sweep'))
    finally:
        # The sweep scrapes /metrics, and the collector gathers at most once per
        # interval for the whole process: left fresh for whichever test scrapes next.
        metrics.metrics_collector.last_collection = 0
    return plan


@contextlib.contextmanager
def _ordinary_application(tmp):
    """The application built the ordinary way (the walk's is built without its
    templates and answers every page with a 500), seeded the way the walk's is."""
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
        certbot = world.Certbot()
        with world.certbot_standing_in(certbot):
            seeded = world.seed(container, 0)
            sweep = Shadow(app, token, container=container)
            sweep.world = seeded
            yield sweep, app, certbot


def _sweep(plan, tmp):
    """The routes the walk does not call: everything outside /api/ (the pages,
    /metrics, /health) and the dashboard's own /api/web/ routes.

    GET with nothing, and every other verb with an empty body: enough to see a
    route that answers a restricted key, and not enough to prove one refuses a
    valid request. The walk proves that for the routes it has, and
    `dashboard` below for the dashboard's routes that take a body.
    """
    with _ordinary_application(tmp) as (sweep, app, _certbot):
        seeded = sweep.world
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
                for who, credentials in sweep._keys().items():
                    sweep.forget_the_rate()
                    kwargs = {'headers': credentials}
                    if verb != 'GET':
                        kwargs['json'] = {}
                    response = sweep.admin.open(path, method=verb, **kwargs)
                    # Everything is read but an event stream, which has no end.
                    endless = response.mimetype == 'text/event-stream'
                    text = '' if endless else response.get_data().decode('utf-8', 'replace')
                    status = response.status_code
                    response.close()
                    plan.swept += 1
                    plan._judge(key, path, verb, False, who, status, text, owner_status=599,
                                sent=path, about_a_domain='domain>' in template)


def test_no_call_of_the_walk_gives_a_restricted_key_what_is_not_its_own(shadow):
    assert not shadow.findings, (
        f'{len(shadow.findings)} answer(s) to a key restricted to {NOT_THEIRS}:\n  '
        + '\n  '.join(shadow.findings[:40]))


def test_the_walk_was_tried_and_the_instance_did_hold_those_names(shadow):
    """CONTROL: without this, an instance that held nothing, or keys that were
    never tried, would pass the test above."""
    assert shadow.tried > 600, shadow.tried
    assert shadow.refused > 300, shadow.refused
    assert shadow.owner_saw_names > 40, shadow.owner_saw_names
    assert shadow.swept > 100, shadow.swept


def test_every_exception_is_still_one(shadow):
    assert shadow.exposed == set(KNOWN_EXPOSED), (
        'no longer exposed, remove from KNOWN_EXPOSED: '
        f'{sorted(set(KNOWN_EXPOSED) - shadow.exposed)}')
    assert shadow.answered == set(MAY_ANSWER), (
        'no longer answered, remove from MAY_ANSWER: '
        f'{sorted(set(MAY_ANSWER) - shadow.answered)}')


# The dashboard's own routes are outside the walk, and an empty body is answered
# about the body before anything is said about the caller's domains. These are
# the ones that take a body and are open to a viewer or an operator.
@pytest.fixture(scope='module')
def dashboard(tmp_path_factory):
    tmp = tmp_path_factory.mktemp('restricted-dashboard')
    try:
        with _ordinary_application(tmp) as (sweep, _app, certbot):
            held = sorted(path.name for path in (tmp / 'certs').iterdir())
            owner = {'Authorization': f'Bearer {sweep.token}'}

            def post(path, body, credentials):
                sweep.forget_the_rate()
                response = sweep.admin.post(path, json=body, headers=credentials)
                payload = response.get_data()
                response.close()
                return response.status_code, payload

            yield {'post': post, 'keys': sweep._keys(), 'owner': owner, 'held': held,
                   'certbot': certbot, 'certs': tmp / 'certs', 'theirs': sweep.world.domain}
    finally:
        metrics.metrics_collector.last_collection = 0


def _bundled(payload):
    return zipfile.ZipFile(io.BytesIO(payload)).namelist()


def test_the_dashboard_bundle_holds_nothing_for_a_restricted_key(dashboard):
    post, held = dashboard['post'], dashboard['held']

    # CONTROL: the owner gets every certificate it asks for.
    status, payload = post('/api/web/certificates/download/batch', {'domains': held}, dashboard['owner'])
    assert status == 200 and len(_bundled(payload)) == len(held) > 0, (status, held)

    for who, credentials in dashboard['keys'].items():
        status, payload = post('/api/web/certificates/download/batch', {'domains': held}, credentials)
        assert status == 200 and _bundled(payload) == [], (who, status, _bundled(payload))


@pytest.mark.parametrize('body', [
    {'domain': 'outside-a.example.test'},
    {'domain': 'in.nothing.example', 'san_domains': ['outside-b.example.test']},
], ids=['a name outside the scope', 'a name inside it with one outside'])
def test_the_dashboard_creates_nothing_for_a_restricted_key(dashboard, body):
    post, certbot = dashboard['post'], dashboard['certbot']
    for who, credentials in dashboard['keys'].items():
        before = len(certbot.commands)
        status, _payload = post('/api/web/certificates/create', body, credentials)
        assert status == 403, (who, status)
        assert len(certbot.commands) == before, f'{who}: certbot was run'
    assert not (dashboard['certs'] / body['domain']).exists()


def test_the_dashboard_batch_creates_nothing_for_a_restricted_key(dashboard):
    post, certbot = dashboard['post'], dashboard['certbot']
    wanted = ['outside-c.example.test', dashboard['theirs']]
    for who, credentials in dashboard['keys'].items():
        before = len(certbot.commands)
        status, payload = post('/api/web/certificates/batch', {'domains': wanted}, credentials)
        if status == 403:
            continue  # the viewer: below the route's role
        results = json.loads(payload)
        assert status == 200 and [entry['success'] for entry in results] == [False, False], (who, results)
        assert len(certbot.commands) == before, f'{who}: certbot was run'
    assert not (dashboard['certs'] / 'outside-c.example.test').exists()


def test_the_dashboard_does_create_for_the_owner(dashboard):
    """CONTROL: the same request the restricted keys were refused."""
    post, certbot = dashboard['post'], dashboard['certbot']
    before = len(certbot.commands)
    status, payload = post('/api/web/certificates/create', {'domain': 'outside-a.example.test'},
                           dashboard['owner'])
    assert status == 200, (status, payload[:200])
    assert len(certbot.commands) > before
