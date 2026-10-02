"""What every route of the API actually answers.

`tests/contract_support.py` compares the OpenAPI document with the version, and the
document declares a response schema for 7 of its 69 operations (#1105): what the other 62
send, and under which status codes, was described in docs/api.md and nowhere a test could
read. The 42 routes that are plain Flask routes were not in the document at all (#1086).
This module calls ALL of them (108 of the 111; 3 cannot be called, see `NOT_CALLED`) on the
real app, in a fixed order and on a state it builds itself, and records the STRUCTURE of
every answer: which fields, of which type, under which status code. Values are never
recorded.

The world it runs in is built by `tests/contract_world.py`: a seeded instance, certbot
replaced by a stand-in that writes what certbot writes, and a seal that refuses every
connection beyond the loopback interface, every DNS query and every child process, so a
route that would reach the world can be called and answers as it does when the world does not
answer. The plan itself is `tests/contract_plan.py` (the routes the OpenAPI document
describes) and `_walk` below (the plain Flask routes).

It characterizes, it does not specify: it records what the routes do today, so that
a change to it is a change somebody reads and, by the rule beside
API_CONTRACT_VERSION, classifies. What it cannot see is written down in the snapshot
and not left out of it:

  * the REQUEST side (the fields a route accepts live in the handlers and the docs);
  * `not_called`: routes this plan does not call, each with the reason;
  * `no_success`: routes whose plan reaches no 2xx answer, each with the reason;
  * `known_defects`: calls that showed a wrong answer. They are made, checked to still be
    wrong, and NOT recorded: a snapshot of a wrong answer is a test that guards it;
  * `unseen_items`: answers that held an empty list, whose elements were not seen;
  * `opaque`: sub-objects that change with what happened rather than with the code
    (an audit entry's `details`), recorded as "an object" and nothing below.

Regenerate after moving the version:

    python tests/contract_support.py write
"""
import json
import re
import time

from tests.contract_support import MAJOR, MINOR, ORDER, REPO, REVIEW

SNAPSHOT = REPO / 'tests' / 'api_routes_surface.json'

UUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')

# Paths whose children are keyed by something the caller chooses (a username, a
# domain): the keys are not part of the shape. (A key that is a UUID is collapsed
# wherever it is.)
MAPS_BY_ROUTE = {
    'GET /api/users': {'users'},
    'GET /api/deploy/config': {'domain_hooks'},
}

# Sub-objects whose fields depend on which operation happened, not on the code: an
# audit entry's `details` has the fields of the action that wrote it. Recorded as an
# object, nothing below, or any new kind of event would move a response that did not.
OPAQUE_BY_ROUTE = {
    'GET /api/audit/export': {'entries[].entry.details'},
    'GET /api/activity': {'entries[].details'},
}

# Routes deliberately not called, each with the reason. A route outside the OpenAPI
# document that is in neither the plan nor this table fails the test, so a new one
# has to be decided about.
# Routes whose plan reaches no 2xx answer, each with the reason. A route with only error answers
# recorded is a route whose success shape is not compared with anything, and that has to be said.
# The entry goes when the route gets a 2xx (the test fails if it stays).
NO_SUCCESS = {
    'POST /api/deploy/test/<X>': 'the only answer a hook that ran can get today is a 404 (#1107); the call that '
                                 'shows it is a known defect and is not recorded',
    'POST /api/storage/azure-keyvault/backfill-certificates': 'it copies the certificates into a real Azure Key '
                                                              'Vault, which needs the Azure SDK and the vault',
}

NOT_CALLED = {
    'GET /api/swagger.json': 'it is the OpenAPI document itself; tests/test_the_contract_moves_with_the_models.py compares it',
    'GET /api/auth/oidc/callback': 'the return leg of a login at an identity provider; needs one',
    'GET /api/auth/oidc/login': 'redirects to an identity provider; needs one',
}


def says_success(status, payload):
    """An error status whose body says it worked. A client that reads the status and one that
    reads the body then disagree about what happened, and `POST /api/deploy/test/<id>` answered
    404 for every hook that ran and succeeded (#1107)."""
    return (status >= 400 and isinstance(payload, dict)
            and (payload.get('success') is True or payload.get('ok') is True
                 or payload.get('status') == 'success'))


def _type(value):
    if value is None:
        return 'null'
    if isinstance(value, bool):
        return 'bool'
    if isinstance(value, int):
        return 'int'
    if isinstance(value, float):
        return 'number'
    if isinstance(value, str):
        return 'str'
    return 'list' if isinstance(value, list) else 'dict'


def flatten(value, maps=(), opaque=(), prefix='', out=None):
    """{path: {types}} for a JSON value. Lists are `[]`, mapped dicts are `*`."""
    out = {} if out is None else out
    out.setdefault(prefix or '.', set()).add(_type(value))
    if prefix in opaque:
        return out
    if isinstance(value, dict):
        for key, child in value.items():
            collapsed = prefix in maps or (isinstance(key, str) and UUID.match(key))
            name = '*' if collapsed else key
            flatten(child, maps, opaque, f'{prefix}.{name}' if prefix else name, out)
    elif isinstance(value, list):
        for child in value:
            flatten(child, maps, opaque, f'{prefix}[]', out)
    return out


def finish(paths):
    """Types as sorted lists. `null` is kept only where nothing else was ever seen.

    A field that is null in one state and a string in another is the same field; if
    `null` counted, the snapshot would depend on which state the plan built.
    """
    return {path: sorted(types - {'null'}) or ['null'] for path, types in sorted(paths.items())}


def unseen_items(paths):
    """Paths that are lists none of whose elements were seen (an empty answer)."""
    return sorted(path for path, types in paths.items()
                  if 'list' in types and f'{"" if path == "." else path}[]' not in paths)


class Plan:
    def __init__(self, app, token, trace=None, certbot=None, container=None):
        self.app, self.token, self.trace = app, token, trace
        self.admin = app.test_client()
        self.headers = {'Authorization': f'Bearer {token}'}
        self.seen = {}
        self.context = {}
        self.certbot, self.container = certbot, container
        self.last_body = None
        self.world = None
        self.defects = []           # (call, issue, expected status, status it answered)
        self.contradictions = []    # answers whose status and body disagree

    def call(self, verb, template, path=None, body=None, client=None, headers=None,
             stream=False, query=None, data=None, keep=False, limited=False, defect=None):
        path = path or template
        if not limited:
            self.forget_the_rate()
        key = f'{verb.upper()} {re.sub(r"<[^>]+>", "<X>", template)}'
        client = client or self.admin
        kwargs = {'headers': self.headers if headers is None else headers}
        if body is not None:
            kwargs['json'] = body
        if data is not None:
            kwargs.update(data=data, content_type='multipart/form-data')
        if query:
            kwargs['query_string'] = query
        response = getattr(client, verb)(path, **kwargs)
        self.last_body = None
        if stream:
            payload = {'<stream>': response.content_type.split(';')[0]}
            if keep:        # never for an event stream: it has no end
                self.last_body = response.get_data()
            response.close()
        else:
            payload = response.get_json(silent=True)
            if payload is None:
                payload = {'<non-json>': (response.content_type or '').split(';')[0]}
        if self.trace is not None:
            self.trace.append((key, path, response.status_code))
        if defect is not None:
            # A call that shows a known defect is not recorded: a snapshot of a wrong answer is a
            # test that guards the wrong answer. It is kept here, with its issue, and the test
            # fails when the answer stops being the wrong one, so the entry cannot go stale.
            issue, expected = defect
            self.defects.append((f'{key} {path}', issue, expected, response.status_code))
            return response, payload
        if says_success(response.status_code, payload):
            self.contradictions.append(f'{key} [{response.status_code}] {path}')
        by_status = self.seen.setdefault(key, {})
        entry = by_status.setdefault(str(response.status_code), {})
        for found, types in flatten(payload, MAPS_BY_ROUTE.get(key, ()),
                                    OPAQUE_BY_ROUTE.get(key, ())).items():
            entry.setdefault(found, set()).update(types)
        return response, payload

    def forget_the_rate(self):
        """Every call arrives in a minute of its own. The plan makes hundreds of calls and the API
        answers 429 after 100 a minute: a plan that counted on the clock would record 429 for
        whatever route happened to be called after the hundredth. `limited=True` leaves the
        count alone, which is how the rate-limit answer itself is reached on purpose."""
        limiter = (self.container.managers.get('rate_limiter') if self.container else None)
        if limiter is not None:
            limiter.requests.clear()

    def wait_job(self, job_id, until=('succeeded', 'failed'), seconds=30):
        """Wait for an async issuance job to reach one of the states `until`. The job runs on a
        thread of its own; a walk that went on without it would record answers that depend on
        who got there first."""
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            response = self.admin.get(f'/api/certificates/jobs/{job_id}', headers=self.headers)
            if (response.get_json(silent=True) or {}).get('status') in until:
                return
            time.sleep(0.02)
        raise AssertionError(f'job {job_id} did not reach {until} in {seconds}s')


def _target():
    return {'type': 'webhook', 'id': 'lb', 'name': 'Load balancer', 'enabled': True,
            'domains': ['shop.example.com'],
            'config': {'url': 'https://lb.example.com:8443/api/certificate',
                       'payload_template': '{"domain": "{{domain}}"}', 'allow_internal': True}}


def run(app, token, trace=None, report=None):
    """Call the plan. Returns (routes, unseen) where routes is
    {route: {status: {path: [types]}}}.

    The plan runs in a sealed world (tests/contract_world.py): nothing leaves the process, and
    certbot is a stand-in that writes what certbot writes. `report`, when given, is a dict that
    receives `escapes` (what the seal refused, so a caller can see how close the plan came),
    `defects` (calls that showed a known defect and were not recorded), `contradictions` and
    `cwds` (where certbot was run from).

    The plan logs in (a wrong password and a right one) and the login rate limiter is a module
    global of the PROCESS, not of the app: left as it is, the plan spends the budget of every
    test that logs in after it (CI saw "Too many attempts" in a dozen unrelated tests, #1098).
    It is emptied before, so the plan does not depend on who ran first, and after, so it leaves
    nothing behind.
    """
    from modules.web import routes as web_routes
    from tests import contract_world as world
    buckets = (web_routes._login_attempts_by_ip, web_routes._login_attempts_by_user)
    for bucket in buckets:
        bucket.clear()
    try:
        container = app.extensions['certmate_container']
        world.warm_up()
        certbot = world.Certbot()
        with world.sealed() as seal, world.certbot_standing_in(certbot), world.working_directory(), \
                world.serving() as port, world.environment():
            seeded = world.seed(container, port)
            try:
                return _walk(app, token, trace, certbot, container, seeded, report)
            finally:
                if report is not None:
                    report['escapes'] = list(seal.attempts)
                    report['cwds'] = list(certbot.cwds)
    finally:
        for bucket in buckets:
            bucket.clear()


def _walk(app, token, trace, certbot, container, seeded, report):
    from tests import contract_plan
    plan = Plan(app, token, trace, certbot, container)
    plan.world = seeded
    call = plan.call
    password = 'correct-horse-9-battery'

    # --- the routes the OpenAPI document describes (tests/contract_plan.py)
    contract_plan.walk(plan)

    # --- users, and a login and a logout. The browser is a client of its own so its
    # session cookie touches nothing else; local authentication has to be on for a
    # login to be answered at all, and it needs a user to be turned on.
    call('post', '/api/users', body={'username': 'alice', 'password': password, 'role': 'viewer'})
    call('post', '/api/users', body={'username': 'alice', 'password': password})            # 409
    call('post', '/api/users', body={'username': 'x'})                                       # 400
    call('get', '/api/users')
    call('put', '/api/users/<username>', path='/api/users/alice', body={'role': 'operator'})
    call('put', '/api/users/<username>', path='/api/users/nobody', body={'role': 'operator'})

    call('post', '/api/auth/config', body={'local_auth_enabled': True})
    browser = plan.app.test_client()
    origin = {'Origin': 'http://localhost'}
    call('post', '/api/auth/login', client=browser, headers=origin,
         body={'username': 'alice', 'password': 'not-the-password'})
    call('post', '/api/auth/login', client=browser, headers=origin,
         body={'username': 'alice', 'password': password})
    call('get', '/api/auth/me', client=browser, headers=origin)
    call('get', '/api/events/stream', client=browser, headers=origin, stream=True)
    call('post', '/api/auth/logout', client=browser, headers=origin)
    call('post', '/api/auth/config', body={'local_auth_enabled': False})

    call('delete', '/api/users/<username>', path='/api/users/alice')
    call('delete', '/api/users/<username>', path='/api/users/alice')                         # 404

    # --- API keys
    _, created = call('post', '/api/keys', body={'name': 'ci', 'role': 'viewer', 'allowed_domains': ['*.example.test'],
                                                  'expires_at': '2099-01-01T00:00:00+00:00'})
    key_id = (created or {}).get('id')
    call('post', '/api/keys', body={})                                                       # 400
    call('get', '/api/keys')
    if key_id:
        call('patch', '/api/keys/<key_id>', path=f'/api/keys/{key_id}', body={'confirmed': True})  # 400: not from setup
        call('patch', '/api/keys/<key_id>', path=f'/api/keys/{key_id}', body={})             # 400
        call('delete', '/api/keys/<key_id>', path=f'/api/keys/{key_id}')
    setup_key = plan.world.setup_key
    call('patch', '/api/keys/<key_id>', path=f'/api/keys/{setup_key}', body={'confirmed': True})  # vouched for
    call('patch', '/api/keys/<key_id>', path=f'/api/keys/{setup_key}', body={'confirmed': True})  # already
    call('patch', '/api/keys/<key_id>', path='/api/keys/does-not-exist', body={'confirmed': True})
    call('delete', '/api/keys/<key_id>', path='/api/keys/does-not-exist')

    # --- deprecated DNS accounts
    call('post', '/api/dns-providers/accounts',
                   body={'name': 'acct1', 'provider': 'cloudflare', 'config': {'api_token': 'x' * 24}})
    call('post', '/api/dns-providers/accounts', body={})                                     # 400
    call('get', '/api/dns-providers/accounts')
    # The forms with no provider in the path find it when the id belongs to one provider
    # (#1088 was a 500 and a 200 that wrote under a provider called null).
    call('put', '/api/dns-providers/accounts/<account_id>', path='/api/dns-providers/accounts/acct1',
         body={'api_token': 'y' * 24})
    call('put', '/api/dns-providers/accounts/<account_id>', path='/api/dns-providers/accounts/nope',
         body={'api_token': 'y' * 24})                                                          # 404
    call('put', '/api/dns-providers/accounts/<account_id>', path='/api/dns-providers/accounts/default',
         body={'api_token': 'y' * 24})                                                          # 409
    call('delete', '/api/dns-providers/accounts/<account_id>', path='/api/dns-providers/accounts/acct1')
    call('delete', '/api/dns-providers/accounts/<account_id>', path='/api/dns-providers/accounts/nope')

    # --- deploy
    call('get', '/api/deploy/config')
    call('post', '/api/deploy/config',
         body={'enabled': False, 'domain_hooks': {}, 'targets': [_target()],
               'global_hooks': [{'id': 'h1', 'name': 'h1', 'command': 'echo hi', 'enabled': True,
                                 'on_events': ['created', 'renewed']}]})
    call('get', '/api/deploy/config')
    call('get', '/api/deploy/history')
    call('get', '/api/deploy/pending')
    call('post', '/api/deploy/targets/preview', body=_target())
    keyed = _target()
    keyed['config'].update(payload_template='{"cert": "{{fullchain}}", "key": "{{privkey_pkcs8}}"}',
                           acknowledge_key_delivery_to='lb.example.com')
    call('post', '/api/deploy/targets/preview', body=keyed)
    call('post', '/api/deploy/targets/preview', body={'type': 'nope'})                       # 400
    call('post', '/api/deploy/test/<hook_id>', path='/api/deploy/test/unknown', body={})
    call('post', '/api/deploy/test/<hook_id>', path='/api/deploy/test/h1', body={},          # runs: nothing launched
         defect=(contract_plan.DEFECT_DEPLOY_TEST, 404))

    # --- notifications. `test` sends a real message when the channel is real, so it
    # is only called with a channel type that does not exist.
    call('get', '/api/notifications/config')
    call('post', '/api/notifications/config', body={})
    call('post', '/api/notifications/test', body={'channel_type': 'no-such-channel', 'config': {}})
    call('post', '/api/notifications/test', body={})                                         # 400
    call('post', '/api/notifications/webhook/preview',
         body={'config': {'url': 'https://hooks.example.com/x', 'payload_template': '{"e": "{{event}}"}'}})
    call('post', '/api/notifications/webhook/preview', body={'config': {}, 'event': 'Not An Event'})
    call('post', '/api/digest/send', body={})
    call('get', '/api/webhooks/deliveries')

    # --- rate limits
    call('get', '/api/settings/rate-limits')
    call('put', '/api/settings/rate-limits', body={'enabled': True})
    call('put', '/api/settings/rate-limits', body={'limits': {'nope': 1}})                   # 400
    # The 429 every route can answer: a limit of one, then two calls in the same minute.
    call('put', '/api/settings/rate-limits', body={'limits': {'default': 1}})
    plan.forget_the_rate()
    call('get', '/api/health', limited=True)
    call('get', '/api/health', limited=True)                                                 # 429
    call('put', '/api/settings/rate-limits', body={'limits': {'default': 100}})

    # --- single sign-on and authentication settings (last of the writers: they change auth)
    call('get', '/api/auth/oidc/config')
    call('get', '/api/auth/oidc/settings')
    call('post', '/api/auth/oidc/settings', body={'enabled': True})                          # 400: no issuer
    call('post', '/api/auth/oidc/settings',
         body={'enabled': False, 'role_mappings': [{'claim_value': 'certmate-admins', 'role': 'admin'}]})
    call('get', '/api/auth/oidc/settings')
    call('get', '/api/auth/config')
    call('post', '/api/auth/config', body={'local_auth_enabled': True})                      # 400: no user left

    # --- audit, activity, the event stream
    call('get', '/api/audit/public-key')
    call('get', '/api/audit/verify')
    call('get', '/api/audit/export')
    call('get', '/api/activity')

    routes = {key: {status: finish(paths) for status, paths in sorted(by_status.items())}
              for key, by_status in sorted(plan.seen.items())}
    unseen = {key: sorted({path for paths in by_status.values() for path in unseen_items(paths)})
              for key, by_status in sorted(plan.seen.items())}
    if report is not None:
        report['defects'] = list(plan.defects)
        report['contradictions'] = list(plan.contradictions)
    return routes, {key: paths for key, paths in unseen.items() if paths}


# --------------------------------------------------------------------------
# Comparison.
# --------------------------------------------------------------------------

def compare(recorded, current):
    """Every difference between two {route: {status: {path: [types]}}}, as
    (severity, text), worst first.

    Types are compared as sets: a field that is `['str']` and becomes `['int', 'str']`
    has been retyped, and one that is only ever `null` in the plan and then holds a
    value is REVIEW, because the plan's state may be what changed, not the route.
    """
    found = []

    def add(severity, text):
        found.append((severity, text))

    for route in sorted(set(current) - set(recorded)):
        add(MINOR, f'{route} is answered by the plan now and was not recorded (a new route, or a plan step added)')
    for route in sorted(set(recorded) - set(current)):
        add(MAJOR, f'{route} was recorded and the plan no longer reaches it')
    for route in sorted(set(recorded) & set(current)):
        old, new = recorded[route], current[route]
        for status in sorted(set(new) - set(old)):
            add(REVIEW, f'{route}: a {status} answer appears (a code for a new condition is a MINOR; '
                        f'a changed code for an existing condition is a MAJOR)')
        for status in sorted(set(old) - set(new)):
            add(MAJOR, f'{route}: the {status} answer is gone (or its code changed)')
        for status in sorted(set(old) & set(new)):
            before, after = old[status], new[status]
            where = f'{route} [{status}]'
            for path in sorted(set(after) - set(before)):
                add(MINOR, f'{where}: {path} is a new field ({"/".join(after[path])})')
            for path in sorted(set(before) - set(after)):
                add(MAJOR, f'{where}: {path} was removed')
            for path in sorted(set(before) & set(after)):
                if before[path] == after[path]:
                    continue
                if before[path] == ['null'] or after[path] == ['null']:
                    add(REVIEW, f'{where}: {path} went {"/".join(before[path])} -> {"/".join(after[path])} '
                                f'(a field the plan only ever saw as null: the state may have changed, not the route)')
                else:
                    add(MAJOR, f'{where}: {path} changed type: {"/".join(before[path])} -> {"/".join(after[path])}')
    return sorted(found, key=lambda item: (ORDER[item[0]], item[1]))


def document(routes, unseen, defects=()):
    sys_path_fix()
    from modules.core.constants import API_CONTRACT_VERSION
    return {'contract_version': API_CONTRACT_VERSION, 'routes': routes,
            'not_called': dict(sorted(NOT_CALLED.items())),
            'no_success': dict(sorted(NO_SUCCESS.items())),
            'known_defects': {call: issue for call, issue, _expected, _got in sorted(defects)},
            'unseen_items': unseen,
            'opaque': {k: sorted(v) for k, v in sorted(OPAQUE_BY_ROUTE.items())}}


def sys_path_fix():
    import sys
    if str(REPO) not in sys.path:
        sys.path.insert(0, str(REPO))


def write_snapshot(built):
    report = {}
    routes, unseen = run(*built, report=report)
    SNAPSHOT.write_text(json.dumps(document(routes, unseen, report['defects']), indent=1, sort_keys=True) + '\n',
                        encoding='utf-8')
    statuses = sum(len(v) for v in routes.values())
    print(f'wrote {SNAPSHOT.relative_to(REPO)}: {len(routes)} routes, {statuses} answers, '
          f'{len(NOT_CALLED)} not called, {len(NO_SUCCESS)} with no success, '
          f'{len(report["defects"])} known defects, {len(unseen)} with elements unseen')
