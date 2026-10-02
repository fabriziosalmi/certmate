"""What the routes outside the OpenAPI document actually answer.

`tests/contract_support.py` compares the OpenAPI document with the version. A route
that is a plain Flask route is not in that document: its fields are described in
docs/api.md and nowhere a test can read, so nothing compared them with the version
(#1086). This module calls each of them on the real app, in a fixed order and on a
state it builds itself (a user, a key, a DNS account, a webhook target), and records
the STRUCTURE of every answer: which fields, of which type, under which status
code. Values are never recorded.

It characterizes, it does not specify: it records what the routes do today, so that
a change to it is a change somebody reads and, by the rule beside
API_CONTRACT_VERSION, classifies. What it cannot see is written down in the snapshot
and not left out of it:

  * the REQUEST side (the fields a route accepts live in the handlers and the docs);
  * `not_called`: routes this plan does not call, each with the reason;
  * `unseen_items`: answers that held an empty list, whose elements were not seen;
  * `opaque`: sub-objects that change with what happened rather than with the code
    (an audit entry's `details`), recorded as "an object" and nothing below.

Regenerate after moving the version:

    python tests/contract_support.py write
"""
import json
import re

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
NOT_CALLED = {
    'GET /api/swagger.json': 'it is the OpenAPI document itself; tests/test_the_contract_moves_with_the_models.py compares it',
    'GET /api/auth/oidc/callback': 'the return leg of a login at an identity provider; needs one',
    'GET /api/auth/oidc/login': 'redirects to an identity provider; needs one',
}


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
    def __init__(self, app, token, trace=None):
        self.app, self.token, self.trace = app, token, trace
        self.admin = app.test_client()
        self.headers = {'Authorization': f'Bearer {token}'}
        self.seen = {}
        self.context = {}

    def call(self, verb, template, path=None, body=None, client=None, headers=None,
             stream=False, query=None):
        path = path or template
        key = f'{verb.upper()} {re.sub(r"<[^>]+>", "<X>", template)}'
        client = client or self.admin
        kwargs = {'headers': self.headers if headers is None else headers}
        if body is not None:
            kwargs['json'] = body
        if query:
            kwargs['query_string'] = query
        response = getattr(client, verb)(path, **kwargs)
        if stream:
            payload = {'<stream>': response.content_type.split(';')[0]}
            response.close()
        else:
            payload = response.get_json(silent=True)
            if payload is None:
                payload = {'<non-json>': (response.content_type or '').split(';')[0]}
        if self.trace is not None:
            self.trace.append((key, path, response.status_code))
        by_status = self.seen.setdefault(key, {})
        entry = by_status.setdefault(str(response.status_code), {})
        for found, types in flatten(payload, MAPS_BY_ROUTE.get(key, ()),
                                    OPAQUE_BY_ROUTE.get(key, ())).items():
            entry.setdefault(found, set()).update(types)
        return response, payload


def _target():
    return {'type': 'webhook', 'id': 'lb', 'name': 'Load balancer', 'enabled': True,
            'domains': ['shop.example.com'],
            'config': {'url': 'https://lb.example.com:8443/api/certificate',
                       'payload_template': '{"domain": "{{domain}}"}', 'allow_internal': True}}


def run(app, token, trace=None):
    """Call the plan. Returns (routes, unseen) where routes is
    {route: {status: {path: [types]}}}."""
    plan = Plan(app, token, trace)
    call = plan.call
    password = 'correct-horse-9-battery'

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
    _, created = call('post', '/api/keys', body={'name': 'ci', 'role': 'viewer'})
    key_id = (created or {}).get('id')
    call('post', '/api/keys', body={})                                                       # 400
    call('get', '/api/keys')
    if key_id:
        call('patch', '/api/keys/<key_id>', path=f'/api/keys/{key_id}', body={'confirmed': True})
        call('patch', '/api/keys/<key_id>', path=f'/api/keys/{key_id}', body={})             # 400
        call('delete', '/api/keys/<key_id>', path=f'/api/keys/{key_id}')
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


def document(routes, unseen):
    sys_path_fix()
    from modules.core.constants import API_CONTRACT_VERSION
    return {'contract_version': API_CONTRACT_VERSION, 'routes': routes,
            'not_called': dict(sorted(NOT_CALLED.items())), 'unseen_items': unseen,
            'opaque': {k: sorted(v) for k, v in sorted(OPAQUE_BY_ROUTE.items())}}


def sys_path_fix():
    import sys
    if str(REPO) not in sys.path:
        sys.path.insert(0, str(REPO))


def write_snapshot(built):
    routes, unseen = run(*built)
    SNAPSHOT.write_text(json.dumps(document(routes, unseen), indent=1, sort_keys=True) + '\n',
                        encoding='utf-8')
    statuses = sum(len(v) for v in routes.values())
    print(f'wrote {SNAPSHOT.relative_to(REPO)}: {len(routes)} routes, {statuses} answers, '
          f'{len(NOT_CALLED)} not called, {len(unseen)} with elements unseen')
