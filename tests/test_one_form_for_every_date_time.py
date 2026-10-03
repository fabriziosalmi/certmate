"""Every date-time the API answers with has one form: ISO 8601, UTC, with a `Z` (#1127).

modules/api/timestamps.py rewrites the fields it names on the way out. This holds it to every
answer of every route the walk calls, and to every response example in docs/api.md: a date-time
in another form fails, with the route and the field, so a new field is named there or here.
`expiry_date` keeps its own form on purpose (deprecated; `expires_at` is the same instant).
"""
import json
import re

import pytest

from modules.api import timestamps

pytestmark = [pytest.mark.unit]

# Anything a reader would take for a date-time: a date and a time, with or without an offset.
DATE_TIME = re.compile(r'^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?$')
ONE_FORM = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$')
OWN_FORM = {'expiry_date'}


def _odd(payload, where, path=''):
    found = []
    if isinstance(payload, dict):
        for key, value in payload.items():
            found += _odd(value, where, f'{path}.{key}' if path else key)
    elif isinstance(payload, list):
        for item in payload:
            found += _odd(item, where, f'{path}[]')
    elif isinstance(payload, str) and DATE_TIME.match(payload) and not ONE_FORM.match(payload):
        if path.rsplit('.', 1)[-1] not in OWN_FORM:
            found.append(f'{where} {path}: {payload}')
    return found


@pytest.fixture(scope='module')
def answers():
    from tests import contract_routes as routes
    from tests import contract_support as support

    seen = []
    original = routes.Plan.call

    def call(plan, verb, template, *args, **kwargs):
        response, payload = original(plan, verb, template, *args, **kwargs)
        seen.append((f'{verb.upper()} {template} [{response.status_code}]', payload))
        return response, payload

    routes.Plan.call = call
    try:
        routes.run(*support.build_app())
    finally:
        routes.Plan.call = original
    return seen


def test_every_date_time_the_routes_answer_with_has_the_one_form(answers):
    odd = sorted({line for where, payload in answers for line in _odd(payload, where)})
    assert odd == [], ('date-times in another form; name the field in '
                       'modules/api/timestamps.TIMESTAMP_KEYS:\n  ' + '\n  '.join(odd))


def test_the_walk_saw_date_times_at_all(answers):
    """CONTROL: a walk whose answers held no date-time would pass the test above by having
    nothing to check."""
    count = sum(1 for _where, payload in answers for _ in re.finditer(
        r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z', json.dumps(payload)))
    assert count > 100, count


def test_every_response_example_in_the_reference_has_the_one_form():
    from tests import docs_shapes

    odd = []
    for relative in docs_shapes.DOCS:
        for block in docs_shapes.blocks(relative):
            if not block.marker.strip().startswith('<!-- response:'):
                continue
            odd += _odd(json.loads(block.body), f'{relative}:{block.line}')
    assert odd == [], 'response examples with a date-time in another form:\n  ' + '\n  '.join(odd)


@pytest.mark.parametrize('value, expected', [
    ('2026-10-02T22:26:14.669591', '2026-10-02T22:26:14.669591Z'),
    ('2026-10-02T22:26:14', '2026-10-02T22:26:14Z'),
    ('2026-10-02T22:26:14+00:00', '2026-10-02T22:26:14Z'),
    ('2026-10-02T22:26:14Z', '2026-10-02T22:26:14Z'),
    ('2026-10-02T22:26:14+02:00', '2026-10-02T22:26:14+02:00'),   # not UTC: not ours to restate
    ('2026-11-30 09:17:11', '2026-11-30 09:17:11'),               # expiry_date's own form
    ('a note', 'a note'), (None, None), (42, 42),
])
def test_a_value_is_restated_only_when_it_is_utc_without_the_z(value, expected):
    assert timestamps.with_z(value) == expected


def test_only_named_fields_are_touched():
    """An operator's note can hold a date and is not one."""
    payload = {'created_at': '2026-10-02T22:26:14', 'notes': '2026-10-02T22:26:14',
               'items': [{'renewed_at': '2026-10-02T22:26:14+00:00'}]}
    out, changed = timestamps.normalize(payload)
    assert changed
    assert out == {'created_at': '2026-10-02T22:26:14Z', 'notes': '2026-10-02T22:26:14',
                   'items': [{'renewed_at': '2026-10-02T22:26:14Z'}]}


def test_the_hook_rewrites_json_answers_under_api_and_nothing_else():
    """Through a real Flask app: a JSON answer under /api/ is restated; one outside /api/, one
    that is not JSON, and one whose JSON body cannot be read pass through byte for byte."""
    from flask import Flask, Response, jsonify

    app = Flask(__name__)
    timestamps.apply_timestamp_form(app)

    @app.route('/api/thing')
    def thing():
        return jsonify({'created_at': '2026-10-02T22:26:14'})

    @app.route('/page')
    def page():
        return jsonify({'created_at': '2026-10-02T22:26:14'})

    @app.route('/api/broken')
    def broken():
        return Response('{not json', mimetype='application/json')

    @app.route('/api/text')
    def text():
        return Response('created_at 2026-10-02T22:26:14', mimetype='text/plain')

    client = app.test_client()
    assert client.get('/api/thing').get_json() == {'created_at': '2026-10-02T22:26:14Z'}
    assert client.get('/page').get_json() == {'created_at': '2026-10-02T22:26:14'}
    assert client.get('/api/broken').get_data() == b'{not json'
    assert client.get('/api/text').get_data() == b'created_at 2026-10-02T22:26:14'
