"""The examples in docs/api.md are held to the answers the routes give (#1105, stage 2).

How a block says what it is, and how it is compared, is in `tests/docs_shapes.py`. The record of
the answers is the route walk's snapshot, which `tests/test_the_contract_moves_with_the_routes.py`
holds equal to the routes, so comparing with the file is comparing with the routes.
"""
import json

import pytest

from tests import docs_shapes as shapes

pytestmark = [pytest.mark.unit]


@pytest.fixture(scope='module')
def measured():
    return shapes.current()


def test_every_block_says_what_it_is_and_names_a_call_the_walk_makes(measured):
    _found, problems = measured
    assert problems == [], (
        'Every code block in the API reference (bar `bash`) carries a marker on the line before it, '
        'and a response or request block is JSON that names a route and status the walk records. '
        'See tests/docs_shapes.py:\n  ' + '\n  '.join(problems))


def test_the_examples_are_out_of_line_only_where_the_baseline_says(measured):
    found, _problems = measured
    baseline = json.loads(shapes.BASELINE.read_text(encoding='utf-8'))
    new = {block: delta for block, delta in found.items() if baseline.get(block) != delta}
    fixed = sorted(block for block in baseline if block not in found)
    lines = []
    for block, delta in sorted(new.items()):
        was = baseline.get(block, {})
        for kind in shapes.DIFFERENCES:
            for path in sorted(set(delta.get(kind, ())) - set(was.get(kind, ()))):
                lines.append(f'  {block}: {kind} {path}')
            for path in sorted(set(was.get(kind, ())) - set(delta.get(kind, ()))):
                lines.append(f'  {block}: no longer {kind} {path} (take it out of the baseline)')
    lines += [f'  {block}: in line now (take it out of the baseline)' for block in fixed]
    assert not lines, (
        'docs/api.md and the answers the routes give differ from what '
        f'{shapes.BASELINE.relative_to(shapes.REPO)} records. A new difference is a document to fix, '
        'not a line to add; a difference that went away leaves the baseline with '
        '`python -m tests.docs_shapes write`, which refuses to add one:\n'
        + '\n'.join(lines))


SHAPE = {'.': ['dict'], 'name': ['str'], 'count': ['int'], 'ratio': ['number'],
         'owner': ['dict'], 'owner.id': ['str'], 'gone': ['null'],
         'items': ['list'], 'items[]': ['dict'], 'items[].id': ['str'], 'empty': ['list'],
         'by_usage': ['dict'], 'by_usage.*': ['int']}


@pytest.mark.parametrize('example, excerpt, expected', [
    ({'name': 'a', 'count': 1, 'ratio': 2, 'owner': {'id': 'x'}, 'gone': None, 'items': [{'id': 'i'}],
      'empty': [], 'by_usage': {'vpn': 1, 'api-mtls': 2}}, False, {}),
    ({'name': 'a', 'status': 'active'}, True, {'never_seen': ['status']}),
    ({'name': 'a', 'renewal': {'enabled': True}}, True, {'never_seen': ['renewal']}),
    ({'name': 1}, True, {'mistyped': ['name: int, sent as str']}),
    ({'name': 'a'}, False, {'omitted': ['by_usage', 'count', 'empty', 'gone', 'items', 'owner', 'ratio']}),
    ({'name': 'a', 'items': []}, True, {}),
    ({'items': [{}]}, False, {'omitted': ['by_usage', 'count', 'empty', 'gone', 'items[].id', 'name',
                                          'owner', 'ratio']}),
    ({'gone': {'deep': 1}}, True, {'unverified': ['gone']}),
    ({'empty': [{'x': 1}]}, True, {'unverified': ['empty[]']}),
])
def test_a_block_is_compared_field_by_field(example, excerpt, expected):
    assert shapes.differences(example, SHAPE, unseen=['empty'], maps={'by_usage'}, excerpt=excerpt) == expected


def test_a_concrete_path_finds_its_template():
    routes = {'GET /api/crl/download/<X>': {}, 'GET /api/client-certs/<X>': {}, 'GET /api/client-certs/stats': {}}
    assert shapes.route_of('GET', '/api/crl/download/info', routes) == 'GET /api/crl/download/<X>'
    assert shapes.route_of('GET', '/api/client-certs/stats', routes) == 'GET /api/client-certs/stats'
    assert shapes.route_of('GET', '/api/client-certs/<identifier>', routes) == 'GET /api/client-certs/<X>'
    assert shapes.route_of('POST', '/api/client-certs/stats', routes) is None


@pytest.mark.parametrize('marker, body, lang, problem', [
    ('', '{}', 'json', 'no marker'),
    ('', 'Authorization: Bearer x', '', 'no marker'),
    ('<!-- respons: GET /api/health 200 -->', '{}', 'json', 'no marker'),
    ('<!-- response: GET /api/health -->', '{}', 'json', 'cannot read'),
    ('<!-- response: GET /api/nothing 200 -->', '{}', 'json', 'not a route'),
    ('<!-- response: GET /api/health 418 -->', '{}', 'json', 'no 418 answer'),
    ('<!-- response: GET /api/health 200 -->', '{ "ok": true, ... }', 'json', 'must be JSON'),
    ('<!-- request: POST /api/health -->', '{}', 'json', 'not a route'),
    ('<!-- response: GET /api/health 200 -->', '{}', 'json', None),
    ('<!-- illustration: the error envelope -->', 'anything at all', '', None),
    ('', 'curl ...', 'bash', None),
])
def test_a_marker_is_read_or_refused(marker, body, lang, problem):
    routes = {'GET /api/health': {'200': {}}}
    _kind, _details, found = shapes.read_marker(shapes.Block('x.md', 2, lang, marker, body), routes)
    if problem is None:
        assert found is None
    else:
        assert found is not None and problem in found


def test_writing_the_baseline_never_adds_a_difference():
    baseline = {'docs/api.md GET /x 200': {'omitted': ['a']}}
    assert shapes.growth({'docs/api.md GET /x 200': {'omitted': ['a']}}, baseline) == []
    assert shapes.growth({}, baseline) == []
    assert shapes.growth({'docs/api.md GET /x 200': {'omitted': ['a', 'b']}}, baseline) == [
        'docs/api.md GET /x 200: omitted b']
    assert shapes.growth({'docs/api.md GET /y 200': {'never_seen': ['c']}}, baseline) == [
        'docs/api.md GET /y 200: never_seen c']


def test_every_api_reference_is_read():
    """The five files are the English page and its four translations; a sixth would be unread."""
    on_disk = sorted(str(path.relative_to(shapes.REPO)) for path in shapes.REPO.glob('docs/**/api.md'))
    assert on_disk == sorted(shapes.DOCS)
