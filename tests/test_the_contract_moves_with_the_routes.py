"""The routes the OpenAPI document does not describe move the contract too (#1086).

42 of the API's 111 routes are plain Flask routes: users, API keys, deploy
configuration, authentication, the audit trail. They are described in docs/api.md and
nowhere a test can read, so `tests/test_the_contract_moves_with_the_models.py`, which
compares the OpenAPI document with the version, cannot see them: a field added to one
of those answers, or removed, moved nothing.

`tests/contract_routes.py` calls each of them on the real app, in a fixed order and on a
state it builds, and records the structure of every answer (fields, types, status
codes; never values) in `tests/api_routes_surface.json`. This test fails when an answer
no longer matches, saying for each difference which way the contract version has to
move by the rule beside `API_CONTRACT_VERSION`.

It characterizes; it does not specify. It records what the routes do today, so a change
is read and classified. What it cannot see is recorded in the snapshot rather than left
out of it: the request side, the routes not called (each with its reason), answers that
held an empty list, and the sub-objects that change with what happened rather than with
the code. A route that answers wrongly today is listed as not called with the issue, not
recorded: a snapshot of a 500 is a test that guards the defect.

Regenerate after moving the version:

    python tests/contract_support.py write
"""
import json

import pytest

from modules.core.constants import API_CONTRACT_VERSION
from tests import contract_routes as routes
from tests import contract_support as support

pytestmark = [pytest.mark.unit]


@pytest.fixture(scope='module')
def built():
    return support.build_app()


@pytest.fixture(scope='module')
def outcome(built):
    return routes.run(*built)


@pytest.fixture(scope='module')
def snapshot():
    return json.loads(routes.SNAPSHOT.read_text(encoding='utf-8'))


def test_the_recorded_answers_are_the_ones_the_routes_give(outcome, snapshot):
    differences = routes.compare(snapshot['routes'], outcome[0])
    if not differences:
        return
    lines = [f'  [{severity}] {text}' for severity, text in differences]
    pytest.fail(
        'The routes outside the OpenAPI document no longer answer what '
        f'{routes.SNAPSHOT.relative_to(support.REPO)} records at contract '
        f'{snapshot["contract_version"]}. The rule is beside API_CONTRACT_VERSION in '
        'modules/core/constants.py: a new field on an answer, a new route are a MINOR; '
        'a field removed or retyped, a changed status code, a removed route are a MAJOR. '
        'Move the version, write the history line, update docs/api.md, regenerate the '
        'snapshot (python tests/contract_support.py write):\n' + '\n'.join(lines))


def test_what_the_plan_could_not_see_is_recorded_as_it_is_now(outcome, snapshot):
    """The blind spots are part of the file, so a diff shows them move."""
    assert snapshot['unseen_items'] == outcome[1], (
        'Answers whose list elements were never seen changed (a list that now holds '
        'something is good: its fields are compared from now on). Regenerate: '
        'python tests/contract_support.py write')
    assert snapshot['not_called'] == dict(sorted(routes.NOT_CALLED.items()))
    assert snapshot['opaque'] == {k: sorted(v) for k, v in sorted(routes.OPAQUE_BY_ROUTE.items())}


def test_every_route_outside_the_document_is_called_or_explained(built, outcome):
    """A route added to the app and to neither the plan nor the table is noticed here,
    and a table entry for a route that is gone or now inside the document is stale."""
    app, _token = built
    spec = support.reduce(support.swagger_spec(built))
    outside = set(support.outside_openapi(support.route_surface(app), spec['operations']))
    called = set(outcome[0])

    undecided = sorted(outside - called - set(routes.NOT_CALLED))
    assert not undecided, (
        'Routes outside the OpenAPI document that the plan neither calls nor explains. '
        'Add a call to tests/contract_routes.py:run, or an entry (with the reason) to '
        'NOT_CALLED:\n  ' + '\n  '.join(undecided))
    stale = sorted((set(routes.NOT_CALLED) | called) - outside)
    assert not stale, (
        'Routes the plan knows that are not outside the document any more (gone, or '
        'described in it now, which is where they should be compared):\n  ' + '\n  '.join(stale))
    both = sorted(called & set(routes.NOT_CALLED))
    assert not both, f'Called and listed as not called: {both}'


def test_every_route_not_called_says_why():
    for route, reason in routes.NOT_CALLED.items():
        assert isinstance(reason, str) and len(reason) > 20, route


def test_the_recorded_version_is_the_one_the_app_sends(snapshot):
    assert snapshot['contract_version'] == API_CONTRACT_VERSION, (
        f'{routes.SNAPSHOT.relative_to(support.REPO)} records contract '
        f'{snapshot["contract_version"]} and the app sends {API_CONTRACT_VERSION}. '
        f'Whichever moved, the other has to follow in the same commit.')


# --------------------------------------------------------------------------
# The instrument. A snapshot that is not repeatable is worse than none: it fails
# for nothing, and people learn to regenerate it without reading it.
# --------------------------------------------------------------------------

def test_the_instrument_sees_the_routes(outcome):
    """CONTROL. A plan that stopped reaching its routes would record nothing and
    compare nothing with nothing."""
    answers = sum(len(by_status) for by_status in outcome[0].values())
    fields = sum(len(paths) for by_status in outcome[0].values() for paths in by_status.values())
    assert len(outcome[0]) >= 30 and answers >= 45 and fields >= 250, (
        f'{len(outcome[0])} routes, {answers} answers, {fields} fields: too few to be this API')


def test_no_answer_in_the_plan_is_a_server_error(outcome):
    """A 500 is not a contract: it is a defect, and recording it would make it one
    (#1088 is the case that found this). The plan must not reach one."""
    errors = sorted(f'{route} [{status}]' for route, by_status in outcome[0].items()
                    for status in by_status if status.startswith('5'))
    assert not errors, (
        'The plan reaches a server error. If the route is wrong, fix it and keep it in '
        'the plan; if it is a known defect, take the call out and list the route in '
        'NOT_CALLED with its issue:\n  ' + '\n  '.join(errors))


def test_the_plan_gives_the_same_answer_on_a_fresh_instance(outcome):
    """CONTROL on repeatability: a second app, built from nothing, answers the same."""
    again = routes.run(*support.build_app())
    assert routes.compare(outcome[0], again[0]) == [], 'the plan depends on something it does not build'
    assert outcome[1] == again[1]


def test_what_changes_with_the_event_is_not_recorded(snapshot):
    """CONTROL on the opaque subtrees: an audit entry's `details` has the fields of
    the action that wrote it, so a new kind of event must not move a response that did
    not change. They are an object and nothing below it."""
    export = snapshot['routes']['GET /api/audit/export']['200']
    assert export['entries[].entry.details'] == ['dict']
    assert not [path for path in export if path.startswith('entries[].entry.details.')]


def test_a_field_added_without_moving_the_version_is_what_this_exists_to_catch(snapshot):
    """CONTROL on the comparison, with the case it exists for: an answer gains a field
    and the record still describes the answer before it."""
    recorded = json.loads(json.dumps(snapshot['routes']))
    assert 'users.*.role' in recorded['GET /api/users']['200'], (
        'the snapshot no longer has the field this control is built on')
    del recorded['GET /api/users']['200']['users.*.role']
    now = json.loads(json.dumps(snapshot['routes']))
    assert routes.compare(recorded, now) == [
        (support.MINOR, 'GET /api/users [200]: users.*.role is a new field (str)')]


# --------------------------------------------------------------------------
# The comparison and the flattening, on small documents: each clause has a case.
# --------------------------------------------------------------------------

def _route(paths=None, status='200'):
    return {'GET /x': {status: paths or {'.': ['dict'], 'a': ['str']}}}


def _severities(before, after):
    return [severity for severity, _text in routes.compare(before, after)]


@pytest.mark.parametrize('label, before, after, expected', [
    ('no change', _route(), _route(), []),
    ('a field added', _route(), _route({'.': ['dict'], 'a': ['str'], 'b': ['int']}), [support.MINOR]),
    ('a field removed', _route(), _route({'.': ['dict']}), [support.MAJOR]),
    ('a field retyped', _route(), _route({'.': ['dict'], 'a': ['int']}), [support.MAJOR]),
    ('a type added to a field', _route(), _route({'.': ['dict'], 'a': ['int', 'str']}), [support.MAJOR]),
    ('null -> a value', _route({'.': ['dict'], 'a': ['null']}), _route(), [support.REVIEW]),
    ('a value -> null', _route(), _route({'.': ['dict'], 'a': ['null']}), [support.REVIEW]),
    ('a status appears', _route(), {'GET /x': {**_route()['GET /x'], '409': {'.': ['dict']}}}, [support.REVIEW]),
    ('a status disappears', {'GET /x': {**_route()['GET /x'], '409': {'.': ['dict']}}}, _route(), [support.MAJOR]),
    ('a status changes', _route(status='200'), _route(status='204'), [support.MAJOR, support.REVIEW]),
    ('a route the plan no longer reaches', _route(), {}, [support.MAJOR]),
    ('a route the plan reaches now', {}, _route(), [support.MINOR]),
    ('the same field in a list', _route({'.': ['list'], '[]': ['dict'], '[].a': ['str']}),
     _route({'.': ['list'], '[]': ['dict'], '[].a': ['str'], '[].b': ['str']}), [support.MINOR]),
])
def test_each_clause_of_the_rule_is_classified(label, before, after, expected):
    assert _severities(before, after) == expected, label


def test_the_worst_difference_is_listed_first():
    before = _route()
    after = {'GET /x': {'200': {'.': ['dict'], 'a': ['int'], 'extra': ['str']}}}
    severities = _severities(before, after)
    assert severities == sorted(severities, key=lambda s: support.ORDER[s])
    assert severities[0] == support.MAJOR


def test_a_uuid_key_and_a_named_map_collapse_to_one_shape():
    uuid = '6e783249-b1da-4321-bbd8-ebb40055684d'
    other = '2dee7933-53b7-4eaf-9370-f173385cd78c'
    first = routes.flatten({uuid: {'name': 'a'}})
    second = routes.flatten({other: {'name': 'b'}, uuid: {'name': 'c'}})
    assert first == second == {'.': {'dict'}, '*': {'dict'}, '*.name': {'str'}}
    mapped = routes.flatten({'users': {'alice': {'role': 'x'}, 'bob': {'role': 'y'}}}, maps={'users'})
    assert set(mapped) == {'.', 'users', 'users.*', 'users.*.role'}


def test_an_opaque_subtree_is_an_object_and_nothing_below_it():
    flat = routes.flatten({'entries': [{'details': {'x': 1}}]}, opaque={'entries[].details'})
    assert flat['entries[].details'] == {'dict'}
    assert not [path for path in flat if path.startswith('entries[].details.')]


def test_null_counts_only_where_nothing_else_was_ever_seen():
    assert routes.finish({'a': {'null'}, 'b': {'null', 'str'}, 'c': {'int', 'str'}}) == {
        'a': ['null'], 'b': ['str'], 'c': ['int', 'str']}


def test_a_list_none_of_whose_elements_were_seen_is_reported():
    seen = routes.flatten({'items': [], 'full': [{'a': 1}]})
    assert routes.unseen_items(seen) == ['items']
    assert routes.unseen_items(routes.flatten([])) == ['.']
