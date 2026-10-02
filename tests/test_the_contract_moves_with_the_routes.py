"""What every route answers moves the contract too (#1086, #1105).

The OpenAPI document declares a response schema for 7 of its 69 operations, and 42 more
routes are plain Flask routes it does not describe at all: users, API keys, deploy
configuration, authentication, the audit trail. What 104 of the API's 111 routes send was
written in docs/api.md and nowhere a test could read, so
`tests/test_the_contract_moves_with_the_models.py`, which compares the OpenAPI document
with the version, could not see a field added to one of those answers, or removed, or a
status code that changed: nothing moved the version.

`tests/contract_routes.py` calls every route it can (108 of 111) on the real app, in a
fixed order, on a state it builds, in a world sealed from the network
(`tests/contract_world.py`), and records the structure of every answer (fields, types,
status codes; never values) in `tests/api_routes_surface.json`. This test fails when an
answer no longer matches, saying for each difference which way the contract version has to
move by the rule beside `API_CONTRACT_VERSION`.

It characterizes; it does not specify. It records what the routes do today, so a change
is read and classified. What it cannot see is recorded in the snapshot rather than left
out of it: the request side, the routes not called and the routes with no success answer
(each with its reason), answers that held an empty list, and the sub-objects that change
with what happened rather than with the code. A call that shows a wrong answer is listed
under `known_defects` with its issue, made and checked, and not recorded: a snapshot of a
wrong answer is a test that guards the wrong answer.

Regenerate after moving the version:

    python tests/contract_support.py write
"""
import json
import re

import pytest

from modules.core.constants import API_CONTRACT_VERSION
from tests import contract_routes as routes
from tests import contract_support as support

pytestmark = [pytest.mark.unit]


@pytest.fixture(scope='module')
def built():
    return support.build_app()


@pytest.fixture(scope='module')
def ran(built):
    report = {}
    return routes.run(*built, report=report), report


@pytest.fixture(scope='module')
def outcome(ran):
    return ran[0]


@pytest.fixture(scope='module')
def report(ran):
    return ran[1]


@pytest.fixture(scope='module')
def snapshot():
    return json.loads(routes.SNAPSHOT.read_text(encoding='utf-8'))


def test_the_recorded_answers_are_the_ones_the_routes_give(outcome, snapshot):
    differences = routes.compare(snapshot['routes'], outcome[0])
    if not differences:
        return
    lines = [f'  [{severity}] {text}' for severity, text in differences]
    pytest.fail(
        'The routes no longer answer what '
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
    assert snapshot['no_success'] == dict(sorted(routes.NO_SUCCESS.items()))
    assert snapshot['opaque'] == {k: sorted(v) for k, v in sorted(routes.OPAQUE_BY_ROUTE.items())}
    assert snapshot['maps'] == {k: sorted(v) for k, v in sorted(routes.MAPS_BY_ROUTE.items())}
    assert snapshot['catalogues'] == {k: dict(sorted(v.items()))
                                      for k, v in sorted(routes.CATALOGUES_BY_ROUTE.items())}


def test_every_route_is_called_or_explained(built, outcome):
    """A route added to the app and to neither the plan nor the table is noticed here,
    and a table entry for a route that is gone is stale."""
    app, _token = built
    surface = support.route_surface(app)
    called = set(outcome[0])

    undecided = sorted(surface - called - set(routes.NOT_CALLED))
    assert not undecided, (
        'Routes the plan neither calls nor explains. Add a call to tests/contract_plan.py '
        '(the routes the OpenAPI document describes) or to tests/contract_routes.py:_walk '
        '(the others), or an entry (with the reason) to NOT_CALLED:\n  ' + '\n  '.join(undecided))
    stale = sorted((set(routes.NOT_CALLED) | called) - surface)
    assert not stale, ('Routes the plan knows that the app does not serve any more:\n  '
                       + '\n  '.join(stale))
    both = sorted(called & set(routes.NOT_CALLED))
    assert not both, f'Called and listed as not called: {both}'


def test_a_route_with_no_success_answer_says_why(outcome):
    """A route whose recorded answers are all errors has a success shape nothing compares.
    That is allowed, but it has to be written down, and the entry has to go the day the
    route gets a 2xx."""
    without = {route for route, by_status in outcome[0].items()
               if not any(status.startswith('2') for status in by_status)}
    unexplained = sorted(without - set(routes.NO_SUCCESS))
    assert not unexplained, (
        'Routes the plan reaches only with error answers. Reach a 2xx (a state to seed, a '
        'body to send) or add the route, with the reason, to NO_SUCCESS in '
        'tests/contract_routes.py:\n  ' + '\n  '.join(unexplained))
    stale = sorted(set(routes.NO_SUCCESS) - without)
    assert not stale, (
        'NO_SUCCESS lists routes that now have a 2xx answer in the plan; remove them:\n  '
        + '\n  '.join(stale))
    for route, reason in routes.NO_SUCCESS.items():
        assert len(reason) > 20, route


def test_the_plan_leaves_the_login_limiter_empty(outcome):
    """The plan logs in; the limiter is per process. CI failed a dozen unrelated tests with "Too many
    attempts" because the first version left its attempts behind."""
    from modules.web import routes as web_routes
    assert outcome[0]['POST /api/auth/login'], 'CONTROL: the plan did log in'
    assert not web_routes._login_attempts_by_ip and not web_routes._login_attempts_by_user


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
    assert len(outcome[0]) >= 100 and answers >= 160 and fields >= 700, (
        f'{len(outcome[0])} routes, {answers} answers, {fields} fields: too few to be this API')


def test_no_answer_in_the_plan_is_a_server_error(outcome):
    """A 500 is not a contract: it is a defect, and recording it would make it one
    (#1088 is the case that found this). The plan must not reach one."""
    errors = sorted(f'{route} [{status}]' for route, by_status in outcome[0].items()
                    for status in by_status if status.startswith('5'))
    assert not errors, (
        'The plan reaches a server error. If the route is wrong, fix it and keep it in '
        'the plan; if it is a known defect, pass `defect=(issue, status)` to the call so '
        'that it is checked and not recorded:\n  ' + '\n  '.join(errors))


def test_no_answer_has_a_status_and_a_body_that_disagree(report):
    """`POST /api/deploy/test/<id>` answered 404 for every hook that ran and succeeded, with
    `"success": true` in the body (#1107). A client that reads the status and one that reads
    the body disagree about what happened, and each is right by its own reading."""
    assert report['contradictions'] == []


def test_no_answer_records_a_name_from_the_data_as_a_field(report):
    """`GET /api/client-certs/stats` was recorded with `by_organization.CertMate` and the zombie
    scan with `results[].domains.shop.example.test`: the seeded organization and domains as if
    they were fields, so seeding another name moved the snapshot with no change to the API. A key
    that is not snake_case is a name from the data unless the object is declared a map (keys
    collapse to `*`) or a catalogue (keys fixed by the code), with the reason (#1105)."""
    assert report['data_keys'] == [], (
        'These answers have keys that are not field names. Declare the object in MAPS_BY_ROUTE '
        '(keyed by data) or CATALOGUES_BY_ROUTE (keyed by the code, with the reason) in '
        'tests/contract_routes.py:\n  ' + '\n  '.join(report['data_keys']))


def test_every_map_and_catalogue_is_one_the_plan_sees(outcome):
    """A declaration for an object no answer has is an exemption waiting for the wrong thing."""
    stale = []
    for route, paths in routes.MAPS_BY_ROUTE.items():
        recorded = {p for shape in outcome[0].get(route, {}).values() for p in shape}
        stale += [f'map {route} {path}' for path in paths
                  if f'{path}.*' not in recorded and not (path == '.' and '*' in recorded)]
    for route, paths in routes.CATALOGUES_BY_ROUTE.items():
        recorded = {p for shape in outcome[0].get(route, {}).values() for p in shape}
        stale += [f'catalogue {route} {path}' for path in paths if path not in recorded]
    assert stale == []


def test_every_known_defect_still_shows_the_defect(report, snapshot):
    """The calls that show a wrong answer are made and not recorded. They are checked
    here, so the entry cannot outlive the defect: when the answer changes, the fix has
    arrived, and the call goes back to being an ordinary one."""
    fixed = [f'{call} answered {got}, which is no longer the {expected} that {issue} is about: '
             f'drop `defect=` from the call and regenerate'
             for call, issue, expected, got in report['defects'] if got != expected]
    assert not fixed, '\n'.join(fixed)
    for call, issue, _expected, _got in report['defects']:
        assert re.fullmatch(r'#\d+', issue), f'{call}: {issue!r} is not an issue number'
    assert snapshot['known_defects'] == {call: issue for call, issue, _e, _g in sorted(report['defects'])}


def test_the_plan_gives_the_same_answer_on_a_fresh_instance(outcome, report):
    """CONTROL on repeatability: a second app, built from nothing, answers the same. A snapshot
    that is not repeatable fails for nothing, and people learn to regenerate it without reading it."""
    second = {}
    again = routes.run(*support.build_app(), report=second)
    assert routes.compare(outcome[0], again[0]) == [], 'the plan depends on something it does not build'
    assert outcome[1] == again[1]
    assert second['defects'] == report['defects']


def test_the_plan_does_not_depend_on_what_ran_in_the_process_before_it(outcome, report):
    """The full suite was where the walk disagreed with its own snapshot, twice: the platform
    module remembers `uname -p` for the life of the process (a fresh one failed under the seal
    and answered with an `errors` block, a used one did not), and the metrics collector reports
    `0`, an int, until someone collects and a float after. Run alone, or twice in a row, the
    walk agreed with itself. So the process is made fresh in one way and used in the other, and
    the answers have to be the same as the ones recorded."""
    import platform
    import time

    from modules.core import metrics
    saved = platform._uname_cache, metrics.metrics_collector.last_collection
    try:
        platform._uname_cache = None                          # a process that never asked
        cold = routes.run(*support.build_app(), report={})
        platform._uname_cache = None
        metrics.metrics_collector.last_collection = time.time()   # a process where something collected
        used = routes.run(*support.build_app(), report={})
    finally:
        platform._uname_cache, metrics.metrics_collector.last_collection = saved
    assert routes.compare(outcome[0], cold[0]) == [], 'the answers depend on a cold process'
    assert routes.compare(outcome[0], used[0]) == [], 'the answers depend on a used process'
    assert metrics.metrics_collector.last_collection == saved[1], 'the walk left the collector changed'


def _inside_temp(container):
    import tempfile
    from pathlib import Path
    temp = Path(tempfile.gettempdir()).resolve()
    stray = []
    for name in ('cert_dir', 'data_dir', 'backup_dir', 'logs_dir'):
        path = Path(getattr(container, name)).resolve()
        if temp not in path.parents or support.REPO in path.parents:
            stray.append(f'{name} is {path}')
    return stray


def test_the_plan_leaves_nothing_outside_the_instance_it_built(built):
    """The plan creates certificates, backups, accounts and users, and restores a backup over
    the instance. All of it has to land in the directory the app was built in."""
    assert _inside_temp(built[0].extensions['certmate_container']) == []


def test_the_plan_issues_from_a_directory_of_its_own(report):
    """The credentials file certbot reads is written relative to the working directory. The plan
    issues certificates, so with the checkout as the working directory it would put a credential
    file in the repository tree (measured), and the tree is not the instance it built."""
    import tempfile
    from pathlib import Path
    assert report['cwds'], 'CONTROL: the plan ran certbot, so there is a working directory to check'
    temp = Path(tempfile.gettempdir()).resolve()
    for cwd in set(report['cwds']):
        assert temp in Path(cwd).resolve().parents and support.REPO not in Path(cwd).resolve().parents, cwd


def test_an_instance_pointing_at_a_real_tree_is_not_the_one_the_plan_runs_on(tmp_path, monkeypatch):
    """CONTROL. CERTMATE_*_DIR take precedence over the anchor the app is built on, and a developer
    with them exported would have the plan delete their certificates and restore a backup over
    them. `build_app` must not read them."""
    for name in support.RUNTIME_DIR_VARIABLES:
        monkeypatch.setenv(name, str(tmp_path / name.lower()))
    container = support.build_app()[0].extensions['certmate_container']
    assert _inside_temp(container) == []
    assert not any(tmp_path.iterdir()), 'the app wrote into a directory named by the environment'
    import os
    assert all(os.environ[name] == str(tmp_path / name.lower()) for name in support.RUNTIME_DIR_VARIABLES), (
        'build_app did not put the environment back')


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


@pytest.mark.parametrize('payload, maps, catalogues, expected', [
    ({'domains': {'shop.example.test': 'ok'}}, (), {}, [('domains', 'shop.example.test')]),
    ({'by_org': {'CertMate': 1}}, (), {}, [('by_org', 'CertMate')]),
    ({'r': [{'by_usage': {'api-mtls': 1}}]}, (), {}, [('r[].by_usage', 'api-mtls')]),
    ({'domains': {'shop.example.test': 'ok'}}, {'domains'}, {}, []),
    ({'expiry': {'7': 0, '30': 1}}, (), {'expiry': 'buckets'}, []),
    ({'6e783249-b1da-4321-bbd8-ebb40055684d': {'name': 'a'}}, (), {}, []),
    ({'field_name': 1, 'other2': {'nested_one': True}}, (), {}, []),
])
def test_a_key_from_the_data_is_found_on_the_raw_key(payload, maps, catalogues, expected):
    assert routes.data_keys(payload, maps, catalogues) == expected


def test_an_opaque_subtree_has_no_data_keys_to_find():
    assert routes.data_keys({'details': {'Some Key': 1}}, opaque={'details'}) == []


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


# --------------------------------------------------------------------------
# The rules the plan applies to what it sees, on small apps: each has a case that fires.
# --------------------------------------------------------------------------

@pytest.mark.parametrize('status, payload, expected', [
    (404, {'success': True}, True),
    (500, {'ok': True}, True),
    (400, {'status': 'success'}, True),
    (200, {'success': True}, False),            # the ordinary case
    (404, {'success': False}, False),
    (404, {'error': 'no such hook'}, False),
    (404, ['success'], False),
    (404, None, False),
])
def test_an_error_status_with_a_body_that_says_it_worked_is_found(status, payload, expected):
    assert routes.says_success(status, payload) is expected


def _tiny_app():
    from flask import Flask, jsonify
    app = Flask(__name__)
    app.add_url_rule('/wrong', 'wrong', lambda: (jsonify({'error': 'boom'}), 500))
    app.add_url_rule('/liar', 'liar', lambda: (jsonify({'success': True}), 404))
    app.add_url_rule('/fine', 'fine', lambda: jsonify({'a': 'x'}))
    return app


def test_a_call_that_shows_a_known_defect_is_checked_and_not_recorded():
    plan = routes.Plan(_tiny_app(), 'token')
    plan.call('get', '/wrong', defect=('#1', 500))
    assert plan.seen == {}, 'a defect was recorded, so the snapshot would guard it'
    assert plan.defects == [('GET /wrong /wrong', '#1', 500, 500)]

    plan.call('get', '/fine')
    assert 'GET /fine' in plan.seen and plan.defects == plan.defects[:1]


def test_a_call_whose_status_and_body_disagree_is_reported_unless_it_is_a_known_defect():
    plan = routes.Plan(_tiny_app(), 'token')
    plan.call('get', '/liar')
    assert plan.contradictions == ['GET /liar [404] /liar']
    plan.call('get', '/liar', defect=('#2', 404))
    assert len(plan.contradictions) == 1, 'a known defect is reported once, in its own list'
