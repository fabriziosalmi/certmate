"""A field added to a response, or a request field that becomes required, must move the contract.

The rule beside `API_CONTRACT_VERSION` has six clauses: a new endpoint, a new field
on a response, a new optional request field (each a MINOR), and an endpoint
removed, a field removed or retyped, a request field that becomes required, a
status code that changes (each a MAJOR). `tests/test_the_contract_moves_with_the_
surface.py` records the routes and sees the first and the fourth. The comment
under the constant says so itself: "all of those can ship with this number
unmoved, and one already did". Then another did.

#1071 added two optional fields to the Route53 account (`auth_mode` and
`assume_role_arn`), a MINOR by the rule, and merged with the number where it was:
nothing compares what a model contains with the version that describes it.

This does. `tests/api_models_surface.json` records the structure of the OpenAPI
document the app serves at /api/swagger.json (models, their fields and types and
enums, which are required, each operation's parameters and status codes), taken at
the contract version the file names, and the test fails when the app describes
something else, saying for each difference which way the version has to move. It is
a snapshot and not a derivation, for the reason the route snapshot is: changing
what a response contains should make you open the file where the version is
written down.

`tests/contract_support.py` reduces the document and compares two reductions.
Regenerate the snapshot after moving the version:

    python tests/contract_support.py write

Prose is not recorded (descriptions, examples, defaults), so fixing a typo in one
never fails this.
"""
import json

import pytest

from modules.core.constants import API_CONTRACT_VERSION
from tests import contract_support as support

pytestmark = [pytest.mark.unit]


@pytest.fixture(scope='module')
def built():
    return support.build_app()


@pytest.fixture(scope='module')
def current(built):
    return support.reduce(support.swagger_spec(built))


@pytest.fixture(scope='module')
def snapshot():
    return json.loads(support.SNAPSHOT.read_text(encoding='utf-8'))


def test_the_recorded_models_are_the_ones_the_app_describes(current, snapshot):
    differences = support.compare(snapshot, current)
    if not differences:
        return
    lines = [f'  [{severity}] {text}' for severity, text in differences]
    pytest.fail(
        'The OpenAPI document the app serves no longer matches '
        f'{support.SNAPSHOT.relative_to(support.REPO)}, which records contract '
        f'{snapshot["contract_version"]}. The rule is beside API_CONTRACT_VERSION in '
        'modules/core/constants.py: a new field on a response, a new optional '
        'request field, a new value of an existing request field, a new endpoint '
        'are a MINOR; a field removed or retyped, a request field that becomes '
        'required, a changed status code, a removed endpoint are a MAJOR. Move the '
        'version, write the history line, update docs/api.md, regenerate the '
        'snapshot (python tests/contract_support.py write):\n' + '\n'.join(lines))


def test_the_routes_the_document_does_not_describe_are_the_ones_recorded(built, current, snapshot):
    """The limit of this gate, written down where a diff shows it.

    A route that is not in the OpenAPI document is a plain Flask route whose fields are
    described in docs/api.md and nowhere a test can read: nothing compares what it
    returns with the version. The list is recorded so that a route entering or leaving
    the document, or a new route that stays outside it, is a change somebody reads.
    Describing a route in the document is what brings it under the comparison above.
    """
    now = support.outside_openapi(support.route_surface(built[0]), current['operations'])
    recorded = snapshot['outside_openapi']
    added, gone = sorted(set(now) - set(recorded)), sorted(set(recorded) - set(now))
    assert not (added or gone), (
        'The routes outside the OpenAPI document changed. Routes that now sit outside it '
        '(their fields are compared with nothing; describe them in the document if you '
        f'can):\n  ' + '\n  '.join(added or ['(none)']) +
        '\nRoutes that are now inside it (good; they are compared from now on):\n  ' +
        '\n  '.join(gone or ['(none)']) +
        '\nRegenerate the snapshot: python tests/contract_support.py write')


def test_the_recorded_version_is_the_one_the_app_sends(snapshot):
    assert snapshot['contract_version'] == API_CONTRACT_VERSION, (
        f'{support.SNAPSHOT.relative_to(support.REPO)} records contract '
        f'{snapshot["contract_version"]} and the app sends {API_CONTRACT_VERSION}. '
        f'Whichever moved, the other has to follow in the same commit.')


def test_the_instrument_sees_the_models(current):
    """CONTROL. A reduction that stopped finding the models would compare two empty
    documents and pass while proving nothing."""
    properties = sum(len(model['properties']) for model in current['models'].values())
    assert len(current['models']) >= 40 and properties >= 200 and len(current['operations']) >= 60, (
        f'{len(current["models"])} models, {properties} fields, {len(current["operations"])} '
        f'operations: too few to be this application')


def test_a_field_added_without_moving_the_version_is_what_this_exists_to_catch(snapshot):
    """CONTROL on the comparison, with the case that happened (#1071): a model gains a
    field and the record still describes the model before it. Built from the snapshot
    itself, by taking the field out of the recorded copy, so it does not depend on which
    version the snapshot is at."""
    recorded = json.loads(json.dumps({k: snapshot[k] for k in ('models', 'operations')}))
    assert 'auth_mode' in recorded['models']['Route53Config']['properties'], (
        'the snapshot no longer has the field this control is built on')
    del recorded['models']['Route53Config']['properties']['auth_mode']
    now = {k: snapshot[k] for k in ('models', 'operations')}
    assert support.compare(recorded, now) == [
        (support.MINOR, 'Route53Config.auth_mode is a new field')]


# --------------------------------------------------------------------------
# The comparison itself, on small documents: each clause of the rule has a case.
# --------------------------------------------------------------------------

def _doc(properties=None, required=None, parameters=None, responses=None):
    return {
        'models': {'Thing': {'required': required or [], 'properties': properties or {}}},
        'operations': {'GET /things': {'parameters': parameters or {}, 'responses': responses or {'200': None}}},
    }


def _severities(before, after):
    return [severity for severity, _text in support.compare(before, after)]


BASE_PROPS = {'name': {'type': 'string'}, 'mode': {'type': 'string', 'enum': ['a', 'b']}}


@pytest.mark.parametrize('label, before, after, expected', [
    ('no change', _doc(BASE_PROPS), _doc(BASE_PROPS), []),
    ('a field added to a response', _doc(BASE_PROPS), _doc({**BASE_PROPS, 'extra': {'type': 'string'}}), [support.MINOR]),
    ('a field removed', _doc(BASE_PROPS), _doc({'name': {'type': 'string'}}), [support.MAJOR]),
    ('a field retyped', _doc(BASE_PROPS), _doc({**BASE_PROPS, 'name': {'type': 'integer'}}), [support.MAJOR]),
    ('an enum value added', _doc(BASE_PROPS), _doc({**BASE_PROPS, 'mode': {'type': 'string', 'enum': ['a', 'b', 'c']}}), [support.MINOR]),
    ('an enum value removed', _doc(BASE_PROPS), _doc({**BASE_PROPS, 'mode': {'type': 'string', 'enum': ['a']}}), [support.MAJOR]),
    ('a field becomes required', _doc(BASE_PROPS), _doc(BASE_PROPS, required=['name']), [support.REVIEW]),
    ('an optional request parameter added', _doc(), _doc(parameters={'query:q': {'required': False, 'shape': {'type': 'string'}}}), [support.MINOR]),
    ('a required request parameter added', _doc(), _doc(parameters={'query:q': {'required': True, 'shape': {'type': 'string'}}}), [support.MAJOR]),
    ('a parameter removed', _doc(parameters={'query:q': {'required': False, 'shape': {'type': 'string'}}}), _doc(), [support.MAJOR]),
    ('a parameter becomes required', _doc(parameters={'query:q': {'required': False, 'shape': {'type': 'string'}}}), _doc(parameters={'query:q': {'required': True, 'shape': {'type': 'string'}}}), [support.MAJOR]),
    ('a status code appears', _doc(), _doc(responses={'200': None, '409': None}), [support.REVIEW]),
    ('a status code disappears', _doc(responses={'200': None, '404': None}), _doc(), [support.MAJOR]),
    ('a response changes shape', _doc(responses={'200': {'$ref': '#/definitions/A'}}), _doc(responses={'200': {'$ref': '#/definitions/B'}}), [support.MAJOR]),
])
def test_each_clause_of_the_rule_is_classified(label, before, after, expected):
    assert _severities(before, after) == expected, label


def test_a_model_that_is_new_or_gone_is_reported():
    before = _doc(BASE_PROPS)
    after = json.loads(json.dumps(before))
    after['models']['Other'] = {'required': [], 'properties': {}}
    assert _severities(before, after) == [support.NOTE]
    assert _severities(after, before) == [support.MAJOR]


def test_the_worst_difference_is_listed_first():
    before = _doc(BASE_PROPS)
    after = _doc({'name': {'type': 'integer'}, 'extra': {'type': 'string'}})
    severities = _severities(before, after)
    assert severities == sorted(severities, key=lambda s: support.ORDER[s])
    assert severities[0] == support.MAJOR


def test_prose_does_not_move_the_snapshot():
    """Descriptions, examples and defaults are not the contract."""
    spec = {'definitions': {'Thing': {'properties': {'name': {
        'type': 'string', 'description': 'A name', 'example': 'x', 'default': 'y'}}}}, 'paths': {}}
    reworded = {'definitions': {'Thing': {'properties': {'name': {
        'type': 'string', 'description': 'The name, reworded', 'example': 'z'}}}}, 'paths': {}}
    assert support.compare(support.reduce(spec), support.reduce(reworded)) == []
