"""The 7 operations that declare a response schema are compared with what they send (#1105).

`tests/test_the_contract_moves_with_the_models.py` compares the OpenAPI document with the
version: a field added to a model moves it. It compares a DECLARATION with an earlier
declaration, so a model that promises a field the code never fills, or a field declared with the
wrong type, is unchanged and passes. `tests/contract_routes.py` records what is SENT, by calling
the route. This puts the two side by side, for the operations that have a schema, from the two
snapshots (it calls nothing; the snapshots are compared with the live app by the tests beside
it).

  * a field the answer sends that the model does not declare (a client generated from the
    document does not know it);
  * a declared field the answer never sends;
  * a field whose type in the answer is not the declared one (a generated client parses it
    wrongly);
  * a declared field that is `null` in every answer the plan got: either state the plan did
    not build, or a promise nothing keeps. The second kind is written down with its issue.

What is written down is checked as hard as what is not: an entry for a field that now has a
value, or the right type, fails, so the list cannot outlive the defect it records.
"""
import json
import re

import pytest

from tests import contract_support as support

pytestmark = [pytest.mark.unit]

MODELS = support.REPO / 'tests' / 'api_models_surface.json'
ROUTES = support.REPO / 'tests' / 'api_routes_surface.json'

# JSON-schema type -> the types the walk records.
WALKED = {'string': {'str'}, 'integer': {'int'}, 'number': {'int', 'number'}, 'boolean': {'bool'},
          'object': {'dict'}, 'array': {'list'}}

# Declared fields that are `null` in every answer, route -> {path: why}. A reason that is an
# issue number is a promise nothing keeps; any other reason is state the plan does not build.
NEVER_FILLED = {
    'GET /api/certificates': {
        '[].total_issued': '#1108', '[].total_active': '#1108', '[].total_expired': '#1108',
        '[].total_revoked': '#1108', '[].latest_issuance': '#1108', '[].oldest_active_issuance': '#1108',
        '[].renewal_info': 'the ARI window, filled once the renewal-info check has run',
        '[].storage_warning': 'set only when the external storage backend failed',
    },
    'GET /api/certificates/<X>/deployment-status': {
        'code': 'set only when the probe fails with a classified error',
        'error': 'set only when the probe could not run',
    },
    'GET /api/settings': {
        'api_bearer_token': 'null even with a token saved in the settings (measured): the answer never carries it',
    },
}

# Routes whose null-only fields are not compared: every field is a provider credential, null
# until an account is configured, and the names are what the model snapshot compares.
NULLS_NOT_COMPARED = {
    'GET /api/settings/dns-providers': 'a block of provider credentials, null until one is configured',
}

# Declared with one type and sent with another, route -> {path: why}.
WRONG_TYPE = {}


def _declared(models, schema, prefix=''):
    """{path: (declared type, free-form)} for a schema, in the walk's path syntax."""
    out = {}
    name = prefix or '.'
    if '$ref' in schema:
        schema = models[schema['$ref'].rsplit('/', 1)[1]]
    if schema.get('type') == 'array' or 'items' in schema:
        out[name] = ('array', False)
        out.update(_declared(models, schema.get('items') or {}, prefix + '[]'))
    elif 'properties' in schema:
        out[name] = ('object', False)
        for key, child in schema['properties'].items():
            out.update(_declared(models, child, f'{prefix}.{key}' if prefix else key))
    else:
        kind = schema.get('type', 'object')
        out[name] = (kind, kind == 'object')
    return out


def _compare(models, schema, walked, unseen=()):
    """What differs between a declared schema and the types a route was seen to send."""
    declared = _declared(models, schema)
    free = [p for p, (_kind, loose) in declared.items() if loose]
    below_unseen = [f'{u}[]' for u in unseen]

    def skipped(path):
        return any(path == f or path.startswith(f + '.') for f in free) or any(
            path == b or path.startswith((b + '.', b + '[')) for b in below_unseen)

    return {
        'undeclared': sorted(p for p in walked if p not in declared and not skipped(p)),
        'unsent': sorted(p for p in declared if p not in walked and not skipped(p)),
        'wrong_type': sorted(p for p, types in walked.items()
                             if p in declared and types != ['null']
                             and not set(types) <= WALKED.get(declared[p][0], {declared[p][0]})),
        'never_filled': sorted(p for p, types in walked.items() if p in declared and types == ['null']),
    }


@pytest.fixture(scope='module')
def comparison():
    models_doc = json.loads(MODELS.read_text(encoding='utf-8'))
    walked_doc = json.loads(ROUTES.read_text(encoding='utf-8'))
    found = {}
    for key, operation in sorted(models_doc['operations'].items()):
        schema = operation['responses'].get('200')
        if not schema:
            continue
        verb, path = key.split(' ', 1)
        route = f'{verb} /api{path}'.replace('{X}', '<X>')
        found[route] = _compare(models_doc['models'], schema, walked_doc['routes'][route]['200'],
                                walked_doc['unseen_items'].get(route, []))
    return found


def test_the_instrument_found_the_seven_operations_that_have_a_schema(comparison):
    """CONTROL. A comparison that found nothing to compare would pass every test below."""
    assert sorted(comparison) == [
        'GET /api/backups', 'GET /api/cache/stats', 'GET /api/certificates',
        'GET /api/certificates/<X>/deployment-status', 'GET /api/settings',
        'GET /api/settings/dns-providers', 'POST /api/cache/clear'], sorted(comparison)


def test_an_answer_sends_nothing_the_model_does_not_declare(comparison):
    extra = {route: found['undeclared'] for route, found in comparison.items() if found['undeclared']}
    assert not extra, ('The answer carries fields the OpenAPI model does not declare, so a client '
                       f'generated from the document does not know them: {extra}')


def test_an_answer_sends_everything_the_model_declares(comparison):
    missing = {route: found['unsent'] for route, found in comparison.items() if found['unsent']}
    assert not missing, f'Declared fields the answer never sends: {missing}'


def test_a_field_is_sent_with_the_type_the_model_declares(comparison):
    wrong = {route: [p for p in found['wrong_type'] if p not in WRONG_TYPE.get(route, {})]
             for route, found in comparison.items()}
    wrong = {route: paths for route, paths in wrong.items() if paths}
    assert not wrong, ('Fields sent with a type other than the declared one. Fix the model, or '
                       f'write the field down in WRONG_TYPE with its issue: {wrong}')
    stale = {route: sorted(set(known) - set(comparison[route]['wrong_type']))
             for route, known in WRONG_TYPE.items()}
    stale = {route: paths for route, paths in stale.items() if paths}
    assert not stale, f'WRONG_TYPE lists fields that are sent with the declared type now; remove them: {stale}'


def test_a_declared_field_that_is_always_null_is_written_down(comparison):
    unexplained = {}
    for route, found in comparison.items():
        if route in NULLS_NOT_COMPARED:
            continue
        paths = [p for p in found['never_filled'] if p not in NEVER_FILLED.get(route, {})]
        if paths:
            unexplained[route] = paths
    assert not unexplained, (
        'Declared fields that are null in every answer the plan got. Build the state that fills '
        '(tests/contract_world.py, tests/contract_plan.py), or, if nothing can fill it, write it '
        f'down in NEVER_FILLED with the reason: {unexplained}')


def test_what_is_written_down_as_never_filled_still_is(comparison):
    stale = {route: sorted(set(known) - set(comparison[route]['never_filled']))
             for route, known in NEVER_FILLED.items()}
    stale = {route: paths for route, paths in stale.items() if paths}
    assert not stale, ('NEVER_FILLED lists fields that have a value in some answer now (the defect '
                       f'is fixed, or the plan builds the state); remove them: {stale}')


def test_every_entry_says_why():
    for table in (NEVER_FILLED, WRONG_TYPE):
        for route, entries in table.items():
            for path, why in entries.items():
                assert len(why) >= 5, f'{route} {path}'
    for route, why in NULLS_NOT_COMPARED.items():
        assert len(why) > 20, route
    issues = {why for entries in (*NEVER_FILLED.values(), *WRONG_TYPE.values()) for why in entries.values()
              if why.startswith('#')}
    assert all(re.match(r'#\d+\b', why) for why in issues)


# --------------------------------------------------------------------------
# The comparison itself, on small documents: each clause has a case it must catch.
# --------------------------------------------------------------------------

_MODELS = {
    'Item': {'properties': {'a': {'type': 'string'}, 'b': {'type': 'integer'}, 'bag': {'type': 'object'}}},
    'Page': {'properties': {'items': {'items': {'$ref': '#/definitions/Item'}, 'type': 'array'}}},
}


def test_declared_paths_follow_references_arrays_and_free_form_objects():
    paths = _declared(_MODELS, {'$ref': '#/definitions/Page'})
    assert paths == {'.': ('object', False), 'items': ('array', False), 'items[]': ('object', False),
                     'items[].a': ('string', False), 'items[].b': ('integer', False),
                     'items[].bag': ('object', True)}
    assert _declared(_MODELS, {'items': {'$ref': '#/definitions/Item'}, 'type': 'array'})['[].a'] == ('string', False)


@pytest.mark.parametrize('label, walked, expected', [
    ('nothing differs', {'.': ['dict'], 'a': ['str'], 'b': ['int'], 'bag': ['dict']}, {}),
    ('a field the model does not declare', {'.': ['dict'], 'a': ['str'], 'b': ['int'], 'bag': ['dict'], 'c': ['str']},
     {'undeclared': ['c']}),
    ('a declared field never sent', {'.': ['dict'], 'a': ['str'], 'bag': ['dict']}, {'unsent': ['b']}),
    ('a field sent with another type', {'.': ['dict'], 'a': ['int'], 'b': ['int'], 'bag': ['dict']},
     {'wrong_type': ['a']}),
    ('a declared field that is always null', {'.': ['dict'], 'a': ['null'], 'b': ['int'], 'bag': ['dict']},
     {'never_filled': ['a']}),
    ('anything below a free-form object is allowed', {'.': ['dict'], 'a': ['str'], 'b': ['int'], 'bag': ['dict'],
                                                    'bag.x': ['str']}, {}),
    ('an int is a number', {'.': ['dict'], 'a': ['str'], 'b': ['int'], 'bag': ['dict']}, {}),
])
def test_each_clause_of_the_comparison_has_a_case_it_must_catch(label, walked, expected):
    models = {'Thing': {'properties': {'a': {'type': 'string'}, 'b': {'type': 'integer'}, 'bag': {'type': 'object'}}}}
    found = _compare(models, {'$ref': '#/definitions/Thing'}, walked)
    assert {key: value for key, value in found.items() if value} == expected, label
