"""What the API says below its routes: the fields a response contains and a request takes.

`tests/test_the_contract_moves_with_the_surface.py` records the ROUTES and catches
an endpoint appearing or going away, which is two of the six clauses of the rule
beside `API_CONTRACT_VERSION`. The other four live in the OpenAPI document the app
serves at /api/swagger.json: a field added to a response, a field removed or
retyped, a request field that becomes required, a status code that changes. This
module reduces that document to its structure (names, types, enums, which fields
are required, which parameters, which status codes) and compares two reductions,
saying for each difference which way the contract version has to move.

Prose is left out on purpose. A description or an example is not the contract, and
a gate that fails when someone fixes a typo in one teaches people to regenerate
the snapshot without reading it.

Regenerate the recorded snapshot after moving the version, from the repository
root:

    python tests/contract_support.py write
"""
import json
import os
import pathlib
import re
import secrets
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent
SNAPSHOT = REPO / 'tests' / 'api_models_surface.json'

HTTP_VERBS = ('get', 'post', 'put', 'patch', 'delete')
MAJOR, MINOR, REVIEW, NOTE = 'MAJOR', 'MINOR', 'REVIEW', 'NOTE'
ORDER = {MAJOR: 0, REVIEW: 1, MINOR: 2, NOTE: 3}


def build_app():
    """The app, built the way the route-surface test builds it, with its token."""
    saved = {k: os.environ.get(k) for k in ('TESTING', 'FLASK_ENV', 'API_BEARER_TOKEN')}
    token = secrets.token_urlsafe(32)
    os.environ.update(TESTING='true', FLASK_ENV='testing', API_BEARER_TOKEN=token)
    try:
        root = pathlib.Path(tempfile.mkdtemp()) / 'certmate'
        (root / 'modules' / 'core').mkdir(parents=True)
        anchor = root / 'modules' / 'core' / 'factory.py'
        anchor.write_text('# test path anchor\n', encoding='utf-8')
        sys.path.insert(0, str(REPO))
        from unittest import mock
        from modules.factory import create_app
        with mock.patch('modules.factory.__file__', str(anchor)):
            result = create_app()
        app = result[0] if isinstance(result, tuple) else result
        return app, token
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def swagger_spec(app_and_token=None):
    """The OpenAPI document the app serves."""
    app, token = app_and_token or build_app()
    response = app.test_client().get(
        '/api/swagger.json', headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200, response.status_code
    return response.get_json()


def route_surface(app):
    """Every verb+path the app serves under /api/, bar the dashboard's /api/web/."""
    surface = set()
    for rule in app.url_map.iter_rules():
        path = str(rule)
        if not path.startswith('/api/') or path.startswith('/api/web/'):
            continue
        path = re.sub(r'<[^>]+>', '<X>', path).rstrip('/') or '/'
        for verb in rule.methods:
            if verb not in ('HEAD', 'OPTIONS'):
                surface.add(f'{verb} {path}')
    return surface


def outside_openapi(routes, operations):
    """The routes the app serves that the OpenAPI document does not describe.

    Their fields are in no machine-readable form, so nothing here can compare them with
    the version: they are plain Flask routes, described in docs/api.md only.
    """
    described = set()
    for key in operations:
        verb, path = key.split(' ', 1)
        described.add(f'{verb} /api{path}'.replace('{X}', '<X>'))
    return sorted(set(routes) - described)


def _shape(node):
    """The structural part of a schema node: type, format, reference, items, enum."""
    if not isinstance(node, dict):
        return None
    shape = {}
    for key in ('type', 'format', '$ref'):
        if key in node:
            shape[key] = node[key]
    if 'enum' in node:
        shape['enum'] = sorted(map(str, node['enum']))
    if 'items' in node:
        shape['items'] = _shape(node['items'])
    if isinstance(node.get('additionalProperties'), dict):
        shape['additionalProperties'] = _shape(node['additionalProperties'])
    return shape


def reduce(spec):
    """The document, reduced to what a client can depend on."""
    models = {}
    for name, definition in (spec.get('definitions') or {}).items():
        models[name] = {
            'required': sorted(definition.get('required') or []),
            'properties': {prop: _shape(node)
                           for prop, node in (definition.get('properties') or {}).items()},
        }
    operations = {}
    for path, item in (spec.get('paths') or {}).items():
        shared = item.get('parameters') or []
        generic = re.sub(r'\{[^}]+\}', '{X}', path).rstrip('/') or '/'
        for verb in HTTP_VERBS:
            operation = item.get(verb)
            if not isinstance(operation, dict):
                continue
            parameters = {}
            for parameter in shared + (operation.get('parameters') or []):
                location = parameter.get('in', '?')
                name = parameter.get('name', '?') if location != 'path' else '{X}'
                node = parameter.get('schema') if location == 'body' else parameter
                parameters[f'{location}:{name}'] = {
                    'required': bool(parameter.get('required')), 'shape': _shape(node)}
            responses = {str(code): _shape((response or {}).get('schema'))
                         for code, response in (operation.get('responses') or {}).items()}
            operations[f'{verb.upper()} {generic}'] = {
                'parameters': parameters, 'responses': responses}
    return {'models': models, 'operations': operations}


def _describe(shape):
    return json.dumps(shape, sort_keys=True)


def compare(recorded, current):
    """Every difference between two reductions, as (severity, text), worst first."""
    found = []

    def add(severity, text):
        found.append((severity, text))

    old_models, new_models = recorded['models'], current['models']
    for name in sorted(set(new_models) - set(old_models)):
        add(NOTE, f'model {name} is new (it moves the contract only through the endpoint or field that uses it)')
    for name in sorted(set(old_models) - set(new_models)):
        add(MAJOR, f'model {name} was removed')
    for name in sorted(set(old_models) & set(new_models)):
        old, new = old_models[name], new_models[name]
        for prop in sorted(set(new['properties']) - set(old['properties'])):
            add(MINOR, f'{name}.{prop} is a new field')
        for prop in sorted(set(old['properties']) - set(new['properties'])):
            add(MAJOR, f'{name}.{prop} was removed')
        for prop in sorted(set(old['properties']) & set(new['properties'])):
            before, after = old['properties'][prop] or {}, new['properties'][prop] or {}
            if before == after:
                continue
            if {k: v for k, v in before.items() if k != 'enum'} != {k: v for k, v in after.items() if k != 'enum'}:
                add(MAJOR, f'{name}.{prop} changed type: {_describe(before)} -> {_describe(after)}')
                continue
            was, now = set(before.get('enum') or []), set(after.get('enum') or [])
            if now - was:
                add(MINOR, f'{name}.{prop} accepts new values: {sorted(now - was)}')
            if was - now:
                add(MAJOR, f'{name}.{prop} no longer accepts: {sorted(was - now)}')
        if old['required'] != new['required']:
            add(REVIEW, f'{name} changed which fields are required: {old["required"]} -> {new["required"]} '
                        f'(MAJOR if a request field became required)')

    old_ops, new_ops = recorded['operations'], current['operations']
    for key in sorted(set(new_ops) - set(old_ops)):
        add(MINOR, f'operation {key} is new')
    for key in sorted(set(old_ops) - set(new_ops)):
        add(MAJOR, f'operation {key} was removed')
    for key in sorted(set(old_ops) & set(new_ops)):
        old, new = old_ops[key], new_ops[key]
        for param in sorted(set(new['parameters']) - set(old['parameters'])):
            required = new['parameters'][param]['required']
            add(MAJOR if required else MINOR,
                f'{key}: new {"required" if required else "optional"} parameter {param}')
        for param in sorted(set(old['parameters']) - set(new['parameters'])):
            add(MAJOR, f'{key}: parameter {param} was removed')
        for param in sorted(set(old['parameters']) & set(new['parameters'])):
            before, after = old['parameters'][param], new['parameters'][param]
            if before['required'] != after['required']:
                add(MAJOR if after['required'] else MINOR,
                    f'{key}: parameter {param} is {"now" if after["required"] else "no longer"} required')
            if before['shape'] != after['shape']:
                add(MAJOR, f'{key}: parameter {param} changed: {_describe(before["shape"])} -> {_describe(after["shape"])}')
        for code in sorted(set(new['responses']) - set(old['responses'])):
            add(REVIEW, f'{key}: new response status {code} (a code for a new condition is a MINOR; '
                        f'a changed code for an existing condition is a MAJOR)')
        for code in sorted(set(old['responses']) - set(new['responses'])):
            add(MAJOR, f'{key}: response status {code} was removed')
        for code in sorted(set(old['responses']) & set(new['responses'])):
            if old['responses'][code] != new['responses'][code]:
                add(MAJOR, f'{key}: the {code} response changed shape: '
                           f'{_describe(old["responses"][code])} -> {_describe(new["responses"][code])}')
    return sorted(found, key=lambda item: (ORDER[item[0]], item[1]))


def write_snapshot():
    sys.path.insert(0, str(REPO))
    from modules.core.constants import API_CONTRACT_VERSION
    built = build_app()
    reduced = reduce(swagger_spec(built))
    document = {'contract_version': API_CONTRACT_VERSION, **reduced,
                'outside_openapi': outside_openapi(route_surface(built[0]), reduced['operations'])}
    SNAPSHOT.write_text(json.dumps(document, indent=1, sort_keys=True) + '\n', encoding='utf-8')
    print(f'wrote {SNAPSHOT.relative_to(REPO)}: contract {API_CONTRACT_VERSION}, '
          f'{len(document["models"])} models, {len(document["operations"])} operations, '
          f'{len(document["outside_openapi"])} routes outside the document')


if __name__ == '__main__':
    if sys.argv[1:] == ['write']:
        write_snapshot()
    else:
        sys.exit(__doc__)
