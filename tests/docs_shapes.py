"""What docs/api.md shows an answer to be, set beside what the route answers (#1105, stage 2).

The route walk (`tests/contract_routes.py`) records the structure of every answer the API gives,
and `tests/test_the_contract_moves_with_the_routes.py` holds that record equal to the routes. The
62 operations with no response schema are described only in docs/api.md, and its examples had
drifted from the answers the way the models had: the client-certificate examples showed fields
no answer sends and left out most of the ones it does. Nothing compared them, because an example
is prose: it has example values, sometimes ellipses, and nothing said which blocks were meant to
be the shape.

So every code block in the five api.md files (English and the four translations) says what it is,
in an HTML comment on the line before the fence, which does not render and is the same in every
language:

    <!-- response: GET /api/client-certs 200 -->            the whole answer, every field
    <!-- response: GET /api/client-certs 200 excerpt -->    some fields; none the walk never saw
    <!-- request: POST /api/client-certs/create -->         a request body
    <!-- illustration: the error envelope of every route --> not one route's answer; the reason

A `bash` block is a command and needs no marker. A response or request block is JSON (no
ellipses: the values are examples, the fields are not). A response block is flattened the way the
walk flattens an answer and compared with the walk's snapshot:

  * never_seen: a field the block shows and no answer of the walk held. Either the route does
    not send it (the client-certificate examples showed six such fields), or it sends it only in
    a state the walk's world does not build (`next_step`, only when certificates remain): reading
    the handler tells which, and the second is a step for the walk's seed;
  * mistyped: a field the block shows with a type the route never sends it with;
  * omitted:  a field the route sends and a complete block does not show;
  * unverified: a field under something the walk only ever saw as `null`, or as an empty list.
    Not a defect of the document: what the walk's world does not hold yet.

What is out of line today is in `tests/api_docs_shapes_baseline.json`, and the test holds the
document equal to it in both directions: a new difference fails, and so does a fixed one left in
the file. It only shrinks.

    python -m tests.docs_shapes write     shrink the baseline to what is still out of line (it
                                          refuses a difference the baseline does not have)
"""
import json
import re
import sys
from dataclasses import dataclass

from tests.contract_routes import MAPS_BY_ROUTE, MARKERS, OPAQUE_BY_ROUTE, SNAPSHOT, flatten
from tests.contract_support import REPO

DOCS = ('docs/api.md', 'docs/de/api.md', 'docs/es/api.md', 'docs/fr/api.md', 'docs/it/api.md')
BASELINE = REPO / 'tests' / 'api_docs_shapes_baseline.json'

COMMANDS = {'bash'}
FENCE = re.compile(r'^```(\S*)\s*$')
MARKER = re.compile(r'^<!-- (\w+): (.+?) -->$')
RESPONSE = re.compile(r'^(GET|POST|PUT|PATCH|DELETE) (/\S+) (\d{3})( excerpt)?$')
REQUEST = re.compile(r'^(GET|POST|PUT|PATCH|DELETE) (/\S+)$')
KINDS = ('response', 'request', 'illustration')
DIFFERENCES = ('never_seen', 'mistyped', 'omitted', 'unverified')


@dataclass
class Block:
    file: str
    line: int           # the opening fence, 1-based
    lang: str
    marker: str         # the line before the fence
    body: str

    @property
    def where(self):
        return f'{self.file}:{self.line}'


def blocks(relative):
    lines = (REPO / relative).read_text(encoding='utf-8').split('\n')
    found, index = [], 0
    while index < len(lines):
        opening = FENCE.match(lines[index])
        if opening:
            end = index + 1
            while end < len(lines) and not lines[end].startswith('```'):
                end += 1
            found.append(Block(relative, index + 1, opening.group(1),
                               lines[index - 1] if index else '', '\n'.join(lines[index + 1:end])))
            index = end
        index += 1
    return found


def _template(path):
    path = re.sub(r'<[^>]+>|\{[^}]+\}', '<X>', path.split('?')[0])
    return path.rstrip('/') or '/'


def route_of(method, path, routes):
    """The walk's key for a documented call: exact, or the one template a concrete path fits
    (`/api/crl/download/info` is `/api/crl/download/<X>`)."""
    key = f'{method} {_template(path)}'
    if key in routes:
        return key
    fits = [known for known in routes
            if known.split(' ', 1)[0] == method
            and re.fullmatch(re.escape(known.split(' ', 1)[1]).replace(re.escape('<X>'), '[^/]+'),
                             _template(path))]
    return fits[0] if len(fits) == 1 else None


def read_marker(block, routes):
    """(kind, details, problem). details: {'route', 'status', 'excerpt'} for a response,
    {'route'} for a request, {'reason'} for an illustration."""
    if block.lang in COMMANDS:
        return None, {}, None
    marker = MARKER.match(block.marker.strip())
    if not marker or marker.group(1) not in KINDS:
        return None, {}, (f'{block.where}: a ```{block.lang or ""} block with no marker on the line before it '
                          f'(<!-- response|request|illustration: ... -->)')
    kind, rest = marker.groups()
    if kind == 'illustration':
        return kind, {'reason': rest}, None
    parsed = (RESPONSE if kind == 'response' else REQUEST).match(rest)
    if not parsed:
        return kind, {}, f'{block.where}: cannot read the {kind} marker {rest!r}'
    route = route_of(parsed.group(1), parsed.group(2), routes)
    if route is None:
        return kind, {}, f'{block.where}: {parsed.group(1)} {parsed.group(2)} is not a route the walk calls'
    try:
        json.loads(block.body)
    except ValueError as error:
        return kind, {}, f'{block.where}: a {kind} block must be JSON ({error})'
    if kind == 'request':
        return kind, {'route': route}, None
    status = parsed.group(3)
    if status not in routes[route]:
        return kind, {}, f'{block.where}: the walk records no {status} answer for {route} ({sorted(routes[route])})'
    return kind, {'route': route, 'status': status, 'excerpt': bool(parsed.group(4))}, None


def parent(path):
    if path.endswith('[]'):
        return path[:-2] or '.'
    return path.rsplit('.', 1)[0] if '.' in path else '.'


def differences(example, shape, unseen=(), maps=(), opaque=(), excerpt=False):
    """{kind: [paths]} for one example against one recorded shape ({path: [types]}). A missing
    or never-seen subtree is reported once, at its top."""
    documented = flatten(example, maps, opaque)
    found = {kind: [] for kind in DIFFERENCES}
    for path, types in sorted(documented.items()):
        if path in shape:
            sent = set(shape[path]) - {'null'}
            shown = types - {'null'}
            if 'number' in sent:                    # 3 is a fine example of a number
                shown = {'number' if t == 'int' else t for t in shown}
            if not sent and shown:
                found['unverified'].append(path)
            elif sent and not shown <= sent:
                found['mistyped'].append(f'{path}: {"/".join(sorted(shown))}, '
                                         f'sent as {"/".join(sorted(sent))}')
            continue
        above = parent(path)
        if above not in shape or above in opaque:
            continue                                # reported at its top, or not recorded at all
        if shape[above] == ['null']:
            continue                                # reported at `above`, which the walk saw only null
        if above in unseen:
            found['unverified'].append(path)
        else:
            found['never_seen'].append(path)
    if not excerpt:
        found['omitted'] = [path for path in sorted(shape)
                            if path != '.' and path not in documented and parent(path) in documented
                            and path.rsplit('.', 1)[-1] not in MARKERS]
    return {kind: paths for kind, paths in found.items() if paths}


def current():
    """{(file, marker id): {kind: [paths]}} for every response block, plus the problems
    (unmarked blocks, unreadable markers, routes or statuses the walk does not have)."""
    snapshot = json.loads(SNAPSHOT.read_text(encoding='utf-8'))
    routes = snapshot['routes']
    found, problems = {}, []
    for relative in DOCS:
        seen = {}
        for block in blocks(relative):
            kind, details, problem = read_marker(block, routes)
            if problem:
                problems.append(problem)
                continue
            if kind != 'response':
                continue
            route, status = details['route'], details['status']
            ident = f'{route} {status}'
            seen[ident] = seen.get(ident, 0) + 1
            if seen[ident] > 1:
                ident = f'{ident} #{seen[ident]}'
            delta = differences(json.loads(block.body), routes[route][status],
                                snapshot['unseen_items'].get(route, ()), MAPS_BY_ROUTE.get(route, ()),
                                OPAQUE_BY_ROUTE.get(route, ()), details['excerpt'])
            if delta:
                found[f'{relative} {ident}'] = delta
    return found, problems


def growth(found, baseline):
    """What `found` has that `baseline` does not: a block, or a path in a block."""
    grown = []
    for block, delta in sorted(found.items()):
        was = baseline.get(block, {})
        grown += [f'{block}: {kind} {path}' for kind in DIFFERENCES
                  for path in delta.get(kind, ()) if path not in was.get(kind, ())]
    return grown


def write():
    """Shrink the baseline to what is still out of line. It never grows: a new difference is a
    document to fix. The first baseline is written only when there is none."""
    found, problems = current()
    if problems:
        sys.exit('fix these first:\n  ' + '\n  '.join(problems))
    if BASELINE.exists():
        grown = growth(found, json.loads(BASELINE.read_text(encoding='utf-8')))
        if grown:
            sys.exit('the baseline only shrinks; fix the document for:\n  ' + '\n  '.join(grown))
    BASELINE.write_text(json.dumps(found, indent=1, sort_keys=True) + '\n', encoding='utf-8')
    total = sum(len(paths) for delta in found.values() for paths in delta.values())
    print(f'wrote {BASELINE.relative_to(REPO)}: {len(found)} blocks out of line, {total} paths')


if __name__ == '__main__':
    if sys.argv[1:] == ['write']:
        write()
    else:
        sys.exit(__doc__)
