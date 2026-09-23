#!/usr/bin/env python3
"""Every endpoint the wiki states must be one the application serves.

The wiki is the fourth place CertMate documents its API, and the only one no
gate could reach. `tests/test_advertised_endpoints_exist.py` asks the right
question of README.md, README.dockerhub.md and templates/help.html, and
`tests/test_the_api_surface_is_documented.py` asks the reverse of those plus
docs/api.md. Neither can see github.com/fabriziosalmi/certmate.wiki, because it
is a separate git repository with no CI of its own.

Left alone it rots, and it did. On 2026-09-17, 27 days and seven releases after
its last edit, the Multi-Account Support section of DNS-Providers.md carried six
copy-pasteable curl commands that all answered 404, against a prefix that does
not exist and a `default-account` endpoint that never has. The main repository
has a test asserting exactly that `default-account` has never existed; it could
not see the page that documented it.

WEEKLY AND ADVISORY, not a merge gate, and the reason is structural rather than
taste: editing the wiki does not run this repository's CI, so a merge gate here
would only ever check the wiki at moments when the wiki had not changed. The
same reasoning as the advisories job, which is weekly because it needs the live
alert list that no test can see.

Verbs are unioned across every rule whose shape matches, never taken from the
first. `/api/certificates/create` and `/api/certificates/<domain>` have the same
shape, so taking the first reports a documented `GET /api/certificates/<domain>`
as a path that "accepts POST". This file's first draft did exactly that and
produced three false positives out of six findings; the repository's own
test_advertised_endpoints_exist.py carries the same warning.

Usage:
  check_wiki_endpoints.py <path-to-wiki-checkout>
"""
from __future__ import annotations

import os
import re
import secrets
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

# Strings that look like a path but are not a claim about this API: generic
# placeholders in prose, and prefixes used as labels in diagrams or lists.
# Listed rather than guessed at, so adding one is a visible decision.
NOT_A_CLAIM = frozenset({
    '/api', '/api/endpoint', '/api/test',
    '/api/crl', '/api/ocsp', '/api/deploy', '/api/web/certificates',
})


def route_table():
    """Every /api/ rule the application serves, as path -> set of verbs."""
    root = tempfile.mkdtemp()
    for variable in ('CERTMATE_CERT_DIR', 'CERTMATE_DATA_DIR',
                     'CERTMATE_BACKUP_DIR', 'CERTMATE_LOGS_DIR'):
        directory = os.path.join(root, variable)
        os.makedirs(directory, exist_ok=True)
        os.environ[variable] = directory
    os.environ.setdefault('API_BEARER_TOKEN', secrets.token_urlsafe(32))
    os.environ['TESTING'] = 'true'

    from modules.core.factory import create_app
    result = create_app()
    app = result[0] if isinstance(result, tuple) else result

    table: dict[str, set[str]] = {}
    for rule in app.url_map.iter_rules():
        path = normalise(str(rule))
        if not path.startswith('/api/'):
            continue
        table.setdefault(path, set()).update(
            method for method in rule.methods if method not in ('HEAD', 'OPTIONS'))
    return table


def normalise(path: str) -> str:
    path = re.sub(r'<[^>]+>', '<X>', path)
    path = re.sub(r'\{[^}]+\}', '<X>', path)
    return path.rstrip('/') or '/'


def verbs_for(path: str, table) -> tuple[bool, set[str]]:
    """(the path exists, every verb any matching rule accepts). See the module
    docstring for why this unions instead of returning the first match."""
    wanted = path.strip('/').split('/')
    found, verbs = False, set()
    for candidate, candidate_verbs in table.items():
        parts = candidate.strip('/').split('/')
        if len(parts) != len(wanted):
            continue
        # Only the ROUTE's placeholder stands for a value the wiki wrote out
        # (`/api/certificates/example.com` is `/api/certificates/<domain>`). A
        # placeholder in the WIKI says nothing about a fixed route segment:
        # matching it both ways let `/api/{x}/create` "exist" because
        # `/api/certificates/create` does. The mirror of the same fix in
        # tests/test_the_api_surface_is_documented.py.
        if all(p == '<X>' or p == w for p, w in zip(parts, wanted)):
            found = True
            verbs |= candidate_verbs
    return found, verbs


def claims(wiki: Path):
    """(file, line, verb, path) for every verb+path the wiki states.

    Three shapes, because the wiki states endpoints in three ways: a markdown
    table row, a curl command, and an inline `VERB /path` code span.
    """
    patterns = (
        re.compile(r'\|\s*(GET|POST|PUT|PATCH|DELETE)\s*\|\s*`([^`]+)`'),
        re.compile(r'curl\s+-X\s+(GET|POST|PUT|PATCH|DELETE)\s+\S*?(/api/\S*)'),
        re.compile(r'`(GET|POST|PUT|PATCH|DELETE)\s+(/api/[^`\s]+)`'),
    )
    found = []
    for page in sorted(wiki.glob('*.md')):
        for number, line in enumerate(page.read_text(encoding='utf-8').splitlines(), 1):
            for pattern in patterns:
                for match in pattern.finditer(line):
                    found.append((page.name, number, match.group(1), match.group(2)))
    return found


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    wiki = Path(sys.argv[1])
    if not wiki.is_dir() or not list(wiki.glob('*.md')):
        print(f'{wiki} is not a wiki checkout: no .md files. Refusing to report '
              f'success on a check that read nothing.', file=sys.stderr)
        return 2

    table = route_table()
    stated = claims(wiki)
    if not stated:
        print('the wiki states no endpoints at all, which cannot be right: the '
              'extractor is not reading it.', file=sys.stderr)
        return 2

    problems = []
    for name, number, verb, raw in stated:
        path = normalise(raw.split('?')[0].rstrip('.,);:'))
        if not path.startswith('/api/') or path in NOT_A_CLAIM:
            continue
        exists, verbs = verbs_for(path, table)
        if not exists:
            problems.append(f'{name}:{number}  {verb} {path}  is not a route')
        elif verb not in verbs:
            problems.append(
                f'{name}:{number}  {verb} {path}  exists but accepts '
                f'{", ".join(sorted(verbs))}')

    if problems:
        print(f'\nThe wiki states {len(problems)} endpoint(s) the application '
              f'does not serve:\n', file=sys.stderr)
        for problem in problems:
            print(f'  {problem}', file=sys.stderr)
        print('\nThe wiki is a separate repository: fix it at '
              'https://github.com/fabriziosalmi/certmate/wiki\n', file=sys.stderr)
        return 1

    print(f'Wiki endpoints OK: {len(stated)} stated, all served.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
