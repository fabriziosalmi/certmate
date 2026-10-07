"""No function is left in the application that nothing calls.

Ten were found by measurement, seven of them from the first refactor in July
2025 and never called since: `get_ca_account_display_info`, `log_error`,
`log_ca_provider_changed`, `get_domain_name`, `get_current_token`,
`create_certificate_legacy`, `create_route53_config`, `require_admin`,
`get_cache_instance` and `get_metrics_collector`. About a hundred lines that
every reader of those files had to read and decide were alive.

The measure is deliberately plain and deliberately on the safe side. A function
or method of `modules/` or `app.py` is dead when

* it has no decorator (a decorated function is registered by its decorator: a
  route, a hook, a handler, and is reached without its name being written),
* it is not a dunder and not an HTTP verb of a resource, and
* its name occurs **once** among the identifiers of every tracked text file,
  which is its own definition. A mention anywhere counts as a use: in a test,
  a template, a document, a string handed to `getattr`. A function that is only
  called from its own test is therefore not found, which is a miss and never a
  false alarm.

A tool built for this (vulture) was tried first and reported 147 candidates, 62
of them routes, and skipped a file whose comment began with `type:` because it
parses type comments (see the last test).
"""
import ast
import collections
import pathlib
import re
import subprocess

import pytest

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent
IDENTIFIER = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')
HTTP_VERBS = {'get', 'post', 'put', 'delete', 'patch', 'head', 'options'}
BINARY_OR_GENERATED = ('.png', '.gif', '.svg', '.jpg', '.ico', '.pdf', '.woff', '.woff2',
                       '.lock', '.min.js', '.min.css', '.map')
NOT_TRACKED = {'.git', 'node_modules', '.venv', 'venv', 'dist', '__pycache__', '.mypy_cache',
               '.ruff_cache', '.pytest_cache', 'htmlcov'}


def _tracked_files():
    """The files git tracks, or the tree below the root when this is not a checkout."""
    try:
        listed = subprocess.run(['git', 'ls-files'], cwd=REPO, capture_output=True, text=True, check=True)
        return [name for name in listed.stdout.split('\n') if name]
    except (OSError, subprocess.CalledProcessError):
        return [str(path.relative_to(REPO)) for path in REPO.rglob('*')
                if path.is_file() and not NOT_TRACKED & set(path.relative_to(REPO).parts)]


def _read_text_files():
    texts = {}
    for name in _tracked_files():
        if name.endswith(BINARY_OR_GENERATED) or 'redoc.standalone' in name:
            continue
        try:
            texts[name] = (REPO / name).read_text(encoding='utf-8')
        except (UnicodeDecodeError, OSError):
            continue
    return texts


def unreferenced(texts):
    """`(functions scanned, ['path:line name', ...])` over a `{path: text}` of the tracked files."""
    names = collections.Counter()
    for text in texts.values():
        names.update(IDENTIFIER.findall(text))
    scanned, dead = 0, []
    for path, text in texts.items():
        if not (path == 'app.py' or (path.startswith('modules/') and path.endswith('.py'))):
            continue
        for node in ast.walk(ast.parse(text)):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            scanned += 1
            dunder = node.name.startswith('__') and node.name.endswith('__')
            if node.decorator_list or dunder or node.name in HTTP_VERBS:
                continue
            if names[node.name] <= 1:
                dead.append(f'{path}:{node.lineno} {node.name}')
    return scanned, sorted(dead)


def test_no_function_of_the_application_is_one_nothing_mentions():
    scanned, dead = unreferenced(_read_text_files())

    assert scanned >= 1500, f'only {scanned} functions were looked at: the scan has lost its subject'
    assert dead == [], (
        'nothing in the repository mentions these, not even a test or a document. Delete them, '
        'or, if something reaches one without writing its name, say so where it is defined: '
        + ', '.join(dead))


def test_the_scan_finds_a_function_nothing_mentions():
    """CONTROL: against a tree where one is, the scan names it and only it."""
    scanned, dead = unreferenced({
        'modules/core/example.py': 'def used():\n    return 1\n\ndef orphan():\n    return 2\n',
        'modules/core/caller.py': 'from .example import used\nused()\n',
    })

    assert scanned == 2
    assert dead == ['modules/core/example.py:4 orphan']


def test_what_is_reached_without_its_name_or_by_a_mention_is_not_found():
    """CONTROL for the other side: the scan must not call these dead."""
    _, dead = unreferenced({
        'modules/web/routes.py': (
            '@app.route("/x")\ndef handler():\n    pass\n\n'
            'class Thing:\n    def __repr__(self):\n        return ""\n\n'
            '    def get(self):\n        pass\n\n'
            'def named_in_a_template():\n    pass\n\n'
            'def named_in_a_document():\n    pass\n\n'
            'def named_in_a_test():\n    pass\n'),
        'templates/page.html': '{{ named_in_a_template() }}',
        'docs/guide.md': 'call `named_in_a_document` to ...',
        'tests/test_it.py': 'def test_it():\n    named_in_a_test()\n',
    })

    assert dead == []


def test_the_application_can_be_read_by_a_parser_that_reads_type_comments():
    """A comment that begins with `type:` is a type comment to `ast.parse(...,
    type_comments=True)`, which is what vulture uses, and it raised a syntax
    error on `modules/core/private_ca.py`: the dead-code scan skipped the whole
    file without a word. mypy tolerates it; the tool that looks for dead code
    did not."""
    unreadable = []
    for name, text in _read_text_files().items():
        if name.endswith('.py'):
            try:
                ast.parse(text, type_comments=True)
            except SyntaxError as error:
                unreadable.append(f'{name}:{error.lineno} {error.msg}')

    assert unreadable == [], 'a comment starting with `type:` reads as a type annotation: ' + ', '.join(unreadable)


def test_the_parser_does_object_to_a_comment_that_starts_with_type():
    """CONTROL: the shape in `private_ca.py` was a syntax error, so the test above can fail."""
    source = 'def f(x):\n    if x:\n        # type: say what the value has to be\n        raise ValueError(x)\n'

    with pytest.raises(SyntaxError):
        ast.parse(source, type_comments=True)
    ast.parse(source)                   # and it is a fine program without type comments
