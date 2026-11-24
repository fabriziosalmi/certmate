"""Every DNS hook runs the way certbot runs it: as a script (#1534).

Certbot starts a hook as ``python /app/modules/core/<name>_hook.py --config
... --action auth``. Run that way, the file has no parent package, and a
relative import (``from .pinned_https import ...``) raises "attempted relative
import with no known parent package". From v2.51.1 (fda930d, #1309) the
acme-dns hook did exactly that inside the request it sends, so no acme-dns
certificate could be issued or renewed, while every unit test, which imports
the module as ``modules.core.dns_alias_hook``, passed.

These tests run the hook as a subprocess, from another working directory,
against a fake acme-dns server on 127.0.0.1, and check that the request
arrives. A static check keeps the same class of bug out of every hook.
"""
import ast
import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit]

REPO = Path(__file__).resolve().parent.parent
HOOKS = sorted((REPO / 'modules' / 'core').glob('*_hook.py'))
ALIAS_HOOK = REPO / 'modules' / 'core' / 'dns_alias_hook.py'


class _Recorder(BaseHTTPRequestHandler):
    """Records each request; answers 200, or a redirect when told to."""

    def _answer(self):
        length = int(self.headers.get('Content-Length') or 0)
        body = self.rfile.read(length).decode('utf-8') if length else ''
        self.server.seen.append({
            'method': self.command,
            'path': self.path,
            'headers': {k.lower(): v for k, v in self.headers.items()},
            'body': body,
        })
        if self.server.redirect_to:
            self.send_response(302)
            # A fixed path, not the request's: a header is never built from
            # what the client sent.
            self.send_header('Location', self.server.redirect_to + '/update')
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        payload = json.dumps({'txt': 'ok'}).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_POST = _answer
    do_GET = _answer

    def log_message(self, *args):  # keep test output quiet
        pass


def _serve(redirect_to=None):
    server = HTTPServer(('127.0.0.1', 0), _Recorder)
    server.seen = []
    server.redirect_to = redirect_to
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _base(server):
    return f'http://127.0.0.1:{server.server_address[1]}'


def _run_hook(tmp_path, api_url):
    config = {
        'provider': 'acme-dns',
        'domain_alias': 'validation.example.test',
        'config': {
            'api_url': api_url,
            'username': 'hook-user',
            'password': 'hook-key',
            'subdomain': 'validation.example.test',
        },
    }
    config_file = tmp_path / 'alias.json'
    config_file.write_text(json.dumps(config), encoding='utf-8')
    elsewhere = tmp_path / 'cwd'
    elsewhere.mkdir()
    env = {
        'PATH': '/usr/bin:/bin',
        'CERTBOT_DOMAIN': 'sub.example.test',
        'CERTBOT_VALIDATION': 'abc123',
    }
    return subprocess.run(
        [sys.executable, str(ALIAS_HOOK), '--config', str(config_file), '--action', 'auth'],
        cwd=elsewhere, env=env, capture_output=True, text=True, timeout=60,
    )


def test_the_acme_dns_hook_run_as_a_script_reaches_the_update_endpoint(tmp_path):
    server = _serve()
    try:
        result = _run_hook(tmp_path, _base(server))
    finally:
        server.shutdown()
    assert 'relative import' not in result.stderr, result.stderr
    assert result.returncode == 0, f'hook failed: {result.stderr}'
    updates = [r for r in server.seen if r['method'] == 'POST' and r['path'] == '/update']
    assert len(updates) == 1, f'expected one POST /update, saw {server.seen}'
    sent = updates[0]
    assert sent['headers'].get('x-api-user') == 'hook-user'
    assert sent['headers'].get('x-api-key') == 'hook-key'
    assert json.loads(sent['body']) == {'subdomain': 'validation.example.test', 'txt': 'abc123'}


def test_the_acme_dns_hook_does_not_follow_a_redirect_with_its_key(tmp_path):
    """urllib follows a 302 and sends the same X-Api-User and X-Api-Key to the
    new host, and the metadata check only ever saw the first URL. The hook
    must refuse the redirect, so the key never reaches the second server."""
    other = _serve()
    first = _serve(redirect_to=_base(other))
    try:
        result = _run_hook(tmp_path, _base(first))
    finally:
        first.shutdown()
        other.shutdown()
    assert len(first.seen) == 1, first.seen
    assert other.seen == [], f'the key followed the redirect: {other.seen}'
    assert result.returncode != 0, 'a redirected update was reported as a success'
    assert 'redirect' in result.stderr.lower(), result.stderr


def _unguarded_relative_imports(path):
    """Relative imports that are not inside a try whose handler catches
    ImportError (the pattern that also works when the file is a script)."""
    tree = ast.parse(path.read_text(encoding='utf-8'))
    guarded = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        catches = False
        for handler in node.handlers:
            names = []
            if isinstance(handler.type, ast.Name):
                names = [handler.type.id]
            elif isinstance(handler.type, ast.Tuple):
                names = [e.id for e in handler.type.elts if isinstance(e, ast.Name)]
            if {'ImportError', 'ModuleNotFoundError'} & set(names):
                catches = True
        if catches:
            for inner in node.body:
                for sub in ast.walk(inner):
                    if isinstance(sub, ast.ImportFrom) and sub.level:
                        guarded.add(id(sub))
    return [
        f'{path.name}:{node.lineno}'
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.level and id(node) not in guarded
    ]


def test_there_are_hooks_to_check():
    assert ALIAS_HOOK in HOOKS and len(HOOKS) >= 2, HOOKS


@pytest.mark.parametrize('hook', HOOKS, ids=lambda p: p.name)
def test_a_hook_has_no_relative_import_that_breaks_when_run_as_a_script(hook):
    assert _unguarded_relative_imports(hook) == []


def test_the_relative_import_check_can_fail(tmp_path):
    probe = tmp_path / 'probe_hook.py'
    probe.write_text('def f():\n    from .pinned_https import x\n', encoding='utf-8')
    assert _unguarded_relative_imports(probe) == ['probe_hook.py:2']
    probe.write_text(
        'try:\n    from .pinned_https import x\nexcept ImportError:\n    from pinned_https import x\n',
        encoding='utf-8')
    assert _unguarded_relative_imports(probe) == []
