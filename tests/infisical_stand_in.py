"""A stand-in for the Infisical API, for exercising the real `infisical-python` SDK.

Run as a script (`python tests/infisical_stand_in.py PORT [--redirect-to PORT]`) and in
its OWN PROCESS, never a thread of the test: the SDK is a Rust core called with the GIL
held, so a server in the same interpreter can never answer it and the call hangs.

It speaks only what the SDK sends, which was read off the wire (not out of the SDK's
docs): a universal-auth login, then `/api/v3/secrets/raw` for get, create (POST), update
(PATCH), delete and list, with the secret in a `secret` / `secrets` envelope. A secret
that is not there is a 404, a create over an existing name is a 400, as on the real API.

Beside that it answers two paths of its own for the tests: `GET /__state` (the stored
secrets, name -> value) and `GET /__requests` (every request received, with its body and the headers a
credential could ride in). With `--redirect-to PORT` the secret endpoints answer
`307 Location: http://127.0.0.1:PORT/api/v3/secrets/raw/redirected` (a FIXED address: nothing the
request said is echoed into a header) instead of serving, which is how a test asks
what the SDK does with its access token when the server sends it somewhere else. With
`--accept-any` it serves without checking the credentials header, as a host that was never
meant to receive the request (and does not care who sent it) would.
"""
import http.server
import json
import sys
import urllib.parse

TOKEN = 'stand-in-access-token'
STORE = {}
REQUESTS = []
REDIRECT_TO = None
ACCEPT_ANY = False


def _secret(name, value, workspace, environment):
    return {'id': f'id-{name}', 'workspace': workspace, 'environment': environment, 'version': 1,
            'type': 'shared', 'secretKey': name, 'secretValue': value, 'secretComment': '',
            'secretPath': '/'}


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *args):
        pass

    def _reply(self, status, body, headers=None):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(raw)

    def _handle(self):
        length = int(self.headers.get('Content-Length') or 0)
        body = json.loads(self.rfile.read(length).decode() or '{}') if length else {}
        url = urllib.parse.urlparse(self.path)
        query = {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()}
        path = url.path

        if path == '/__state':
            return self._reply(200, {k: v for k, v in STORE.items()})
        if path == '/__requests':
            return self._reply(200, REQUESTS)
        REQUESTS.append({'method': self.command, 'path': self.path, 'body': body,
                         'authorization': self.headers.get('Authorization', ''),
                         'cookie': self.headers.get('Cookie', '')})

        if path == '/api/v1/auth/universal-auth/login':
            return self._reply(200, {'accessToken': TOKEN, 'expiresIn': 7200,
                                     'accessTokenMaxTTL': 43200, 'tokenType': 'Bearer'})
        if not path.startswith('/api/v3/secrets/raw'):
            return self._reply(404, {'message': 'not an endpoint of the stand-in'})
        if not ACCEPT_ANY and self.headers.get('Authorization') != f'Bearer {TOKEN}':
            return self._reply(401, {'message': 'not authenticated'})
        if REDIRECT_TO:
            return self._reply(307, {'message': 'moved'},
                               {'Location': f'http://127.0.0.1:{REDIRECT_TO}/api/v3/secrets/raw/redirected'})

        workspace = body.get('workspaceId') or query.get('workspaceId', '')
        environment = body.get('environment') or query.get('environment', '')
        name = urllib.parse.unquote(path[len('/api/v3/secrets/raw/'):]) if path != '/api/v3/secrets/raw' else ''

        if not name:                                            # list
            secrets = [_secret(k, v, workspace, environment) for k, v in sorted(STORE.items())]
            return self._reply(200, {'secrets': secrets, 'imports': []})
        if self.command == 'GET':
            if name not in STORE:
                return self._reply(404, {'message': f"Secret with name '{name}' not found."})
            return self._reply(200, {'secret': _secret(name, STORE[name], workspace, environment)})
        if self.command == 'POST':
            if name in STORE:
                return self._reply(400, {'message': f"Secret with name '{name}' already exists."})
            STORE[name] = body.get('secretValue', '')
            return self._reply(200, {'secret': _secret(name, STORE[name], workspace, environment)})
        if self.command == 'PATCH':
            if name not in STORE:
                return self._reply(404, {'message': f"Secret with name '{name}' not found."})
            STORE[name] = body.get('secretValue', '')
            return self._reply(200, {'secret': _secret(name, STORE[name], workspace, environment)})
        if self.command == 'DELETE':
            if name not in STORE:
                return self._reply(404, {'message': f"Secret with name '{name}' not found."})
            value = STORE.pop(name)
            return self._reply(200, {'secret': _secret(name, value, workspace, environment)})
        return self._reply(405, {'message': 'method not supported by the stand-in'})

    do_GET = do_POST = do_PATCH = do_DELETE = _handle


def main(argv):
    global REDIRECT_TO, ACCEPT_ANY
    port = int(argv[1])
    ACCEPT_ANY = '--accept-any' in argv
    if '--redirect-to' in argv:
        REDIRECT_TO = int(argv[argv.index('--redirect-to') + 1])
    server = http.server.ThreadingHTTPServer(('127.0.0.1', port), Handler)
    server.serve_forever()


if __name__ == '__main__':
    main(sys.argv)
