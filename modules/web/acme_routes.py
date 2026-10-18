"""The ACME server's HTTP surface, under /acme/ (RFC 8555 section 7, #476).

Outside /api on purpose: this is a protocol other software speaks (certbot,
lego, acme.sh, cert-manager), with its own authentication (every POST is a
JWS signed by an account key) and its own error format, not CertMate's REST
API, and it does not move the API contract. The routes carry no CertMate
role for the same reason: tests/test_every_route_is_protected_or_listed.py
lists each one as public, with why.

Every route answers 404 while `acme_server.enabled` is false, so a server
that never turned ACME on shows no trace of it. Over plain HTTP it refuses
unless `allow_http` is set: section 6.1 requires HTTPS, and behind a proxy
that ends TLS, BEHIND_PROXY makes the request look as it did to the client.
"""
from flask import Blueprint, abort, g, jsonify, make_response, request

from ..core.acme_jws import verify_request
from ..core.acme_problems import AcmeProblem


class AcmeUrls:
    """The absolute URLs of the ACME resources, as the client reached this server."""

    def __init__(self, url_root):
        self.base = url_root.rstrip('/') + '/acme/'

    def directory(self):
        return self.base + 'directory'

    def new_nonce(self):
        return self.base + 'new-nonce'

    def new_account(self):
        return self.base + 'new-account'

    def key_change(self):
        return self.base + 'key-change'

    def account_prefix(self):
        return self.base + 'account/'

    def account(self, account_id):
        return self.account_prefix() + account_id

    def orders(self, account_id):
        return self.account(account_id) + '/orders'


def register_acme_routes(app, managers):
    server = managers.get('acme_server')
    if server is None:
        return
    bp = Blueprint('acme', __name__, url_prefix='/acme')

    def urls():
        return AcmeUrls(request.url_root)

    def verified(key_from):
        return verify_request(
            request.get_data(cache=False), request.content_type, request.url, server.nonces,
            key_from=key_from, account_url_prefix=urls().account_prefix(),
            find_account=server.store.account)

    def account_answer(account, status=200):
        response = jsonify(server.account_json(account, urls()))
        response.status_code = status
        response.headers['Location'] = urls().account(account['id'])
        return response

    def as_the_named_account(req, account_id):
        if req.account['id'] != account_id:
            raise AcmeProblem('unauthorized', 'The request is signed as another account')

    @bp.before_request
    def _gate():
        config = server.config()
        g.acme_enabled = bool(config.get('enabled'))
        if not g.acme_enabled:
            abort(404)
        if not request.is_secure and not config.get('allow_http'):
            raise AcmeProblem('malformed', 'This ACME server answers over HTTPS only (RFC 8555 section 6.1). '
                              'If TLS ends at a proxy, set BEHIND_PROXY so the request keeps its scheme.')

    @bp.after_request
    def _protocol_headers(response):
        if g.get('acme_enabled'):
            # Section 6.5: a fresh nonce on every answer, refusals included,
            # so a client that got badNonce can retry at once.
            response.headers['Replay-Nonce'] = server.nonces.issue()
            response.headers['Link'] = f'<{urls().directory()}>;rel="index"'
            response.headers['Cache-Control'] = 'no-store'
        return response

    @bp.errorhandler(AcmeProblem)
    def _problem(problem):
        response = jsonify(problem.to_json())
        response.status_code = problem.status
        response.mimetype = 'application/problem+json'
        for name, value in problem.headers.items():
            response.headers[name] = value
        return response

    @bp.route('/directory', methods=['GET'])
    def directory():
        u = urls()
        # Only the resources that answer. newOrder and revokeCert join with
        # orders and issuance (#476).
        return jsonify({
            'newNonce': u.new_nonce(),
            'newAccount': u.new_account(),
            'keyChange': u.key_change(),
            'meta': {'externalAccountRequired': bool(server.config().get('eab_required', True))},
        })

    @bp.route('/new-nonce', methods=['GET', 'HEAD'])
    def new_nonce():
        # Section 7.2: 200 to HEAD, 204 to GET; the nonce is the header.
        return make_response('', 200 if request.method == 'HEAD' else 204)

    @bp.route('/new-account', methods=['POST'])
    def new_account():
        req = verified('jwk')
        account, created = server.new_account(req, urls())
        return account_answer(account, 201 if created else 200)

    @bp.route('/account/<account_id>', methods=['POST'])
    def account(account_id):
        req = verified('kid')
        as_the_named_account(req, account_id)
        return account_answer(server.update_account(req, req.account))

    @bp.route('/account/<account_id>/orders', methods=['POST'])
    def account_orders(account_id):
        req = verified('kid')
        as_the_named_account(req, account_id)
        if not req.is_post_as_get:
            raise AcmeProblem('malformed', 'The orders list is read with POST-as-GET')
        return jsonify({'orders': []})

    @bp.route('/key-change', methods=['POST'])
    def key_change():
        req = verified('kid')
        return account_answer(server.change_key(req, req.account, urls()))

    app.register_blueprint(bp)
