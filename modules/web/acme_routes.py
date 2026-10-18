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
from flask import Blueprint, Response, abort, g, jsonify, make_response, request

from ..core import acme_server
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

    def new_order(self):
        return self.base + 'new-order'

    def order(self, order_id):
        return self.base + 'order/' + order_id

    def finalize(self, order_id):
        return self.order(order_id) + '/finalize'

    def authz(self, authz_id):
        return self.base + 'authz/' + authz_id

    def challenge(self, challenge_id):
        return self.base + 'chall/' + challenge_id

    def certificate(self, certificate_id):
        return self.base + 'cert/' + certificate_id

    def revoke_cert(self):
        return self.base + 'revoke-cert'

    def renewal_info(self):
        return self.base + 'renewal-info'


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
            response.headers.add('Link', f'<{urls().directory()}>;rel="index"')
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
        return jsonify({
            'newNonce': u.new_nonce(),
            'newAccount': u.new_account(),
            'newOrder': u.new_order(),
            'revokeCert': u.revoke_cert(),
            'keyChange': u.key_change(),
            'renewalInfo': u.renewal_info(),
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
        u = urls()
        return jsonify({'orders': [u.order(i) for i in server.store.order_ids_of(account_id)]})

    @bp.route('/new-order', methods=['POST'])
    def new_order():
        req = verified('kid')
        created = server.new_order(req)
        response = jsonify(server.order_json(created, urls()))
        response.status_code = 201
        response.headers['Location'] = urls().order(created['id'])
        return response

    @bp.route('/order/<order_id>', methods=['POST'])
    def order(order_id):
        req = verified('kid')
        if not req.is_post_as_get:
            raise AcmeProblem('malformed', 'An order is read with POST-as-GET')
        found = server.owned(server.store.order(order_id), req.account, 'order')
        return jsonify(server.order_json(found, urls()))

    @bp.route('/order/<order_id>/finalize', methods=['POST'])
    def finalize(order_id):
        req = verified('kid')
        found = server.owned(server.store.order(order_id), req.account, 'order')
        response = jsonify(server.order_json(server.finalize(req, found, urls()), urls()))
        response.headers['Location'] = urls().order(order_id)
        return response

    @bp.route('/cert/<certificate_id>', methods=['POST'])
    def certificate(certificate_id):
        req = verified('kid')
        if not req.is_post_as_get:
            raise AcmeProblem('malformed', 'A certificate is read with POST-as-GET')
        found = server.owned(server.store.certificate(certificate_id), req.account, 'certificate')
        # Decision G3 on #476: the leaf alone; the root is installed from /acme/root.
        return Response(found['pem'], mimetype='application/pem-certificate-chain')

    @bp.route('/revoke-cert', methods=['POST'])
    def revoke_cert():
        server.revoke(verified('either'))
        return make_response('', 200)

    @bp.route('/renewal-info/<cert_id>', methods=['GET'])
    def renewal_info(cert_id):
        # RFC 9773 section 4.1: a plain GET, no JWS; the answer says when to
        # renew, and Retry-After when to ask again.
        info = server.renewal_info(cert_id)
        if info is None:
            raise AcmeProblem('malformed', 'No certificate of this server has that identifier', status=404)
        response = jsonify(info)
        response.headers['Retry-After'] = str(acme_server.ARI_RETRY_AFTER_SECONDS)
        return response

    @bp.route('/root', methods=['GET'])
    def root():
        pem = server.ca.root_pem()
        if pem is None:
            abort(503)
        return Response(pem, mimetype='application/pem-certificate-chain')

    @bp.route('/crl', methods=['GET'])
    def crl():
        der = server.crl_der()
        if der is None:
            abort(503)
        return Response(der, mimetype='application/pkix-crl')

    @bp.route('/authz/<authz_id>', methods=['POST'])
    def authz(authz_id):
        req = verified('kid')
        found = server.owned(server.store.authorization(authz_id), req.account, 'authorization')
        return jsonify(server.authz_json(server.update_authz(req, found), urls()))

    @bp.route('/chall/<challenge_id>', methods=['POST'])
    def challenge(challenge_id):
        req = verified('kid')
        found = server.store.challenge(challenge_id)
        owner = server.store.authorization(found['authz_id']) if found else None
        server.owned(owner, req.account, 'challenge')
        answered = server.respond_to_challenge(req, found, owner)
        response = jsonify(server.challenge_json(answered, urls()))
        # Section 7.5.1: a challenge points up to its authorization.
        response.headers.add('Link', f'<{urls().authz(owner["id"])}>;rel="up"')
        return response

    @bp.route('/key-change', methods=['POST'])
    def key_change():
        req = verified('kid')
        return account_answer(server.change_key(req, req.account, urls()))

    app.register_blueprint(bp)
