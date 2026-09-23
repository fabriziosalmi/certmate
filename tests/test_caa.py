"""Tests for the CAA check (``modules/core/caa.py``) and where it is used.

Three layers:

* the RFC 8659 logic, against a scripted resolver: climbing the tree,
  ``issuewild`` for wildcards, ``validationmethods`` (RFC 8657), a critical
  unknown tag, an empty issuer, a lookup that fails;
* the two places it speaks: a failed create and a failed renewal carry the
  explanation in their error, driven through the real CertificateManager with
  certbot failing;
* the preview endpoint, including the scope boundary a scoped key must not
  cross.

conftest.py makes the whole suite's CAA lookups find nothing; every test here
passes or patches its own resolver. One test asks the real DNS and is marked
``network``.
"""
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask, request
from flask_restx import Api, Namespace

from modules.core import caa
from modules.core.caa import (
    STATUS_ALLOWED,
    STATUS_FORBIDDEN,
    STATUS_NO_POLICY,
    STATUS_NOT_APPLICABLE,
    STATUS_UNKNOWN,
    LookupFailed,
    check,
    check_domain,
    explain_failure,
)

pytestmark = [pytest.mark.unit]

LE = caa.CA_IDENTIFIERS['letsencrypt']


def _zone(records):
    """A resolver over ``{name: [(flags, tag, value)] | Exception}``."""
    asked = []

    def resolve(name):
        asked.append(name)
        found = records.get(name, [])
        if isinstance(found, Exception):
            raise found
        return found

    resolve.asked = asked
    return resolve


# --------------------------------------------------------------------------- #
# RFC 8659 / 8657 logic
# --------------------------------------------------------------------------- #

def test_named_ca_is_allowed():
    r = check_domain('example.com', LE, resolve=_zone({
        'example.com': [(0, 'issue', 'letsencrypt.org')]}))
    assert r['status'] == STATUS_ALLOWED


def test_other_ca_is_forbidden_and_says_which():
    r = check_domain('example.com', LE, resolve=_zone({
        'example.com': [(0, 'issue', 'pki.goog'), (0, 'issue', 'digicert.com')]}))
    assert r['status'] == STATUS_FORBIDDEN
    assert 'digicert.com, pki.goog' in r['reason']
    assert r['records'] == ['0 issue "pki.goog"', '0 issue "digicert.com"']


def test_no_records_anywhere_is_no_policy():
    resolve = _zone({})
    r = check_domain('a.b.example.com', LE, resolve=resolve)
    assert r['status'] == STATUS_NO_POLICY
    assert resolve.asked == ['a.b.example.com', 'b.example.com', 'example.com', 'com']


def test_climbs_to_the_first_name_with_records_and_stops():
    resolve = _zone({
        'example.com': [(0, 'issue', 'pki.goog')],
        'com': [(0, 'issue', 'letsencrypt.org')],   # must never be reached
    })
    r = check_domain('deep.app.example.com', LE, resolve=resolve)
    assert r['status'] == STATUS_FORBIDDEN
    assert r['relevant_name'] == 'example.com'
    assert 'com' not in resolve.asked


def test_the_closest_record_wins_over_a_permissive_parent():
    r = check_domain('app.example.com', LE, resolve=_zone({
        'app.example.com': [(0, 'issue', 'pki.goog')],
        'example.com': [(0, 'issue', 'letsencrypt.org')],
    }))
    assert r['status'] == STATUS_FORBIDDEN


def test_wildcard_uses_issuewild_when_present():
    zone = {'example.com': [(0, 'issue', 'letsencrypt.org'), (0, 'issuewild', 'pki.goog')]}
    assert check_domain('example.com', LE, resolve=_zone(zone))['status'] == STATUS_ALLOWED
    wild = check_domain('*.example.com', LE, resolve=_zone(zone))
    assert wild['status'] == STATUS_FORBIDDEN
    assert 'issuewild' in wild['reason']


def test_wildcard_falls_back_to_issue_without_issuewild():
    r = check_domain('*.example.com', LE, resolve=_zone({
        'example.com': [(0, 'issue', 'letsencrypt.org')]}))
    assert r['status'] == STATUS_ALLOWED


def test_issuewild_does_not_restrict_a_non_wildcard():
    r = check_domain('example.com', LE, resolve=_zone({
        'example.com': [(0, 'issuewild', 'pki.goog')]}))
    assert r['status'] == STATUS_ALLOWED


def test_empty_issuer_forbids_every_ca():
    r = check_domain('example.com', LE, resolve=_zone({'example.com': [(0, 'issue', ';')]}))
    assert r['status'] == STATUS_FORBIDDEN
    assert '(no CA)' in r['reason']


def test_records_that_restrict_nothing_allow():
    r = check_domain('example.com', LE, resolve=_zone({
        'example.com': [(0, 'iodef', 'mailto:security@example.com')]}))
    assert r['status'] == STATUS_ALLOWED


def test_issuer_match_ignores_case_parameters_and_trailing_dot():
    r = check_domain('example.com', LE, resolve=_zone({
        'example.com': [(0, 'issue', 'LetsEncrypt.org. ; validationmethods=dns-01')]}))
    assert r['status'] == STATUS_ALLOWED
    assert r['reason'] == 'example.com issue names letsencrypt.org'


def test_accounturi_is_reported_not_enforced():
    r = check_domain('example.com', LE, resolve=_zone({
        'example.com': [(0, 'issue', 'letsencrypt.org; accounturi=https://acme/acct/1')]}))
    assert r['status'] == STATUS_ALLOWED
    assert 'https://acme/acct/1' in r['reason']


def test_validationmethods_that_exclude_the_challenge_forbid():
    zone = {'example.com': [(0, 'issue', 'letsencrypt.org; validationmethods=dns-01')]}
    assert check_domain('example.com', LE, challenge_type='dns-01',
                        resolve=_zone(zone))['status'] == STATUS_ALLOWED
    r = check_domain('example.com', LE, challenge_type='http-01', resolve=_zone(zone))
    assert r['status'] == STATUS_FORBIDDEN
    assert 'only for dns-01' in r['reason'] and 'http-01' in r['reason']


def test_a_second_record_can_allow_what_the_first_restricts():
    r = check_domain('example.com', LE, challenge_type='http-01', resolve=_zone({
        'example.com': [(0, 'issue', 'letsencrypt.org; validationmethods=dns-01'),
                        (0, 'issue', 'letsencrypt.org')]}))
    assert r['status'] == STATUS_ALLOWED


def test_critical_unknown_tag_forbids():
    r = check_domain('example.com', LE, resolve=_zone({
        'example.com': [(0, 'issue', 'letsencrypt.org'), (128, 'tbs', 'x')]}))
    assert r['status'] == STATUS_FORBIDDEN
    assert 'critical' in r['reason']


def test_non_critical_unknown_tag_is_ignored():
    r = check_domain('example.com', LE, resolve=_zone({
        'example.com': [(0, 'issue', 'letsencrypt.org'), (0, 'tbs', 'x')]}))
    assert r['status'] == STATUS_ALLOWED


def test_a_failed_lookup_is_unknown_not_allowed():
    r = check_domain('example.com', LE, resolve=_zone({
        'example.com': LookupFailed('SERVFAIL for example.com')}))
    assert r['status'] == STATUS_UNKNOWN
    assert 'SERVFAIL' in r['reason']


# --------------------------------------------------------------------------- #
# check(): aggregation, CAs, messages
# --------------------------------------------------------------------------- #

def test_the_worst_name_decides():
    zone = _zone({
        'ok.example.com': [(0, 'issue', 'letsencrypt.org')],
        'bad.example.com': [(0, 'issue', 'pki.goog')],
        'down.example.com': LookupFailed('timeout'),
    })
    result = check('letsencrypt', ['ok.example.com', 'down.example.com', 'bad.example.com'],
                   resolve=zone)
    assert result['status'] == STATUS_FORBIDDEN
    assert [d['status'] for d in result['domains']] == [STATUS_ALLOWED, STATUS_UNKNOWN, STATUS_FORBIDDEN]


def test_unknown_outranks_allowed():
    zone = _zone({'a.example.com': LookupFailed('timeout')})
    assert check('letsencrypt', ['a.example.com', 'b.example.org'], resolve=zone)['status'] == STATUS_UNKNOWN


def test_names_are_deduplicated_case_insensitively():
    zone = _zone({})
    result = check('letsencrypt', ['Example.com', 'example.com', ' example.com '], resolve=zone)
    assert len(result['domains']) == 1


def test_private_ca_is_not_applicable_and_asks_nothing():
    zone = _zone({})
    result = check('private_ca', ['example.com'], resolve=zone)
    assert result['status'] == STATUS_NOT_APPLICABLE
    assert zone.asked == []


def test_zerossl_is_recognised_by_sectigo_identifiers():
    result = check('zerossl', ['example.com'],
                   resolve=_zone({'example.com': [(0, 'issue', 'sectigo.com')]}))
    assert result['status'] == STATUS_ALLOWED


def test_message_names_the_ca_the_record_and_the_fix():
    result = check('letsencrypt', ['example.com'], ca_name="Let's Encrypt",
                   resolve=_zone({'example.com': [(0, 'issue', 'pki.goog')]}))
    msg = result['message']
    assert "Let's Encrypt (letsencrypt.org) will refuse example.com" in msg
    assert 'example.com. CAA 0 issue "letsencrypt.org" or choose a CA' in msg
    assert '`' not in msg  # read in a form and in a notification, not rendered as markdown
    assert result['suggested_record'] == 'example.com. CAA 0 issue "letsencrypt.org"'


def test_message_for_a_wildcard_suggests_issuewild():
    result = check('letsencrypt', ['*.example.com'],
                   resolve=_zone({'example.com': [(0, 'issuewild', 'pki.goog')]}))
    assert 'CAA 0 issuewild "letsencrypt.org"' in result['message']
    assert result['suggested_record'] == 'example.com. CAA 0 issuewild "letsencrypt.org"'


def test_nothing_to_say_when_allowed():
    result = check('letsencrypt', ['example.com'],
                   resolve=_zone({'example.com': [(0, 'issue', 'letsencrypt.org')]}))
    assert result['message'] is None
    assert result['suggested_record'] is None


def test_a_malformed_name_is_unknown_not_a_crash():
    """dnspython rejects `a..example.com` before sending anything; the real
    resolver turns that into LookupFailed, so no network is involved."""
    result = check('letsencrypt', ['a..example.com'], resolve=caa._dnspython_resolver(1.0))
    assert result['status'] == STATUS_UNKNOWN
    assert 'EmptyLabel' in result['domains'][0]['reason']


def test_without_dnspython_the_answer_is_unknown_and_says_why(monkeypatch):
    def missing(timeout, nameservers=None):
        raise ImportError("No module named 'dns'")
    monkeypatch.setattr(caa, 'resolver_factory', missing)
    result = check('letsencrypt', ['example.com'])
    assert result['status'] == STATUS_UNKNOWN
    assert "No module named 'dns'" in result['message']


def test_explain_failure_speaks_only_for_a_refusal():
    forbid = _zone({'example.com': [(0, 'issue', 'pki.goog')]})
    allow = _zone({'example.com': [(0, 'issue', 'letsencrypt.org')]})
    down = _zone({'example.com': LookupFailed('timeout')})
    assert explain_failure('letsencrypt', ['example.com'], resolve=forbid).startswith('CAA:')
    assert explain_failure('letsencrypt', ['example.com'], resolve=allow) is None
    assert explain_failure('letsencrypt', ['example.com'], resolve=down) is None


# --------------------------------------------------------------------------- #
# Where it speaks: failed create, failed renewal
# --------------------------------------------------------------------------- #

def _forbidding_resolver(timeout, nameservers=None):
    return _zone({'example.com': [(0, 'issue', 'pki.goog')]})


def _cert_mgr(tmp_path, shell, **settings):
    from modules.core.certificates import CertificateManager
    settings_mgr = MagicMock()
    settings_mgr.load_settings.return_value = dict({
        'default_ca': 'letsencrypt', 'challenge_type': 'dns-01',
        'dns_propagation_seconds': {'duckdns': 1},
        'default_key_type': 'ecdsa', 'default_elliptic_curve': 'secp384r1',
    }, **settings)
    settings_mgr.get_domain_dns_provider.return_value = 'duckdns'
    dns_mgr = MagicMock()
    dns_mgr.get_dns_provider_account_config.return_value = ({'api_token': 't'}, 'default')
    ca_mgr = MagicMock()
    ca_mgr.ca_providers = {'letsencrypt': {'name': "Let's Encrypt"}}
    ca_mgr.get_ca_config.return_value = (None, None)
    return CertificateManager(cert_dir=tmp_path, settings_manager=settings_mgr,
                              dns_manager=dns_mgr, storage_manager=None,
                              ca_manager=ca_mgr, shell_executor=shell)


def _failing_shell():
    from modules.core.shell import MockShellExecutor
    shell = MockShellExecutor()
    shell.set_next_result(returncode=1, stderr='urn:ietf:params:acme:error:caa: CAA record prevents issuance')
    return shell


def test_failed_create_explains_the_caa_refusal(tmp_path, monkeypatch):
    monkeypatch.setattr(caa, 'resolver_factory', _forbidding_resolver)
    mgr = _cert_mgr(tmp_path, _failing_shell())
    with patch('modules.core.certificates.check_certbot_plugin_installed', return_value=True):
        with pytest.raises(RuntimeError) as err:
            mgr.create_certificate(domain='www.example.com', email='t@example.com',
                                   dns_provider='duckdns', ca_provider='letsencrypt')
    text = str(err.value)
    assert text.startswith('Certificate creation failed:')
    assert "CAA: example.com issue allows only pki.goog, so Let's Encrypt (letsencrypt.org)" in text


def test_failed_create_adds_nothing_when_caa_allows(tmp_path):
    # conftest's resolver finds no records: no policy, nothing to explain.
    mgr = _cert_mgr(tmp_path, _failing_shell())
    with patch('modules.core.certificates.check_certbot_plugin_installed', return_value=True):
        with pytest.raises(RuntimeError) as err:
            mgr.create_certificate(domain='www.example.com', email='t@example.com',
                                   dns_provider='duckdns', ca_provider='letsencrypt')
    assert 'CAA:' not in str(err.value)


def _existing(tmp_path, domain, metadata):
    import json
    d = tmp_path / domain
    d.mkdir(parents=True, exist_ok=True)
    (d / 'cert.pem').write_bytes(b'existing\n')
    (d / 'metadata.json').write_text(json.dumps(metadata))


def test_failed_renewal_explains_the_caa_refusal(tmp_path, monkeypatch):
    monkeypatch.setattr(caa, 'resolver_factory', _forbidding_resolver)
    _existing(tmp_path, 'app.example.com', {'ca_provider': 'letsencrypt',
                                            'san_domains': ['www.example.com']})
    mgr = _cert_mgr(tmp_path, _failing_shell())
    with pytest.raises(RuntimeError) as err:
        mgr.renew_certificate('app.example.com')
    assert 'Renewal failed' in str(err.value)
    assert 'CAA: example.com issue allows only pki.goog' in str(err.value)


def test_renewal_without_a_recorded_ca_uses_the_default(tmp_path, monkeypatch):
    """Metadata written before ca_provider was recorded: the certificate came
    from the default CA, so that is the one the CAA records are read for."""
    monkeypatch.setattr(caa, 'resolver_factory', lambda timeout, nameservers=None: _zone({
        'example.com': [(0, 'issue', 'letsencrypt.org')]}))
    _existing(tmp_path, 'app.example.com', {})
    mgr = _cert_mgr(tmp_path, _failing_shell(), default_ca='google')
    with pytest.raises(RuntimeError) as err:
        mgr.renew_certificate('app.example.com')
    assert 'google (pki.goog) will refuse' in str(err.value)


def test_an_error_while_explaining_keeps_the_original_error(tmp_path, monkeypatch):
    def broken(timeout, nameservers=None):
        raise RuntimeError('dnspython exploded')
    monkeypatch.setattr(caa, 'check', MagicMock(side_effect=RuntimeError('boom')))
    monkeypatch.setattr(caa, 'resolver_factory', broken)
    mgr = _cert_mgr(tmp_path, _failing_shell())
    with patch('modules.core.certificates.check_certbot_plugin_installed', return_value=True):
        with pytest.raises(RuntimeError) as err:
            mgr.create_certificate(domain='www.example.com', email='t@example.com',
                                   dns_provider='duckdns', ca_provider='letsencrypt')
    assert 'Certificate creation failed: ' in str(err.value)
    assert 'CAA' in str(err.value)  # certbot's own text, untouched
    assert 'boom' not in str(err.value)


# --------------------------------------------------------------------------- #
# The preview endpoint
# --------------------------------------------------------------------------- #

def _passthrough(*args, **kwargs):
    if len(args) == 1 and callable(args[0]) and not kwargs:
        return args[0]
    return lambda fn: fn


@pytest.fixture
def caa_app(tmp_path, monkeypatch):
    from modules.api.models import create_api_models
    from modules.api.resources import create_api_resources

    resolver = _zone({'example.com': [(0, 'issue', 'pki.goog')],
                      'tenant-a.example': [(0, 'issue', 'letsencrypt.org')]})
    monkeypatch.setattr(caa, 'resolver_factory', lambda timeout, nameservers=None: resolver)

    auth = MagicMock()
    auth.require_role = MagicMock(side_effect=_passthrough)

    def can_access(user, domain):
        scope = (user or {}).get('allowed_domains')
        if scope is None:
            return True
        return any(domain == p or (p.startswith('*.') and domain.endswith(p[1:])) for p in scope)
    auth.user_can_access_domain.side_effect = can_access

    settings = MagicMock()
    settings.load_settings.return_value = {'default_ca': 'letsencrypt', 'challenge_type': 'dns-01'}
    certificates = MagicMock()
    certificates.ca_manager.ca_providers = {'letsencrypt': {'name': "Let's Encrypt"}}
    managers = {'auth': auth, 'settings': settings, 'certificates': certificates,
                'file_ops': MagicMock(cert_dir=Path(tmp_path)), 'cache': MagicMock(),
                'dns': MagicMock(), 'audit': MagicMock()}

    app = Flask(__name__)
    app.config['TESTING'] = True
    api = Api(app, prefix='/api')
    resources = create_api_resources(api, create_api_models(api), managers)
    ns = Namespace('certificates')
    api.add_namespace(ns)
    ns.add_resource(resources['CheckCAA'], '/check-caa')
    app.resolver = resolver
    return app


def _as(app, allowed_domains):
    @app.before_request
    def _user():
        request.current_user = {'username': 'u', 'role': 'viewer',
                                'allowed_domains': allowed_domains}


def test_endpoint_reports_a_refusal_with_settings_defaults(caa_app):
    _as(caa_app, None)
    r = caa_app.test_client().post('/api/certificates/check-caa',
                                   json={'domain': 'www.example.com'})
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body['status'] == 'forbidden'
    assert body['ca_provider'] == 'letsencrypt'
    assert "Let's Encrypt (letsencrypt.org) will refuse www.example.com" in body['message']


def test_endpoint_honours_the_chosen_ca(caa_app):
    _as(caa_app, None)
    r = caa_app.test_client().post('/api/certificates/check-caa',
                                   json={'domain': 'www.example.com', 'ca_provider': 'google'})
    assert r.get_json()['status'] == 'allowed'


def test_scoped_key_cannot_learn_about_an_out_of_scope_san(caa_app):
    """The DNS-alias check leaked topology this way once (audit M5). A SAN
    outside the key's scope is refused before a single lookup is made."""
    _as(caa_app, ['*.tenant-a.example'])
    r = caa_app.test_client().post('/api/certificates/check-caa', json={
        'domain': 'app.tenant-a.example', 'san_domains': ['www.example.com']})
    assert r.status_code == 403
    assert r.get_json()['code'] == 'DOMAIN_OUT_OF_SCOPE'
    assert caa_app.resolver.asked == []


def test_scoped_key_can_check_its_own_names(caa_app):
    _as(caa_app, ['*.tenant-a.example'])
    r = caa_app.test_client().post('/api/certificates/check-caa',
                                   json={'domain': 'app.tenant-a.example'})
    assert r.status_code == 200
    assert r.get_json()['status'] == 'allowed'


@pytest.mark.parametrize('payload', [
    {},
    {'domain': ''},
    {'domain': 5},
    {'domain': 'example.com', 'san_domains': 'www.example.com'},
    {'domain': 'example.com', 'san_domains': [1, 2]},
    {'domain': 'example.com', 'san_domains': [f'h{i}.example.com' for i in range(100)]},
])
def test_endpoint_rejects_bad_input_with_a_code(caa_app, payload):
    _as(caa_app, None)
    r = caa_app.test_client().post('/api/certificates/check-caa', json=payload)
    assert r.status_code == 400
    assert r.get_json()['code'] == 'INVALID_REQUEST'
    assert caa_app.resolver.asked == []


# --------------------------------------------------------------------------- #
# Real DNS
# --------------------------------------------------------------------------- #

@pytest.mark.network
def test_real_dns_google_allows_only_its_own_ca():
    """google.com publishes `issue "pki.goog"`, so Let's Encrypt is refused
    and Google Trust Services is not; maps.google.com has no records of its
    own and inherits google.com's by climbing. Uses the real dnspython
    resolver, not conftest's stand-in."""
    resolve = caa._dnspython_resolver(5.0)
    assert check('letsencrypt', ['maps.google.com'], resolve=resolve)['status'] == STATUS_FORBIDDEN
    assert check('google', ['maps.google.com'], resolve=resolve)['status'] == STATUS_ALLOWED


# --------------------------------------------------------------------------- #
# The dependency
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize('lockfile', ['requirements.lock', 'requirements-minimal.lock'])
def test_dnspython_is_in_what_the_image_installs(lockfile):
    """dnspython reaches the image only transitively, through the DNS plugins.

    Pinning it directly is right, and was tried: regenerating the locks for
    that one line also re-resolved a dozen unrelated transitive packages
    (filelock 3 -> 4 among them), which does not belong inside a CAA change.
    Until that pin lands on its own, this is what notices a plugin dropping
    it. Without dnspython, caa.check answers 'unknown' and says why; it never
    breaks an issuance — but the warning would be gone.
    """
    text = (Path(__file__).resolve().parent.parent / lockfile).read_text()
    assert any(line.startswith('dnspython==') for line in text.splitlines()), (
        f'dnspython is no longer in {lockfile}; pin it in the matching '
        'requirements file, or the CAA check silently stops working')


# --------------------------------------------------------------------------- #
# The dnspython resolver's translation of what DNS answers, offline
# --------------------------------------------------------------------------- #

class _FakeRdata:
    def __init__(self, flags, tag, value):
        self.flags, self.tag, self.value = flags, tag, value


@pytest.mark.parametrize('raised, expected', [
    ('NoAnswer', []),         # the name exists, no CAA: climb
    ('NXDOMAIN', []),         # the name does not exist: climb
])
def test_dnspython_no_records_means_climb(monkeypatch, raised, expected):
    import dns.resolver
    exc = getattr(dns.resolver, raised)

    def resolve(self, name, rdtype):
        raise exc()
    monkeypatch.setattr(dns.resolver.Resolver, 'resolve', resolve)
    assert caa._dnspython_resolver(1.0)('example.com') == expected


@pytest.mark.parametrize('exc_path', [
    'dns.resolver.NoNameservers',      # SERVFAIL everywhere
    'dns.exception.Timeout',
    'dns.name.EmptyLabel',             # any other DNSException
])
def test_dnspython_failures_are_lookup_failed_not_no_records(monkeypatch, exc_path):
    """A SERVFAIL is not 'no CAA records': a CA that gets one refuses, so
    reading it as permission to climb would call a refusal allowed."""
    import importlib
    import dns.resolver
    module, _, name = exc_path.rpartition('.')
    exc = getattr(importlib.import_module(module), name)

    def resolve(self, qname, rdtype):
        raise exc()
    monkeypatch.setattr(dns.resolver.Resolver, 'resolve', resolve)
    with pytest.raises(LookupFailed):
        caa._dnspython_resolver(1.0)('example.com')


def test_dnspython_records_are_decoded(monkeypatch):
    import dns.resolver

    def resolve(self, name, rdtype):
        assert rdtype == 'CAA'
        return [_FakeRdata(0, b'issue', b'letsencrypt.org'),
                _FakeRdata(128, b'tbs', b'\xff\xfe')]
    monkeypatch.setattr(dns.resolver.Resolver, 'resolve', resolve)
    assert caa._dnspython_resolver(1.0)('example.com') == [
        (0, 'issue', 'letsencrypt.org'), (128, 'tbs', '��')]


def test_dnspython_timeout_is_passed_as_the_resolver_lifetime(monkeypatch):
    import dns.resolver
    seen = {}

    def resolve(self, name, rdtype):
        seen['lifetime'] = self.lifetime
        return []
    monkeypatch.setattr(dns.resolver.Resolver, 'resolve', resolve)
    caa._dnspython_resolver(2.5)('example.com')
    assert seen['lifetime'] == 2.5
