"""The ACME server's account half follows RFC 8555, rule by rule (#476).

Every POST to an ACME server is a JWS, and each check on it is a place where
a server that skipped it would accept a request it should not: a replayed
nonce, a request signed for another URL, a key named both ways, `alg: none`,
an account key too weak to trust. Each test below breaks one rule and expects
the refusal the RFC names, so taking the check out fails its test.

Then the accounts themselves: created only with an External Account Binding
this instance issued (D2 on #476), found again by their key, updated,
deactivated for good, and moved to a new key only with proof of both keys.
"""
import json
import os
import sqlite3
import zipfile

import pytest

from tests import contract_support
from tests.acme_support import AcmeTestClient, b64s, ec_key, enable, problem, raw_jws, rsa_key

pytestmark = [pytest.mark.unit]


@pytest.fixture
def app():
    application, _token = contract_support.build_app()
    return application


@pytest.fixture
def eab(app):
    return enable(app)


@pytest.fixture
def client(app, eab):
    return AcmeTestClient(app)


@pytest.fixture
def registered(client, eab):
    response = client.new_account(eab)
    assert response.status_code == 201, response.get_data(as_text=True)
    return client


# --- what the server shows -------------------------------------------------

ROUTES = [('get', 'directory'), ('head', 'new-nonce'), ('get', 'new-nonce'), ('post', 'new-account'),
          ('post', 'account/x'), ('post', 'account/x/orders'), ('post', 'key-change')]


@pytest.mark.parametrize('verb,path', ROUTES)
def test_a_server_that_never_turned_it_on_shows_nothing(app, verb, path):
    response = getattr(app.test_client(), verb)(f'https://localhost/acme/{path}')
    assert response.status_code == 404
    assert 'Replay-Nonce' not in response.headers


def test_plain_http_is_refused_unless_allowed(app):
    enable(app)
    response = app.test_client().get('http://localhost/acme/directory')
    assert response.status_code == 400 and problem(response) == 'malformed'
    assert 'HTTPS' in response.get_json()['detail']
    enable(app, allow_http=True)
    assert app.test_client().get('http://localhost/acme/directory').status_code == 200


def test_the_directory_names_what_answers(client):
    response = client.http.get(client.url('directory'))
    assert response.status_code == 200
    assert response.get_json() == {
        'newNonce': 'https://localhost/acme/new-nonce',
        'newAccount': 'https://localhost/acme/new-account',
        'keyChange': 'https://localhost/acme/key-change',
        'meta': {'externalAccountRequired': True},
    }
    assert response.headers['Link'] == '<https://localhost/acme/directory>;rel="index"'


def test_new_nonce_answers_head_and_get_with_a_fresh_nonce_each_time(client):
    head = client.http.head(client.url('new-nonce'))
    get = client.http.get(client.url('new-nonce'))
    assert (head.status_code, get.status_code) == (200, 204)
    assert head.headers['Replay-Nonce'] != get.headers['Replay-Nonce']
    assert get.headers['Cache-Control'] == 'no-store'


# --- the JWS, one rule at a time ------------------------------------------

def test_a_well_formed_new_account_is_created(client, eab):
    response = client.new_account(eab)
    assert response.status_code == 201
    body = response.get_json()
    assert body['status'] == 'valid' and body['contact'] == ['mailto:ops@lab.internal']
    assert response.headers['Location'].startswith('https://localhost/acme/account/')
    assert body['orders'] == response.headers['Location'] + '/orders'
    assert response.headers['Replay-Nonce']


def test_the_content_type_must_be_jose_json(client, eab):
    response = client.post('new-account', {'termsOfServiceAgreed': True}, kid=None, content_type='application/json')
    assert response.status_code == 415 and problem(response) == 'malformed'


@pytest.mark.parametrize('nonce', [None, 'AAAAAAAAAAAAAAAAAAAAAA'], ids=['missing', 'never-issued'])
def test_a_request_without_a_nonce_this_server_issued_is_refused(client, nonce):
    response = client.post('new-account', {}, kid=None, nonce=nonce)
    assert response.status_code == 400 and problem(response) == 'badNonce'
    assert response.headers['Replay-Nonce']


def test_a_nonce_is_good_for_one_request(client, eab):
    nonce = client.nonce()
    first = client.post('new-account', {'externalAccountBinding': client.eab(eab)}, kid=None, nonce=nonce)
    replay = client.post('new-account', {'externalAccountBinding': client.eab(eab)}, kid=None, nonce=nonce)
    assert first.status_code == 201
    assert replay.status_code == 400 and problem(replay) == 'badNonce'


def test_a_request_signed_for_another_url_is_refused(client):
    header = client.protected(client.url('key-change'), kid=None)
    response = client.post('new-account', {}, protected=header)
    assert response.status_code == 403 and problem(response, 'not the URL this request was sent to') == 'unauthorized'


def test_a_request_must_be_a_flattened_jws_with_nothing_unprotected(client):
    good = raw_jws(client.protected(client.url('new-account'), kid=None), b'{}', client.key)
    with_header = dict(good, header={'kid': 'x'})
    general = {'payload': good['payload'], 'signatures': [{'protected': good['protected'],
                                                           'signature': good['signature']}]}
    for body, because in ((with_header, 'flattened'), (general, 'flattened'), ('{not json', 'not JSON'), ('[]', 'flattened')):
        response = client.post('new-account', None, body=body)
        assert response.status_code == 400 and problem(response, because) == 'malformed', body


@pytest.mark.parametrize('alg', ['none', 'HS256'])
def test_no_request_is_accepted_unsigned_or_mac_signed(client, alg):
    header = dict(client.protected(client.url('new-account'), kid=None), alg=alg)
    body = raw_jws(header, b'{}', client.key)
    body['signature'] = ''
    response = client.post('new-account', None, body=body)
    assert problem(response) == 'badSignatureAlgorithm'
    assert 'ES256' in response.get_json()['algorithms']


def test_a_critical_extension_is_refused(client):
    header = dict(client.protected(client.url('new-account'), kid=None), crit=['exp'], exp=1)
    response = client.post('new-account', {}, protected=header)
    assert problem(response) == 'malformed'
    assert 'critical' in response.get_json()['detail']


def test_a_key_must_be_named_exactly_once(client, registered):
    header = registered.protected(registered.url('new-account'), kid=None)
    header['kid'] = registered.account_url
    assert problem(registered.post('new-account', {}, protected=header), 'exactly one of jwk and kid') == 'malformed'


def test_new_account_takes_jwk_and_every_other_request_kid(registered):
    as_kid = registered.post('new-account', {}, kid=registered.account_url)
    as_jwk = registered.post(registered.account_url, None, kid=None)
    assert problem(as_kid, 'sign it with jwk') == 'malformed'
    assert problem(as_jwk, 'sign it with kid') == 'malformed'


def test_a_broken_signature_is_refused(client):
    body = raw_jws(client.protected(client.url('new-account'), kid=None), b'{}', client.key)
    body['signature'] = b64s(b'\x00' * 64)
    assert problem(client.post('new-account', None, body=body), 'does not verify') == 'malformed'


@pytest.mark.parametrize('make_key,accepted', [
    (lambda: rsa_key(1024), False),
    (lambda: rsa_key(2048), True),
    (lambda: ec_key(), True),
], ids=['rsa-1024', 'rsa-2048', 'ec-p256'])
def test_an_account_key_must_be_strong_enough(app, eab, make_key, accepted):
    client = AcmeTestClient(app, key=make_key())
    response = client.new_account(eab)
    if accepted:
        assert response.status_code == 201
    else:
        assert problem(response) == 'badPublicKey'


def test_a_kid_that_is_no_account_here_is_refused(registered):
    for kid in (registered.url('account/nobody'), 'https://elsewhere.example/acme/account/x'):
        response = registered.post(registered.account_url, None, kid=kid)
        assert problem(response) == 'accountDoesNotExist', kid


def test_an_account_cannot_act_on_another(app, eab, registered):
    other = AcmeTestClient(app)
    assert other.new_account(eab).status_code == 201
    response = registered.post(other.account_url, None)
    assert problem(response, 'another account') == 'unauthorized'


# --- External Account Binding (D2 on #476) ------------------------------------

def test_without_an_eab_there_is_no_account(client):
    response = client.new_account(None)
    assert response.status_code == 400 and problem(response) == 'externalAccountRequired'


def test_an_instance_that_does_not_require_eab_takes_accounts_without(app):
    enable(app, eab_required=False)
    response = AcmeTestClient(app).new_account(None)
    assert response.status_code == 201


def _eab_with(client, entry, *, kid=None, url=None, key=None, mac_key=None, alg='HS256', bound=None):
    import josepy
    from josepy import b64
    header = {'alg': alg, 'kid': kid or entry['kid'], 'url': url or client.url('new-account')}
    payload = json.dumps((bound or client.key).public_key().to_partial_json()).encode()
    secret = josepy.JWKOct(key=b64.b64decode(mac_key or entry['hmac_key']))
    return raw_jws(header, payload, secret, getattr(josepy, alg))


@pytest.mark.parametrize('how', ['wrong-mac', 'unknown-kid', 'another-url', 'another-key'])
def test_an_eab_that_does_not_hold_is_refused(client, eab, how):
    broken = {
        'wrong-mac': lambda: _eab_with(client, eab, mac_key=b64s(os.urandom(32))),
        'unknown-kid': lambda: _eab_with(client, eab, kid='team-z'),
        'another-url': lambda: _eab_with(client, eab, url=client.url('key-change')),
        'another-key': lambda: _eab_with(client, eab, bound=ec_key()),
    }[how]()
    because = {'wrong-mac': 'MAC does not verify', 'unknown-kid': 'unknown or disabled',
               'another-url': 'another URL', 'another-key': 'another account key'}[how]
    response = client.post('new-account', {'externalAccountBinding': broken}, kid=None)
    assert response.status_code == 403 and problem(response, because) == 'unauthorized'


def test_an_eab_signed_with_an_account_key_is_refused(client, eab):
    header = {'alg': 'ES256', 'kid': eab['kid'], 'url': client.url('new-account')}
    signed = raw_jws(header, json.dumps(client.key.public_key().to_partial_json()).encode(), client.key)
    response = client.post('new-account', {'externalAccountBinding': signed}, kid=None)
    assert problem(response, 'must be signed with HS256') == 'malformed'


def test_a_disabled_eab_key_enrols_no_one(app, eab):
    enable(app, eab_keys=[dict(eab, disabled=True)])
    response = AcmeTestClient(app).new_account(eab)
    assert problem(response, 'unknown or disabled') == 'unauthorized'


def test_the_account_records_its_eab_key(app, registered):
    server = app.extensions['certmate_container'].managers['acme_server']
    account_id = registered.account_url.rsplit('/', 1)[-1]
    assert server.store.account(account_id)['eab_kid'] == 'team-a'


# --- accounts ------------------------------------------------------------

def test_the_same_key_finds_the_same_account(registered, eab):
    first = registered.account_url
    again = registered.new_account(eab)
    assert again.status_code == 200 and again.headers['Location'] == first


def test_only_return_existing_creates_nothing(app, eab):
    client = AcmeTestClient(app)
    response = client.new_account(eab, onlyReturnExisting=True)
    assert problem(response) == 'accountDoesNotExist'
    assert client.new_account(eab).status_code == 201


@pytest.mark.parametrize('contact,kind', [
    (['tel:+390000000'], 'unsupportedContact'),
    (['mailto:a@x.example,b@x.example'], 'invalidContact'),
    (['mailto:nobody'], 'invalidContact'),
])
def test_contacts_are_one_email_address_each(app, eab, contact, kind):
    response = AcmeTestClient(app).new_account(eab, contact=contact)
    assert problem(response) == kind


def test_an_account_is_read_and_its_contact_changed(registered):
    read = registered.post(registered.account_url, None)
    assert read.status_code == 200 and read.get_json()['status'] == 'valid'
    changed = registered.post(registered.account_url, {'contact': ['mailto:pki@lab.internal']})
    assert changed.get_json()['contact'] == ['mailto:pki@lab.internal']


def test_the_orders_list_is_read_with_post_as_get(registered):
    url = registered.account_url + '/orders'
    assert registered.post(url, None).get_json() == {'orders': []}
    assert problem(registered.post(url, {}), 'POST-as-GET') == 'malformed'


def test_a_deactivated_account_authorizes_nothing_again(registered, eab):
    gone = registered.post(registered.account_url, {'status': 'deactivated'})
    assert gone.get_json()['status'] == 'deactivated'
    assert problem(registered.post(registered.account_url, None), 'deactivated') == 'unauthorized'
    assert problem(registered.new_account(eab), 'deactivated') == 'unauthorized'


def test_any_status_but_deactivated_is_ignored(registered):
    """Section 7.3.2: ignored, not refused. certbot sends "valid" back with a contact change."""
    for status in ('valid', 'revoked'):
        response = registered.post(registered.account_url, {'status': status, 'contact': ['mailto:x@lab.internal']})
        assert response.status_code == 200 and response.get_json()['status'] == 'valid', status


# --- key rollover (section 7.3.5) -----------------------------------------------

def _key_change(client, new_key, *, url=None, account=None, old_key=None, inner_nonce=False):
    inner_header = {'alg': 'ES256', 'url': url or client.url('key-change'),
                    'jwk': new_key.public_key().to_partial_json()}
    if inner_nonce:
        inner_header['nonce'] = client.nonce()
    inner_payload = json.dumps({'account': account or client.account_url,
                                'oldKey': (old_key or client.key).public_key().to_partial_json()}).encode()
    return client.post('key-change', raw_jws(inner_header, inner_payload, new_key))


def test_a_key_change_moves_the_account_to_the_new_key(registered):
    new_key = ec_key()
    response = _key_change(registered, new_key)
    assert response.status_code == 200, response.get_data(as_text=True)
    assert problem(registered.post(registered.account_url, None), 'does not verify') == 'malformed'
    registered.key = new_key
    assert registered.post(registered.account_url, None).status_code == 200


@pytest.mark.parametrize('how', ['another-url', 'another-account', 'wrong-old-key'])
def test_a_key_change_that_does_not_prove_both_keys_is_refused(registered, how):
    new_key = ec_key()
    args, because = {'another-url': ({'url': registered.url('new-account')}, 'another URL'),
                     'another-account': ({'account': registered.url('account/somebody')}, 'another account'),
                     'wrong-old-key': ({'old_key': ec_key()}, 'oldKey')}[how]
    assert problem(_key_change(registered, new_key, **args), because) == 'unauthorized'


def test_a_key_change_inner_jws_carries_no_nonce(registered):
    assert problem(_key_change(registered, ec_key(), inner_nonce=True), 'neither kid nor nonce') == 'malformed'


def test_a_key_another_account_has_is_not_taken(app, eab, registered):
    other = AcmeTestClient(app)
    assert other.new_account(eab).status_code == 201
    response = _key_change(registered, other.key)
    assert response.status_code == 409
    assert response.headers['Location'] == other.account_url


# --- what survives -------------------------------------------------------------

def test_the_settings_page_cannot_hand_out_eab_keys(app):
    from modules.core.settings import validate_settings_post
    _, rejected, _ = validate_settings_post({'acme_server': {'eab_keys': [{'kid': 'x', 'hmac_key': 'y'}]}})
    assert rejected == ['acme_server']


def test_a_backup_carries_the_accounts_as_a_database_that_opens(app, registered, tmp_path, monkeypatch):
    monkeypatch.delenv('CERTMATE_BACKUP_PASSPHRASE', raising=False)
    managers = app.extensions['certmate_container'].managers
    settings = managers['settings'].load_settings()
    backup = managers['file_ops'].create_unified_backup(settings, 'manual')
    path = backup if isinstance(backup, str) and os.path.exists(backup) else None
    if path is None:
        candidates = sorted((managers['file_ops'].backup_dir / 'unified').glob('*.zip'))
        path = candidates[-1]
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        assert not [n for n in names if n.endswith(('-journal', '-wal', '-shm'))]
        copy = tmp_path / 'acme.db'
        copy.write_bytes(archive.read('data/acme/acme.db'))
    with sqlite3.connect(copy) as con:
        assert con.execute('SELECT count(*) FROM accounts').fetchone()[0] == 1


# --- the nonce store, on its own ------------------------------------------------

def test_a_nonce_expires():
    from modules.core.acme_nonces import NonceStore
    clock = [100.0]
    store = NonceStore(ttl_seconds=60, clock=lambda: clock[0])
    stale, fresh = store.issue(), None
    clock[0] += 61
    fresh = store.issue()  # issuing forgets what has expired
    assert not store.consume(stale)
    assert store.consume(fresh)
    assert len(store) == 0


def test_the_nonce_store_keeps_the_newest_when_full():
    from modules.core.acme_nonces import NonceStore
    store = NonceStore(capacity=3)
    issued = [store.issue() for _ in range(5)]
    assert len(store) == 3
    assert [store.consume(n) for n in issued] == [False, False, True, True, True]
    assert not store.consume(None)


# --- more ways an EAB, a contact or a key change can be wrong ---------------------

def test_an_eab_carries_no_nonce(client, eab):
    import josepy
    from josepy import b64
    header = {'alg': 'HS256', 'kid': eab['kid'], 'url': client.url('new-account'), 'nonce': client.nonce()}
    payload = json.dumps(client.key.public_key().to_partial_json()).encode()
    signed = raw_jws(header, payload, josepy.JWKOct(key=b64.b64decode(eab['hmac_key'])), josepy.HS256)
    response = client.post('new-account', {'externalAccountBinding': signed}, kid=None)
    assert problem(response, 'neither a nonce nor a jwk') == 'malformed'


def test_an_eab_whose_payload_is_no_key_is_refused(client, eab):
    import josepy
    from josepy import b64
    header = {'alg': 'HS256', 'kid': eab['kid'], 'url': client.url('new-account')}
    signed = raw_jws(header, b'"not a key"', josepy.JWKOct(key=b64.b64decode(eab['hmac_key'])), josepy.HS256)
    response = client.post('new-account', {'externalAccountBinding': signed}, kid=None)
    assert problem(response, 'payload is not a JWK') == 'malformed'


@pytest.mark.parametrize('contact,because', [
    (['mailto:a@lab.internal'] * 11, 'at most 10'),
    ('mailto:a@lab.internal', 'must be a list'),
    ([42], 'reasonable length'),
])
def test_contact_is_a_short_list_of_strings(app, eab, contact, because):
    response = AcmeTestClient(app).new_account(eab, contact=contact)
    assert problem(response, because) in ('malformed', 'invalidContact')


def test_a_key_change_payload_must_name_the_account_and_old_key(registered):
    new_key = ec_key()
    header = {'alg': 'ES256', 'url': registered.url('key-change'), 'jwk': new_key.public_key().to_partial_json()}
    response = registered.post('key-change', raw_jws(header, b'{"account": "x"}', new_key))
    assert problem(response, 'must carry account and oldKey') == 'malformed'


def test_a_backup_keeps_writes_that_are_still_in_the_write_ahead_log(app, registered, tmp_path, monkeypatch):
    """A raw copy of the .db file, without its -wal, loses what the log holds.
    The online backup reads the database as SQLite sees it."""
    monkeypatch.delenv('CERTMATE_BACKUP_PASSPHRASE', raising=False)
    managers = app.extensions['certmate_container'].managers
    db = managers['acme_server'].db_path
    holder = sqlite3.connect(db)
    try:
        holder.execute('PRAGMA journal_mode=WAL')
        holder.execute('PRAGMA wal_autocheckpoint=0')
        holder.execute("INSERT INTO accounts VALUES ('in-the-log', 'tp', '{}', 'valid', '[]', NULL, 'now')")
        holder.commit()
        assert db.with_name('acme.db-wal').stat().st_size > 0
        managers['file_ops'].create_unified_backup(managers['settings'].load_settings(), 'manual')
    finally:
        holder.close()
    path = sorted((managers['file_ops'].backup_dir / 'unified').glob('*.zip'))[-1]
    copy = tmp_path / 'acme.db'
    with zipfile.ZipFile(path) as archive:
        copy.write_bytes(archive.read('data/acme/acme.db'))
    with sqlite3.connect(copy) as con:
        ids = {row[0] for row in con.execute('SELECT id FROM accounts')}
    assert 'in-the-log' in ids and len(ids) == 2
