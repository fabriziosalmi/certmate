"""A refusal of a settings write says which request field it is about (#1511, P61).

The settings page used to guess the field from words in the message: a key
id "ipv6-lab" that already existed marked the names field, because the text
carried "ipv6"; an SSO issuer refused for being a link-local address carried
no "issuer_url" at all, so nothing was named or marked. The server knows the
field it refused, so it says so in `field` (API contract 2.73), and the page
marks that field and no other.
"""
import pytest

from tests import contract_support

pytestmark = [pytest.mark.unit]


@pytest.fixture
def client():
    app, token = contract_support.build_app()
    client = app.test_client()
    client.environ_base['HTTP_AUTHORIZATION'] = f'Bearer {token}'
    return client


@pytest.mark.parametrize('body, field', [
    ({'allowed_identifiers': ['*.lab.internal'], 'kid': 'not a kid'}, 'kid'),
    ({'allowed_identifiers': []}, 'allowed_identifiers'),
    ({'allowed_identifiers': ['2001:db8::1']}, 'allowed_identifiers'),
    ({'allowed_identifiers': ['not a name!']}, 'allowed_identifiers'),
    ({'allowed_identifiers': ['*.lab.internal'], 'note': 'x' * 1000}, 'note'),
])
def test_a_refused_eab_key_names_its_field(client, body, field):
    answer = client.post('/api/acme/eab-keys', json=body)
    assert answer.status_code == 400
    assert answer.get_json()['field'] == field, answer.get_json()


def test_a_kid_that_exists_is_about_the_kid_whatever_it_says(client):
    """'ipv6-lab' carries words of the names field's errors; the field is the kid."""
    body = {'kid': 'ipv6-lab', 'allowed_identifiers': ['*.lab.internal']}
    assert client.post('/api/acme/eab-keys', json=body).status_code == 201
    answer = client.post('/api/acme/eab-keys', json=body)
    assert answer.status_code == 409
    assert answer.get_json()['field'] == 'kid'


@pytest.mark.parametrize('body, field', [
    ({'validity_days': 0}, 'validity_days'),
    ({'allowed_identifiers': ['2001:db8::/32']}, 'allowed_identifiers'),
])
def test_a_refused_acme_option_names_its_field(client, body, field):
    answer = client.patch('/api/acme/server', json=body)
    assert answer.status_code == 400
    assert answer.get_json()['field'] == field, answer.get_json()


def test_a_refusal_about_no_field_has_none(client):
    answer = client.patch('/api/acme/server', json={'colour': 'blue'})
    assert answer.status_code == 400
    assert 'field' not in answer.get_json()


SSO = {'enabled': True, 'issuer_url': 'https://idp.example.com/realms/main', 'client_id': 'certmate',
       'scopes': ['openid', 'email'], 'default_role': 'viewer', 'role_mappings': []}


@pytest.mark.parametrize('change, field', [
    ({'issuer_url': ''}, 'issuer_url'),
    ({'issuer_url': 'not a url'}, 'issuer_url'),
    ({'issuer_url': 'http://idp.example.com'}, 'issuer_url'),
    # The link-local refusal does not say "issuer_url" in its text.
    ({'issuer_url': 'https://169.254.169.254/realm'}, 'issuer_url'),
    ({'client_id': ''}, 'client_id'),
    ({'default_role': 'root'}, 'default_role'),
    ({'scopes': ['email']}, 'scopes'),
    ({'scopes': 'openid'}, 'scopes'),
    ({'role_mappings': [{'claim_value': '', 'role': 'admin'}]}, 'role_mappings'),
])
def test_a_refused_sso_save_names_its_field(client, change, field):
    answer = client.post('/api/auth/oidc/settings', json=dict(SSO, **change))
    assert answer.status_code == 400, answer.get_json()
    assert answer.get_json()['field'] == field, answer.get_json()


def test_turning_off_the_only_credential_is_about_the_enable_switch(tmp_path):
    from tests.test_setup_mode_is_a_one_way_door import CONFIGURED_OIDC, _build
    app, _auth = _build(tmp_path, oidc=CONFIGURED_OIDC, local_auth=False)
    answer = app.test_client().post('/api/auth/oidc/settings', json={**CONFIGURED_OIDC, 'enabled': False})
    assert answer.status_code == 409
    assert answer.get_json()['field'] == 'enabled'


@pytest.mark.parametrize('body', [[1], 'x', [], 5])
def test_an_sso_body_that_is_not_an_object_is_refused_with_no_field(client, body):
    """[1] or "x" answered 500 (payload.items()), and [] was read as {} and saved."""
    answer = client.post('/api/auth/oidc/settings', json=body)
    assert answer.status_code == 400, answer.get_data(as_text=True)[:200]
    assert 'field' not in answer.get_json()
