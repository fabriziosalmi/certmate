"""`POST /api/inventory/config` applies a request entirely or not at all (#1109).

The body may carry five sections (discovery, CT monitoring, domain registration, domain health,
the DNS resolver). Each is validated and saved by its own manager, one after the other, and the
route answered 400 for the first one that refused AFTER having saved the ones before it:

    {"ct_monitoring": {"domains": ["ct.example.test"]},
     "domain_registration": {"extra_domains": ["example.test"]}}
    -> 400, and ct_monitoring.domains had changed.

A 400 tells a client nothing was applied, and a client that retries with the bad section fixed
cannot know which sections it already changed. The matrix below is every pair of sections, one
valid and one refused, in both orders the route can meet them: each has to leave the
configuration exactly as it was.

The same functions raised TypeError for a body that was malformed in another way (`null` where a
number goes, a number where a list goes), which is a 500 for a request the caller got wrong.
"""
import itertools

import pytest

from modules.core.request_fields import json_list, json_number
from tests import contract_support as support

pytestmark = [pytest.mark.unit]

VALID = {
    'discovery': {'enabled': False, 'endpoints': ['valid.example.com:443']},
    'ct_monitoring': {'domains': ['ct.example.com']},
    'domain_registration': {'extra_domains': ['example.com']},
    'domain_health': {'extra_domains': ['example.com']},
    'dns_resolver': {'nameservers': ['192.0.2.53']},
}
REFUSED = {
    'discovery': {'endpoints': [':']},
    'ct_monitoring': {'max_new_per_run': 'many'},
    'domain_registration': {'extra_domains': ['example.test']},      # no public suffix
    'domain_health': {'extra_domains': ['not a domain']},
    'dns_resolver': {'nameservers': ['not-an-ip']},
}
# Where each section lives in the settings, so a test can put the instance back as it was.
SETTINGS_KEYS = ('monitored_endpoints', 'ct_monitoring', 'domain_registration', 'domain_health', 'dns_resolver')


@pytest.fixture(scope='module')
def instance():
    app, token = support.build_app()
    container = app.extensions['certmate_container']
    client = app.test_client()
    headers = {'Authorization': f'Bearer {token}'}

    class Instance:
        settings = container.managers['settings']
        managers = container.managers

        @staticmethod
        def post(body):
            container.managers['rate_limiter'].requests.clear()
            return client.post('/api/inventory/config', json=body, headers=headers)

        @staticmethod
        def config():
            container.managers['rate_limiter'].requests.clear()
            return client.get('/api/inventory/config', headers=headers).get_json()

        @staticmethod
        def reset():
            def forget(settings):
                for key in SETTINGS_KEYS:
                    settings.pop(key, None)
            Instance.settings.update(forget, 'test_reset')

    return Instance


@pytest.fixture(autouse=True)
def fresh(instance):
    instance.reset()
    yield
    instance.reset()


@pytest.mark.parametrize('good, bad', list(itertools.permutations(VALID, 2)),
                         ids=lambda name: name)
def test_a_refused_section_leaves_the_sections_that_were_valid_unsaved(instance, good, bad):
    before = instance.config()
    response = instance.post({good: VALID[good], bad: REFUSED[bad]})
    assert response.status_code == 400, response.get_json()
    assert instance.config() == before, (
        f'a 400 for {bad} changed the configuration: the valid {good} section was saved')


def test_the_reproduction_in_the_issue(instance):
    response = instance.post({'ct_monitoring': {'domains': ['ct.example.test']},
                              'domain_registration': {'extra_domains': ['example.test']}})
    assert response.status_code == 400
    assert instance.config()['ct_monitoring']['domains'] == []


def test_a_request_whose_sections_are_all_valid_saves_all_of_them(instance):
    response = instance.post(VALID)
    assert response.status_code == 200, response.get_json()
    config = instance.config()
    assert config['discovery']['endpoints'] == ['valid.example.com:443']
    assert config['ct_monitoring']['domains'] == ['ct.example.com']
    assert config['domain_registration']['extra_domains'] == ['example.com']
    assert config['domain_health']['extra_domains'] == ['example.com']
    assert config['dns_resolver']['nameservers'] == ['192.0.2.53']
    assert response.get_json() == config, 'the answer is the effective configuration'


def test_sections_the_request_does_not_carry_are_left_alone(instance):
    instance.post({'ct_monitoring': {'domains': ['kept.example.com']}})
    response = instance.post({'domain_health': {'extra_domains': ['other.example.com']}})
    assert response.status_code == 200
    assert instance.config()['ct_monitoring']['domains'] == ['kept.example.com']


@pytest.mark.parametrize('section, body', [
    ('ct_monitoring', {'max_new_per_run': None}),
    ('ct_monitoring', {'min_request_interval': None}),
    ('ct_monitoring', {'domains': 5}),
    ('ct_monitoring', {'domains': 'ct.example.com'}),
    ('discovery', {'endpoints': 5}),
    ('discovery', {'endpoints': 'host:443'}),
    ('domain_registration', {'extra_domains': 5}),
    ('domain_health', {'extra_domains': 'a.example.com'}),
], ids=lambda value: str(value))
def test_a_body_that_is_malformed_is_a_400_and_never_a_500(instance, section, body):
    before = instance.config()
    response = instance.post({section: body})
    assert response.status_code == 400, (response.status_code, response.get_json())
    assert 'must be' in response.get_json()['error']
    assert instance.config() == before


def test_checking_a_section_writes_nothing(instance):
    """`clean_config` is the validation `save_config` runs, without the write: the route calls it
    for every section before it saves any, so it must be free of side effects."""
    before = dict(instance.settings.load_settings())
    for name, section in (('cert_discovery', 'discovery'), ('ct_monitor', 'ct_monitoring'),
                          ('domain_registration', 'domain_registration'), ('domain_health', 'domain_health')):
        assert instance.managers[name].clean_config(VALID[section])
    assert dict(instance.settings.load_settings()) == before


# --- the helpers ---------------------------------------------------------------

@pytest.mark.parametrize('value, expected', [
    (None, []), ([], []), ('', []), (0, []), (['a', 'b'], ['a', 'b']), (('a',), ['a']),
])
def test_a_list_field_is_a_list(value, expected):
    assert json_list({'f': value}, 'f') == expected
    assert json_list({}, 'f') == []


@pytest.mark.parametrize('value', [5, 'a', {'a': 1}, True])
def test_a_list_field_that_is_not_a_list_is_refused_by_name(value):
    with pytest.raises(ValueError, match='f must be a list'):
        json_list({'f': value}, 'f')


@pytest.mark.parametrize('value, cast, expected', [
    (5, int, 5), ('5', int, 5), (2.5, float, 2.5), (3, float, 3.0), ('0.5', float, 0.5),
])
def test_a_number_field_is_a_number(value, cast, expected):
    assert json_number({'f': value}, 'f', 1, cast) == expected


def test_a_number_field_that_is_absent_takes_its_default():
    assert json_number({}, 'f', 100, int) == 100


@pytest.mark.parametrize('value', [None, 'many', [], {}, '5.5x'])
def test_a_number_field_that_is_not_a_number_is_refused_by_name(value):
    with pytest.raises(ValueError, match='f must be a number'):
        json_number({'f': value}, 'f', 1, int)
