"""A hook test is recorded with its outcome, and a refused hook says what was refused.

Found by the #1511 perception audit.

P41: the Test button writes a `test` entry to Activity, and that entry was
always `success`, written before anyone looked at the result: a test that ran
and exited 1, and a test of a hook that was not in settings at all (a 404),
were both logged as successes.

P40: a save refused by the command guard said only "contains dangerous shell
metacharacters", so the operator had to find the `;` themselves among the
characters the page lists, and nothing pointed at the field. The refusal now
names what it found, and the answer carries the hook's id and the field so the
page can mark it.

The real application, through the real routes.
"""
import secrets
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit]

CHECKOUT = Path(__file__).resolve().parent.parent


@pytest.fixture
def client(tmp_path, monkeypatch):
    from modules.factory import create_app
    root = tmp_path / 'certmate' / 'modules' / 'core'
    root.mkdir(parents=True)
    (root / 'factory.py').write_text('# anchor\n')
    for name in ('templates', 'static'):
        (root.parent / name).symlink_to(CHECKOUT / name, target_is_directory=True)
    monkeypatch.setattr('modules.factory.__file__', str(root / 'factory.py'))
    token = secrets.token_urlsafe(32)
    monkeypatch.setenv('FLASK_ENV', 'testing')
    monkeypatch.setenv('TESTING', 'true')
    monkeypatch.setenv('API_BEARER_TOKEN', token)
    app, _container = create_app()
    client = app.test_client()
    client.environ_base['HTTP_AUTHORIZATION'] = f'Bearer {token}'
    return client


def _save(client, *commands):
    hooks = [{'id': f'hook-{n}', 'name': f'hook {n}', 'command': command,
              'enabled': True, 'timeout': 10, 'on_events': ['renewed']}
             for n, command in enumerate(commands)]
    return client.post('/api/deploy/config', json={
        'enabled': True, 'global_hooks': hooks, 'domain_hooks': {}})


def _tests_recorded(client):
    answer = client.get('/api/activity', query_string={'operation': 'test', 'limit': 50})
    assert answer.status_code == 200
    return answer.get_json()['entries']


def test_a_hook_test_that_fails_is_recorded_as_a_failure(client):
    assert _save(client, 'exit 1').status_code == 200
    ran = client.post('/api/deploy/test/hook-0', json={})
    assert ran.status_code == 200 and ran.get_json()['success'] is False

    tests = _tests_recorded(client)
    assert len(tests) == 1, tests
    assert tests[0]['status'] == 'failure', (
        f'a test that exited 1 is recorded as {tests[0]["status"]}')
    assert 'exit code 1' in (tests[0]['error'] or ''), tests[0]


def test_testing_a_hook_that_is_not_in_settings_is_recorded_as_a_failure(client):
    answer = client.post('/api/deploy/test/never-saved', json={})
    assert answer.status_code == 404

    tests = _tests_recorded(client)
    assert len(tests) == 1, tests
    assert tests[0]['status'] == 'failure', tests[0]
    assert 'not in settings' in (tests[0]['error'] or ''), tests[0]


def test_a_hook_test_that_passes_is_recorded_as_a_success(client):
    """CONTROL: a guard that recorded every test as failed would pass the two
    tests above."""
    assert _save(client, 'true').status_code == 200
    ran = client.post('/api/deploy/test/hook-0', json={})
    assert ran.status_code == 200 and ran.get_json()['success'] is True

    tests = _tests_recorded(client)
    assert [t['status'] for t in tests] == ['success'], tests
    assert tests[0]['error'] is None


@pytest.mark.parametrize('command, named', [
    ('echo a; echo b', "';'"),
    ('make && make install', "'&&'"),
    ('echo $(id)', "'$('"),
    ('cat x > /etc/passwd', "'> /'"),
    ('eval ls', "'eval'"),
])
def test_a_refused_save_names_what_it_refused_and_which_hook(client, command, named):
    answer = _save(client, 'echo fine', command)
    assert answer.status_code == 400
    body = answer.get_json()
    assert named in body['error'], f'the refusal does not name {named}: {body["error"]}'
    assert body.get('hook_id') == 'hook-1', body
    assert body.get('field') == 'command', body


def test_a_line_break_is_named_in_words(client):
    body = _save(client, 'echo a\necho b').get_json()
    assert 'a line break' in body['error'], body['error']
    assert body.get('hook_id') == 'hook-0'


def test_a_save_that_is_accepted_names_no_hook(client):
    """CONTROL: the id is the hook that was refused, not any hook."""
    answer = _save(client, 'echo fine')
    assert answer.status_code == 200
    assert 'hook_id' not in answer.get_json()


def test_the_refusal_reads_the_same_in_the_log():
    """The reason goes into a log line through the logging sanitiser, which
    redacts the word after a "secret-ish name:" shape. The reason must survive
    it whole."""
    from modules.core.deployer import DeployManager
    from modules.core.structured_logging import sanitize_text
    safe, reason = DeployManager._is_command_safe('echo a; echo b')
    assert safe is False
    message = f"Deploy hook 'reload' command rejected: {reason}"
    assert sanitize_text(message) == message


@pytest.mark.parametrize('command, shown', [
    ('cat x >\n/etc/passwd', r"'>\n/'"),
    ('cat x >\t/etc/passwd', r"'>\t/'"),
])
def test_a_control_character_in_what_is_named_is_shown_not_sent(client, command, shown):
    """The named sequence goes into a toast and a log line: a raw line break
    in it would break both."""
    body = _save(client, command).get_json()
    assert shown in body['error'], body['error']
    assert '\n' not in body['error'] and '\t' not in body['error']


def test_a_refusal_that_is_not_a_hook_names_no_hook(client):
    """`enabled` is checked before the hooks: the answer must not point at a
    hook while its error is about something else."""
    hooks = [{'id': 'bad', 'name': 'bad', 'command': 'echo a; echo b', 'enabled': True}]
    answer = client.post('/api/deploy/config', json={
        'enabled': 'yes', 'global_hooks': hooks, 'domain_hooks': {}})
    assert answer.status_code == 400
    body = answer.get_json()
    assert 'enabled' in body['error'], body
    assert 'hook_id' not in body, body
