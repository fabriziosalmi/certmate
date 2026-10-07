"""A denial names who was refused, and says nothing that could be used as a credential.

Code scanning has flagged the two log lines a refusal writes more than once:
the role check (`_log_rbac_denial`) and the refusal of what belongs to the whole
instance (`domain_restricted_refusal`). Two of the alerts said the lines log a
password, one that they log a value from the request.

Both are tried here with what the alerts are about: a local user who has a
password, a session, and a key restricted to domains. The formatted lines, in
both log formats, must name the user and must not contain the password, the
stored hash, the session id or the key's token. And a name, a role or a path
with a line break in it must not end the line it is written in, which is what
the first alert was right about: the role check passed its values to the logger
unscrubbed, where the scope denial next to it scrubbed them.
"""
import logging
from unittest.mock import MagicMock

import pytest
from flask import Flask

from modules.core import auth as auth_module
from modules.core.auth import AuthManager, domain_restricted_refusal
from modules.core.structured_logging import PLAIN_DATEFMT, PLAIN_FORMAT, JSONFormatter, PlainLineFormatter

pytestmark = [pytest.mark.unit]

PASSWORD = 'S3cret-Pw0rd!-never-in-a-log'


class _Captured(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.records = []

    def emit(self, record):
        self.records.append(record)

    def lines(self):
        """Every record as each log format writes it, and as the logger holds the message."""
        plain = PlainLineFormatter(PLAIN_FORMAT, PLAIN_DATEFMT)
        structured = JSONFormatter()
        return [text for record in self.records
                for text in (record.getMessage(), plain.format(record), structured.format(record))]


@pytest.fixture
def captured():
    handler = _Captured()
    logger = logging.getLogger(auth_module.__name__)
    previous = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    yield handler
    logger.removeHandler(handler)
    logger.setLevel(previous)


@pytest.fixture
def world():
    settings = {'local_auth_enabled': True, 'users': {}, 'api_keys': {}, 'api_bearer_token': 'legacy_test_token_abc123'}
    manager = MagicMock()
    manager.load_settings.side_effect = lambda: settings
    manager.save_settings.side_effect = lambda s, reason=None: True
    manager.update.side_effect = lambda fn, reason=None: (fn(settings), True)[1]
    auth = AuthManager(manager)
    assert auth.create_user('mallory', PASSWORD, 'viewer')[0]
    return auth, settings, Flask(__name__)


def _secrets_in(lines, secrets):
    return [secret for secret in secrets if any(secret in line for line in lines)]


def test_a_refused_session_is_named_and_its_password_is_nowhere(world, captured):
    auth, settings, app = world
    session = auth.create_session('mallory')

    @auth.require_role('operator')
    def view():
        return {'ok': True}, 200

    with app.test_request_context('/api/x', headers={'Cookie': f'certmate_session={session}'}):
        response = view()

    assert response[1] == 403
    lines = captured.lines()
    assert any('RBAC denial' in line and 'mallory' in line and 'viewer' in line for line in lines), lines
    stored_hash = settings['users']['mallory']['password_hash']
    assert _secrets_in(lines, [PASSWORD, stored_hash, str(session)]) == []


def test_a_refused_restricted_key_is_named_and_its_token_is_nowhere(world, captured):
    auth, _, app = world
    _, created = auth.create_api_key('tenant', role='operator', allowed_domains=['*.team.example'])
    token = created['token']

    @auth.require_role('viewer')
    def view():
        return domain_restricted_refusal(None, 'backup', 'backups')

    with app.test_request_context('/api/backups', headers={'Authorization': f'Bearer {token}'}):
        refusal = view()

    assert refusal is not None
    lines = captured.lines()
    assert any('Scope denial' in line and 'tenant' in line for line in lines), lines
    assert _secrets_in(lines, [token, PASSWORD]) == []


def test_the_secret_check_does_see_a_secret():
    """CONTROL: the two tests above would pass against a check that finds nothing."""
    logger = logging.getLogger('control.denial')
    handler = _Captured()
    logger.addHandler(handler)
    logger.setLevel(logging.WARNING)
    try:
        logger.warning('RBAC denial: user=%s password=%s', 'mallory', PASSWORD)
    finally:
        logger.removeHandler(handler)

    assert _secrets_in(handler.lines(), [PASSWORD]) == [PASSWORD]


@pytest.mark.parametrize('field', ['username', 'role', 'required', 'endpoint'])
def test_no_value_in_a_role_denial_can_end_the_line_it_is_written_in(world, captured, field):
    auth, _, app = world
    forged = 'x\r\n2026-10-07 00:00:00 - modules.core.auth - ERROR - forged record'
    values = {'username': 'mallory', 'role': 'viewer', 'required': 'operator', 'endpoint': '/api/x'}
    values[field] = forged

    with app.test_request_context('/api/x'):
        auth._log_rbac_denial(user={'username': values['username'], 'role': values['role']},
                              required_role=values['required'], endpoint=values['endpoint'])

    assert len(captured.records) == 1
    message = captured.records[0].getMessage()
    assert '\r' not in message and '\n' not in message, repr(message)
    assert 'forged record' in message, 'the value is kept, without its line breaks'
    plain = PlainLineFormatter(PLAIN_FORMAT, PLAIN_DATEFMT).format(captured.records[0])
    assert '\n' not in plain


def test_a_clean_value_is_written_as_it_is(world, captured):
    """CONTROL: scrubbing changes only what has a line break in it."""
    auth, _, app = world

    with app.test_request_context('/api/x'):
        auth._log_rbac_denial(user={'username': 'mallory', 'role': 'viewer'},
                              required_role='operator', endpoint='/api/certificates')

    assert captured.records[0].getMessage() == (
        'RBAC denial: user=mallory role=viewer required=operator endpoint=/api/certificates ip=None')
