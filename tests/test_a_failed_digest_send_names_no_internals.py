"""A digest that fails to send says so, and not with the exception's text.

POST /api/digest/send answered a failure with str(e), which can carry a
filesystem path or what a mail server said. The text goes to the log.
"""
import pytest

from tests import contract_support

pytestmark = [pytest.mark.unit]


def test_the_answer_carries_no_exception_text(monkeypatch):
    app, token = contract_support.build_app()
    digest = app.extensions['certmate_container'].managers['digest']

    def fail():
        raise RuntimeError('cannot open /app/data/internal/mail.cfg')
    monkeypatch.setattr(digest, 'send', fail)
    answer = app.test_client().post('/api/digest/send', headers={'Authorization': f'Bearer {token}'})
    assert answer.status_code == 500
    assert answer.get_json() == {'success': False, 'error': 'Failed to send the digest'}
