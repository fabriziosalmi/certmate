"""First-class notification channels: Telegram, ntfy, Gotify.

These ride the existing webhooks framework (per-type formatting in
_send_webhook). The tests capture the actual urllib Request so a wrong
URL/body/header — which would silently fail to deliver — breaks the build.
"""
import json
from unittest.mock import MagicMock, patch

import pytest

from modules.core.notifier import Notifier

pytestmark = [pytest.mark.unit]


class _Resp:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _notifier(tmp_path):
    return Notifier(settings_manager=MagicMock(), data_dir=str(tmp_path))


def _send(n, cfg):
    cap = {}

    def fake_urlopen(req, timeout=None):
        cap['url'] = req.full_url
        cap['data'] = req.data
        cap['headers'] = {k.lower(): v for k, v in req.header_items()}
        return _Resp()

    with patch('modules.core.notifier.urlopen', side_effect=fake_urlopen):
        res = n._send_webhook(cfg, 'renewal_failed', 'Cert expiring',
                              'example.com expires in 3 days', {'domain': 'example.com'})
    return res, cap


def test_telegram_uses_bot_api_url_and_body(tmp_path):
    res, cap = _send(_notifier(tmp_path),
                     {'type': 'telegram', 'token': 'BOTTOK', 'chat_id': '12345'})
    assert res.get('success')
    assert cap['url'] == 'https://api.telegram.org/botBOTTOK/sendMessage'
    payload = json.loads(cap['data'])
    assert payload['chat_id'] == '12345'
    # Plain text, no parse_mode (see test_telegram_sends_plain_text_no_markdown_parsing)
    assert 'parse_mode' not in payload
    # Assert on the whole title + message lines. A bare-host substring check
    # ('example.com' in ...) trips CodeQL's url-sanitization heuristic — a false
    # positive in a content assertion — and the full-line check is stronger.
    assert 'Cert expiring' in payload['text']
    assert 'example.com expires in 3 days' in payload['text']


def test_telegram_requires_token_and_chat_id(tmp_path):
    res, _ = _send(_notifier(tmp_path), {'type': 'telegram', 'token': 'X'})  # no chat_id
    assert 'error' in res and 'chat_id' in res['error']


def test_ntfy_posts_to_topic_with_title_and_priority(tmp_path):
    res, cap = _send(_notifier(tmp_path),
                     {'type': 'ntfy', 'url': 'https://ntfy.sh/certmate', 'priority': 'high'})
    assert res.get('success')
    assert cap['url'] == 'https://ntfy.sh/certmate'
    assert b'example.com expires in 3 days' in cap['data']
    assert cap['headers']['title'] == 'Cert expiring'
    assert cap['headers']['priority'] == 'high'


def test_ntfy_optional_token_sets_bearer_auth(tmp_path):
    _, cap = _send(_notifier(tmp_path),
                   {'type': 'ntfy', 'url': 'https://ntfy.example/t', 'token': 'tk_secret'})
    assert cap['headers']['authorization'] == 'Bearer tk_secret'


def test_gotify_posts_to_message_endpoint_with_key(tmp_path):
    res, cap = _send(_notifier(tmp_path),
                     {'type': 'gotify', 'url': 'https://gotify.example/', 'token': 'GTOK', 'priority': 8})
    assert res.get('success')
    assert cap['url'] == 'https://gotify.example/message'
    assert cap['headers']['x-gotify-key'] == 'GTOK'
    payload = json.loads(cap['data'])
    assert payload['title'] == 'Cert expiring'
    assert payload['priority'] == 8


def test_gotify_requires_url_and_token(tmp_path):
    res, _ = _send(_notifier(tmp_path), {'type': 'gotify', 'url': 'https://g.example'})  # no token
    assert 'error' in res and 'token' in res['error']


def test_existing_slack_discord_generic_unchanged(tmp_path):
    n = _notifier(tmp_path)
    _, slack = _send(n, {'type': 'slack', 'url': 'https://hooks.slack.com/x'})
    assert 'blocks' in json.loads(slack['data'])
    _, discord = _send(n, {'type': 'discord', 'url': 'https://discord.com/api/webhooks/x'})
    assert json.loads(discord['data']).get('embeds')
    # generic still signs with HMAC and applies custom headers
    _, generic = _send(n, {'type': 'generic', 'url': 'https://x.example',
                           'secret': 's3cr3t', 'headers': {'X-Env': 'prod'}})
    assert generic['headers'].get('x-certmate-signature')
    assert generic['headers'].get('x-env') == 'prod'


def test_telegram_sends_plain_text_no_markdown_parsing(tmp_path):
    # Failure events carry '_acme-challenge', '*.example.com', backticks etc.
    # parse_mode=Markdown would make the Bot API reject the message with HTTP 400
    # "can't parse entities" and silently drop the alert, so the request must NOT
    # set parse_mode and must carry the raw text verbatim.
    n = _notifier(tmp_path)
    cap = {}

    def fake_urlopen(req, timeout=None):
        cap['data'] = req.data
        return _Resp()

    nasty_title = 'Renewal failed for *.example.com'
    nasty_msg = 'DNS problem: NXDOMAIN looking up TXT for _acme-challenge.example.com'
    with patch('modules.core.notifier.urlopen', side_effect=fake_urlopen):
        res = n._send_webhook({'type': 'telegram', 'token': 'T', 'chat_id': '1'},
                              'certificate_failed', nasty_title, nasty_msg,
                              {'error': 'see `certbot` log [details]'})
    assert res.get('success')
    payload = json.loads(cap['data'])
    assert 'parse_mode' not in payload            # no Markdown parsing -> no 400
    assert nasty_title in payload['text']          # raw content preserved verbatim
    assert '_acme-challenge.example.com' in payload['text']
