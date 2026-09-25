"""Google Chat cards use the existing webhook delivery and secret handling."""

import json
from unittest.mock import MagicMock, patch

import pytest

from modules.core.notifier import Notifier, google_chat_card, validate_webhook_config
from modules.core.settings import SECRET_MASK_SENTINEL, _restore_masked_list_secrets, mask_secrets_in_settings
from modules.web.misc_routes import _unmasked_test_config


pytestmark = pytest.mark.unit

CHAT_URL = 'https://chat.googleapis.com/v1/spaces/SPACE/messages?key=example-key&token=example-token'
CERTMATE_URL = 'https://certmate.example.com'


class Response:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def test_google_chat_sends_only_one_card_with_certmate_buttons(tmp_path):
    notifier = Notifier(MagicMock(), data_dir=str(tmp_path))
    sent = []
    with patch('modules.core.notifier.urlopen', side_effect=lambda req, timeout: sent.append(req) or Response()), \
         patch('modules.core.notifier._webhook_url_is_internal', return_value=False):
        result = notifier._send_webhook(
            {'type': 'google_chat', 'name': 'Operations', 'url': CHAT_URL,
             'certmate_url': CERTMATE_URL + '/'},
            'certificate_expiring', 'Certificate Expiring', 'Expires in 3 days',
            {'domain': 'example.com', 'days_left': 3})

    assert result == {'success': True, 'status': 200}
    request = sent[0]
    assert request.full_url == CHAT_URL
    assert request.get_method() == 'POST'
    assert request.get_header('Content-type') == 'application/json'
    body = json.loads(request.data)
    assert 'text' not in body  # A separate top-level text shows as a second notification.
    card = body['cardsV2'][0]
    assert card['cardId'] == 'certmate-notification'
    assert card['card']['header']['title'] == '⚠️ Certificate Expiring'
    assert card['card']['header']['subtitle'] == 'CertMate · Certificate Expiring'
    sections = card['card']['sections']
    assert sections[0]['widgets'][0]['textParagraph']['text'] == 'Expires in 3 days'
    assert sections[1]['header'] == 'Details'
    assert sections[1]['widgets'] == [
        {'decoratedText': {'topLabel': 'domain', 'text': 'example.com'}},
        {'decoratedText': {'topLabel': 'days_left', 'text': '3'}},
    ]
    assert sections[2]['widgets'][0]['buttonList']['buttons'] == [
        {'text': 'View certificate', 'onClick': {'openLink': {
            'url': CERTMATE_URL + '/?cert=example.com'}}},
        {'text': 'Open CertMate', 'onClick': {'openLink': {
            'url': CERTMATE_URL + '/'}}},
    ]


def test_google_chat_can_send_a_card_without_certmate_url_or_buttons(tmp_path):
    notifier = Notifier(MagicMock(), data_dir=str(tmp_path))
    sent = []
    with patch('modules.core.notifier.urlopen', side_effect=lambda req, timeout: sent.append(req) or Response()), \
         patch('modules.core.notifier._webhook_url_is_internal', return_value=False):
        result = notifier.test_channel('webhook', {'type': 'google_chat', 'url': CHAT_URL})
    assert result['success'] is True
    body = json.loads(sent[0].data)
    assert 'text' not in body
    assert body['cardsV2'][0]['card']['header']['title'] == '✅ Test Notification'
    assert not any('buttonList' in widget for section in body['cardsV2'][0]['card']['sections']
                   for widget in section['widgets'])


def test_google_chat_escapes_card_html_and_bounds_size():
    card = google_chat_card('certificate_failed', 'Issuance failed', '<script>alert(1)</script>', {
        'error': '<b>error</b>', 'long': 'x' * 100_000,
    }, certmate_url=CERTMATE_URL)
    sections = card['cardsV2'][0]['card']['sections']
    assert sections[0]['widgets'][0]['textParagraph']['text'] == '&lt;script&gt;alert(1)&lt;/script&gt;'
    assert sections[1]['widgets'][0]['decoratedText']['text'] == '&lt;b&gt;error&lt;/b&gt;'
    assert len(sections[1]['widgets'][1]['decoratedText']['text']) == 200
    assert len(json.dumps(card, ensure_ascii=False).encode()) < 32_000
    escaped = google_chat_card('certificate_failed', '&' * 200, '&' * 100_000,
                               {f'{i}' + '&' * 100: '&' * 100_000 for i in range(12)},
                               certmate_url=CERTMATE_URL)
    assert len(json.dumps(escaped, ensure_ascii=False).encode()) < 32_000


def test_google_chat_card_fits_chats_message_limit_with_unicode():
    card = google_chat_card('certificate_failed', '🚨' * 200, '🚨' * 100_000,
                            {f'{i}' + '🚨' * 100: '🚨' * 100_000 for i in range(12)},
                            certmate_url=CERTMATE_URL)
    assert len(json.dumps(card, ensure_ascii=False).encode()) < 32_000


def test_buttons_encode_domain_and_omit_certificate_link_for_other_events():
    card = google_chat_card('certificate_created', 'Created', 'Ready',
                            {'domain': '*.example.com'}, certmate_url=CERTMATE_URL + '/certmate')
    buttons = card['cardsV2'][0]['card']['sections'][-1]['widgets'][0]['buttonList']['buttons']
    assert buttons[0]['onClick']['openLink']['url'] == CERTMATE_URL + '/certmate/?cert=%2A.example.com'
    other = google_chat_card('domain_expiring', 'Domain expiry', 'Registration expiring',
                             {'domain': 'example.com'}, certmate_url=CERTMATE_URL)
    buttons = other['cardsV2'][0]['card']['sections'][-1]['widgets'][0]['buttonList']['buttons']
    assert [button['text'] for button in buttons] == ['Open CertMate']


@pytest.mark.parametrize('url', [
    'http://chat.googleapis.com/v1/spaces/x/messages?key=k&token=t',
    'https://chat.googleapis.com.evil.example/v1/spaces/x/messages?key=k&token=t',
    'https://hooks.slack.com/services/example',
])
def test_google_chat_refuses_other_webhook_targets_without_sending(tmp_path, url):
    notifier = Notifier(MagicMock(), data_dir=str(tmp_path))
    assert 'Google Chat' in validate_webhook_config({
        'type': 'google_chat', 'url': url, 'certmate_url': CERTMATE_URL})
    with patch('modules.core.notifier.urlopen') as send:
        result = notifier.test_channel('webhook', {'type': 'google_chat', 'url': url,
                                                   'certmate_url': CERTMATE_URL})
    assert result['config_error'] is True
    assert 'Google Chat' in result['error']
    assert 'token=' not in result['error']
    send.assert_not_called()


@pytest.mark.parametrize('base', [
    'http://certmate.example.com', 'javascript:alert(1)',
    'https://certmate.example.com/?next=evil',
    'https://user:secret@certmate.example.com',
])
def test_google_chat_needs_a_safe_certmate_url_for_buttons(tmp_path, base):
    notifier = Notifier(MagicMock(), data_dir=str(tmp_path))
    assert 'CertMate URL' in validate_webhook_config({
        'type': 'google_chat', 'url': CHAT_URL, 'certmate_url': base})
    with patch('modules.core.notifier.urlopen') as send:
        result = notifier.test_channel('webhook', {
            'type': 'google_chat', 'url': CHAT_URL, 'certmate_url': base})
    assert result['config_error'] is True
    assert 'CertMate URL' in result['error']
    assert 'secret' not in result['error']
    send.assert_not_called()


def test_masked_chat_url_survives_save_and_test_without_cross_leak(tmp_path):
    saved = [{'type': 'google_chat', 'name': 'prod', 'enabled': True, 'url': CHAT_URL,
              'certmate_url': CERTMATE_URL},
             {'type': 'google_chat', 'name': 'dev', 'enabled': True,
              'url': 'https://chat.googleapis.com/v1/spaces/DEV/messages?key=dev&token=dev',
              'certmate_url': CERTMATE_URL}]
    settings = {'notifications': {'channels': {'webhooks': saved}}}
    masked = mask_secrets_in_settings(settings)['notifications']['channels']['webhooks']
    assert masked[0]['url'] == masked[1]['url'] == SECRET_MASK_SENTINEL
    updated = [dict(masked[0], enabled=False), dict(masked[1])]
    _restore_masked_list_secrets(saved, updated)
    assert updated[0]['url'] == CHAT_URL
    assert updated[1]['url'] == saved[1]['url']

    manager = MagicMock()
    manager.load_settings.return_value = settings
    restored = _unmasked_test_config(manager, 'webhook', masked[0])
    assert restored['url'] == CHAT_URL
    notifier = Notifier(manager, data_dir=str(tmp_path))
    with patch('modules.core.notifier.urlopen', return_value=Response()) as send, \
         patch('modules.core.notifier._webhook_url_is_internal', return_value=False):
        assert notifier.test_channel('webhook', restored)['success']
    assert send.call_args.args[0].full_url == CHAT_URL


def test_google_chat_uses_existing_event_filter_and_delivery_log(tmp_path):
    manager = MagicMock()
    manager.load_settings.return_value = {'notifications': {
        'enabled': True,
        'channels': {'webhooks': [{'name': 'prod', 'type': 'google_chat', 'enabled': True,
                                   'events': ['certificate_renewed'], 'url': CHAT_URL,
                                   'certmate_url': CERTMATE_URL}]},
    }}
    notifier = Notifier(manager, data_dir=str(tmp_path))
    with patch('modules.core.notifier.urlopen', return_value=Response()) as send, \
         patch('modules.core.notifier._webhook_url_is_internal', return_value=False):
        assert notifier.notify('certificate_created', 'Created', 'example.com') == {}
        result = notifier.notify('certificate_renewed', 'Renewed', 'example.com',
                                 {'domain': 'example.com'})
    assert result['prod']['success'] is True
    assert send.call_count == 1
    delivery = notifier.get_deliveries()[0]
    assert delivery['webhook_type'] == 'google_chat'
    assert delivery['url'] == 'https://chat.googleapis.com'
    assert 'example-token' not in json.dumps(delivery)
