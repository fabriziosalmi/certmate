"""The settings page offers a backup that can restore the instance, when backups are encrypted.

Found by the UX audit of 2026-11-17: every backup made from the page was a
masked one ("cannot restore"), because the page never sent include_secrets,
while the page said "Backups contain sensitive data (private keys, tokens)",
which is false for those archives. Decided on 2026-11-17: offer a complete,
restorable backup from the page only when CERTMATE_BACKUP_PASSPHRASE is set,
so it is encrypted at rest; otherwise say what the backups hold and how to
make complete ones.

Through the real application with its bearer token.
"""
import secrets
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit]

PASSPHRASE = 'correct horse battery staple 2026'
CHECKOUT = Path(__file__).resolve().parent.parent


@pytest.fixture
def instance(tmp_path, monkeypatch):
    """The real app, anchored in tmp_path with the checkout's pages linked in."""
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
    monkeypatch.delenv('CERTMATE_BACKUP_PASSPHRASE', raising=False)
    app, _container = create_app()
    client = app.test_client()
    client.environ_base['HTTP_AUTHORIZATION'] = f'Bearer {token}'
    return client, monkeypatch


def _page(client):
    answer = client.get('/settings')
    assert answer.status_code == 200, answer.status_code
    return answer.get_data(as_text=True)


def test_without_a_passphrase_the_page_says_what_backups_hold(instance):
    client, _ = instance
    page = _page(client)
    assert 'id="backupIncludeSecrets"' not in page
    assert 'cannot restore' in page and 'CERTMATE_BACKUP_PASSPHRASE' in page
    assert 'Backups contain sensitive data (private keys, tokens)' not in page


def test_with_a_passphrase_the_page_offers_a_complete_backup(instance):
    client, monkeypatch = instance
    monkeypatch.setenv('CERTMATE_BACKUP_PASSPHRASE', PASSPHRASE)
    page = _page(client)
    assert 'id="backupIncludeSecrets"' in page
    box = page[page.index('id="backupIncludeSecrets"') - 200:page.index('id="backupIncludeSecrets"') + 200]
    assert 'checked' in box


def test_the_backup_the_page_asks_for_is_encrypted_and_can_restore(instance):
    """What the box sends, include_secrets, with the passphrase set."""
    client, monkeypatch = instance
    monkeypatch.setenv('CERTMATE_BACKUP_PASSPHRASE', PASSPHRASE)
    made = client.post('/api/backups/create', json={
        'type': 'unified', 'reason': 'manual_backup', 'include_secrets': True})
    assert made.status_code in (200, 201), made.get_json()

    listed = client.get('/api/backups').get_json()['unified'][0]
    assert listed['filename'].endswith('.enc'), listed['filename']
    assert listed.get('can_restore') is True, listed


def test_a_masked_backup_still_cannot_restore(instance):
    """CONTROL: without the box (no passphrase), the archive is the masked one."""
    client, _ = instance
    made = client.post('/api/backups/create', json={'type': 'unified', 'reason': 'manual_backup',
                                                    'include_secrets': False})
    assert made.status_code in (200, 201), made.get_json()
    listed = client.get('/api/backups').get_json()['unified'][0]
    assert listed.get('can_restore') is False, listed
