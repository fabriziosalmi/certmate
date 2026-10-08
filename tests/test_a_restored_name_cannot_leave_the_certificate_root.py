"""A name that is a path, arriving by a restore, does not make the application read or remove what is outside its root.

`settings.json` holds the names of the certificates the instance manages, and a restore
writes the archive's `settings.json` over the one on disk. The routes validate the name they
are given, and so do the entry points of the certificate manager, but a name that is already
in the settings is not given by a route: the listing, the renewal sweep and the dashboard read
it from there. This is the whole path, on the real application: an archive whose settings
name a directory beside the certificate root is restored through the route, and then every
place that reads the settings is asked what it knows. A directory next to the root holds a
certificate and a key; none of them may appear in an answer, and the directory must be as it
was.
"""
import hashlib
import json
import os
import secrets
import sys
import urllib.parse
import zipfile
from unittest import mock

import pytest

from tests.contract_world import sealed, write_certificate

pytestmark = [pytest.mark.unit]

# The audit hook is process-wide and cannot be removed; it watches only while `WATCH` holds a root.
WATCH = {'root': None, 'seen': []}
TOUCHING = {'open', 'os.remove', 'os.rmdir', 'os.rename', 'os.listdir', 'os.scandir', 'shutil.rmtree', 'os.mkdir'}


def _watch(event, arguments):
    root = WATCH['root']
    if root is None or event not in TOUCHING or not arguments:
        return
    target = arguments[0]
    if isinstance(target, (str, bytes, os.PathLike)):
        try:
            path = os.path.realpath(os.fsdecode(target))
        except (ValueError, OSError):
            return
        if path == root or path.startswith(root + os.sep):
            WATCH['seen'].append((event, path))


sys.addaudithook(_watch)

HOSTILE = ['../outside', '../../outside', 'sub/../../outside', '/etc', 'name\nwith-a-break']


def _tree(path):
    return {str(p.relative_to(path)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(path.rglob('*')) if p.is_file()}


@pytest.fixture(scope='module')
def restored(tmp_path_factory):
    tmp = tmp_path_factory.mktemp('restored-names')
    token = secrets.token_urlsafe(32)
    with pytest.MonkeyPatch.context() as patch:
        for var, sub in (('CERTMATE_CERT_DIR', 'certs'), ('CERTMATE_DATA_DIR', 'data'),
                         ('CERTMATE_BACKUP_DIR', 'backups'), ('CERTMATE_LOGS_DIR', 'logs')):
            (tmp / sub).mkdir(exist_ok=True)
            patch.setenv(var, str(tmp / sub))
        patch.setenv('FLASK_ENV', 'testing')
        patch.setenv('TESTING', 'true')
        patch.setenv('API_BEARER_TOKEN', token)
        os.environ['API_BEARER_TOKEN'] = token
        from modules.factory import create_app
        app, container = create_app()
        outside = tmp / 'outside'
        write_certificate(outside, 'outside.example.test')
        (outside / 'metadata.json').write_text(json.dumps({'domain': 'outside.example.test', 'dns_provider': 'cloudflare'}))
        write_certificate(tmp / 'certs' / 'mine.example.test', 'mine.example.test')
        settings = container.managers['settings']
        current = settings.load_settings()
        current['domains'] = [{'domain': 'mine.example.test', 'dns_provider': 'cloudflare'}]
        settings.save_settings(current)
        client = app.test_client()
        headers = {'Authorization': f'Bearer {token}'}
        made = client.post('/api/backups/create', headers=headers, json={'type': 'unified', 'include_secrets': True})
        assert made.status_code in (200, 201), made.get_json()
        filename = made.get_json()['backups'][0]['filename']
        archive = next((tmp / 'backups').rglob(filename))
        # The archive, as a hostile one would carry its settings.
        members = {}
        with zipfile.ZipFile(archive) as z:
            for info in z.infolist():
                members[info.filename] = z.read(info.filename)
        print('MEMBERS', [m for m in members if 'settings' in m or 'metadata' in m])
        hostile = json.loads(members['settings.json'])
        # Each hostile name twice: as an entry of the current shape and as a bare string, the old one.
        as_entries = [{'domain': name, 'dns_provider': 'cloudflare'} for name in HOSTILE]
        kept = [{'domain': 'extra.example.test', 'dns_provider': 'cloudflare'},
                {'domain': 'mine.example.test', 'dns_provider': 'cloudflare'}]
        hostile['settings']['domains'] = as_entries + list(HOSTILE) + kept
        members['settings.json'] = json.dumps(hostile).encode()
        with zipfile.ZipFile(archive, 'w') as z:
            for name, content in members.items():
                z.writestr(name, content)
        before = _tree(outside)
        answer = client.post('/api/backups/restore/unified', headers=headers, json={'filename': filename})
        yield client, headers, container, tmp, outside, before, answer


def _everything_that_reads_the_settings(client, headers, container):
    """Every reader of the restored names that can be reached without issuing anything."""
    answers = []
    for path in ('/api/certificates', '/api/web/certificates', '/api/inventory', '/metrics', '/', '/settings',
                 '/api/web/settings', '/api/cache/stats', '/api/backups', '/api/activity'):
        answers.append((path, client.get(path, headers=headers)))
    for name in HOSTILE:
        quoted = urllib.parse.quote(name, safe='')
        for path in (f'/api/certificates/{quoted}', f'/api/certificates/{quoted}/download/privkey',
                     f'/api/certificates/{quoted}/download'):
            answers.append((path, client.get(path, headers=headers)))
        answers.append((f'DELETE /api/certificates/{quoted}', client.delete(f'/api/certificates/{quoted}', headers=headers)))
    certificates = container.managers['certificates']
    certificates.check_renewals()
    current = container.managers['settings'].load_settings()
    container.managers['file_ops'].create_unified_backup(current, 'manual', include_secrets=True)
    return answers


def test_the_restore_leaves_the_names_in_the_settings_which_is_the_premise(restored):
    """The restore writes the archive's settings as they are, so a hostile name does arrive.

    If the restore ever starts refusing them, this test is the one to turn into a test of the
    refusal; the tests below would then be passing for another reason.
    """
    _client, _headers, _container, tmp, _outside, _before, answer = restored
    assert answer.status_code == 200, answer.get_data(as_text=True)
    on_disk = json.loads((tmp / 'data' / 'settings.json').read_text())['domains']
    names = {entry['domain'] if isinstance(entry, dict) else entry for entry in on_disk}
    assert set(HOSTILE) <= names


def test_no_reader_of_the_restored_names_touches_what_is_outside_the_root(restored):
    client, headers, container, _tmp, outside, before, _answer = restored
    key = (outside / 'privkey.pem').read_text()
    marker = key.splitlines()[1][:40]
    WATCH['root'], WATCH['seen'] = os.path.realpath(outside), []
    try:
        with sealed():
            answers = _everything_that_reads_the_settings(client, headers, container)
    finally:
        WATCH['root'] = None
    assert answers, 'nothing was asked'
    assert WATCH['seen'] == [], WATCH['seen'][:5]
    assert _tree(outside) == before
    for path, response in answers:
        text = response.get_data(as_text=True)
        assert marker not in text, path
        assert 'outside.example.test' not in text, path


def test_the_renewal_sweep_asks_about_a_name_even_when_the_settings_let_it_through(restored):
    """The settings are validated when they are saved, and that is one layer. The sweep builds
    paths from the names it reads, so it must not depend on that layer alone.

    The settings manager is made to hand over the hostile names as they are in the archive, the
    way it would if its own check were not there, and the sweep is run on them.
    """
    _client, _headers, container, _tmp, outside, before, _answer = restored
    settings = container.managers['settings']
    handed_over = dict(settings.load_settings())
    handed_over['domains'] = ([{'domain': name, 'dns_provider': 'cloudflare', 'auto_renew': True} for name in HOSTILE]
                              + [{'domain': 'outside.example.test', 'dns_provider': 'cloudflare'}])
    WATCH['root'], WATCH['seen'] = os.path.realpath(outside), []
    try:
        with sealed(), mock.patch.object(settings, 'load_settings', return_value=handed_over):
            container.managers['certificates'].check_renewals()
    finally:
        WATCH['root'] = None
    assert WATCH['seen'] == [], WATCH['seen'][:5]
    assert _tree(outside) == before
