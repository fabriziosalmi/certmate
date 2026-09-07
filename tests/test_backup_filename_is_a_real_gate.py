"""What a backup filename is allowed to be, proved by trying to break it.

Code scanning reports five paths through the backup endpoints where a request
value reaches a filesystem path or a log line. Four of them were already
defended and one was not, and the only way to tell those apart is to run them.

The four path-expression reports are guarded three deep: `backup_type` must
equal the literal 'unified', the filename goes through
`_validate_backup_filename`, and the resolved path must still sit under the
backup directory. This exercises that end to end rather than asserting it from
reading, because "the validator handles it" is exactly the claim that turns out
to be wrong when it is wrong.

The fifth needed work: the validator rejected NUL but no other control
character, and a filename is reported back in log output. Control characters
are now refused at the validator rather than handled at each log site, since it
is the single point all five endpoints already go through.
"""
from unittest.mock import MagicMock

import pytest
from flask import Flask
from flask_restx import Api

from modules.api.resource_context import ApiContext
from modules.api.resources_backup import (
    _validate_backup_filename,
    create_backup_resources,
)

pytestmark = [pytest.mark.unit]

TRAVERSAL = [
    '../../etc/passwd',
    '..%2f..%2fetc%2fpasswd.zip',
    'sub/dir/backup.zip',
    '..\\..\\windows\\system32.zip',
    'backup.zip\x00.png',
    '....//backup.zip',
]

CONTROL_CHARS = [
    'x\nSECOND.zip',
    'x\rSECOND.zip',
    'x\tSECOND.zip',
    'x\x1bSECOND.zip',
    'x\x7fSECOND.zip',
]

LEGITIMATE = [
    'backup_20260101_120000.zip',
    'backup_20260101_120000.zip.enc',
    'certmate-backup.zip',
]


@pytest.mark.parametrize('filename', TRAVERSAL)
def test_traversal_shapes_are_refused(filename):
    assert _validate_backup_filename(filename) is not None, (
        f'{filename!r} was accepted as a backup filename'
    )


@pytest.mark.parametrize('filename', CONTROL_CHARS)
def test_control_characters_are_refused(filename):
    assert _validate_backup_filename(filename) is not None, (
        f'{filename!r} was accepted; a control character in a filename reaches '
        f'the log output that reports it back'
    )


@pytest.mark.parametrize('filename', LEGITIMATE)
def test_the_names_this_application_actually_writes_are_accepted(filename):
    """CONTROL: a validator that rejects everything would pass every test above
    while breaking backups entirely."""
    assert _validate_backup_filename(filename) is None, (
        f'{filename!r} is a name CertMate itself writes and it was refused'
    )


def _download_endpoint(tmp_path):
    file_ops = MagicMock()
    file_ops.backup_dir = tmp_path
    ctx = ApiContext(
        auth=MagicMock(), settings=MagicMock(), certificates=None,
        file_ops=file_ops, cache=None, dns=None, deployer=None, audit=None,
        cert_service=None, cert_executor=None, managers={'file_ops': file_ops},
    )
    ctx.auth.require_role = lambda role: (lambda fn: fn)
    app = Flask(__name__)
    api = Api(app, prefix='/api')
    models = {'backup_model': MagicMock(), 'backup_list_model': MagicMock()}
    return app, create_backup_resources(api, models, ctx)['BackupDownload']


@pytest.mark.parametrize('filename', TRAVERSAL + CONTROL_CHARS)
def test_the_download_endpoint_refuses_them_too(tmp_path, filename):
    """The reports are against the endpoint, so the endpoint is what is tested.

    A validator can be correct and still be bypassed by a caller reaching the
    path expression another way, which is the shape code scanning warns about.
    """
    app, endpoint = _download_endpoint(tmp_path)
    with app.test_request_context('/'):
        result = endpoint().get('unified', filename)

    status = result[1] if isinstance(result, tuple) else 200
    assert status in (400, 403, 404), (
        f'{filename!r} produced {status}; a traversal or control-character '
        f'name must be refused, not served'
    )


def test_the_download_endpoint_pins_the_backup_type(tmp_path):
    """CONTROL: the filename is only half of the path expression.

    `backup_type` is also interpolated into it. It is pinned to one literal, so
    it cannot carry a traversal — if that check is ever relaxed, the filename
    validation above stops being sufficient on its own.
    """
    app, endpoint = _download_endpoint(tmp_path)
    with app.test_request_context('/'):
        result = endpoint().get('../../etc', 'backup_20260101_120000.zip')

    status = result[1] if isinstance(result, tuple) else 200
    assert status == 400, (
        f'a backup_type other than "unified" produced {status}; it is '
        f'interpolated straight into the path'
    )


def test_a_legitimate_name_that_is_absent_reaches_the_not_found_path(tmp_path):
    """CONTROL: proves the refusals above are refusals, not a dead endpoint.

    Without this, an endpoint that returned 404 unconditionally — because the
    resource never built, or every call raised — would satisfy every assertion
    above while testing nothing.
    """
    app, endpoint = _download_endpoint(tmp_path)
    (tmp_path / 'unified').mkdir()
    (tmp_path / 'unified' / 'backup_20260101_120000.zip').write_bytes(b'PK')

    with app.test_request_context('/'):
        result = endpoint().get('unified', 'backup_20260101_120000.zip')

    status = result[1] if isinstance(result, tuple) else 200
    assert status == 200, (
        f'a real backup file was not served ({status}); the endpoint refuses '
        f'everything, so the refusal tests above prove nothing'
    )
