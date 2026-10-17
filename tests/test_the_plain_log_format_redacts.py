"""The plain log format redacts what the JSON one redacts.

`CERTMATE_LOG_JSON=false` is the format an operator picks to read the log by
eye, and it wrote a token or a private key that reached a log message as it
was: the redaction lived in JSONFormatter.format alone. Measured before the
fix, `{"api_token": "..."}` and `Authorization: Bearer ...` came out in clear
in the plain format and as "[REDACTED]" in the JSON one.

The lines are the ones the handlers configure_structured_logging installs
write, console and file, so this is what the application writes and not a
formatter built by hand. The JSON format is the control: every secret here is
one it redacts, so a pass means the plain format agrees with it.
"""
import io
import logging

import pytest

from modules.core.structured_logging import configure_structured_logging

pytestmark = [pytest.mark.unit]

TOKEN = 'FAKE-token-0123456789abcdefghij'
BEARER = 'FAKEbearer0123456789abcdefghij'
KEY_BODY = 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7'
PEM = f'-----BEGIN PRIVATE KEY-----\n{KEY_BODY}\n-----END PRIVATE KEY-----'
SECRETS = (TOKEN, BEARER, KEY_BODY)


def _write(tmp_path, json_output):
    """Log one message per secret and one traceback; return (console, file)."""
    log_file = tmp_path / f'certmate-json-{json_output}.log'
    configure_structured_logging(level=logging.INFO, json_output=json_output,
                                 log_file=str(log_file))
    root = logging.getLogger()
    console = io.StringIO()
    for handler in root.handlers:
        if type(handler) is logging.StreamHandler:
            handler.setStream(console)
    logger = logging.getLogger('certmate.test_plain_redaction')
    logger.info('dns config {"api_token": "%s"}', TOKEN)
    logger.info('calling the API with Authorization: Bearer %s', BEARER)
    logger.info('certbot said:\n%s', PEM)
    try:
        raise RuntimeError(f'request failed: api_token={TOKEN}')
    except RuntimeError:
        logger.exception('the call failed')
    for handler in root.handlers:
        handler.flush()
    return console.getvalue(), log_file.read_text()


@pytest.fixture
def write(tmp_path):
    root = logging.getLogger()
    saved_handlers, saved_level = root.handlers[:], root.level
    yield lambda json_output: _write(tmp_path, json_output)
    for handler in root.handlers[:]:
        root.removeHandler(handler)
        handler.close()
    for handler in saved_handlers:
        root.addHandler(handler)
    root.setLevel(saved_level)


def test_the_json_format_redacts_every_secret_here(write):
    """The control: if this fails, the inputs no longer test anything."""
    for text in write(True):
        assert 'the call failed' in text
        for secret in SECRETS:
            assert secret not in text


def test_the_plain_format_redacts_them_too(write):
    for text in write(False):
        assert 'the call failed' in text, 'the plain format wrote nothing'
        assert '[REDACTED]' in text and '[PEM REDACTED]' in text
        for secret in SECRETS:
            assert secret not in text, f'{secret} written in clear by the plain format'


def test_the_plain_format_still_writes_one_record_per_line(write):
    """Redaction does not undo the escaping of line breaks."""
    console, _ = write(False)
    records = [line for line in console.split('\n') if line and not line.startswith(' ')]
    assert len(records) == 4, console
