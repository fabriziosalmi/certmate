"""#829 reached the clients too.

`days_until_expiry` is whole days and truncates, so a certificate with 23 hours
of life reports 0. Anything deriving validity from it calls that certificate
expired, which is what CertMate's own dashboard did until server 2.32.2, and
what the CLI printed as a red "0".

Server 2.32.2 sends `expired` and `seconds_left` (API contract 2.2). The SDK
surfaces both and answers the question once, so callers stop deriving it, and
answers None rather than guessing on the one day where a day count genuinely
cannot tell.
"""
import pytest

pytest.importorskip("certmate", reason="certmate-sdk not installed")
pytest.importorskip("certmate_cli", reason="certmate-cli not installed")

from unittest.mock import MagicMock, patch  # noqa: E402

from typer.testing import CliRunner  # noqa: E402

from certmate.models import Certificate  # noqa: E402
from certmate_cli.main import app  # noqa: E402

pytestmark = [pytest.mark.unit]

runner = CliRunner()


def _cert(**fields):
    base = {"domain": "abc.local", "expiry_date": "2026-09-17T01:00:00"}
    base.update(fields)
    return Certificate.from_dict(base)


@pytest.mark.parametrize("payload,expected,why", [
    ({"expired": False, "days_until_expiry": 0}, False,
     "23 hours left: the server says not expired and days_until_expiry cannot"),
    ({"expired": True, "days_until_expiry": 0}, True,
     "lapsed within the last day: the same 0, the opposite answer"),
    ({"expired": True, "days_until_expiry": -4}, True, "plainly expired"),
    ({"expired": False, "days_until_expiry": 45}, False, "plainly valid"),
    ({"days_until_expiry": -3}, True, "older server: negative is unambiguous"),
    ({"days_until_expiry": 45}, False, "older server: positive is unambiguous"),
    ({"days_until_expiry": 0}, None,
     "older server, zero days: the ambiguous day, so no answer rather than a guess"),
    ({}, None, "nothing to go on"),
    ({"expired": None, "days_until_expiry": None}, None,
     "the server could not parse it, which is neither expired nor fine"),
])
def test_has_expired_answers_only_what_it_knows(payload, expected, why):
    assert _cert(**payload).has_expired() is expected, why


def _run(certs, *args):
    client = MagicMock()
    client.list_certificates.return_value = certs
    client.get_certificate.return_value = certs[0]
    with patch("certmate_cli.main._client", return_value=client):
        return runner.invoke(app, list(args))


def test_the_listing_does_not_print_zero_for_a_valid_certificate():
    result = _run([_cert(expired=False, days_until_expiry=0, seconds_left=82799)],
                  "cert", "ls")
    assert result.exit_code == 0
    assert "expired" not in result.output.lower(), (
        "a certificate with 23 hours left was listed as expired"
    )
    assert "<1" in result.output, result.output


def test_the_listing_says_expired_rather_than_a_number():
    result = _run([_cert(expired=True, days_until_expiry=0, seconds_left=-3600)],
                  "cert", "ls")
    assert result.exit_code == 0
    assert "expired" in result.output.lower()


def test_info_does_not_say_zero_days_for_a_valid_certificate():
    result = _run([_cert(expired=False, days_until_expiry=0, seconds_left=82799)],
                  "cert", "info", "abc.local")
    assert result.exit_code == 0
    assert "less than a day" in result.output
    assert "(0 days)" not in result.output


def test_an_older_server_is_not_guessed_about():
    """Zero days from a server that cannot say more must not become a verdict."""
    result = _run([_cert(days_until_expiry=0)], "cert", "info", "abc.local")
    assert result.exit_code == 0
    assert "expired" not in result.output.lower()
    assert "less than a day" not in result.output
    assert "? days" in result.output
