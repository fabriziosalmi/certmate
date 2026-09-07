"""Values bound into a log message must not be able to become a log *record*.

The scope-denial log binds caller-supplied values (username, domain, scope)
into a message. The JSON formatter escapes a newline inside a string, so the
default configuration is unaffected — which is precisely why this was easy to
believe settled. It is not: `CERTMATE_LOG_JSON=false` (app.py) selects a plain
line formatter, and there a newline in a bound value ends the record and starts
another one whose timestamp and level the value chooses.

So the property under test is not "the formatter escapes it". It is that the
values are scrubbed at the call site, under EITHER formatter.

Two-sided on purpose: the control below feeds the same value through an
unscrubbed message and proves the harness can actually observe forging. Without
it, a test that only ever sees one line cannot distinguish a working defence
from a blind assertion.
"""
import logging
from io import StringIO

import pytest

from modules.core.structured_logging import JSONFormatter, scrub_log_value

pytestmark = [pytest.mark.unit]

# The plain formatter app.py selects when CERTMATE_LOG_JSON is not 'true'.
PLAIN = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)

# A value carrying a line break plus a complete, well-formed second record.
HOSTILE = 'someone\n2026-01-01 00:00:00 - modules.core.auth - INFO - forged'


def _emit(formatter, message, *args):
    """Emit one log call and return the physical lines it produced."""
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(formatter)
    logger = logging.getLogger(f'probe.{id(stream)}')
    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(logging.INFO)
    logger.warning(message, *args)
    return [line for line in stream.getvalue().strip().splitlines()
            if line.strip()]


@pytest.mark.parametrize('formatter,label', [
    (PLAIN, 'plain'), (JSONFormatter(), 'json'),
])
def test_a_scrubbed_value_stays_inside_one_record(formatter, label):
    lines = _emit(formatter, 'denial: user=%s', scrub_log_value(HOSTILE))
    assert len(lines) == 1, (
        f'under the {label} formatter a scrubbed value still produced '
        f'{len(lines)} records; a caller-supplied value must never be able to '
        f'append an entry of its own choosing to the log'
    )


def test_the_harness_can_actually_observe_forging():
    """CONTROL: the same value, unscrubbed, must break the record in two.

    If this ever stops producing a second line, the assertions above are
    passing because nothing can forge here, not because the scrub works.
    """
    lines = _emit(PLAIN, 'denial: user=%s', HOSTILE)
    assert len(lines) == 2, (
        'the plain formatter no longer splits on a newline, so the test above '
        'proves nothing — re-derive what it should assert'
    )


def test_the_json_formatter_alone_is_not_the_defence():
    """Records why the scrub is required even though JSON escapes newlines.

    JSON output is immune on its own, so a reader may reasonably conclude the
    call-site scrub is redundant and remove it. It is not redundant: the plain
    formatter is operator-selectable, and the control above shows what it does.
    """
    assert len(_emit(JSONFormatter(), 'denial: user=%s', HOSTILE)) == 1
    assert len(_emit(PLAIN, 'denial: user=%s', HOSTILE)) == 2


def test_the_denial_path_itself_scrubs_what_it_logs():
    """The one that guards the actual code.

    Everything above tests the helper and the formatters; none of it would
    notice the scrub being dropped from the denial path, which is where the
    values are bound. This drives `check_domain_scope` and counts the records
    the plain formatter produces.
    """
    from flask import Flask

    from modules.api.resource_context import ApiContext
    from modules.api import resource_context as rc

    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(PLAIN)
    rc.logger.handlers = [handler]
    rc.logger.propagate = False
    rc.logger.setLevel(logging.INFO)

    class _DenyAll:
        def user_can_access_domain(self, user, domain):
            return False

    ctx = ApiContext(
        auth=_DenyAll(), settings=None, certificates=None, file_ops=None,
        cache=None, dns=None, deployer=None, audit=None, cert_service=None,
        cert_executor=None,
    )

    app = Flask(__name__)
    with app.test_request_context('/'):
        from flask import request
        request.current_user = {'username': HOSTILE, 'allowed_domains': ['x']}
        body, status = check_scope(ctx)

    assert status == 403, 'the request must still be denied'
    lines = [line for line in stream.getvalue().strip().splitlines()
             if line.strip()]
    assert len(lines) == 1, (
        f'the scope-denial log emitted {len(lines)} records for one denial; '
        f'a caller-supplied username must not be able to append a record of '
        f'its own to the log'
    )


def check_scope(ctx):
    from modules.api.resource_context import check_domain_scope
    return check_domain_scope(ctx, 'blocked.example.com', 'renew')


def test_scrub_preserves_values_it_has_no_business_changing():
    """A scrub that mangles ordinary values would only be found in
    production."""
    assert scrub_log_value('alice') == 'alice'
    assert scrub_log_value('*.example.com') == '*.example.com'
    assert scrub_log_value(['a.example.com', 'b.example.com']) == \
        "['a.example.com', 'b.example.com']"
    assert scrub_log_value(None) is None
