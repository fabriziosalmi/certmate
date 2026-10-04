"""In the plain log format, one record is one line.

`CERTMATE_LOG_JSON=false` selects a plain format,
`<time> - <logger> - <level> - <message>`. JSON escapes a line break inside a
string; the plain format wrote it as it was, so a value carrying one (a domain
in a request, the text of an exception that quotes it) started a line of its
own. Readers and shippers of that format split records on line starts.

`scrub_log_value` handles this at the call sites that remember to use it. The
formatter now does it for every call site: line breaks in the message are
escaped, and the lines a traceback adds are indented, so only a record's own
first line starts at the left margin.
"""
import io
import logging
import re

import pytest

from modules.core.structured_logging import PlainLineFormatter, configure_structured_logging

pytestmark = [pytest.mark.unit]

RECORD_START = re.compile(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} - ')


def _emit(log_call):
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(PlainLineFormatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
    logger = logging.getLogger('test.plain_line')
    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    log_call(logger)
    return stream.getvalue()


def test_a_line_break_in_an_argument_stays_on_the_record_line():
    out = _emit(lambda log: log.error('creation failed for %s', 'x.com\nsecond line'))
    lines = out.rstrip('\n').split('\n')
    assert len(lines) == 1, lines
    assert 'x.com\\nsecond line' in lines[0]


def test_a_carriage_return_is_escaped_too():
    out = _emit(lambda log: log.error('value %s', 'a\rb'))
    assert '\r' not in out and 'a\\rb' in out


def test_only_the_first_line_of_a_record_with_a_traceback_starts_at_the_margin():
    def log_exception(log):
        try:
            raise ValueError("Invalid SAN domain 'x.com\nsecond line'")
        except ValueError:
            log.exception('creation failed')
    lines = _emit(log_exception).rstrip('\n').split('\n')
    assert RECORD_START.match(lines[0])
    assert len(lines) > 1, 'the traceback should follow on its own lines'
    for line in lines[1:]:
        assert line.startswith(' '), f'a traceback line starts at the margin: {line!r}'


def test_a_traceback_cached_by_another_formatter_is_still_indented():
    """logging.Formatter caches the formatted traceback on the record
    (`exc_text`). A record formatted first by another handler must not hand
    this one its unindented copy."""
    record = logging.LogRecord('t', logging.ERROR, __file__, 1, 'failed', None, None)
    try:
        raise ValueError('one\ntwo')
    except ValueError:
        import sys
        record.exc_info = sys.exc_info()
    logging.Formatter().format(record)          # caches an unindented exc_text
    out = PlainLineFormatter('%(levelname)s - %(message)s').format(record)
    for line in out.split('\n')[1:]:
        assert line.startswith(' '), line


def test_an_ordinary_record_is_unchanged():
    """CONTROL: nothing but line breaks changes."""
    out = _emit(lambda log: log.info('renewed %s in %.1fs', 'example.com', 2.5))
    assert out.rstrip('\n').endswith(' - test.plain_line - INFO - renewed example.com in 2.5s')


def test_the_plain_configuration_uses_it():
    """The application's own setup, not just the class: CERTMATE_LOG_JSON=false
    goes through configure_structured_logging(json_output=False)."""
    root = logging.getLogger()
    saved = root.handlers[:], root.level
    try:
        configure_structured_logging(json_output=False)
        assert any(isinstance(h.formatter, PlainLineFormatter) for h in root.handlers)
    finally:
        root.handlers, level = saved[0], saved[1]
        root.setLevel(level)
