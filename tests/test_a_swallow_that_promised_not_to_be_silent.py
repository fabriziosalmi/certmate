"""A swallow that promised not to be silent, and was (#671).

`AuthManager` records `last_used_at` for an API key on every authenticated
request, and swallows a failure to write it. The swallow is right: nobody
should be refused a valid key because a timestamp column could not be updated.

Its written reason said more than that, though — *"never silent either: this
swallow already hid one defect"*, remembering a `json.dump` that refused a
datetime and left the column empty for every key, forever. It logged at DEBUG.
`CERTMATE_LOG_LEVEL` defaults to INFO, so on a default install that line does
not exist and the defect it remembers would hide in the same place twice.

Raising it to WARNING outright is the other failure: this runs once per
API-key request, so a settings file that stays unwritable would fill the log
at request rate, which hides things just as well. Once per process is the
shape that keeps the promise the comment made.

Found by the #671 pass over the 28 broad handlers whose stated reason contains
a claim that can be false. See tests/test_a_timestamp_that_could_not_be_read.py
for the other one that did not survive, which was a defect rather than a
comment.
"""
import pytest

pytestmark = [pytest.mark.unit]

class TestTheLastUsedWriteIsNotSilent:
    """Once per process, loudly; after that, out of the way."""

    @staticmethod
    def _reset():
        from modules.core import auth
        auth._LAST_USED_WRITE_WARNED = False

    def test_the_first_failure_is_visible_at_the_default_level(self, caplog):
        from modules.core import auth
        self._reset()

        with caplog.at_level('INFO'):
            auth._warn_once_about_last_used(OSError('read-only file system'))

        warnings = [r for r in caplog.records if r.levelname == 'WARNING']
        assert warnings, 'nothing at INFO or above — silent on a default install'
        assert 'read-only file system' in warnings[0].getMessage()

    def test_it_says_the_key_still_works(self, caplog):
        """An operator reading this must not think authentication is broken."""
        from modules.core import auth
        self._reset()

        with caplog.at_level('INFO'):
            auth._warn_once_about_last_used(OSError('nope'))

        assert 'still authenticates' in caplog.records[0].getMessage()

    def test_it_does_not_repeat_once_per_request(self, caplog):
        """The reason it was DEBUG: this runs per API-key request, so a
        persistent failure at WARNING would fill the log at request rate."""
        from modules.core import auth
        self._reset()

        with caplog.at_level('DEBUG'):
            for _ in range(5):
                auth._warn_once_about_last_used(OSError('nope'))

        levels = [r.levelname for r in caplog.records]
        assert levels.count('WARNING') == 1, levels
        assert levels.count('DEBUG') == 4, levels
