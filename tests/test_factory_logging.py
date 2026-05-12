"""
Unit tests for request-watchdog helpers in the app factory.
"""

import threading

from modules.core.factory import _env_float, _format_thread_stack


def test_env_float_falls_back_on_invalid_value(monkeypatch):
    monkeypatch.setenv('CERTMATE_SLOW_REQUEST_THRESHOLD_SECONDS', 'not-a-number')
    assert _env_float('CERTMATE_SLOW_REQUEST_THRESHOLD_SECONDS', 12.5) == 12.5


def test_format_thread_stack_returns_current_thread_stack():
    stack = _format_thread_stack(threading.current_thread().ident or 0)
    assert 'test_format_thread_stack_returns_current_thread_stack' in stack
