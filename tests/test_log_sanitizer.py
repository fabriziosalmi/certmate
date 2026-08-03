import json
import logging
import pytest
from modules.core.structured_logging import JSONFormatter, StructuredLogger

def test_json_formatter_sanitizes_dict():
    formatter = JSONFormatter()
    raw_data = {
        "user": "admin",
        "password": "super_secret_password",
        "api_key": "key-12345",
        "cloudflare_token": "token-9999",
        "normal_field": "hello-world",
        "nested": {
            "secret_key": "some-secret",
            "safe_val": 42
        }
    }
    
    sanitized = formatter.sanitize_data(raw_data)
    
    assert sanitized["user"] == "admin"
    assert sanitized["password"] == "[REDACTED]"
    assert sanitized["api_key"] == "[REDACTED]"
    assert sanitized["cloudflare_token"] == "[REDACTED]"
    assert sanitized["normal_field"] == "hello-world"
    assert sanitized["nested"]["secret_key"] == "[REDACTED]"
    assert sanitized["nested"]["safe_val"] == 42


def test_json_formatter_sanitizes_pem_blocks():
    formatter = JSONFormatter()
    pem_block = (
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC78J9...\n"
        "-----END PRIVATE KEY-----"
    )
    
    # 1. Direct string value in dict
    data = {"key_data": pem_block, "safe": "ok"}
    sanitized = formatter.sanitize_data(data)
    assert sanitized["key_data"] == "[PEM REDACTED]"
    assert sanitized["safe"] == "ok"
    
    # 2. In log message
    message = f"Loaded key successfully: {pem_block}"
    sanitized_msg = formatter.sanitize_data(message)
    assert sanitized_msg == "Loaded key successfully: [PEM REDACTED]"


def test_json_formatter_sanitizes_inline_assignments():
    formatter = JSONFormatter()
    
    cases = [
        ("Invalid cloudflare_token: abc123xyz", "Invalid cloudflare_token: \"[REDACTED]\""),
        ("password = 'mysecretpassword'", "password = \"[REDACTED]\""),
        ("API token: \"bearer-99\"", "API token: \"[REDACTED]\""),
        ("key_pem: 'someval'", "key_pem: \"[REDACTED]\""),
        ("Safe text: no credentials", "Safe text: no credentials")
    ]
    
    for input_str, expected_str in cases:
        assert formatter.sanitize_data(input_str) == expected_str


import io

def test_logger_integration():
    # Setup test logger
    logger = logging.getLogger("test_sanitizer")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    
    # Avoid duplicate handlers if test runs multiple times
    logger.handlers = []
    
    log_stream = io.StringIO()
    handler = logging.StreamHandler(log_stream)
    handler.setFormatter(JSONFormatter(include_hostname=False, include_pid=False))
    logger.addHandler(handler)
    
    s_logger = StructuredLogger(logger)
    
    # Test logging with extra fields
    s_logger.info("Configuration update", cloudflare_token="token-abc", safe_field="ok")
    
    log_stream.seek(0)
    log_line = log_stream.getvalue().strip()
    log_json = json.loads(log_line)
    
    assert log_json["message"] == "Configuration update"
    assert log_json["cloudflare_token"] == "[REDACTED]"
    assert log_json["safe_field"] == "ok"
    
    # Clear stream for next log
    log_stream.seek(0)
    log_stream.truncate(0)
    
    # Test logging an exception with a secret in message
    try:
        raise ValueError("Failed login with password = 'admin123'")
    except Exception as e:
        s_logger.exception("Error during authentication")
        
    log_stream.seek(0)
    log_line = log_stream.getvalue().strip()
    log_json = json.loads(log_line)
    
    assert log_json["message"] == "Error during authentication"
    assert "exception" in log_json
    assert "admin123" not in log_json["exception"]
    assert "password = \"[REDACTED]\"" in log_json["exception"]


def test_pem_redaction_is_linear_on_unclosed_blocks():
    """A blob that opens PEM blocks and never closes them must not stall.

    The old single-regex form restarted its `.*?` forward scan at every
    `-----BEGIN`, so cost grew with anchors x length: 0.4 s at 2000 anchors,
    6.6 s at 8000. `sanitize_text` runs on UNBOUNDED deploy-hook output
    (deployer.py) on one of the process's eight gunicorn threads, so that is
    a thread-exhaustion lever, not just a slow function.

    The bound below is loose on purpose — this asserts "not quadratic", not a
    benchmark, so it does not go red on a loaded CI runner. The old code
    needed minutes here.
    """
    import time
    from modules.core.structured_logging import sanitize_text

    payload = ("-----BEGIN" + "A" * 20) * 40_000  # ~1.2 MB, zero closers
    started = time.perf_counter()
    sanitize_text(payload)
    elapsed = time.perf_counter() - started
    assert elapsed < 5.0, f"PEM redaction took {elapsed:.1f}s — quadratic again?"


def test_pem_redaction_matches_the_regex_it_replaced():
    """The linear scanner must redact exactly what PEM_RE would have.

    PEM_RE is kept on the class as the reference; this pins the scanner to it
    over the shapes that actually distinguish them — unclosed blocks, nested
    openers, malformed headers, several blocks in one string.
    """
    from modules.core.structured_logging import JSONFormatter, _redact_pem_blocks

    cases = [
        "",
        "nothing to see here",
        "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----",
        "head -----BEGIN X-----body-----END X----- tail",
        "-----BEGIN A-----1-----END A----------BEGIN B-----2-----END B-----",
        "-----BEGIN never closed",
        "-----BEGIN-----",                      # empty header, no match
        "-----BEGIN A-----no closer at all",
        "-----BEGIN -----BEGIN A-----x-----END A-----",
        "junk-----END A-----junk",
    ]
    for case in cases:
        assert _redact_pem_blocks(case) == \
            JSONFormatter.PEM_RE.sub('[PEM REDACTED]', case), repr(case)
