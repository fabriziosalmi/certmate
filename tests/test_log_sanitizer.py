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
