"""
Unit tests for the AuditLogger module.
"""

import json

from modules.core.audit import AuditLogger


def _audit_line(ts: str, payload: dict) -> str:
    return f"{ts} - certmate.audit - INFO - {json.dumps(payload)}\n"


def test_get_recent_entries_uses_tail_and_preserves_order(tmp_path):
    audit = AuditLogger(tmp_path)
    try:
        lines = []
        for i in range(1, 2001):
            lines.append(_audit_line(
                f"2026-05-12 00:{i // 60:02d}:{i % 60:02d}",
                {
                    "timestamp": f"2026-05-12T00:00:{i:02d}Z",
                    "operation": "create",
                    "resource_type": "certificate",
                    "resource_id": f"domain-{i}",
                    "status": "success",
                    "user": "system",
                    "ip_address": "unknown",
                    "details": {},
                    "error": None,
                },
            ))

        audit.audit_log_file.write_text("".join(lines))

        entries = audit.get_recent_entries(limit=3)
        assert [e["resource_id"] for e in entries] == ["domain-1998", "domain-1999", "domain-2000"]
    finally:
        audit.audit_logger.removeHandler(audit.file_handler)
        audit.file_handler.close()
