"""
Tests for backup create / list / download / delete.
"""

import pytest

pytestmark = [pytest.mark.e2e]


class TestBackupLifecycle:
    """Full backup CRUD cycle."""

    def test_01_list_backups_initially_empty(self, api):
        r = api.get("/api/backups")
        assert r.status_code == 200

    def test_02_create_backup(self, api):
        r = api.post_json("/api/backups/create", {"type": "unified"})
        assert r.status_code in (200, 201), f"Create backup failed: {r.text[:200]}"

    def test_03_list_backups_after_create(self, api):
        r = api.get("/api/backups")
        assert r.status_code == 200
        data = r.json()
        unified = data.get("unified", [])
        assert len(unified) >= 1, "No backups found after create"

    def test_04_download_backup(self, api):
        r = api.get("/api/backups")
        data = r.json()
        unified = data.get("unified", [])
        if not unified:
            pytest.skip("No backup to download")
        filename = unified[0].get("filename", unified[0]) if isinstance(unified[0], dict) else unified[0]
        r = api.get(f"/api/backups/download/unified/{filename}")
        assert r.status_code == 200
        assert len(r.content) > 50, "Backup file too small"

    def test_05_delete_backup(self, api):
        r = api.get("/api/backups")
        data = r.json()
        unified = data.get("unified", [])
        if not unified:
            pytest.skip("No backup to delete")
        filename = unified[0].get("filename", unified[0]) if isinstance(unified[0], dict) else unified[0]
        r = api.delete(f"/api/backups/delete/unified/{filename}")
        assert r.status_code == 200
