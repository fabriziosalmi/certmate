"""
File operations module for CertMate
Handles file I/O, backup management, and safe file operations
"""

import os
import json
import tempfile
import zipfile
import shutil
from datetime import datetime, timedelta
from pathlib import Path
import fcntl
import logging

logger = logging.getLogger(__name__)

# Backup constants
BACKUP_RETENTION_DAYS = 30  # Keep backups for 30 days
MAX_BACKUPS_PER_TYPE = 50   # Maximum number of backups to keep per type


class FileOperations:
    """Class to handle file operations and backup management"""
    
    def __init__(self, cert_dir, data_dir, backup_dir, logs_dir):
        self.cert_dir = Path(cert_dir)
        self.data_dir = Path(data_dir)
        self.backup_dir = Path(backup_dir)
        self.logs_dir = Path(logs_dir)
        self.allowed_dirs = [
            self.cert_dir.resolve(),
            self.data_dir.resolve(),
            self.backup_dir.resolve(),
            self.logs_dir.resolve()
        ]

    def safe_file_read(self, file_path, is_json=False, default=None):
        """Safely read a file with proper error handling and file locking"""
        try:
            # Validate file path to prevent path traversal
            file_path = Path(file_path).resolve()
            
            # Ensure the file is within allowed directories
            if not any(str(file_path).startswith(str(allowed_dir)) for allowed_dir in self.allowed_dirs):
                logger.error(f"Access denied: file outside allowed directories: {file_path}")
                return default
            
            if not file_path.exists():
                return default
                
            with open(file_path, 'r', encoding='utf-8') as f:
                # Use file locking for safety
                fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                try:
                    content = f.read()
                    if is_json:
                        return json.loads(content) if content.strip() else default
                    return content
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                    
        except (json.JSONDecodeError, FileNotFoundError, PermissionError) as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return default
        except Exception as e:
            logger.error(f"Unexpected error reading file {file_path}: {e}")
            return default

    def safe_file_write(self, file_path, data, is_json=True):
        """Safely write data to a file with proper error handling and atomic operations"""
        try:
            # Validate file path to prevent path traversal
            file_path = Path(file_path).resolve()
            
            # Ensure the file is within allowed directories
            if not any(str(file_path).startswith(str(allowed_dir)) for allowed_dir in self.allowed_dirs):
                logger.error(f"Access denied: file outside allowed directories: {file_path}")
                return False
            
            # Ensure parent directory exists
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Use temporary file for atomic writes
            temp_file = Path(f"{file_path}.tmp")
            
            with open(temp_file, 'w', encoding='utf-8') as f:
                # Use file locking for safety
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    if is_json:
                        json.dump(data, f, indent=2, ensure_ascii=False)
                    else:
                        f.write(str(data))
                    f.flush()
                    os.fsync(f.fileno())
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            
            # Atomic move
            temp_file.rename(file_path)
            
            # Set proper permissions
            os.chmod(file_path, 0o600)
            
            return True
            
        except (PermissionError, OSError) as e:
            logger.error(f"Error writing file {file_path}: {e}")
            # Clean up temp file if it exists
            if temp_file.exists():
                temp_file.unlink(missing_ok=True)
            return False
        except Exception as e:
            logger.error(f"Unexpected error writing file {file_path}: {e}")
            # Clean up temp file if it exists
            if temp_file.exists():
                temp_file.unlink(missing_ok=True)
            return False

    def create_settings_backup(self, settings_data, backup_reason="manual"):
        """Create a backup of settings data with timestamp and metadata"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_filename = f"settings_{timestamp}_{backup_reason}.json"
            backup_path = self.backup_dir / "settings" / backup_filename
            
            # Ensure backup directory exists
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Create backup with metadata
            backup_data = {
                "metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "backup_reason": backup_reason,
                    "version": "1.1.15"
                },
                "settings": settings_data
            }
            
            if self.safe_file_write(backup_path, backup_data, is_json=True):
                logger.info(f"Settings backup created: {backup_filename}")
                return backup_filename
            else:
                logger.error(f"Failed to create settings backup: {backup_filename}")
                return None
                
        except Exception as e:
            logger.error(f"Error creating settings backup: {e}")
            return None

    def create_certificates_backup(self, backup_reason="manual"):
        """Create a zip backup of all certificates"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_filename = f"certificates_{timestamp}_{backup_reason}.zip"
            backup_path = self.backup_dir / "certificates" / backup_filename
            
            # Ensure backup directory exists
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Create ZIP file
            with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                # Add metadata
                metadata = {
                    "timestamp": datetime.now().isoformat(),
                    "backup_reason": backup_reason,
                    "version": "1.1.15",
                    "domains": []
                }
                
                # Add certificate directories
                if self.cert_dir.exists():
                    for domain_dir in self.cert_dir.iterdir():
                        if domain_dir.is_dir():
                            metadata["domains"].append(domain_dir.name)
                            for cert_file in domain_dir.rglob("*"):
                                if cert_file.is_file():
                                    # Add file to zip with relative path
                                    arc_path = cert_file.relative_to(self.cert_dir)
                                    zipf.write(cert_file, arc_path)
                
                # Add metadata file
                zipf.writestr("backup_metadata.json", json.dumps(metadata, indent=2))
            
            logger.info(f"Certificates backup created: {backup_filename}")
            return backup_filename
            
        except Exception as e:
            logger.error(f"Error creating certificates backup: {e}")
            return None

    def cleanup_old_settings_backups(self):
        """Remove old settings backups based on retention policy"""
        try:
            settings_backup_dir = self.backup_dir / "settings"
            if not settings_backup_dir.exists():
                return 0
                
            backup_files = []
            for backup_file in settings_backup_dir.glob("settings_*.json"):
                try:
                    stat = backup_file.stat()
                    backup_files.append((backup_file, datetime.fromtimestamp(stat.st_mtime)))
                except Exception as e:
                    logger.warning(f"Could not process backup file {backup_file}: {e}")
                    
            # Sort by modification time (oldest first)
            backup_files.sort(key=lambda x: x[1])
            
            # Remove files older than retention period
            cutoff_date = datetime.now() - timedelta(days=BACKUP_RETENTION_DAYS)
            removed_count = 0
            
            for backup_file, mod_time in backup_files:
                if mod_time < cutoff_date:
                    try:
                        backup_file.unlink()
                        removed_count += 1
                        logger.info(f"Removed old settings backup: {backup_file.name}")
                    except Exception as e:
                        logger.error(f"Error removing old backup {backup_file}: {e}")
            
            # Also enforce maximum backup count
            if len(backup_files) > MAX_BACKUPS_PER_TYPE:
                excess_files = backup_files[:len(backup_files) - MAX_BACKUPS_PER_TYPE]
                for backup_file, _ in excess_files:
                    try:
                        backup_file.unlink()
                        removed_count += 1
                        logger.info(f"Removed excess settings backup: {backup_file.name}")
                    except Exception as e:
                        logger.error(f"Error removing excess backup {backup_file}: {e}")
            
            if removed_count > 0:
                logger.info(f"Cleanup completed: {removed_count} old settings backups removed")
                
            return removed_count
            
        except Exception as e:
            logger.error(f"Error during settings backup cleanup: {e}")
            return 0

    def cleanup_old_certificate_backups(self):
        """Remove old certificate backups based on retention policy"""
        try:
            cert_backup_dir = self.backup_dir / "certificates"
            if not cert_backup_dir.exists():
                return 0
                
            backup_files = []
            for backup_file in cert_backup_dir.glob("certificates_*.zip"):
                try:
                    stat = backup_file.stat()
                    backup_files.append((backup_file, datetime.fromtimestamp(stat.st_mtime)))
                except Exception as e:
                    logger.warning(f"Could not process backup file {backup_file}: {e}")
                    
            # Sort by modification time (oldest first)
            backup_files.sort(key=lambda x: x[1])
            
            # Remove files older than retention period
            cutoff_date = datetime.now() - timedelta(days=BACKUP_RETENTION_DAYS)
            removed_count = 0
            
            for backup_file, mod_time in backup_files:
                if mod_time < cutoff_date:
                    try:
                        backup_file.unlink()
                        removed_count += 1
                        logger.info(f"Removed old certificate backup: {backup_file.name}")
                    except Exception as e:
                        logger.error(f"Error removing old backup {backup_file}: {e}")
                        
            # Also enforce maximum backup count
            if len(backup_files) > MAX_BACKUPS_PER_TYPE:
                excess_files = backup_files[:len(backup_files) - MAX_BACKUPS_PER_TYPE]
                for backup_file, _ in excess_files:
                    try:
                        backup_file.unlink()
                        removed_count += 1
                        logger.info(f"Removed excess certificate backup: {backup_file.name}")
                    except Exception as e:
                        logger.error(f"Error removing excess backup {backup_file}: {e}")
            
            if removed_count > 0:
                logger.info(f"Cleanup completed: {removed_count} old certificate backups removed")
                
            return removed_count
            
        except Exception as e:
            logger.error(f"Error during certificate backup cleanup: {e}")
            return 0

    def list_backups(self):
        """List all available backups with metadata"""
        try:
            backups = {
                "settings": [],
                "certificates": []
            }
            
            # List settings backups
            settings_backup_dir = self.backup_dir / "settings"
            if settings_backup_dir.exists():
                for backup_file in settings_backup_dir.glob("settings_*.json"):
                    try:
                        stat = backup_file.stat()
                        metadata = {"size": stat.st_size, "created": datetime.fromtimestamp(stat.st_mtime).isoformat()}
                        
                        # Try to read backup metadata
                        backup_data = self.safe_file_read(backup_file, is_json=True)
                        if backup_data and "metadata" in backup_data:
                            metadata.update(backup_data["metadata"])
                            
                        backups["settings"].append({
                            "filename": backup_file.name,
                            "metadata": metadata
                        })
                    except Exception as e:
                        logger.warning(f"Could not process settings backup {backup_file}: {e}")
            
            # List certificate backups
            cert_backup_dir = self.backup_dir / "certificates"
            if cert_backup_dir.exists():
                for backup_file in cert_backup_dir.glob("certificates_*.zip"):
                    try:
                        stat = backup_file.stat()
                        metadata = {"size": stat.st_size, "created": datetime.fromtimestamp(stat.st_mtime).isoformat()}
                        
                        # Try to read ZIP metadata
                        try:
                            with zipfile.ZipFile(backup_file, 'r') as zipf:
                                if "backup_metadata.json" in zipf.namelist():
                                    metadata_content = zipf.read("backup_metadata.json")
                                    zip_metadata = json.loads(metadata_content.decode('utf-8'))
                                    metadata.update(zip_metadata)
                        except Exception:
                            pass  # Skip if can't read ZIP metadata
                            
                        backups["certificates"].append({
                            "filename": backup_file.name,
                            "metadata": metadata
                        })
                    except Exception as e:
                        logger.warning(f"Could not process certificate backup {backup_file}: {e}")
            
            return backups
            
        except Exception as e:
            logger.error(f"Error listing backups: {e}")
            return {"settings": [], "certificates": []}

    def restore_settings_backup(self, backup_file_path):
        """Restore settings from a backup file"""
        try:
            backup_path = Path(backup_file_path)
            
            if not backup_path.exists():
                logger.error(f"Backup file not found: {backup_path}")
                return False
            
            # Read backup data
            backup_data = self.safe_file_read(backup_path, is_json=True)
            if not backup_data:
                logger.error(f"Failed to read backup file: {backup_path}")
                return False
            
            # Extract settings from backup structure
            if "settings" in backup_data:
                settings_data = backup_data["settings"]
            else:
                # Direct settings file (legacy format)
                settings_data = backup_data
            
            # Write restored settings to main settings file
            settings_file = self.data_dir / "settings.json"
            if self.safe_file_write(settings_file, settings_data, is_json=True):
                logger.info(f"Settings restored successfully from: {backup_path.name}")
                return True
            else:
                logger.error(f"Failed to write restored settings to: {settings_file}")
                return False
                
        except Exception as e:
            logger.error(f"Error restoring settings backup: {e}")
            return False

    def restore_certificates_backup(self, backup_file_path):
        """Restore certificates from a backup ZIP file"""
        try:
            backup_path = Path(backup_file_path)
            
            if not backup_path.exists():
                logger.error(f"Backup file not found: {backup_path}")
                return False
            
            # Ensure certificates directory exists
            self.cert_dir.mkdir(parents=True, exist_ok=True)
            
            # Extract ZIP file
            with zipfile.ZipFile(backup_path, 'r') as zipf:
                # Get list of files to extract (exclude metadata)
                files_to_extract = [f for f in zipf.namelist() if f != "backup_metadata.json"]
                
                # Extract all certificate files
                for file_info in zipf.infolist():
                    if file_info.filename != "backup_metadata.json":
                        # Ensure target directory exists
                        target_path = self.cert_dir / file_info.filename
                        target_path.parent.mkdir(parents=True, exist_ok=True)
                        
                        # Extract file
                        zipf.extract(file_info, self.cert_dir)
            
            logger.info(f"Certificates restored successfully from: {backup_path.name}")
            return True
            
        except Exception as e:
            logger.error(f"Error restoring certificates backup: {e}")
            return False
