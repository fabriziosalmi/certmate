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
            
            # Use temporary file for atomic writes with restrictive permissions
            temp_file = Path(f"{file_path}.tmp")
            fd = os.open(str(temp_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
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

    def create_unified_backup(self, settings_data, backup_reason="manual"):
        """Create a unified backup containing both settings and certificates"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            backup_id = f"backup_{timestamp}_{backup_reason}"
            backup_filename = f"{backup_id}.zip"
            backup_path = self.backup_dir / "unified" / backup_filename
            
            # Ensure backup directory exists
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Create unified backup metadata
            domains = []
            if self.cert_dir.exists():
                for domain_dir in self.cert_dir.iterdir():
                    if domain_dir.is_dir():
                        domains.append(domain_dir.name)
            
            metadata = {
                "backup_id": backup_id,
                "timestamp": datetime.now().isoformat(),
                "backup_reason": backup_reason,
                "version": "2.0.0",  # New unified format
                "type": "unified",
                "domains": domains,
                "settings_domains": [d.get('domain') if isinstance(d, dict) else d for d in settings_data.get('domains', [])],
                "total_domains": len(domains)
            }
            
            # Create ZIP file with both settings and certificates
            with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                # Add settings data
                settings_backup = {
                    "metadata": metadata,
                    "settings": settings_data
                }
                zipf.writestr("settings.json", json.dumps(settings_backup, indent=2))
                
                # Add all certificate files
                if self.cert_dir.exists():
                    for domain_dir in self.cert_dir.iterdir():
                        if domain_dir.is_dir():
                            for cert_file in domain_dir.rglob("*"):
                                if cert_file.is_file():
                                    # Add file to zip with relative path under certificates/
                                    arc_path = f"certificates/{cert_file.relative_to(self.cert_dir)}"
                                    zipf.write(cert_file, arc_path)
                
                # Add unified metadata
                zipf.writestr("backup_metadata.json", json.dumps(metadata, indent=2))
            
            logger.info(f"Unified backup created: {backup_filename} (contains {len(domains)} domains)")
            return backup_filename
                
        except Exception as e:
            logger.error(f"Error creating unified backup: {e}")
            return None





    def list_backups(self):
        """List all available unified backups with metadata"""
        try:
            backups = {
                "unified": []
            }
            
            # List unified backups (only format)
            unified_backup_dir = self.backup_dir / "unified"
            if unified_backup_dir.exists():
                for backup_file in unified_backup_dir.glob("backup_*.zip"):
                    try:
                        stat = backup_file.stat()
                        metadata = {"size": stat.st_size, "created": datetime.fromtimestamp(stat.st_mtime).isoformat()}
                        
                        # Try to read unified backup metadata
                        try:
                            with zipfile.ZipFile(backup_file, 'r') as zipf:
                                if "backup_metadata.json" in zipf.namelist():
                                    metadata_content = zipf.read("backup_metadata.json")
                                    zip_metadata = json.loads(metadata_content.decode('utf-8'))
                                    metadata.update(zip_metadata)
                                    metadata["type"] = "unified"
                        except Exception:
                            pass  # Skip if can't read ZIP metadata
                            
                        backups["unified"].append({
                            "filename": backup_file.name,
                            "metadata": metadata
                        })
                    except Exception as e:
                        logger.warning(f"Could not process unified backup {backup_file}: {e}")
            
            return backups
            
        except Exception as e:
            logger.error(f"Error listing backups: {e}")
            return {"unified": []}

    def restore_unified_backup(self, backup_file_path):
        """Restore from a unified backup file (both settings and certificates)"""
        try:
            logger.info(f"Starting unified backup restore from: {backup_file_path}")
            backup_path = Path(backup_file_path)
            
            if not backup_path.exists():
                logger.error(f"Backup file not found: {backup_path}")
                return False
            
            # Ensure directories exist
            self.cert_dir.mkdir(parents=True, exist_ok=True)
            self.data_dir.mkdir(parents=True, exist_ok=True)
            
            restored_domains = []
            settings_data = None
            
            # Extract unified backup
            with zipfile.ZipFile(backup_path, 'r') as zipf:
                # First, restore settings
                if "settings.json" in zipf.namelist():
                    settings_content = zipf.read("settings.json")
                    settings_backup = json.loads(settings_content.decode('utf-8'))
                    
                    if "settings" in settings_backup:
                        settings_data = settings_backup["settings"]
                        settings_file = self.data_dir / "settings.json"
                        if self.safe_file_write(settings_file, settings_data, is_json=True):
                            logger.info("Settings restored from unified backup")
                        else:
                            logger.error("Failed to restore settings from unified backup")
                            return False
                
                # Then, restore certificates
                cert_dir_resolved = self.cert_dir.resolve()
                for file_info in zipf.infolist():
                    if file_info.filename.startswith("certificates/") and file_info.filename != "certificates/":
                        # Remove "certificates/" prefix from the path
                        relative_path = file_info.filename[12:]  # len("certificates/") = 12

                        # ZIP Slip protection: reject entries with path traversal
                        if '..' in relative_path or relative_path.startswith('/'):
                            logger.warning(f"Skipping suspicious ZIP entry: {file_info.filename}")
                            continue

                        target_path = self.cert_dir / relative_path

                        # Verify resolved path stays within cert_dir
                        try:
                            target_resolved = target_path.resolve()
                            if not str(target_resolved).startswith(str(cert_dir_resolved) + os.sep) \
                                    and target_resolved != cert_dir_resolved:
                                logger.warning(f"ZIP Slip blocked: {file_info.filename} -> {target_resolved}")
                                continue
                        except (OSError, ValueError):
                            logger.warning(f"Invalid path in ZIP: {file_info.filename}")
                            continue

                        # Decompression bomb protection: reject oversized entries
                        max_entry_size = 10 * 1024 * 1024  # 10 MB per file
                        if file_info.file_size > max_entry_size:
                            logger.warning(f"Skipping oversized ZIP entry: {file_info.filename} ({file_info.file_size} bytes)")
                            continue

                        logger.info(f"Extracting certificate file: {file_info.filename}")

                        # Ensure target directory exists
                        target_path.parent.mkdir(parents=True, exist_ok=True)

                        # Extract file with size limit
                        try:
                            with zipf.open(file_info) as source, open(target_path, 'wb') as target:
                                data = source.read(max_entry_size + 1)
                                if len(data) > max_entry_size:
                                    logger.warning(f"ZIP entry exceeds size limit: {file_info.filename}")
                                    continue
                                target.write(data)
                        except Exception as e:
                            logger.error(f"Error extracting {file_info.filename}: {e}")
                            continue

                        # Set appropriate permissions
                        if target_path.name == 'privkey.pem':
                            os.chmod(target_path, 0o600)
                        else:
                            os.chmod(target_path, 0o644)

                        # Track restored domains
                        if '/' in relative_path:
                            domain = relative_path.split('/')[0]
                            if domain and domain not in restored_domains:
                                logger.info(f"Found domain in unified backup: {domain}")
                                restored_domains.append(domain)
            
            logger.info(f"Unified backup restored successfully from: {backup_path.name}")
            if restored_domains:
                logger.info(f"Restored {len(restored_domains)} domains: {', '.join(restored_domains)}")
            return True
            
        except Exception as e:
            logger.error(f"Error restoring unified backup: {e}")
            return False


