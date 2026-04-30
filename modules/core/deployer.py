"""
Deploy Hooks for CertMate.
Runs shell commands after certificate issuance or renewal.
Hooks are configured in settings under 'deploy_hooks'.
"""

import json
import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30
MAX_TIMEOUT = 300
MAX_HISTORY_ENTRIES = 500


class DeployManager:
    """Manages post-issuance deploy hooks."""

    def __init__(self, settings_manager, shell_executor, audit_logger,
                 event_bus, cert_dir, data_dir='data'):
        self.settings_manager = settings_manager
        self.shell_executor = shell_executor
        self.audit_logger = audit_logger
        self.event_bus = event_bus
        self.cert_dir = Path(cert_dir)
        self._history_path = Path(data_dir) / 'deploy_history.jsonl'

    # ------------------------------------------------------------------
    # EventBus listener
    # ------------------------------------------------------------------

    def on_certificate_event(self, event, data):
        """EventBus callback — triggers deploy hooks on cert events."""
        event_map = {
            'certificate_created': 'created',
            'certificate_renewed': 'renewed',
        }
        event_type = event_map.get(event)
        if not event_type:
            return
        domain = data.get('domain')
        if not domain:
            return
        try:
            self._execute_hooks(domain, event_type)
        except Exception as e:
            logger.error(f"Deploy hooks failed for {domain}: {e}")

    # ------------------------------------------------------------------
    # Hook execution
    # ------------------------------------------------------------------

    def _execute_hooks(self, domain, event_type):
        """Collect and run all matching hooks for a domain/event."""
        config = self.get_config()
        if not config.get('enabled'):
            return []

        hooks = []
        for hook in config.get('global_hooks', []):
            if hook.get('enabled') and event_type in hook.get('on_events', []):
                hooks.append(hook)

        domain_hooks = config.get('domain_hooks', {}).get(domain, [])
        for hook in domain_hooks:
            if hook.get('enabled') and event_type in hook.get('on_events', []):
                hooks.append(hook)

        results = []
        for hook in hooks:
            result = self._run_hook(hook, domain, event_type)
            results.append(result)
        return results

    def _run_hook(self, hook, domain, event_type, dry_run=False):
        """Execute a single deploy hook."""
        hook_id = hook.get('id', '')
        hook_name = hook.get('name', 'unnamed')
        command = hook.get('command', '')
        logger.info("Running deploy hook '%s' for %s: %s", hook_name, domain, command[:120])
        timeout = min(max(hook.get('timeout', DEFAULT_TIMEOUT), 1), MAX_TIMEOUT)

        deploy_env = os.environ.copy()
        deploy_env['CERTMATE_DOMAIN'] = domain
        deploy_env['CERTMATE_CERT_PATH'] = str(self.cert_dir / domain / 'cert.pem')
        deploy_env['CERTMATE_KEY_PATH'] = str(self.cert_dir / domain / 'privkey.pem')
        deploy_env['CERTMATE_FULLCHAIN_PATH'] = str(self.cert_dir / domain / 'fullchain.pem')
        deploy_env['CERTMATE_EVENT'] = event_type
        if dry_run:
            deploy_env['CERTMATE_DRY_RUN'] = '1'

        self.event_bus.publish('deploy_hook_started', {
            'hook_id': hook_id,
            'hook_name': hook_name,
            'domain': domain,
        })

        start = time.time()
        result = {
            'hook_id': hook_id,
            'hook_name': hook_name,
            'domain': domain,
            'event': event_type,
            'command': command,
            'exit_code': None,
            'stdout': '',
            'stderr': '',
            'success': False,
            'duration_ms': 0,
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'error': None,
            'dry_run': dry_run,
        }

        try:
            # Defense in depth: re-validate command at execution time
            safe, reason = self._is_command_safe(command)
            if not safe:
                raise ValueError(f"Command blocked at runtime: {reason}")

            proc = self.shell_executor.run(
                ['sh', '-c', command],
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=deploy_env,
            )
            result['exit_code'] = proc.returncode
            result['stdout'] = (proc.stdout or '')[:4096]
            result['stderr'] = (proc.stderr or '')[:4096]
            result['success'] = proc.returncode == 0
            if proc.returncode != 0:
                result['error'] = f"exit code {proc.returncode}"
        except subprocess.TimeoutExpired:
            result['error'] = f"timeout after {timeout}s"
        except Exception as e:
            result['error'] = str(e)

        result['duration_ms'] = int((time.time() - start) * 1000)

        status = 'success' if result['success'] else 'failure'
        self.audit_logger.log_operation(
            operation='deploy_hook',
            resource_type='certificate',
            resource_id=domain,
            status=status,
            details={
                'hook_name': hook_name,
                'hook_id': hook_id,
                'exit_code': result['exit_code'],
                'duration_ms': result['duration_ms'],
                'dry_run': dry_run,
            },
            error=result.get('error'),
        )

        self.event_bus.publish('deploy_hook_completed', {
            'hook_id': hook_id,
            'hook_name': hook_name,
            'domain': domain,
            'success': result['success'],
            'duration_ms': result['duration_ms'],
        })

        self._log_history(result)
        return result

    # ------------------------------------------------------------------
    # History (JSONL)
    # ------------------------------------------------------------------

    def _log_history(self, result):
        """Append a deploy result to the JSONL history file."""
        try:
            self._history_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._history_path, 'a') as f:
                f.write(json.dumps(result) + '\n')
            self._truncate_history()
        except OSError as e:
            logger.debug(f"Failed to write deploy history: {e}")

    def _truncate_history(self):
        """Keep only the last MAX_HISTORY_ENTRIES entries (atomic)."""
        try:
            from collections import deque
            import tempfile as _tmpmod

            with open(self._history_path, 'r') as f:
                tail = deque(f, maxlen=MAX_HISTORY_ENTRIES)

            if len(tail) < MAX_HISTORY_ENTRIES:
                return  # Nothing to truncate

            tmp_fd, tmp_path = _tmpmod.mkstemp(
                dir=str(self._history_path.parent), suffix='.tmp')
            try:
                with os.fdopen(tmp_fd, 'w') as f:
                    f.writelines(tail)
                os.replace(tmp_path, str(self._history_path))
            except Exception:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise
        except OSError:
            pass

    def get_history(self, limit=50, domain=None):
        """Read recent deploy history entries, newest first.

        Uses a bounded deque to avoid loading the entire file when only
        the tail is needed (the common case when domain=None).
        """
        try:
            if not self._history_path.exists():
                return []

            # When filtering by domain we must scan the whole file;
            # otherwise read only the last `limit` lines.
            from collections import deque
            if domain:
                max_lines = None  # scan all
            else:
                max_lines = limit

            with open(self._history_path, 'r') as f:
                tail = deque(f, maxlen=max_lines)

            entries = []
            for raw in reversed(tail):
                raw = raw.strip()
                if not raw:
                    continue
                entry = json.loads(raw)
                if domain and entry.get('domain') != domain:
                    continue
                entries.append(entry)
                if len(entries) >= limit:
                    break
            return entries
        except (OSError, json.JSONDecodeError) as e:
            logger.debug(f"Failed to read deploy history: {e}")
            return []

    # ------------------------------------------------------------------
    # Config management
    # ------------------------------------------------------------------

    def get_config(self):
        """Return deploy_hooks config with defaults."""
        settings = self.settings_manager.load_settings()
        return settings.get('deploy_hooks', {
            'enabled': False,
            'global_hooks': [],
            'domain_hooks': {},
        })

    def save_config(self, config):
        """Validate and save deploy_hooks config. Returns True on success."""
        if not isinstance(config, dict):
            return False
        if not isinstance(config.get('enabled'), bool):
            config['enabled'] = False

        for hook in config.get('global_hooks', []):
            if not self._validate_hook(hook):
                return False
        for domain, hooks in config.get('domain_hooks', {}).items():
            if not isinstance(hooks, list):
                return False
            for hook in hooks:
                if not self._validate_hook(hook):
                    return False

        settings = self.settings_manager.load_settings()
        settings['deploy_hooks'] = config
        self.settings_manager.save_settings(settings)
        return True

    @staticmethod
    def _is_command_safe(command):
        """Check a deploy hook command for dangerous patterns.

        Returns (safe: bool, reason: str | None).
        """
        import re

        if len(command) > 1024:
            return False, "command exceeds 1024 character limit"

        # Block shell metacharacters that enable chaining, sub-shells, or
        # redirection to absolute paths (which could overwrite system files).
        _DANGEROUS_SHELL = re.compile(
            r'[`]'              # backtick sub-shell
            r'|\$\('            # $() sub-shell
            r'|\$\{'            # ${} parameter expansion
            r'|&&'              # logical AND chaining
            r'|\|\|'            # logical OR chaining
            r'|[;]'             # statement separator
            r'|\|'              # pipe
            r'|>\s*/'           # redirect to absolute path
            r'|<<'              # here-doc
            r'|\beval\b'        # eval built-in
            r'|\bsource\b'     # source built-in
            r'|\b\.\s+/'       # ". /path" (source shorthand)
        )
        if _DANGEROUS_SHELL.search(command):
            return False, "contains dangerous shell metacharacters"

        # Block access to CertMate's own sensitive files.
        _BLOCKED_FILES = re.compile(
            r'(settings\.json|api_bearer_token|client_secret'
            r'|vault_token|\.env\b|private.*key|\.pem\b)',
            re.IGNORECASE,
        )
        if _BLOCKED_FILES.search(command):
            return False, "references sensitive CertMate files"

        return True, None

    def _validate_hook(self, hook):
        """Validate a single hook dict. Returns True if valid."""
        if not isinstance(hook, dict):
            return False
        if not hook.get('id'):
            return False
        if not hook.get('name', '').strip():
            return False
        if not hook.get('command', '').strip():
            return False

        command = hook['command'].strip()
        safe, reason = self._is_command_safe(command)
        if not safe:
            logger.warning("Deploy hook command rejected: %s", reason)
            return False

        hook['timeout'] = min(max(int(hook.get('timeout', DEFAULT_TIMEOUT)), 1), MAX_TIMEOUT)
        if not isinstance(hook.get('on_events'), list):
            hook['on_events'] = ['created', 'renewed']
        if not isinstance(hook.get('enabled'), bool):
            hook['enabled'] = True
        return True

    # ------------------------------------------------------------------
    # Test hook
    # ------------------------------------------------------------------

    def test_hook(self, hook_id, domain='test.example.com'):
        """Find a hook by ID and dry-run it."""
        config = self.get_config()
        hook = self._find_hook(config, hook_id)
        if not hook:
            # Be specific about *why* the hook went missing — the two real
            # causes (issue #101) are stale UI state and a silent save-time
            # rejection by the safety validator. Generic "not found" leaves
            # users guessing.
            return {
                'error': (
                    f'Hook {hook_id} is no longer in settings. This usually '
                    'means the page is out of sync with the server, or the '
                    "hook's command was rejected by the safety validator at "
                    'save time. Refresh the Settings page and re-check '
                    'Settings → Deploy Hooks; if the hook is missing, '
                    're-create it and check the toast for any rejection '
                    'message when you save.'
                ),
                'hook_id': hook_id,
                'reason': 'hook_missing_from_config',
            }
        return self._run_hook(hook, domain, 'test', dry_run=True)

    def _find_hook(self, config, hook_id):
        """Search for a hook by ID in global and domain hooks."""
        for hook in config.get('global_hooks', []):
            if hook.get('id') == hook_id:
                return hook
        for hooks in config.get('domain_hooks', {}).values():
            for hook in hooks:
                if hook.get('id') == hook_id:
                    return hook
        return None
