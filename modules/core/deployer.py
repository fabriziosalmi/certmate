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
        """Keep only the last MAX_HISTORY_ENTRIES entries."""
        try:
            lines = self._history_path.read_text().splitlines()
            if len(lines) > MAX_HISTORY_ENTRIES:
                keep = lines[-MAX_HISTORY_ENTRIES:]
                self._history_path.write_text('\n'.join(keep) + '\n')
        except OSError:
            pass

    def get_history(self, limit=50, domain=None):
        """Read recent deploy history entries, newest first."""
        try:
            if not self._history_path.exists():
                return []
            lines = self._history_path.read_text().splitlines()
            entries = []
            for line in reversed(lines):
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
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
            return {'error': 'Hook not found', 'hook_id': hook_id}
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
