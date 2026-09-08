"""
Deploy Hooks for CertMate.
Runs shell commands after certificate issuance or renewal.
Hooks are configured in settings under 'deploy_hooks'.
"""

import datetime
import json
import logging
import os
import subprocess
import threading
import time
import uuid
from pathlib import Path

from .structured_logging import sanitize_text, JSONFormatter
from .utils import utc_now_iso
from .deploy_targets import run_targets, target_applies, TARGET_TYPES
from .deploy_window import (
    STALE_AFTER_DAYS, WindowError, describe as describe_window, is_open,
    next_open, normalize_window,
)

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30
MAX_TIMEOUT = 300
MAX_HISTORY_ENTRIES = 500

# A deploy run's lifecycle in the history file. `running` is written before the
# command starts, so an interrupted hook leaves a record instead of nothing;
# `success`/`failure` supersede it. `interrupted` is never written — it is what
# `get_history` reports for a `running` record no live run owns, which after a
# restart is every one of them.
STATUS_RUNNING = 'running'
STATUS_SUCCESS = 'success'
STATUS_FAILURE = 'failure'
STATUS_INTERRUPTED = 'interrupted'

# Redacts sensitive-keyed fields recursively before a deploy result is persisted
# to the history JSONL — a deploy hook command / target config can carry a
# credential, and the history file is not the place for it.
_HISTORY_SANITIZER = JSONFormatter(include_hostname=False, include_pid=False)


def _utc_now():
    """Wall-clock now, aware. One definition so tests can pin it in one place."""
    return datetime.datetime.now(datetime.timezone.utc)


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
        # Deploys held for a maintenance window (#632). On disk because the
        # window is typically hours away and a restart in between must not
        # lose the deploy; guarded by a lock because the queue is written from
        # the EventBus listener threads and read by the scheduler's drain.
        self._pending_path = Path(data_dir) / 'pending_deploys.json'
        self._pending_lock = threading.Lock()
        # Run ids of hooks this process has started and not yet finished. A
        # `running` record in the history belongs to one of two situations,
        # and only this set tells them apart: the run is still going (its id
        # is in here), or the process that started it died (it is not, because
        # this set does not survive a restart). See `_run_hook`.
        self._in_flight = set()
        self._in_flight_lock = threading.Lock()

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
            results = self._execute_hooks(domain, event_type)
            # A successful deploy is a lifecycle event in its own right (#474):
            # surface it so notifications/SIEM see "the new cert is live",
            # distinct from the per-hook completion events.
            succeeded = sum(1 for r in results if r.get('success'))
            if succeeded:
                self.event_bus.publish('certificate_deployed', {
                    'domain': domain, 'event': event_type, 'count': succeeded,
                })
        except Exception as e:
            logger.error(f"Deploy hooks failed for {domain}: {e}")

    # ------------------------------------------------------------------
    # Hook execution
    # ------------------------------------------------------------------

    def run_manual_deploy(self, domain):
        """Run every enabled hook for *domain* on demand (issue #109).

        The on_events filter is ignored: a manual trigger means "fire all
        hooks applicable to this domain right now", regardless of whether
        they'd normally only run on create or renew. Hooks see
        CERTMATE_EVENT=manual so they can branch if they care.

        Maintenance windows (#632) are ignored for the same reason. An operator
        who presses Deploy Now has chosen this moment; holding the deploy until
        02:00 would make the button do nothing visible, which is worse than
        deploying outside the window they configured for the automatic path.

        Returns a dict {ok, total, succeeded, failed, results} with
        per-hook results. ok is True iff all hooks exited 0 and at least
        one hook ran. ok is False if no hooks were configured for the
        domain so the caller can surface a useful "nothing to do" message.
        """
        config = self.get_config()
        if not config.get('enabled'):
            return {
                'ok': False,
                'total': 0, 'succeeded': 0, 'failed': 0,
                'results': [],
                'error': 'Deploy hooks are disabled. Enable them in Settings → Deploy.',
            }

        hooks = []
        for hook in config.get('global_hooks', []):
            if hook.get('enabled'):
                hooks.append(hook)
        for hook in config.get('domain_hooks', {}).get(domain, []):
            if hook.get('enabled'):
                hooks.append(hook)

        targets = [t for t in config.get('targets', [])
                   if target_applies(t, domain, 'manual')]

        if not hooks and not targets:
            return {
                'ok': False,
                'total': 0, 'succeeded': 0, 'failed': 0,
                'results': [],
                'error': (
                    f'No enabled hooks or deploy targets configured for {domain}. '
                    'Add a global/domain hook or a typed target in Settings → Deploy.'
                ),
            }

        results = [self._run_hook(h, domain, 'manual') for h in hooks]
        results.extend(self._execute_targets(domain, 'manual', config))
        succeeded = sum(1 for r in results if r.get('success'))
        failed = len(results) - succeeded
        return {
            'ok': failed == 0,
            'total': len(results),
            'succeeded': succeeded,
            'failed': failed,
            'results': results,
        }

    def _execute_hooks(self, domain, event_type):
        """Collect and run all matching hooks for a domain/event.

        A hook or target carrying a maintenance window that is closed right now
        is not run and not skipped — it is queued, and `drain_pending` runs it
        when the window next opens (#632).
        """
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

        now = _utc_now()
        results = []
        for hook in hooks:
            if self._defer_if_closed('hook', hook, domain, event_type, now):
                continue
            results.append(self._run_hook(hook, domain, event_type))

        # Typed deploy targets fire from the same lifecycle points (#475), and
        # take the same windows — a Kubernetes secret rollout is exactly the
        # kind of deploy an operator wants inside a maintenance window.
        targets = [t for t in (config.get('targets') or [])
                   if target_applies(t, domain, event_type)]
        runnable = [t for t in targets
                    if not self._defer_if_closed('target', t, domain,
                                                 event_type, now)]
        results.extend(
            self._execute_targets(domain, event_type, config, targets=runnable))
        return results

    # ------------------------------------------------------------------
    # Maintenance windows (#632)
    # ------------------------------------------------------------------

    @staticmethod
    def _entity_id(kind, entity):
        """Stable identity for a queue entry.

        Hooks carry an id; targets are identified by name, which is what
        `target_applies` and the history already key on.
        """
        return entity.get('id') if kind == 'hook' else entity.get('name')

    def _defer_if_closed(self, kind, entity, domain, event_type, now):
        """Queue this deploy if its window is shut. True when it was queued.

        A window that cannot be read is treated as absent — deploying at the
        wrong hour is a disruption, but never deploying at all is an expired
        certificate. `save_config` refuses an invalid window, so reaching this
        means the file was edited by hand.
        """
        window = entity.get('window')
        if not window:
            return False
        try:
            if is_open(window, now):
                return False
        except WindowError as e:
            logger.warning(
                "Deploy %s %r for %s has an unusable maintenance window (%s); "
                "running it now rather than holding it indefinitely.",
                kind, self._entity_id(kind, entity), domain, e)
            return False

        identity = self._entity_id(kind, entity)
        if not identity:
            logger.warning(
                "Deploy %s for %s has a maintenance window but no %s to queue "
                "it under; running it now.", kind, domain,
                'id' if kind == 'hook' else 'name')
            return False

        key = f'{kind}:{identity}:{domain}'
        with self._pending_lock:
            pending = self._read_pending()
            existing = pending.get(key)
            # A second renewal before the window opens must not queue a second
            # deploy: the hook reads the certificate from disk when it runs, so
            # one deferred run always publishes the newest one.
            # Stamped from the same `now` the window was judged against, not
            # from a second call to the clock. `_warn_if_stale` compares these
            # against the drain's `now`, and two clocks that can disagree is
            # how a queue entry ends up looking as if it were made in the
            # future — which is silent, because a negative age is never stale.
            stamp = now.isoformat()
            pending[key] = {
                'kind': kind,
                'id': identity,
                'domain': domain,
                'event': event_type,
                'queued_at': (existing or {}).get('queued_at') or stamp,
                'last_event_at': stamp,
            }
            self._write_pending(pending)

        logger.info(
            "Deploy %s %r for %s held for its maintenance window (%s); "
            "next opening %s", kind, identity, domain,
            describe_window(window),
            (next_open(window, now) or 'never').isoformat()
            if next_open(window, now) else 'never')
        return True

    def _read_pending(self):
        """The queue as a dict, or {}. Callers hold `_pending_lock`."""
        try:
            with open(self._pending_path) as f:
                data = json.load(f)
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as e:
            # A corrupt queue must not stop the drain from running the entries
            # that come after it, and it must not be silent — a lost queue is
            # a deploy that never happens.
            logger.error(
                "Pending deploy queue at %s is unreadable (%s); starting from "
                "an empty queue. Certificates are unaffected, but any deploy "
                "waiting for a maintenance window has been lost and will not "
                "run until the next renewal.", self._pending_path, e)
            return {}
        return data if isinstance(data, dict) else {}

    def _write_pending(self, pending):
        """Replace the queue atomically. Callers hold `_pending_lock`."""
        import tempfile as _tmpmod
        try:
            self._pending_path.parent.mkdir(parents=True, exist_ok=True)
            if not pending:
                # An empty file and no file mean the same thing; removing it
                # keeps the drain a true no-op on an instance that uses no
                # windows.
                try:
                    self._pending_path.unlink()
                except FileNotFoundError:
                    pass
                return
            tmp_fd, tmp_path = _tmpmod.mkstemp(
                dir=str(self._pending_path.parent), suffix='.tmp')
            try:
                with os.fdopen(tmp_fd, 'w') as f:
                    json.dump(pending, f, indent=2)
                os.replace(tmp_path, str(self._pending_path))
            except Exception:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise
        except OSError as e:
            logger.error(
                "Cannot write the pending deploy queue to %s: %s. A deploy "
                "waiting for a maintenance window will be lost on restart. "
                "Check that the data volume is writable by uid 1000.",
                self._pending_path, e)

    def get_pending(self, now=None):
        """Queued deploys, newest event first, annotated for display."""
        now = now or _utc_now()
        config = self.get_config()
        with self._pending_lock:
            pending = self._read_pending()

        rows = []
        for key, entry in pending.items():
            entity = self._find_windowed(config, entry)
            window = (entity or {}).get('window')
            try:
                when = next_open(window, now) if window else now
                description = describe_window(window)
            except WindowError:
                when, description = None, 'unusable window'
            rows.append({
                **entry,
                'key': key,
                'window': description,
                'next_run': when.isoformat() if when else None,
                'orphaned': entity is None,
            })
        rows.sort(key=lambda r: r.get('last_event_at') or '', reverse=True)
        return rows

    def _find_windowed(self, config, entry):
        """The hook or target an entry refers to, or None if it is gone."""
        if entry.get('kind') == 'hook':
            return self._find_hook(config, entry.get('id'))
        for target in config.get('targets') or []:
            if target.get('name') == entry.get('id'):
                return target
        return None

    def drain_pending(self, now=None):
        """Run every queued deploy whose window is open. Scheduler entry point.

        Returns a summary dict. Never raises: it runs from a scheduler job, and
        one bad entry must not stop the rest of the queue.
        """
        now = now or _utc_now()
        with self._pending_lock:
            pending = self._read_pending()
        if not pending:
            return {'ran': 0, 'held': 0, 'dropped': 0, 'results': []}

        config = self.get_config()
        enabled = bool(config.get('enabled'))
        remaining, results, dropped = {}, [], 0

        for key, entry in pending.items():
            entity = self._find_windowed(config, entry)
            if entity is None or not enabled or (
                    entry.get('kind') == 'hook' and not entity.get('enabled')):
                # The hook was deleted, disabled, or deploy hooks were turned
                # off while this waited. Dropping is the honest answer: the
                # operator's current configuration says do not run it.
                logger.info(
                    "Dropping queued deploy %s: its %s is gone or disabled.",
                    key, entry.get('kind'))
                dropped += 1
                continue

            window = entity.get('window')
            try:
                open_now = is_open(window, now) if window else True
            except WindowError:
                open_now = True

            if not open_now:
                self._warn_if_stale(key, entry, now)
                remaining[key] = entry
                continue

            domain, event_type = entry.get('domain'), entry.get('event')
            try:
                if entry.get('kind') == 'hook':
                    results.append(self._run_hook(entity, domain, event_type))
                else:
                    results.extend(self._execute_targets(
                        domain, event_type, config, targets=[entity]))
            except Exception as e:
                # Failure-isolated like every other deploy path: record it and
                # move on. It is NOT re-queued — a hook that fails inside its
                # window would otherwise retry at every drain for a week.
                logger.error("Queued deploy %s failed: %s", key, e)
                results.append({'success': False, 'hook': entry.get('id'),
                                'domain': domain, 'error': str(e)})

        with self._pending_lock:
            current = self._read_pending()
            # Only drop what this drain actually handled. An event that queued
            # a deploy while the loop above was running keeps its entry.
            for key in pending:
                if key not in remaining:
                    current.pop(key, None)
            for key, entry in remaining.items():
                current.setdefault(key, entry)
            self._write_pending(current)

        succeeded = sum(1 for r in results if r.get('success'))
        for domain in {r.get('domain') for r in results if r.get('success')}:
            self.event_bus.publish('certificate_deployed', {
                'domain': domain, 'event': 'window', 'count': succeeded,
            })
        return {'ran': len(results), 'held': len(remaining),
                'dropped': dropped, 'results': results}

    def _warn_if_stale(self, key, entry, now):
        """A deploy that has waited a week is not waiting, it is stuck."""
        queued_at = entry.get('queued_at')
        if not queued_at:
            return
        try:
            queued = datetime.datetime.fromisoformat(
                queued_at.replace('Z', '+00:00'))
        except ValueError:
            return
        if queued.tzinfo is None:
            queued = queued.replace(tzinfo=datetime.timezone.utc)
        if now - queued > datetime.timedelta(days=STALE_AFTER_DAYS):
            logger.warning(
                "Queued deploy %s has been waiting since %s — more than %s "
                "days. Its maintenance window has not opened in that time; "
                "check the window's days and timezone.",
                key, queued_at, STALE_AFTER_DAYS)

    def _execute_targets(self, domain, event_type, config=None, targets=None):
        """Run every applicable typed deploy target for a domain/event.

        Failure-isolated (like shell hooks): reads the current fullchain +
        private key from disk and applies them via each configured target,
        recording audit + history per target. Never raises into the caller.

        *targets*, when given, is an already-filtered list — the caller has
        applied `target_applies` and removed anything held for a maintenance
        window (#632). Passing it is not an optimisation: re-deriving the list
        here would run the targets the caller deliberately deferred.
        """
        config = config if config is not None else self.get_config()
        if targets is None:
            targets = config.get('targets') or []
        if not any(target_applies(t, domain, event_type) for t in targets):
            return []

        cert_path = self.cert_dir / domain / 'fullchain.pem'
        key_path = self.cert_dir / domain / 'privkey.pem'
        if cert_path.exists() and not key_path.exists():
            # A CSR-only certificate (#599). Every typed target ships the key
            # along with the certificate, so none of them can serve one — and
            # the generic "certificate files unreadable" this used to produce
            # would fire on every renewal, reading as a broken instance rather
            # than an incompatible pairing.
            message = (
                f'{domain} has no private key on this node: it was issued from '
                f'a CSR and the key stays on the device that generated it. '
                f'Typed deploy targets publish the key with the certificate, '
                f'so use a shell hook that fetches only the certificate '
                f'instead.')
            logger.warning("Deploy targets skipped for %s: no local key", domain)
            failure = {'success': False, 'target': None, 'type': None,
                       'domain': domain, 'status_code': None,
                       'message': message}
            self._record_target(failure, domain, event_type)
            return [failure]
        try:
            cert_pem = cert_path.read_bytes()
            key_pem = key_path.read_bytes()
        except OSError as e:
            logger.error("Deploy targets: cannot read cert files for %s: %s", domain, e)
            # An unreadable cert is an operational failure that affects deploy —
            # record it (audit + history + failure alert), don't swallow it.
            failure = {'success': False, 'target': None, 'type': None,
                       'domain': domain, 'status_code': None,
                       'message': f'certificate files unreadable: {e}'}
            self._record_target(failure, domain, event_type)
            return [failure]

        # Typed targets have the same gap shell hooks had: `run_targets`
        # publishes to every target and only then returns, so a process killed
        # part-way through leaves nothing in the history and an operator with
        # no reason to go and look at a cluster that may hold a half-published
        # certificate. One `running` record covers the batch — per-target
        # records would need the results matched back to the targets that
        # produced them, and `run_targets` filters as it goes, so the two lists
        # are not the same length. The batch is the honest unit: what the
        # interrupted record says is "publishing to targets was in progress",
        # which is exactly what is known.
        batch_id = uuid.uuid4().hex
        with self._in_flight_lock:
            self._in_flight.add(batch_id)
        self._log_history({
            'run_id': batch_id,
            'kind': 'target-batch',
            'status': STATUS_RUNNING,
            'success': False,
            'domain': domain,
            'event': event_type,
            'targets': len(targets or []),
            'timestamp': utc_now_iso(),
        })
        try:
            results = run_targets(targets, domain, cert_pem, key_pem, event_type)
            for result in results:
                self._record_target(result, domain, event_type)
            return results
        finally:
            with self._in_flight_lock:
                self._in_flight.discard(batch_id)
            self._log_history({
                'run_id': batch_id,
                'kind': 'target-batch',
                'status': STATUS_SUCCESS,
                'success': True,
                'domain': domain,
                'event': event_type,
                'targets': len(targets or []),
                'timestamp': utc_now_iso(),
            })

    def _record_target(self, result, domain, event_type):
        """Audit + history + failure-event for one typed-target result."""
        status = 'success' if result.get('success') else 'failure'
        try:
            self.audit_logger.log_operation(
                operation='deploy_target',
                resource_type='certificate',
                resource_id=domain,
                status=status,
                details={
                    'target': result.get('target'),
                    'type': result.get('type'),
                    'event': event_type,
                    'status_code': result.get('status_code'),
                    'message': result.get('message') or '',
                },
                error=None if result.get('success') else result.get('message'),
            )
        except Exception:  # pragma: no cover - audit must never break deploy
            logger.debug("Audit emit failed for deploy_target on %s", domain)

        if not result.get('success'):
            # Same "silent deploy" alerting path as a failed shell hook.
            self.event_bus.publish('deploy_hook_failed', {
                'hook_name': result.get('target'),
                'domain': domain,
                'error': result.get('message'),
            })

        self._log_history({
            'kind': 'target',
            'success': result.get('success'),
            'target': result.get('target'),
            'type': result.get('type'),
            'domain': domain,
            'event': event_type,
            'status_code': result.get('status_code'),
            'message': result.get('message'),
            'timestamp': utc_now_iso(),
        })

    def _run_hook(self, hook, domain, event_type, dry_run=False):
        """Execute a single deploy hook."""
        hook_id = hook.get('id', '')
        hook_name = hook.get('name', 'unnamed')
        command = hook.get('command', '')
        logger.info("Running deploy hook '%s' for %s: %s", hook_name, domain, command[:120])
        # Coerce to int defensively: save_config (line ~473) already does this
        # on the write path, but a hand-edited settings.json or a hook coming
        # from an older config schema could carry a string. max(str, 1) raises
        # TypeError in Python 3, which would crash the renewal worker.
        try:
            raw_timeout = int(hook.get('timeout', DEFAULT_TIMEOUT))
        except (TypeError, ValueError):
            raw_timeout = DEFAULT_TIMEOUT
        timeout = min(max(raw_timeout, 1), MAX_TIMEOUT)

        deploy_env = os.environ.copy()
        deploy_env['CERTMATE_DOMAIN'] = domain
        deploy_env['CERTMATE_CERT_PATH'] = str(self.cert_dir / domain / 'cert.pem')
        # A CSR-only certificate has no private key here — the device that
        # generated it kept it (#599). The variable is left UNSET rather than
        # pointed at a file that does not exist, because the path would be a
        # statement that is not true. Both shapes fail visibly if a hook uses
        # it (`cp` errors either way), so this is not about catching a silent
        # failure; it is so a hook can ask `[ -n "$CERTMATE_KEY_PATH" ]` and
        # get a truthful answer. Nothing changes for a key-managed
        # certificate, which is every existing one.
        key_path = self.cert_dir / domain / 'privkey.pem'
        if key_path.exists():
            deploy_env['CERTMATE_KEY_PATH'] = str(key_path)
        else:
            deploy_env.pop('CERTMATE_KEY_PATH', None)
        deploy_env['CERTMATE_FULLCHAIN_PATH'] = str(self.cert_dir / domain / 'fullchain.pem')
        # Intermediate chain on its own — some targets reject a chained cert
        # (fullchain) and want the leaf and intermediates as separate files
        # (issue #232).
        deploy_env['CERTMATE_CHAIN_PATH'] = str(self.cert_dir / domain / 'chain.pem')
        deploy_env['CERTMATE_EVENT'] = event_type
        if dry_run:
            deploy_env['CERTMATE_DRY_RUN'] = '1'

        self.event_bus.publish('deploy_hook_started', {
            'hook_id': hook_id,
            'hook_name': hook_name,
            'domain': domain,
        })

        start = time.time()
        run_id = uuid.uuid4().hex
        result = {
            'run_id': run_id,
            'hook_id': hook_id,
            'hook_name': hook_name,
            'domain': domain,
            'event': event_type,
            'command': command,
            'exit_code': None,
            'stdout': '',
            'stderr': '',
            'success': False,
            'status': STATUS_RUNNING,
            'duration_ms': 0,
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'error': None,
            'dry_run': dry_run,
        }

        # Record that the hook STARTED, before it runs. The record used to be
        # written only after the command returned, so a hook interrupted by
        # process termination — SIGKILL, OOM, the container stopped mid-deploy
        # — left no history entry, no audit record and no failure event. An
        # interrupted publish was indistinguishable from one that never began,
        # which is the worse of the two: the target may hold a half-written
        # certificate and nothing says to go and look.
        #
        # The file is append-only JSONL, so "updating" this record means
        # appending a second one with the same run_id; `get_history` folds the
        # pair and keeps the last. A record still at `running` when read, whose
        # run_id this process does not have in flight, is reported as
        # `interrupted` — which after a restart is every one of them.
        with self._in_flight_lock:
            self._in_flight.add(run_id)
        self._log_history(result)

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
            # Redact secret patterns HERE, at the single point where hook
            # output enters the result dict: everything downstream (history
            # file, audit log, the immutable hash chain) stores this dict, so
            # a hook that echoes a token or key would otherwise persist it
            # forever. Sanitize before truncating so a PEM block cut by the
            # size cap cannot dodge the pattern match.
            result['stdout'] = sanitize_text(proc.stdout or '')[:4096]
            result['stderr'] = sanitize_text(proc.stderr or '')[:4096]
            result['success'] = proc.returncode == 0
            if proc.returncode != 0:
                stderr_snippet = result['stderr'].strip()[:200]
                if stderr_snippet:
                    result['error'] = f"exit code {proc.returncode}: {stderr_snippet}"
                else:
                    result['error'] = f"exit code {proc.returncode}"
        except subprocess.TimeoutExpired:
            result['error'] = f"timeout after {timeout}s"
        except Exception as e:
            result['error'] = str(e)

        result['duration_ms'] = int((time.time() - start) * 1000)
        result['status'] = STATUS_SUCCESS if result['success'] else STATUS_FAILURE
        with self._in_flight_lock:
            self._in_flight.discard(run_id)

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
                'stdout': result.get('stdout') or '',
                'stderr': result.get('stderr') or '',
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

        # A failed deploy hook is the "silent deploy" trap: create/renew has
        # already returned success and the operator sees green, but the service
        # may still be serving the OLD certificate. Publish a dedicated failure
        # event so the notifier actively alerts (email/webhook/etc.) instead of
        # leaving the only trace in logs, the audit trail, and deploy_history.
        # Skipped for dry runs, which are expected to "not deploy".
        if not result['success'] and not dry_run:
            self.event_bus.publish('deploy_hook_failed', {
                'hook_id': hook_id,
                'hook_name': hook_name,
                'domain': domain,
                'exit_code': result['exit_code'],
                'error': result.get('error'),
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
            safe_result = _HISTORY_SANITIZER.sanitize_data(result)
            with open(self._history_path, 'a') as f:
                f.write(json.dumps(safe_result) + '\n')
            self._truncate_history()
        except OSError as e:
            # Surface write failures at warning level so the "history is
            # empty even after a manual trigger" symptom (#165) is
            # diagnosable from production logs. The typical cause on
            # Kubernetes is a PersistentVolume mounted with an owner
            # uid that doesn't match the certmate user (uid 1000) in
            # the container image.
            logger.warning(
                "Failed to write deploy history to %s: %s. "
                "Check that the data volume is writable by uid 1000.",
                self._history_path, e,
            )

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
            except Exception as e:
                logger.warning("Deploy history truncation failed: %s", e)
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise
        except OSError as e:
            logger.warning("Deploy history truncation failed (OS error): %s", e)

    def get_history(self, limit=50, domain=None):
        """Read recent deploy history entries, newest first.

        Uses a bounded deque to avoid loading the entire file when only
        the tail is needed (the common case when domain=None).

        Each run writes two records — `running` before the command and the
        outcome after — so the pair is folded here by `run_id`, newest wins,
        and the reader sees one entry per run exactly as before. A `running`
        record that survives the fold is a run whose outcome was never
        written; unless this process still has it in flight, that means the
        process executing it died, and it is reported as `interrupted`.

        Records written before run ids existed have no `run_id` and are passed
        through untouched: the history file survives upgrades, and a deploy
        that happened is not less true for predating this.
        """
        try:
            if not self._history_path.exists():
                return []

            # When filtering by domain we must scan the whole file;
            # otherwise read only the tail. Two records per run now, so read
            # twice as many lines to still be able to fill `limit` runs.
            from collections import deque
            if domain:
                max_lines = None  # scan all
            else:
                max_lines = limit * 2

            with open(self._history_path, 'r') as f:
                tail = deque(f, maxlen=max_lines)

            with self._in_flight_lock:
                in_flight = set(self._in_flight)

            entries = []
            seen_runs = set()
            for raw in reversed(tail):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    entry = json.loads(raw)
                except json.JSONDecodeError:
                    # A single corrupted line should not blank the whole
                    # history pane. Skip it and carry on with the rest.
                    logger.debug(
                        "Skipping corrupted deploy history line in %s",
                        self._history_path,
                    )
                    continue
                if domain and entry.get('domain') != domain:
                    continue

                run_id = entry.get('run_id')
                if run_id:
                    # Reading newest-first, so the first record seen for a run
                    # is its latest: the outcome if one was written, otherwise
                    # the `running` record left behind.
                    if run_id in seen_runs:
                        continue
                    seen_runs.add(run_id)
                    if entry.get('status') == STATUS_RUNNING:
                        entry = dict(entry)
                        entry['status'] = (
                            STATUS_RUNNING if run_id in in_flight
                            else STATUS_INTERRUPTED)
                        if entry['status'] == STATUS_INTERRUPTED:
                            entry['error'] = (
                                entry.get('error')
                                or 'interrupted: CertMate stopped while this '
                                   'hook was running, so its outcome is '
                                   'unknown. Check the target.')

                entries.append(entry)
                if len(entries) >= limit:
                    break
            return entries
        except OSError as e:
            logger.warning(
                "Failed to read deploy history from %s: %s. "
                "Check filesystem permissions on the data volume.",
                self._history_path, e,
            )
            return []

    # ------------------------------------------------------------------
    # Config management
    # ------------------------------------------------------------------

    def get_config(self):
        """Return deploy_hooks config with defaults."""
        settings = self.settings_manager.load_settings()
        config = settings.get('deploy_hooks', {
            'enabled': False,
            'global_hooks': [],
            'domain_hooks': {},
        })
        # Typed deploy targets (#475) live alongside the shell hooks; default to
        # an empty list so older configs keep working.
        config.setdefault('targets', [])
        return config

    def save_config(self, config):
        """Validate and save deploy_hooks config.

        Returns (success: bool, error: str | None). The error message
        identifies the offending hook + reason when validation fails so the
        UI can show why a save was rejected (issue #102) instead of a
        generic "save failed".

        A key the payload does not mention is left as it was. This is not
        politeness: `deploy_hooks` also holds `targets`, the typed deploy
        targets from #475, and the Settings -> Deploy screen has no editor for
        them — `loadConfig` never reads them and `saveConfig` posts a body
        without them. Replacing the whole block therefore meant that opening
        that screen and pressing Save silently deleted every configured
        Kubernetes secret target. Absent leaves alone; an explicit value,
        including an empty list, replaces.
        """
        if not isinstance(config, dict):
            return False, "Configuration must be an object"
        if not isinstance(config.get('enabled'), bool):
            config['enabled'] = False

        ok, err = self._validate_deploy_config(config)
        if not ok:
            return False, err

        # Atomic via settings_manager.update so two concurrent admin saves
        # (e.g. one editing deploy hooks, another editing DNS providers)
        # cannot lose each other's changes.
        def _mutate(settings):
            existing = settings.get('deploy_hooks')
            merged = dict(existing) if isinstance(existing, dict) else {}
            merged.update(config)
            settings['deploy_hooks'] = merged
        self.settings_manager.update(_mutate, "deploy_hooks_save")
        return True, None

    def _validate_deploy_config(self, config):
        """Pure validation of a deploy_hooks config block — no side effects.

        The single source of truth for "is this deploy_hooks config safe to
        install": save_config calls it before persisting, and the restore path
        (_revalidate_restored_deploy_hooks in file_operations) calls it before
        accepting an archive. Keeping one validator is the point — the restore
        gate used to check only global_hooks and skip per-domain hooks, so a
        command the normal save path rejects could arrive through a restore.

        Returns (ok, error|None). Validates global_hooks, the shape of
        domain_hooks (an object of lists — save_config used to call .items()
        on it unguarded and would crash on a non-object), every per-domain
        hook, and typed targets.
        """
        if not isinstance(config, dict):
            return False, "Configuration must be an object"

        for hook in config.get('global_hooks', []):
            ok, err = self._validate_hook(hook)
            if not ok:
                return False, f"Global hook rejected: {err}"

        domain_hooks = config.get('domain_hooks', {})
        if not isinstance(domain_hooks, dict):
            return False, "domain_hooks must be an object of domain -> [hooks]"
        for domain, hooks in domain_hooks.items():
            if not isinstance(hooks, list):
                return False, f"Hooks for domain '{domain}' must be a list"
            for hook in hooks:
                ok, err = self._validate_hook(hook)
                if not ok:
                    return False, f"Hook for domain '{domain}' rejected: {err}"

        if 'targets' in config:
            if not isinstance(config['targets'], list):
                return False, "targets must be a list"
            for target in config['targets']:
                ok, err = self._validate_target(target)
                if not ok:
                    return False, f"Deploy target rejected: {err}"

        return True, None

    @staticmethod
    def _validate_target(target):
        """Validate one typed deploy target. Returns (ok, error|None)."""
        if not isinstance(target, dict):
            return False, "target must be an object"
        ttype = target.get('type')
        if ttype not in TARGET_TYPES:
            return False, f"unknown target type {ttype!r} (expected one of {TARGET_TYPES})"
        # Same window rule as a shell hook, refused at the same moment (#632).
        try:
            window = normalize_window(target.get('window'))
        except WindowError as e:
            return False, f"target {target.get('name')!r} window: {e}"
        if window is None:
            target.pop('window', None)
        else:
            target['window'] = window
        cfg = target.get('config') or {}
        if not isinstance(cfg, dict):
            return False, "target.config must be an object"
        if ttype == 'kubernetes-secret':
            if not cfg.get('secret_name'):
                return False, "kubernetes-secret needs config.secret_name"
            if cfg.get('in_cluster'):
                return True, None
            if not cfg.get('api_server') or not cfg.get('token'):
                return False, "kubernetes-secret needs config.api_server + config.token (or in_cluster)"
            if not cfg.get('namespace'):
                return False, "kubernetes-secret needs config.namespace"
        return True, None

    @staticmethod
    def _is_command_safe(command):
        """Check a deploy hook command for dangerous patterns.

        Returns (safe: bool, reason: str | None).

        The sanitizer intentionally allows:
        - $CERTMATE_* / ${CERTMATE_*} env vars (injected by CertMate itself)
        - Simple pipes (|) for common post-processing (e.g. curl | jq)
        - Simple output redirection (> file) to non-absolute paths

        It blocks:
        - Backtick sub-shells, $() sub-shells
        - Arbitrary ${...} parameter expansion (except CERTMATE_*)
        - Command chaining (&&, ||, ;)
        - eval / source builtins
        - Redirect to absolute paths (> /etc/... could overwrite system files)
        - References to CertMate-internal sensitive files
        """
        import re

        if len(command) > 1024:
            return False, "command exceeds 1024 character limit"

        # Strip out whitelisted env var references before applying the
        # dangerous-pattern check. CertMate injects these into the hook
        # environment (see _run_hook), so they're safe to reference.
        # Two exact forms are allowed:
        #   $CERTMATE_FOO        (no braces)
        #   ${CERTMATE_FOO}      (braces with name and immediate close)
        # The previous regex `\$\{?CERTMATE_[A-Z_]+\}?` accepted partial
        # brace forms — `${CERTMATE_FOO` (no close) and `${CERTMATE_FOO}`
        # were both matched — which let an attacker smuggle bash parameter
        # expansion operators past the validator:
        #   ${CERTMATE_FOO:-/etc/passwd}    -> opens any path at runtime
        #   ${CERTMATE_FOO:+anything}       -> conditional substitution
        #   ${CERTMATE_FOO//a/b}            -> in-string substitution
        # All three matched the old safe_vars (stripping `${CERTMATE_FOO`)
        # and left only `:-/etc/passwd}` etc., which contains no metachar
        # the dangerous regex catches. By requiring the closing brace
        # IMMEDIATELY after the variable name, none of these forms are
        # ever substituted; the dangerous-shell rule `\$\{` then catches
        # them and the command is rejected.
        _safe_vars = re.compile(r'\$CERTMATE_[A-Z_]+|\$\{CERTMATE_[A-Z_]+\}')
        sanitized = _safe_vars.sub('__SAFE__', command)

        # Block shell metacharacters that enable code injection.
        _DANGEROUS_SHELL = re.compile(
            r'[`]'              # backtick sub-shell
            r'|\$\('            # $() sub-shell
            r'|\$\{'            # ${} parameter expansion (after safe vars removed)
            r'|&&'              # logical AND chaining
            r'|\|\|'            # logical OR chaining
            r'|[;]'             # statement separator
            r'|[\r\n]'          # newline / CR — sh -c treats them as `;`
            r'|>\s*/'           # redirect to absolute path
            r'|<<'              # here-doc
            r'|\beval\b'        # eval built-in
            r'|\bsource\b'     # source built-in
            r'|\b\.\s+/'       # ". /path" (source shorthand)
        )
        if _DANGEROUS_SHELL.search(sanitized):
            return False, "contains dangerous shell metacharacters"

        # Block access to CertMate's own sensitive files.
        _BLOCKED_FILES = re.compile(
            r'(settings\.json|api_bearer_token|client_secret'
            r'|vault_token|\.env\b)',
            re.IGNORECASE,
        )
        if _BLOCKED_FILES.search(command):
            return False, "references sensitive CertMate files"

        return True, None

    def _validate_hook(self, hook):
        """Validate a single hook dict.

        Returns (valid: bool, error: str | None). The error names the
        offending hook (by name) and the specific reason so callers can
        surface it to the user (issue #102: command field rejections used
        to be a generic "save failed").
        """
        if not isinstance(hook, dict):
            return False, "hook entry is not an object"
        if not hook.get('id'):
            return False, "hook is missing its id"
        hook_label = hook.get('name', '').strip() or hook.get('id') or 'unnamed'
        if not hook.get('name', '').strip():
            return False, f"hook '{hook_label}' is missing a name"
        if not hook.get('command', '').strip():
            return False, f"hook '{hook_label}' is missing a command"

        command = hook['command'].strip()
        safe, reason = self._is_command_safe(command)
        if not safe:
            logger.warning("Deploy hook '%s' command rejected: %s", hook_label, reason)
            return False, f"hook '{hook_label}' command {reason}"

        hook['timeout'] = min(max(int(hook.get('timeout', DEFAULT_TIMEOUT)), 1), MAX_TIMEOUT)
        if not isinstance(hook.get('on_events'), list):
            hook['on_events'] = ['created', 'renewed']
        if not isinstance(hook.get('enabled'), bool):
            hook['enabled'] = True

        # A maintenance window is refused here, at save time, rather than
        # discovered when the queue is drained (#632). A window that cannot be
        # read is one that never opens, and the symptom — deploys silently not
        # happening — would surface days after the change that caused it.
        try:
            window = normalize_window(hook.get('window'))
        except WindowError as e:
            return False, f"hook '{hook_label}' window: {e}"
        if window is None:
            hook.pop('window', None)
        else:
            hook['window'] = window
        return True, None

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
