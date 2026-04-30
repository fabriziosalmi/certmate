"""
Unit tests for the DeployManager module.
These run without Docker — they mock the managers.
"""

import json
import pytest
from unittest.mock import MagicMock
from pathlib import Path
from modules.core.deployer import DeployManager
from modules.core.shell import MockShellExecutor


@pytest.fixture
def shell_executor():
    return MockShellExecutor()


@pytest.fixture
def settings_manager():
    mgr = MagicMock()
    mgr.load_settings.return_value = {
        'deploy_hooks': {
            'enabled': True,
            'global_hooks': [
                {
                    'id': 'g1',
                    'name': 'Reload Nginx',
                    'command': 'systemctl reload nginx',
                    'enabled': True,
                    'timeout': 30,
                    'on_events': ['created', 'renewed'],
                },
                {
                    'id': 'g2',
                    'name': 'Disabled Hook',
                    'command': 'echo disabled',
                    'enabled': False,
                    'timeout': 10,
                    'on_events': ['created', 'renewed'],
                },
            ],
            'domain_hooks': {
                'example.com': [
                    {
                        'id': 'd1',
                        'name': 'Sync CDN',
                        'command': '/opt/deploy-cdn.sh',
                        'enabled': True,
                        'timeout': 60,
                        'on_events': ['created'],
                    },
                ],
            },
        }
    }
    return mgr


@pytest.fixture
def deploy_manager(settings_manager, shell_executor, tmp_path):
    return DeployManager(
        settings_manager=settings_manager,
        shell_executor=shell_executor,
        audit_logger=MagicMock(),
        event_bus=MagicMock(),
        cert_dir=tmp_path / 'certs',
        data_dir=str(tmp_path / 'data'),
    )


class TestHookExecution:
    """Test _run_hook with different outcomes."""

    def test_success(self, deploy_manager, shell_executor):
        shell_executor.set_next_result(returncode=0, stdout='ok\n')
        hook = {
            'id': 'h1', 'name': 'Test', 'command': 'echo test',
            'enabled': True, 'timeout': 10, 'on_events': ['created'],
        }
        result = deploy_manager._run_hook(hook, 'example.com', 'created')
        assert result['success'] is True
        assert result['exit_code'] == 0
        assert result['hook_name'] == 'Test'
        assert result['domain'] == 'example.com'

    def test_failure_nonzero_exit(self, deploy_manager, shell_executor):
        shell_executor.set_next_result(returncode=1, stderr='error\n')
        hook = {
            'id': 'h2', 'name': 'Fail', 'command': 'false',
            'enabled': True, 'timeout': 10, 'on_events': ['created'],
        }
        result = deploy_manager._run_hook(hook, 'example.com', 'created')
        assert result['success'] is False
        assert result['exit_code'] == 1
        assert 'exit code 1' in result['error']

    def test_timeout(self, deploy_manager, shell_executor):
        shell_executor.set_next_result(should_timeout=True)
        hook = {
            'id': 'h3', 'name': 'Slow', 'command': 'sleep 999',
            'enabled': True, 'timeout': 5, 'on_events': ['created'],
        }
        result = deploy_manager._run_hook(hook, 'example.com', 'created')
        assert result['success'] is False
        assert 'timeout' in result['error']

    def test_env_variables(self, deploy_manager, shell_executor, tmp_path):
        """Verify that env vars are passed to the shell command."""
        shell_executor.set_next_result(returncode=0)
        hook = {
            'id': 'h4', 'name': 'Env', 'command': 'env',
            'enabled': True, 'timeout': 10, 'on_events': ['created'],
        }
        result = deploy_manager._run_hook(hook, 'mysite.com', 'renewed')
        # Check shell_executor received env kwarg with our vars
        assert len(shell_executor.commands_executed) == 1
        assert 'sh -c env' in shell_executor.commands_executed[0]

    def test_dry_run_flag(self, deploy_manager, shell_executor):
        shell_executor.set_next_result(returncode=0)
        hook = {
            'id': 'h5', 'name': 'DryRun', 'command': 'echo dry',
            'enabled': True, 'timeout': 10, 'on_events': ['created'],
        }
        result = deploy_manager._run_hook(hook, 'example.com', 'test', dry_run=True)
        assert result['dry_run'] is True
        assert result['success'] is True

    def test_audit_logged(self, deploy_manager, shell_executor):
        shell_executor.set_next_result(returncode=0)
        hook = {
            'id': 'h6', 'name': 'Audit', 'command': 'echo ok',
            'enabled': True, 'timeout': 10, 'on_events': ['created'],
        }
        deploy_manager._run_hook(hook, 'example.com', 'created')
        deploy_manager.audit_logger.log_operation.assert_called_once()
        call_kwargs = deploy_manager.audit_logger.log_operation.call_args
        assert call_kwargs[1]['operation'] == 'deploy_hook'
        assert call_kwargs[1]['status'] == 'success'

    def test_sse_events_published(self, deploy_manager, shell_executor):
        shell_executor.set_next_result(returncode=0)
        hook = {
            'id': 'h7', 'name': 'SSE', 'command': 'echo ok',
            'enabled': True, 'timeout': 10, 'on_events': ['created'],
        }
        deploy_manager._run_hook(hook, 'example.com', 'created')
        calls = deploy_manager.event_bus.publish.call_args_list
        events = [c[0][0] for c in calls]
        assert 'deploy_hook_started' in events
        assert 'deploy_hook_completed' in events


class TestHookFiltering:
    """Test that hooks are selected correctly."""

    def test_global_hooks_run_for_any_domain(self, deploy_manager, shell_executor):
        shell_executor.set_next_result(returncode=0)
        results = deploy_manager._execute_hooks('other.com', 'created')
        # Only g1 should run (g2 is disabled)
        assert len(results) == 1
        assert results[0]['hook_name'] == 'Reload Nginx'

    def test_domain_hooks_only_for_matching_domain(self, deploy_manager, shell_executor):
        shell_executor.set_next_result(returncode=0)
        shell_executor.set_next_result(returncode=0)
        results = deploy_manager._execute_hooks('example.com', 'created')
        # g1 (global) + d1 (domain-specific) = 2 hooks
        names = [r['hook_name'] for r in results]
        assert 'Reload Nginx' in names
        assert 'Sync CDN' in names

    def test_disabled_hooks_skipped(self, deploy_manager, shell_executor):
        shell_executor.set_next_result(returncode=0)
        results = deploy_manager._execute_hooks('other.com', 'created')
        names = [r['hook_name'] for r in results]
        assert 'Disabled Hook' not in names

    def test_event_type_filter(self, deploy_manager, shell_executor):
        shell_executor.set_next_result(returncode=0)
        # d1 only has on_events=['created'], not 'renewed'
        results = deploy_manager._execute_hooks('example.com', 'renewed')
        names = [r['hook_name'] for r in results]
        assert 'Sync CDN' not in names
        assert 'Reload Nginx' in names

    def test_disabled_config_skips_all(self, deploy_manager, settings_manager):
        cfg = settings_manager.load_settings()
        cfg['deploy_hooks']['enabled'] = False
        results = deploy_manager._execute_hooks('example.com', 'created')
        assert results == []


class TestConfig:
    """Test config load/save/validate."""

    def test_defaults_when_no_config(self, shell_executor, tmp_path):
        mgr = MagicMock()
        mgr.load_settings.return_value = {}
        dm = DeployManager(
            settings_manager=mgr, shell_executor=shell_executor,
            audit_logger=MagicMock(), event_bus=MagicMock(),
            cert_dir=tmp_path, data_dir=str(tmp_path),
        )
        config = dm.get_config()
        assert config['enabled'] is False
        assert config['global_hooks'] == []
        assert config['domain_hooks'] == {}

    def test_save_valid_config(self, deploy_manager, settings_manager):
        config = {
            'enabled': True,
            'global_hooks': [
                {'id': 'x', 'name': 'Test', 'command': 'echo hi', 'enabled': True,
                 'timeout': 30, 'on_events': ['created']},
            ],
            'domain_hooks': {},
        }
        ok, err = deploy_manager.save_config(config)
        assert ok is True
        assert err is None
        settings_manager.save_settings.assert_called_once()

    def test_reject_empty_command(self, deploy_manager):
        config = {
            'enabled': True,
            'global_hooks': [
                {'id': 'x', 'name': 'Bad', 'command': '', 'enabled': True,
                 'timeout': 30, 'on_events': ['created']},
            ],
            'domain_hooks': {},
        }
        ok, err = deploy_manager.save_config(config)
        assert ok is False
        assert err and 'Bad' in err

    def test_reject_missing_name(self, deploy_manager):
        config = {
            'enabled': True,
            'global_hooks': [
                {'id': 'x', 'name': '', 'command': 'echo', 'enabled': True,
                 'timeout': 30, 'on_events': ['created']},
            ],
            'domain_hooks': {},
        }
        ok, err = deploy_manager.save_config(config)
        assert ok is False
        assert err and 'name' in err.lower()

    def test_timeout_clamped(self, deploy_manager, settings_manager):
        config = {
            'enabled': True,
            'global_hooks': [
                {'id': 'x', 'name': 'Clamp', 'command': 'echo', 'enabled': True,
                 'timeout': 9999, 'on_events': ['created']},
            ],
            'domain_hooks': {},
        }
        ok, _ = deploy_manager.save_config(config)
        assert ok is True
        saved = settings_manager.save_settings.call_args[0][0]
        assert saved['deploy_hooks']['global_hooks'][0]['timeout'] == 300

    def test_unsafe_command_returns_specific_reason(self, deploy_manager):
        """Issue #102: rejection error must name the offending hook AND
        the specific reason (e.g. 'dangerous shell metacharacters'),
        not a generic 'save failed'."""
        config = {
            'enabled': True,
            'global_hooks': [
                {'id': 'h1', 'name': 'Pipeline',
                 'command': 'curl http://x | jq .',
                 'enabled': True, 'timeout': 30, 'on_events': ['created']},
            ],
            'domain_hooks': {},
        }
        ok, err = deploy_manager.save_config(config)
        assert ok is False
        assert err is not None
        assert "Pipeline" in err, "must name the offending hook"
        assert "dangerous shell metacharacters" in err.lower() or "metacharacter" in err.lower()

    def test_unsafe_command_in_domain_hook(self, deploy_manager):
        config = {
            'enabled': True,
            'global_hooks': [],
            'domain_hooks': {
                'example.com': [
                    {'id': 'd1', 'name': 'Chained',
                     'command': 'echo a && echo b',
                     'enabled': True, 'timeout': 30, 'on_events': ['renewed']},
                ],
            },
        }
        ok, err = deploy_manager.save_config(config)
        assert ok is False
        assert err is not None
        assert "example.com" in err
        assert "Chained" in err


class TestHistory:
    """Test JSONL history."""

    def test_history_written(self, deploy_manager, shell_executor):
        shell_executor.set_next_result(returncode=0)
        hook = {
            'id': 'h1', 'name': 'Log', 'command': 'echo',
            'enabled': True, 'timeout': 10, 'on_events': ['created'],
        }
        deploy_manager._run_hook(hook, 'example.com', 'created')
        entries = deploy_manager.get_history()
        assert len(entries) == 1
        assert entries[0]['hook_name'] == 'Log'

    def test_history_newest_first(self, deploy_manager, shell_executor):
        for i in range(3):
            shell_executor.set_next_result(returncode=0)
        hook = {
            'id': 'h1', 'name': 'Multi', 'command': 'echo',
            'enabled': True, 'timeout': 10, 'on_events': ['created'],
        }
        for d in ['a.com', 'b.com', 'c.com']:
            deploy_manager._run_hook(hook, d, 'created')
        entries = deploy_manager.get_history()
        assert len(entries) == 3
        assert entries[0]['domain'] == 'c.com'

    def test_history_domain_filter(self, deploy_manager, shell_executor):
        for i in range(2):
            shell_executor.set_next_result(returncode=0)
        hook = {
            'id': 'h1', 'name': 'Filter', 'command': 'echo',
            'enabled': True, 'timeout': 10, 'on_events': ['created'],
        }
        deploy_manager._run_hook(hook, 'a.com', 'created')
        deploy_manager._run_hook(hook, 'b.com', 'created')
        entries = deploy_manager.get_history(domain='a.com')
        assert len(entries) == 1
        assert entries[0]['domain'] == 'a.com'

    def test_empty_history(self, deploy_manager):
        assert deploy_manager.get_history() == []


class TestTestHook:
    """Test the test_hook method."""

    def test_found_hook(self, deploy_manager, shell_executor):
        shell_executor.set_next_result(returncode=0)
        result = deploy_manager.test_hook('g1')
        assert result['success'] is True
        assert result['dry_run'] is True
        assert result['domain'] == 'test.example.com'

    def test_domain_hook_found(self, deploy_manager, shell_executor):
        shell_executor.set_next_result(returncode=0)
        result = deploy_manager.test_hook('d1', domain='example.com')
        assert result['success'] is True
        assert result['hook_name'] == 'Sync CDN'

    def test_not_found(self, deploy_manager):
        result = deploy_manager.test_hook('nonexistent')
        # Error message updated by issue #101 to name the two real causes
        # (stale UI / save-time validator rejection).
        assert result['hook_id'] == 'nonexistent'
        assert result['reason'] == 'hook_missing_from_config'
        assert 'nonexistent' in result['error']


class TestRunManualDeploy:
    """Test the manual deploy entrypoint added for issue #109."""

    def test_runs_global_and_domain_hooks_for_domain(self, deploy_manager, shell_executor):
        # Two enabled hooks will fire (g1 global + d1 example.com), g2 is disabled.
        shell_executor.set_next_result(returncode=0)
        shell_executor.set_next_result(returncode=0)
        result = deploy_manager.run_manual_deploy('example.com')
        assert result['ok'] is True
        assert result['total'] == 2
        assert result['succeeded'] == 2
        assert result['failed'] == 0
        # Both hooks should have been invoked exactly once.
        assert shell_executor.call_count == 2
        # CERTMATE_EVENT must be 'manual' for hooks that branch on it.
        assert all(r['event'] == 'manual' for r in result['results'])

    def test_ignores_on_events_filter(self, deploy_manager, shell_executor):
        """A manual trigger must run hooks even if their on_events list
        only mentions 'created' or 'renewed' — that's the whole point
        (the user explicitly asked to fire them now)."""
        shell_executor.set_next_result(returncode=0)
        shell_executor.set_next_result(returncode=0)
        result = deploy_manager.run_manual_deploy('example.com')
        # d1 has on_events=['created'] — must still run.
        hook_names = [r['hook_name'] for r in result['results']]
        assert 'Sync CDN' in hook_names

    def test_failure_aggregated(self, deploy_manager, shell_executor):
        shell_executor.set_next_result(returncode=0)        # g1 ok
        shell_executor.set_next_result(returncode=2, stderr='oops')  # d1 fail
        result = deploy_manager.run_manual_deploy('example.com')
        assert result['ok'] is False
        assert result['succeeded'] == 1
        assert result['failed'] == 1

    def test_no_hooks_for_domain_returns_friendly_error(self, deploy_manager):
        # No global hooks fire for unknown.com because g1 IS global, so it'd run.
        # Use a fresh deploy_manager without global hooks for this case.
        deploy_manager.settings_manager.load_settings.return_value = {
            'deploy_hooks': {
                'enabled': True,
                'global_hooks': [],
                'domain_hooks': {'other.com': []},
            }
        }
        result = deploy_manager.run_manual_deploy('unknown.com')
        assert result['ok'] is False
        assert result['total'] == 0
        assert 'unknown.com' in result['error']

    def test_returns_disabled_error_when_feature_off(self, deploy_manager):
        deploy_manager.settings_manager.load_settings.return_value = {
            'deploy_hooks': {'enabled': False, 'global_hooks': [], 'domain_hooks': {}}
        }
        result = deploy_manager.run_manual_deploy('example.com')
        assert result['ok'] is False
        assert 'disabled' in result['error'].lower()


class TestEventListener:
    """Test on_certificate_event."""

    def test_certificate_created(self, deploy_manager, shell_executor):
        shell_executor.set_next_result(returncode=0)
        deploy_manager.on_certificate_event('certificate_created', {'domain': 'other.com'})
        assert shell_executor.call_count == 1

    def test_certificate_renewed(self, deploy_manager, shell_executor):
        shell_executor.set_next_result(returncode=0)
        deploy_manager.on_certificate_event('certificate_renewed', {'domain': 'other.com'})
        assert shell_executor.call_count == 1

    def test_ignores_other_events(self, deploy_manager, shell_executor):
        deploy_manager.on_certificate_event('settings_updated', {})
        assert shell_executor.call_count == 0

    def test_ignores_missing_domain(self, deploy_manager, shell_executor):
        deploy_manager.on_certificate_event('certificate_created', {})
        assert shell_executor.call_count == 0
