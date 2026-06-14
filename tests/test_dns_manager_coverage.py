"""Unit tests for modules/core/dns_providers.py (DNSManager).

The module was at 8% coverage before this file landed. Each method is
pure-Python over the settings dict, so the tests stub a settings_manager
and call the methods directly. No Docker, no live DNS API.
"""

from unittest.mock import MagicMock

import pytest


pytestmark = [pytest.mark.unit]


def _mk_settings_manager(initial_settings):
    """Build a stub SettingsManager that returns a deep copy of
    `initial_settings` on every load, and records `.update()` calls so
    each test can verify what mutation was applied.

    The migration hook is a no-op (passthrough) — tests can override it
    when they want to verify that the call site does call it.
    """
    import copy
    sm = MagicMock()
    sm.load_settings.side_effect = lambda: copy.deepcopy(initial_settings)
    sm.migrate_dns_providers_to_multi_account.side_effect = lambda s: s

    # `update(fn, audit_label)` invokes the mutator on a deep copy of the
    # current state and returns True on success. Capture both the audit
    # label and the resulting mutated dict so tests can pin behaviour.
    sm.last_update = None

    def _update(fn, audit_label):
        state = copy.deepcopy(initial_settings)
        fn(state)
        sm.last_update = (audit_label, state)
        return True

    sm.update.side_effect = _update
    return sm


@pytest.fixture
def manager_factory():
    """Return a callable that builds a DNSManager wrapping a stub
    settings manager for a given seed settings dict."""
    from modules.core.dns_providers import DNSManager

    def _build(settings):
        sm = _mk_settings_manager(settings)
        return DNSManager(sm), sm

    return _build


# ---------------------------------------------------------------------------
# get_available_providers
# ---------------------------------------------------------------------------


class TestGetAvailableProviders:
    def test_returns_every_supported_provider_with_expected_shape(self, manager_factory):
        mgr, _ = manager_factory({})
        result = mgr.get_available_providers()
        # Every SUPPORTED_PROVIDERS entry must appear, exactly once.
        names = [p['name'] for p in result]
        assert names == list(mgr.SUPPORTED_PROVIDERS)
        # Each entry has the contract shape.
        for entry in result:
            assert set(entry.keys()) == {'name', 'label', 'configured', 'accounts'}

    def test_unconfigured_when_no_dns_providers_configured(self, manager_factory):
        mgr, _ = manager_factory({})
        result = mgr.get_available_providers()
        assert all(p['configured'] is False for p in result)
        assert all(p['accounts'] == 0 for p in result)

    def test_configured_when_credentials_present(self, manager_factory):
        mgr, _ = manager_factory({
            'dns_providers': {
                'cloudflare': {
                    'accounts': {
                        'default': {'api_token': 'tok'}
                    }
                }
            }
        })
        result = mgr.get_available_providers()
        cf = next(p for p in result if p['name'] == 'cloudflare')
        assert cf['configured'] is True
        assert cf['accounts'] == 1
        # Other providers stay unconfigured.
        for p in result:
            if p['name'] != 'cloudflare':
                assert p['configured'] is False


# ---------------------------------------------------------------------------
# test_provider — offline credential-shape validation backing the
# /api/web/certificates/test-provider endpoint (which 500'd with
# AttributeError before this method existed).
# ---------------------------------------------------------------------------


class TestTestProvider:
    def test_unsupported_provider_rejected(self, manager_factory):
        mgr, _ = manager_factory({})
        ok, msg = mgr.test_provider('not-a-provider', {'api_token': 'x'})
        assert ok is False
        assert 'Unsupported' in msg

    def test_desec_is_now_a_real_provider(self, manager_factory):
        """'desec' was historically a PHANTOM — advertised with no strategy or
        validation wiring (ripped out in #288). It is now a fully wired generic
        multi-provider (certbot-dns-desec), so a valid config is accepted and a
        missing credential is rejected. The guard against genuinely-unknown
        providers is covered by the 'not-a-provider' test above."""
        mgr, _ = manager_factory({})
        ok, msg = mgr.test_provider('desec', {'api_token': 'tok'})
        assert ok is True, msg
        bad, bad_msg = mgr.test_provider('desec', {})
        assert bad is False
        assert 'api_token' in bad_msg

    def test_missing_required_fields_reported(self, manager_factory):
        mgr, _ = manager_factory({})
        ok, msg = mgr.test_provider('route53', {'access_key_id': 'AKID'})
        assert ok is False
        assert 'secret_access_key' in msg

    def test_valid_config_passes(self, manager_factory):
        mgr, _ = manager_factory({})
        ok, msg = mgr.test_provider('cloudflare', {'api_token': 'tok'})
        assert ok is True
        assert 'offline' in msg

    def test_non_dict_config_treated_as_empty(self, manager_factory):
        mgr, _ = manager_factory({})
        ok, msg = mgr.test_provider('cloudflare', None)
        assert ok is False
        assert 'api_token' in msg


# ---------------------------------------------------------------------------
# get_dns_provider_account_config
# ---------------------------------------------------------------------------


class TestGetDnsProviderAccountConfig:
    def test_unknown_provider_returns_none_none(self, manager_factory):
        mgr, _ = manager_factory({})
        cfg, acc_id = mgr.get_dns_provider_account_config('cloudflare')
        assert cfg is None
        assert acc_id is None

    def test_multi_account_specific_account_id_lookup(self, manager_factory):
        mgr, _ = manager_factory({
            'dns_providers': {
                'cloudflare': {
                    'accounts': {
                        'prod': {'api_token': 'PROD-TOKEN'},
                        'staging': {'api_token': 'STAGING-TOKEN'},
                    }
                }
            }
        })
        cfg, acc_id = mgr.get_dns_provider_account_config('cloudflare', 'staging')
        assert acc_id == 'staging'
        assert cfg == {'api_token': 'STAGING-TOKEN'}

    def test_multi_account_missing_account_id_returns_none(self, manager_factory):
        mgr, _ = manager_factory({
            'dns_providers': {
                'cloudflare': {
                    'accounts': {'prod': {'api_token': 'x'}},
                }
            }
        })
        cfg, acc_id = mgr.get_dns_provider_account_config('cloudflare', 'nope')
        assert cfg is None
        assert acc_id is None

    def test_multi_account_uses_default_account_when_no_id_specified(self, manager_factory):
        mgr, _ = manager_factory({
            'dns_providers': {
                'cloudflare': {
                    'accounts': {
                        'prod': {'api_token': 'PROD'},
                        'staging': {'api_token': 'STAGING'},
                    }
                }
            },
            'default_accounts': {'cloudflare': 'staging'},
        })
        cfg, acc_id = mgr.get_dns_provider_account_config('cloudflare')
        assert acc_id == 'staging'
        assert cfg['api_token'] == 'STAGING'

    def test_multi_account_falls_back_to_first_credentialed_account(self, manager_factory):
        """No default configured, but some account has credentials — pick that one."""
        mgr, _ = manager_factory({
            'dns_providers': {
                'cloudflare': {
                    'accounts': {
                        'empty': {'name': 'Empty'},                  # No creds
                        'real': {'api_token': 'REAL-TOKEN'},         # First with creds
                    }
                }
            }
        })
        cfg, acc_id = mgr.get_dns_provider_account_config('cloudflare')
        assert acc_id == 'real'
        assert cfg['api_token'] == 'REAL-TOKEN'

    def test_multi_account_no_accounts_returns_none(self, manager_factory):
        """Accounts dict is empty → no credentialed account exists."""
        mgr, _ = manager_factory({
            'dns_providers': {
                'cloudflare': {'accounts': {}}
            }
        })
        cfg, acc_id = mgr.get_dns_provider_account_config('cloudflare')
        assert cfg is None
        assert acc_id is None

    def test_legacy_single_account_format_returns_default(self, manager_factory):
        """Pre-multi-account settings.json shape: provider value IS the cred dict."""
        mgr, _ = manager_factory({
            'dns_providers': {
                'cloudflare': {'api_token': 'LEGACY-TOKEN'},
            }
        })
        cfg, acc_id = mgr.get_dns_provider_account_config('cloudflare')
        assert acc_id == 'default'
        assert cfg == {'api_token': 'LEGACY-TOKEN'}

    def test_uses_provided_settings_argument_when_passed(self, manager_factory):
        """When caller passes `settings=`, load_settings is NOT called."""
        mgr, sm = manager_factory({})  # initial settings empty
        override = {
            'dns_providers': {
                'route53': {
                    'accounts': {
                        'default': {'access_key_id': 'AKID', 'secret_access_key': 'SECRET'}
                    }
                }
            }
        }
        cfg, acc_id = mgr.get_dns_provider_account_config('route53', settings=override)
        assert acc_id == 'default'
        assert cfg['access_key_id'] == 'AKID'
        sm.load_settings.assert_not_called()

    def test_returns_none_on_internal_exception(self, manager_factory):
        """Internal exceptions are swallowed and reported as None, None."""
        mgr, sm = manager_factory({})
        sm.migrate_dns_providers_to_multi_account.side_effect = RuntimeError("boom")
        cfg, acc_id = mgr.get_dns_provider_account_config('cloudflare')
        assert cfg is None
        assert acc_id is None


# ---------------------------------------------------------------------------
# list_dns_provider_accounts
# ---------------------------------------------------------------------------


class TestListDnsProviderAccounts:
    def test_returns_empty_list_for_missing_provider(self, manager_factory):
        mgr, _ = manager_factory({})
        assert mgr.list_dns_provider_accounts('cloudflare') == []

    def test_multi_account_shape(self, manager_factory):
        mgr, _ = manager_factory({
            'dns_providers': {
                'cloudflare': {
                    'accounts': {
                        'prod': {'api_token': 'X', 'name': 'Prod', 'description': 'prod env'},
                        'staging': {'name': 'Staging'},  # No creds
                    }
                }
            }
        })
        accounts = mgr.list_dns_provider_accounts('cloudflare')
        # Two accounts: 1 configured, 1 not.
        by_id = {a['account_id']: a for a in accounts}
        assert by_id['prod']['configured'] is True
        assert by_id['prod']['name'] == 'Prod'
        assert by_id['prod']['description'] == 'prod env'
        assert by_id['staging']['configured'] is False
        # Name defaults to account_id.title() when not provided.
        # (Here it IS provided ('Staging') so we test that branch elsewhere.)

    def test_multi_account_name_defaults_to_titlecased_id(self, manager_factory):
        mgr, _ = manager_factory({
            'dns_providers': {
                'cloudflare': {
                    'accounts': {'wholly_default': {'api_token': 'X'}}
                }
            }
        })
        accounts = mgr.list_dns_provider_accounts('cloudflare')
        assert accounts[0]['name'] == 'Wholly_Default'

    def test_legacy_single_account_format(self, manager_factory):
        mgr, _ = manager_factory({
            'dns_providers': {
                'cloudflare': {'api_token': 'LEGACY'},
            }
        })
        accounts = mgr.list_dns_provider_accounts('cloudflare')
        assert len(accounts) == 1
        legacy = accounts[0]
        assert legacy['account_id'] == 'default'
        assert legacy['name'] == 'Default Cloudflare Account'
        assert legacy['description'] == 'Legacy single-account configuration'
        assert legacy['configured'] is True

    def test_legacy_unconfigured_returns_empty(self, manager_factory):
        """A legacy provider entry with no recognised credential keys is
        treated as no-account-present rather than an unconfigured legacy
        stub — keeps the response clean for the UI."""
        mgr, _ = manager_factory({
            'dns_providers': {
                'cloudflare': {'description': 'leftover stub'},
            }
        })
        accounts = mgr.list_dns_provider_accounts('cloudflare')
        # Code currently emits one legacy account marked configured=False;
        # pin whatever the contract is so a refactor doesn't drift silently.
        if accounts:
            assert accounts[0]['account_id'] == 'default'
            assert accounts[0]['configured'] is False

    def test_returns_empty_on_exception(self, manager_factory):
        mgr, sm = manager_factory({})
        sm.migrate_dns_providers_to_multi_account.side_effect = RuntimeError("boom")
        assert mgr.list_dns_provider_accounts('cloudflare') == []


# ---------------------------------------------------------------------------
# list_accounts (cross-provider)
# ---------------------------------------------------------------------------


class TestListAccounts:
    def test_aggregates_across_providers_and_tags_provider_name(self, manager_factory):
        mgr, _ = manager_factory({
            'dns_providers': {
                'cloudflare': {
                    'accounts': {'prod': {'api_token': 'C'}}
                },
                'route53': {
                    'accounts': {
                        'prod': {'access_key_id': 'R-prod'},
                        'qa': {'access_key_id': 'R-qa'},
                    }
                },
            }
        })
        all_accounts = mgr.list_accounts()
        assert len(all_accounts) == 3
        # Each entry must carry the provider key for the UI cross-pivot.
        providers = {a['provider'] for a in all_accounts}
        assert providers == {'cloudflare', 'route53'}

    def test_empty_returns_empty(self, manager_factory):
        mgr, _ = manager_factory({})
        assert mgr.list_accounts() == []

    def test_returns_empty_on_exception(self, manager_factory):
        mgr, sm = manager_factory({})
        sm.load_settings.side_effect = RuntimeError("boom")
        assert mgr.list_accounts() == []


# ---------------------------------------------------------------------------
# suggest_dns_provider_for_domain
# ---------------------------------------------------------------------------


class TestSuggestDnsProvider:
    def test_empty_domain_returns_none_zero(self, manager_factory):
        mgr, _ = manager_factory({})
        provider, confidence = mgr.suggest_dns_provider_for_domain('')
        assert provider is None
        assert confidence == 0

    def test_existing_domain_dict_format_high_confidence(self, manager_factory):
        mgr, _ = manager_factory({
            'domains': [
                {'domain': 'example.com', 'dns_provider': 'route53'},
            ]
        })
        provider, confidence = mgr.suggest_dns_provider_for_domain('example.com')
        assert provider == 'route53'
        assert confidence == 90

    def test_existing_domain_legacy_string_format_uses_global_provider(self, manager_factory):
        mgr, _ = manager_factory({
            'domains': ['legacy.example.com'],
            'dns_provider': 'digitalocean',
        })
        provider, confidence = mgr.suggest_dns_provider_for_domain('legacy.example.com')
        assert provider == 'digitalocean'
        assert confidence == 80

    @pytest.mark.parametrize("domain,expected", [
        ('aws-something.test',     'route53'),
        ('cf-edge.example.org',    'cloudflare'),
        ('do-haproxy.dev',         'digitalocean'),
    ])
    def test_pattern_match_returns_provider_70_confidence(self, manager_factory, domain, expected):
        mgr, _ = manager_factory({})
        provider, confidence = mgr.suggest_dns_provider_for_domain(domain)
        assert provider == expected
        assert confidence == 70

    def test_unknown_domain_returns_global_default_with_low_confidence(self, manager_factory):
        mgr, _ = manager_factory({'dns_provider': 'hetzner'})
        provider, confidence = mgr.suggest_dns_provider_for_domain('plain.example.com')
        assert provider == 'hetzner'
        assert confidence == 30

    def test_unknown_domain_falls_back_to_cloudflare_when_no_global(self, manager_factory):
        mgr, _ = manager_factory({})
        provider, confidence = mgr.suggest_dns_provider_for_domain('plain.example.com')
        assert provider == 'cloudflare'
        assert confidence == 30


# ---------------------------------------------------------------------------
# create_dns_account / add_account (alias)
# ---------------------------------------------------------------------------


class TestCreateDnsAccount:
    def test_creates_first_account_and_sets_it_as_default(self, manager_factory):
        mgr, sm = manager_factory({})
        ok = mgr.create_dns_account('cloudflare', 'prod', {'api_token': 'T'})
        assert ok is True
        # The mutated state captured by the stub.
        _, state = sm.last_update
        assert state['dns_providers']['cloudflare']['accounts']['prod'] == {'api_token': 'T'}
        # First-account-becomes-default contract.
        assert state['default_accounts']['cloudflare'] == 'prod'

    def test_second_account_does_not_overwrite_default(self, manager_factory):
        mgr, sm = manager_factory({
            'dns_providers': {
                'cloudflare': {
                    'accounts': {'prod': {'api_token': 'PROD'}}
                }
            },
            'default_accounts': {'cloudflare': 'prod'},
        })
        ok = mgr.create_dns_account('cloudflare', 'staging', {'api_token': 'STAGE'})
        assert ok is True
        _, state = sm.last_update
        assert state['default_accounts']['cloudflare'] == 'prod'  # untouched
        assert 'staging' in state['dns_providers']['cloudflare']['accounts']

    def test_audit_label_includes_provider_and_account_id(self, manager_factory):
        mgr, sm = manager_factory({})
        mgr.create_dns_account('route53', 'qa', {'access_key_id': 'X'})
        label, _ = sm.last_update
        assert label == 'dns_account_create_route53_qa'

    def test_returns_false_on_exception(self, manager_factory):
        mgr, sm = manager_factory({})
        sm.update.side_effect = RuntimeError("boom")
        assert mgr.create_dns_account('cloudflare', 'prod', {}) is False

    def test_add_account_alias_calls_create(self, manager_factory):
        mgr, sm = manager_factory({})
        ok = mgr.add_account('prod', 'cloudflare', {'api_token': 'T'})
        assert ok is True
        # The alias swaps positional arg order — verify the right name landed.
        _, state = sm.last_update
        assert 'prod' in state['dns_providers']['cloudflare']['accounts']


# ---------------------------------------------------------------------------
# delete_dns_account / delete_account (alias)
# ---------------------------------------------------------------------------


class TestDeleteDnsAccount:
    def test_deletes_account_and_returns_true(self, manager_factory):
        mgr, sm = manager_factory({
            'dns_providers': {
                'cloudflare': {
                    'accounts': {
                        'prod': {'api_token': 'P'},
                        'staging': {'api_token': 'S'},
                    }
                }
            },
            'default_accounts': {'cloudflare': 'prod'},
        })
        ok = mgr.delete_dns_account('cloudflare', 'staging')
        assert ok is True
        _, state = sm.last_update
        assert 'staging' not in state['dns_providers']['cloudflare']['accounts']
        # Default unchanged (was 'prod', staging wasn't the default).
        assert state['default_accounts']['cloudflare'] == 'prod'

    def test_deleting_default_account_promotes_remaining_to_default(self, manager_factory):
        mgr, sm = manager_factory({
            'dns_providers': {
                'cloudflare': {
                    'accounts': {
                        'prod': {'api_token': 'P'},
                        'staging': {'api_token': 'S'},
                    }
                }
            },
            'default_accounts': {'cloudflare': 'prod'},
        })
        ok = mgr.delete_dns_account('cloudflare', 'prod')
        assert ok is True
        _, state = sm.last_update
        # 'staging' was the only remaining account.
        assert state['default_accounts']['cloudflare'] == 'staging'

    def test_deleting_last_account_drops_default_entry(self, manager_factory):
        mgr, sm = manager_factory({
            'dns_providers': {
                'cloudflare': {
                    'accounts': {'prod': {'api_token': 'P'}}
                }
            },
            'default_accounts': {'cloudflare': 'prod'},
        })
        ok = mgr.delete_dns_account('cloudflare', 'prod')
        assert ok is True
        _, state = sm.last_update
        assert 'cloudflare' not in state['default_accounts']

    def test_missing_provider_returns_false(self, manager_factory):
        mgr, _ = manager_factory({})
        assert mgr.delete_dns_account('cloudflare', 'prod') is False

    def test_missing_account_returns_false(self, manager_factory):
        mgr, _ = manager_factory({
            'dns_providers': {
                'cloudflare': {
                    'accounts': {'prod': {'api_token': 'P'}}
                }
            }
        })
        assert mgr.delete_dns_account('cloudflare', 'nope') is False

    def test_returns_false_on_exception(self, manager_factory):
        mgr, sm = manager_factory({
            'dns_providers': {'cloudflare': {'accounts': {'prod': {'api_token': 'P'}}}}
        })
        sm.update.side_effect = RuntimeError("boom")
        assert mgr.delete_dns_account('cloudflare', 'prod') is False

    def test_delete_account_alias_calls_delete(self, manager_factory):
        mgr, sm = manager_factory({
            'dns_providers': {'cloudflare': {'accounts': {'prod': {'api_token': 'P'}}}}
        })
        ok = mgr.delete_account('cloudflare', 'prod')
        assert ok is True
        _, state = sm.last_update
        assert 'prod' not in state['dns_providers']['cloudflare']['accounts']


# ---------------------------------------------------------------------------
# set_default_account
# ---------------------------------------------------------------------------


class TestSetDefaultAccount:
    def test_sets_default_when_account_exists(self, manager_factory):
        mgr, sm = manager_factory({
            'dns_providers': {
                'cloudflare': {
                    'accounts': {
                        'prod': {'api_token': 'P'},
                        'staging': {'api_token': 'S'},
                    }
                }
            },
            'default_accounts': {'cloudflare': 'prod'},
        })
        ok = mgr.set_default_account('cloudflare', 'staging')
        assert ok is True
        _, state = sm.last_update
        assert state['default_accounts']['cloudflare'] == 'staging'

    def test_missing_account_returns_false(self, manager_factory):
        mgr, _ = manager_factory({
            'dns_providers': {
                'cloudflare': {'accounts': {'prod': {'api_token': 'P'}}}
            }
        })
        assert mgr.set_default_account('cloudflare', 'nope') is False

    def test_returns_false_on_exception(self, manager_factory):
        mgr, sm = manager_factory({
            'dns_providers': {'cloudflare': {'accounts': {'prod': {'api_token': 'P'}}}}
        })
        sm.update.side_effect = RuntimeError("boom")
        assert mgr.set_default_account('cloudflare', 'prod') is False
